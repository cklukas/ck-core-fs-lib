// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "metadata_replay.hpp"
#include <algorithm>

namespace ck::files {
namespace {
template<class T> Observation<T> fail(const char* op, ObservationState state = ObservationState::Unsupported,
                                      AdapterError code = AdapterError::ProviderReviewRequired) {
    return Observation<T>::unavailable(state, {ErrorDomain::Adapter, static_cast<std::int64_t>(code), op});
}
template<class T> Observation<T> propagate(const UnavailableObservation& e) {
    return Observation<T>::unavailable(e.state, e.error);
}
template<class T> bool equal(const Observation<T>& a, const Observation<T>& b) {
    if (a.value() || b.value()) return a.value() && b.value() && *a.value() == *b.value();
    return a.state() == b.state();
}
bool identity(const Observation<ObjectIdentity>& a, const Observation<ObjectIdentity>& b) {
    return a.value() && b.value() && compare_identity(*a.value(), *b.value()) == IdentityComparison::Same;
}
bool stable(const BasicMetadata& a, const BasicMetadata& b) {
    return identity(a.identity,b.identity) && equal(a.kind,b.kind) && equal(a.logical_size,b.logical_size) &&
        equal(a.link_count,b.link_count) && equal(a.modified,b.modified) && equal(a.changed,b.changed) &&
        equal(a.created,b.created) && equal(a.posix_uid,b.posix_uid) && equal(a.posix_gid,b.posix_gid) &&
        equal(a.posix_permissions,b.posix_permissions) && equal(a.bsd_flags,b.bsd_flags) &&
        equal(a.windows_attributes,b.windows_attributes);
}
bool attributes_equal(const std::vector<AttributeValue>& a, const std::vector<AttributeValue>& b) {
    if (a.size()!=b.size()) return false;
    for (const auto& x:a) {
        const auto y=std::find_if(b.begin(),b.end(),[&](const auto& v){return v.identifier==x.identifier;});
        if(y==b.end() || x.bytes!=y->bytes || !equal(x.native_flags,y->native_flags)) return false;
    }
    return true;
}
Observation<bool> interrupted() { return fail<bool>("metadata_replay.cancelled",ObservationState::Unknown,AdapterError::InterruptedRead); }
}
bool MetadataReplayPolicy::valid() const noexcept {
    return version==1 && limits.valid() && (scope==RegularMetadataScope::CompleteMetadataV1 ||
        scope==RegularMetadataScope::OrdinaryCallerVisibleV1) &&
        (ownership==MetadataOwnership::Original || ownership==MetadataOwnership::CurrentCaller);
}
Observation<MetadataReplaySnapshot> capture_metadata_replay(const OpenedEntry& entry, MetadataReplayPolicy policy,
                                                            std::stop_token stop) {
    using Result=Observation<MetadataReplaySnapshot>;
    if(!policy.valid()) return fail<MetadataReplaySnapshot>("metadata_replay.policy",ObservationState::Failed,AdapterError::InvalidIdentifier);
    if(stop.stop_requested()) return propagate<MetadataReplaySnapshot>(*interrupted().unavailable_detail());
    auto before=entry.inspect_basic();
    if(!before.value()) return propagate<MetadataReplaySnapshot>(*before.unavailable_detail());
    auto qualified=entry.qualify_metadata_replay(policy);
    if(!qualified.value()) return propagate<MetadataReplaySnapshot>(*qualified.unavailable_detail());
    if(!*qualified.value()) return fail<MetadataReplaySnapshot>("metadata_replay.provider_not_qualified");
    auto view=entry.open_metadata_replay_view(policy);
    if(!view.value()) return propagate<MetadataReplaySnapshot>(*view.unavailable_detail());
    const auto& query=*view.value() ? **view.value() : entry;
    MetadataReplaySnapshot result;result.policy=policy;result.basic=*before.value();
    const auto& basic=result.basic;
    if(!basic.kind.value() || *basic.kind.value()!=ObjectKind::RegularFile || !basic.logical_size.value() ||
       !basic.accessed.value() || !basic.modified.value() || !basic.changed.value() ||
       !basic.identity.value() || !identity(basic.identity,basic.identity))
        return fail<MetadataReplaySnapshot>("metadata_replay.required_basic");
    if(basic.posix_permissions.value() && (*basic.posix_permissions.value() & 07000U) && !policy.allow_privilege_metadata)
        return fail<MetadataReplaySnapshot>("metadata_replay.privilege_bits_require_optin");
    auto catalog=query.inspect_attributes(policy.limits);
    if(!catalog.value()) return propagate<MetadataReplaySnapshot>(*catalog.unavailable_detail());
    if(!identity(catalog.value()->owner,basic.identity) || catalog.value()->coverage==AttributeCoverage::Unknown)
        return fail<MetadataReplaySnapshot>("metadata_replay.attribute_owner_coverage");
    result.attribute_coverage=catalog.value()->coverage;
    std::size_t total=0;
    for(const auto& descriptor:catalog.value()->attributes) {
        if(stop.stop_requested()) return propagate<MetadataReplaySnapshot>(*interrupted().unavailable_detail());
        const auto* name=descriptor.identifier.posix_bytes();
        if(name && (name->starts_with("security.") || *name=="com.apple.macl" || *name=="com.apple.rootless" || name->starts_with("trusted.")) &&
           !policy.allow_privilege_metadata) return fail<MetadataReplaySnapshot>("metadata_replay.security_attribute_requires_optin");
        if(name && (name->starts_with("com.apple.fileprovider.") || *name=="security.ima" || *name=="security.evm"))
            return fail<MetadataReplaySnapshot>("metadata_replay.provider_or_integrity_attribute_unimplemented");
        if(descriptor.role==AttributeRole::StorageRepresentation || descriptor.role==AttributeRole::InterpretationRequired)
            return fail<MetadataReplaySnapshot>("metadata_replay.attribute_provider");
        auto value=query.read_attribute(descriptor.identifier,policy.limits);
        if(!value.value()) return propagate<MetadataReplaySnapshot>(*value.unavailable_detail());
        if(value.value()->identifier!=descriptor.identifier || !identity(value.value()->owner,basic.identity) || !descriptor.value_size.value() ||
           *descriptor.value_size.value()!=value.value()->bytes.size())
            return fail<MetadataReplaySnapshot>("metadata_replay.attribute_changed",ObservationState::Changed,AdapterError::MetadataChanged);
        if(value.value()->bytes.size()>policy.limits.max_native_bytes-total)
            return fail<MetadataReplaySnapshot>("metadata_replay.aggregate_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        total+=value.value()->bytes.size();
        result.attributes.push_back(std::move(value).take_value());
    }
    const auto storage=query.inspect_storage();
    if(!storage.value() || !identity(storage.value()->owner,basic.identity))
        return fail<MetadataReplaySnapshot>("metadata_replay.storage_owner");
    std::vector<SecurityPart> parts;
    switch(storage.value()->model) {
    case StorageModel::DarwinStatFlags: parts={SecurityPart::DarwinExtendedAcl}; break;
    case StorageModel::LinuxStatx: parts={SecurityPart::LinuxAccessAcl}; break;
    case StorageModel::WindowsHandleAttributes:
        parts=policy.scope==RegularMetadataScope::CompleteMetadataV1 ?
            std::vector{SecurityPart::WindowsFullDescriptor} :
            std::vector{SecurityPart::WindowsAccess,SecurityPart::WindowsIntegrity}; break;
    default:return fail<MetadataReplaySnapshot>("metadata_replay.security_model");
    }
    for(const auto part:parts) {
        auto security=query.read_security(part,policy.limits);
        if(!security.value()) return propagate<MetadataReplaySnapshot>(*security.unavailable_detail());
        if(!identity(security.value()->owner,basic.identity) || security.value()->presence==SecurityPresence::Unknown ||
           security.value()->part!=part || security.value()->encoding==SecurityEncoding::Unknown)
            return fail<MetadataReplaySnapshot>("metadata_replay.security_owner_presence");
        if(security.value()->bytes.size()>policy.limits.max_native_bytes-total)
            return fail<MetadataReplaySnapshot>("metadata_replay.aggregate_security_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        total+=security.value()->bytes.size(); result.security.push_back(std::move(security).take_value());
    }
    auto after=entry.inspect_basic();
    if(!after.value()) return propagate<MetadataReplaySnapshot>(*after.unavailable_detail());
    if(!stable(basic,*after.value())) return fail<MetadataReplaySnapshot>("metadata_replay.capture_changed",ObservationState::Changed,AdapterError::MetadataChanged);
    if(stop.stop_requested()) return propagate<MetadataReplaySnapshot>(*interrupted().unavailable_detail());
    return Result::available(std::move(result));
}
Observation<bool> verify_metadata_replay_source(const OpenedEntry& entry,const MetadataReplaySnapshot& snapshot,std::stop_token stop) {
    auto fresh=capture_metadata_replay(entry,snapshot.policy,stop);
    if(!fresh.value()) return propagate<bool>(*fresh.unavailable_detail());
    if(!stable(snapshot.basic,fresh.value()->basic) || snapshot.attribute_coverage!=fresh.value()->attribute_coverage ||
       !attributes_equal(snapshot.attributes,fresh.value()->attributes) || snapshot.security.size()!=fresh.value()->security.size())
        return fail<bool>("metadata_replay.source_changed",ObservationState::Changed,AdapterError::MetadataChanged);
    for(std::size_t i=0;i<snapshot.security.size();++i) {
        const auto& a=snapshot.security[i];const auto& b=fresh.value()->security[i];
        if(a.part!=b.part || a.presence!=b.presence || a.encoding!=b.encoding || a.bytes!=b.bytes || a.native_query_mask!=b.native_query_mask)
            return fail<bool>("metadata_replay.source_security_changed",ObservationState::Changed,AdapterError::MetadataChanged);
    }
    return Observation<bool>::available(true);
}
Observation<bool> apply_metadata_replay(OpenedEntry& target,const MetadataReplaySnapshot& snapshot,std::stop_token stop) {
    if(stop.stop_requested()) return interrupted();
    if(!snapshot.policy.valid()) return fail<bool>("metadata_replay.apply_policy",ObservationState::Failed,AdapterError::InvalidIdentifier);
    for(std::size_t i=0;i<snapshot.attributes.size();++i) {
        if(!identity(snapshot.attributes[i].owner,snapshot.basic.identity))
            return fail<bool>("metadata_replay.apply_attribute_owner",ObservationState::Failed,AdapterError::UnqualifiedIdentity);
        for(std::size_t j=0;j<i;++j) if(snapshot.attributes[i].identifier==snapshot.attributes[j].identifier)
            return fail<bool>("metadata_replay.apply_duplicate_attribute",ObservationState::Failed,AdapterError::InvalidIdentifier);
    }
    for(const auto& security:snapshot.security) if(!identity(security.owner,snapshot.basic.identity))
        return fail<bool>("metadata_replay.apply_security_owner",ObservationState::Failed,AdapterError::UnqualifiedIdentity);
    auto qualified=target.qualify_metadata_replay(snapshot.policy);
    if(!qualified.value() || !*qualified.value()) return qualified;
    const auto target_before=target.inspect_basic();
    if(!target_before.value()) return propagate<bool>(*target_before.unavailable_detail());
    if(!equal(target_before.value()->kind,snapshot.basic.kind) || !equal(target_before.value()->logical_size,snapshot.basic.logical_size))
        return fail<bool>("metadata_replay.target_data_shape",ObservationState::Changed,AdapterError::MetadataChanged);
    auto result=target.apply_replay_ownership(snapshot.basic,snapshot.policy);
    if(!result.value() || !*result.value()) return result;
    // Replace inherited attributes as a set; never report success with extras.
    auto existing=target.inspect_attributes(snapshot.policy.limits);
    if(!existing.value()) return propagate<bool>(*existing.unavailable_detail());
    for(const auto& x:existing.value()->attributes) {
        if(stop.stop_requested()) return interrupted();
        if(std::none_of(snapshot.attributes.begin(),snapshot.attributes.end(),[&](const auto& a){return a.identifier==x.identifier;})) {
            result=target.remove_replay_attribute(x.identifier,snapshot.policy);
            if(!result.value() || !*result.value()) return result;
        }
    }
    // Mode establishes the POSIX ACL mask before the exact ACL is replayed.
    result=target.apply_replay_basic(snapshot.basic,snapshot.policy);
    if(!result.value() || !*result.value()) return result;
    for(const auto& security:snapshot.security) {
        if(stop.stop_requested()) return interrupted();
        result=target.apply_replay_security(security,snapshot.policy);
        if(!result.value() || !*result.value()) return result;
    }
    for(const auto& x:snapshot.attributes) {
        if(stop.stop_requested()) return interrupted();
        result=target.apply_replay_attribute(x,snapshot.policy);
        if(!result.value() || !*result.value()) return result;
    }
    if(stop.stop_requested()) return interrupted();
    result=target.apply_replay_basic(snapshot.basic,snapshot.policy);
    if(!result.value() || !*result.value()) return result;
    const auto target_after=target.inspect_basic();
    if(!target_after.value()) return propagate<bool>(*target_after.unavailable_detail());
    if(!identity(target_before.value()->identity,target_after.value()->identity))
        return fail<bool>("metadata_replay.apply_target_identity",ObservationState::Changed,AdapterError::MetadataChanged);
    return Observation<bool>::available(true);
}
Observation<bool> verify_metadata_replay(const OpenedEntry& target,const MetadataReplaySnapshot& snapshot,
                                        const BasicMetadata& applied,std::stop_token stop) {
    if(stop.stop_requested()) return interrupted();
    auto now=target.inspect_basic();
    if(!now.value()) return propagate<bool>(*now.unavailable_detail());
    const auto& n=*now.value();const auto& s=snapshot.basic;
    if(!identity(applied.identity,n.identity) || !equal(s.kind,n.kind) || !equal(s.logical_size,n.logical_size) ||
       !equal(s.accessed,n.accessed) || !equal(s.modified,n.modified) || !equal(s.posix_permissions,n.posix_permissions) ||
       !equal(s.windows_attributes,n.windows_attributes) || !equal(s.bsd_flags,n.bsd_flags))
        return fail<bool>("metadata_replay.target_basic",ObservationState::Changed,AdapterError::MetadataChanged);
    if(snapshot.policy.scope==RegularMetadataScope::CompleteMetadataV1 && !equal(s.created,n.created))
        return fail<bool>("metadata_replay.target_birthtime",ObservationState::Changed,AdapterError::MetadataChanged);
    const auto& owner=snapshot.policy.ownership==MetadataOwnership::Original?s:applied;
    if(!equal(owner.posix_uid,n.posix_uid) || !equal(owner.posix_gid,n.posix_gid))
        return fail<bool>("metadata_replay.target_owner",ObservationState::Changed,AdapterError::MetadataChanged);
    auto catalog=target.inspect_attributes(snapshot.policy.limits);
    if(!catalog.value()) return propagate<bool>(*catalog.unavailable_detail());
    if(!identity(catalog.value()->owner,n.identity) || catalog.value()->coverage!=snapshot.attribute_coverage ||
       catalog.value()->attributes.size()!=snapshot.attributes.size())
        return fail<bool>("metadata_replay.target_attribute_set",ObservationState::Changed,AdapterError::MetadataChanged);
    for(const auto& x:snapshot.attributes) {
        if(stop.stop_requested()) return interrupted();
        auto value=target.read_attribute(x.identifier,snapshot.policy.limits);
        if(!value.value()) return propagate<bool>(*value.unavailable_detail());
        if(!identity(value.value()->owner,n.identity) || value.value()->bytes!=x.bytes || !equal(value.value()->native_flags,x.native_flags))
            return fail<bool>("metadata_replay.target_attribute_bytes",ObservationState::Changed,AdapterError::MetadataChanged);
    }
    for(const auto& x:snapshot.security) {
        auto result=target.verify_replay_security(x,snapshot.policy);
        if(!result.value() || !*result.value()) return result;
    }
    auto after=target.inspect_basic();
    if(!after.value()) return propagate<bool>(*after.unavailable_detail());
    if(!stable(n,*after.value()) || !equal(n.changed,applied.changed))
        return fail<bool>("metadata_replay.target_changed",ObservationState::Changed,AdapterError::MetadataChanged);
    return stop.stop_requested()?interrupted():Observation<bool>::available(true);
}
} // namespace ck::files
