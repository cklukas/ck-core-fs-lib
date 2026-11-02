// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "regular_metadata_preservation.hpp"
#include "object_inventory_job.hpp"

namespace ck::files {
namespace {
template<class T> Observation<T> review(const char* operation) {
    return Observation<T>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::ProviderReviewRequired), operation});
}
template<class T> Observation<T> unavailable(const UnavailableObservation& error) {
    return Observation<T>::unavailable(error.state, error.error);
}
Observation<bool> cancelled() {
    return Observation<bool>::unavailable(ObservationState::Unknown,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InterruptedRead),
         "regular_metadata.cancelled"});
}
template<class T> bool equal(const Observation<T>& a, const Observation<T>& b) {
    return a.value() && b.value() && *a.value() == *b.value();
}
bool same_object(const BasicMetadata& a, const BasicMetadata& b) {
    return a.identity.value() && b.identity.value() &&
        compare_identity(*a.identity.value(), *b.identity.value()) == IdentityComparison::Same;
}
// atime can change because of this copy's own content reads. ctime is checked
// for intervening chmod/chown/xattr/ACL changes; it is never replayed.
bool unchanged(const BasicMetadata& a, const BasicMetadata& b) {
    return same_object(a, b) && equal(a.kind, b.kind) && equal(a.logical_size, b.logical_size) &&
        equal(a.posix_permissions, b.posix_permissions) && equal(a.posix_uid, b.posix_uid) &&
        equal(a.posix_gid, b.posix_gid) && equal(a.link_count, b.link_count) &&
        equal(a.modified, b.modified) && equal(a.changed, b.changed);
}
Observation<BasicMetadata> inventory(const HeldChild::Pointer& source, std::stop_token stop) {
    auto job = ObjectInventoryJob::for_held_source(source);
    while (job->state() == ObjectInventoryJobState::Collecting || job->state() == ObjectInventoryJobState::Paused) {
        if (stop.stop_requested()) return unavailable<BasicMetadata>(*cancelled().unavailable_detail());
        job->advance(stop);
    }
    auto result = job->completed();
    if (!result.value()) return review<BasicMetadata>("regular_metadata.inventory_incomplete");
    const auto& completed = **result.value();
    const auto& data = completed.data();
    const auto owner_is_same = [&](const Observation<ObjectIdentity>& owner) {
        auto compared = completed.compare_owner(owner);
        return compared.value() && *compared.value() == IdentityComparison::Same;
    };
    if (!data.before.value() || !data.after.value() || !unchanged(*data.before.value(), *data.after.value()) ||
        !same_object(source->metadata(), *data.before.value()))
        return review<BasicMetadata>("regular_metadata.source_changed_or_unknown");
    const auto& metadata = *data.before.value();
    if (!metadata.kind.value() || *metadata.kind.value() != ObjectKind::RegularFile ||
        !metadata.posix_permissions.value() || (*metadata.posix_permissions.value() & ~0777U) != 0 ||
        !metadata.accessed.value() || !metadata.modified.value() ||
        !metadata.link_count.value() || *metadata.link_count.value() != 1)
        return review<BasicMetadata>("regular_metadata.ordinary_mode_times_links");
    if (!data.attributes.value() || data.attributes.value()->coverage != AttributeCoverage::CredentialsVisiblePosix ||
        !owner_is_same(data.attributes.value()->owner))
        return review<BasicMetadata>("regular_metadata.visible_attribute_coverage");
    for (const auto& attribute : data.attributes.value()->attributes) {
        switch (attribute.role) {
        case AttributeRole::Security:
            return review<BasicMetadata>("regular_metadata.visible_security_attribute");
        case AttributeRole::AdditionalData:
            return review<BasicMetadata>("regular_metadata.additional_data_attribute");
        case AttributeRole::StorageRepresentation:
            return review<BasicMetadata>("regular_metadata.storage_attribute");
        default:
            return review<BasicMetadata>("regular_metadata.unhandled_visible_attribute");
        }
    }
    if (!data.storage.value() || !owner_is_same(data.storage.value()->owner) ||
        !data.storage.value()->flags.value() || data.storage.value()->flags.value()->value != 0)
        return review<BasicMetadata>("regular_metadata.storage_provider");
    const auto model = data.storage.value()->model;
    const auto part = model == StorageModel::LinuxStatx ? SecurityPart::LinuxAccessAcl :
        model == StorageModel::DarwinStatFlags ? SecurityPart::DarwinExtendedAcl : SecurityPart::Unknown;
    if (part == SecurityPart::Unknown)
        return review<BasicMetadata>("regular_metadata.security_platform");
    bool absent_acl = false;
    for (std::size_t i = 0; i != inventory_security_parts.size(); ++i) {
        if (inventory_security_parts[i] != part) continue;
        const auto* acl = data.security[i].value();
        absent_acl = acl && acl->part == part && acl->presence == SecurityPresence::Absent &&
            acl->bytes.empty() && owner_is_same(acl->owner);
    }
    if (!absent_acl) return review<BasicMetadata>("regular_metadata.acl_unqualified");
    // This check qualifies the declared ordinary subset, including explicit
    // known security names, inode/project flags and layout. It does not turn
    // credentials-visible coverage into complete hidden-namespace inventory.
    auto qualified = source->qualify_ordinary_regular_metadata();
    if (!qualified.value()) return unavailable<BasicMetadata>(*qualified.unavailable_detail());
    if (!*qualified.value()) return review<BasicMetadata>("regular_metadata.native_coverage");
    auto after = source->inspect_basic();
    if (!after.value() || !unchanged(metadata, *after.value()))
        return review<BasicMetadata>("regular_metadata.qualification_changed");
    return Observation<BasicMetadata>::available(metadata);
}
}

Observation<RegularMetadataPreservation::Pointer> RegularMetadataPreservation::create(
    HeldChild::Pointer source, bool allow_loss, RegularMetadataScope scope, std::stop_token stop) {
    if (!source) return review<Pointer>("regular_metadata.source_missing");
    if (scope != RegularMetadataScope::CompleteMetadataV1 && scope != RegularMetadataScope::OrdinaryCallerVisibleV1)
        return review<Pointer>("regular_metadata.invalid_scope_version");
    if (!allow_loss && scope == RegularMetadataScope::CompleteMetadataV1)
        return review<Pointer>("regular_metadata.complete_scope_unavailable");
    if (stop.stop_requested()) return unavailable<Pointer>(*cancelled().unavailable_detail());
    auto metadata = allow_loss ? source->inspect_basic() : inventory(source, stop);
    if (!metadata.value()) return unavailable<Pointer>(*metadata.unavailable_detail());
    if (!same_object(source->metadata(), *metadata.value()))
        return review<Pointer>("regular_metadata.source_identity");
    return Observation<Pointer>::available(Pointer(new RegularMetadataPreservation(
        std::move(source), std::move(metadata).take_value(), allow_loss, scope)));
}

Observation<OperationMetadataJob::Pointer> RegularMetadataPreservation::prepare(OpenedEntry& staging,
                                                                              std::stop_token stop) {
    if (stop.stop_requested()) return unavailable<OperationMetadataJob::Pointer>(*cancelled().unavailable_detail());
    OperationMetadataRequest request;
    request.apply_traversal_metadata = [this, lifetime = shared_from_this(), &staging](std::stop_token stop) {
        if (stop.stop_requested()) return cancelled();
        if (!allow_loss_) {
            auto source = inventory(source_, stop);
            if (!source.value()) return unavailable<bool>(*source.unavailable_detail());
            if (!unchanged(metadata_, *source.value())) return review<bool>("regular_metadata.source_mutated");
            auto target = staging.qualify_ordinary_regular_metadata();
            if (!target.value() || !*target.value()) return review<bool>("regular_metadata.staging_inheritance");
            auto ownership = staging.apply_current_caller_ownership();
            if (!ownership.value() || !*ownership.value()) return ownership;
        }
        return Observation<bool>::available(true);
    };
    request.apply_security_metadata = [](std::stop_token) { return Observation<bool>::available(true); };
    // All data verification reads have finished before this phase. The native
    // setter masks privilege-affecting bits even with explicit loss consent.
    request.apply_final_times = [this, lifetime = shared_from_this(), &staging](std::stop_token stop) {
        if (stop.stop_requested()) return cancelled();
        auto safe = metadata_;
        if (safe.posix_permissions.value()) safe.posix_permissions =
            Observation<std::uint32_t>::available(*safe.posix_permissions.value() & 0777U);
        auto applied = staging.apply_portable_basic_metadata(safe);
        if (!applied.value() || !*applied.value()) return applied;
        auto current = staging.inspect_basic();
        if (!current.value()) return unavailable<bool>(*current.unavailable_detail());
        applied_ = *current.value();
        return verify(staging, stop);
    };
    request.flush_destination = [this, lifetime = shared_from_this(), &staging](std::stop_token stop) {
        auto flushed = staging.flush_content();
        if (!flushed.value() || !*flushed.value()) return flushed;
        return verify(staging, stop);
    };
    return OperationMetadataJob::create(std::move(request));
}

Observation<bool> RegularMetadataPreservation::verify(OpenedEntry& staging, std::stop_token stop) const {
    if (stop.stop_requested()) return cancelled();
    if (!applied_) return review<bool>("regular_metadata.not_applied");
    auto target = staging.inspect_basic();
    if (!target.value()) return unavailable<bool>(*target.unavailable_detail());
    const auto& current = *target.value();
    if (!same_object(*applied_, current) || !equal(metadata_.kind, current.kind) ||
        !equal(metadata_.logical_size, current.logical_size) ||
        !equal(metadata_.accessed, current.accessed) || !equal(metadata_.modified, current.modified))
        return review<bool>("regular_metadata.basic_verification");
    if (metadata_.posix_permissions.value() && (!current.posix_permissions.value() ||
        *current.posix_permissions.value() != (*metadata_.posix_permissions.value() & 0777U)))
        return review<bool>("regular_metadata.mode_verification");
    if (!allow_loss_) {
        if (!equal(applied_->posix_uid, current.posix_uid) || !equal(applied_->posix_gid, current.posix_gid))
            return review<bool>("regular_metadata.ownership_verification");
        auto source = source_->inspect_basic();
        if (!source.value() || !unchanged(metadata_, *source.value()))
            return review<bool>("regular_metadata.source_changed_before_publication");
        auto target_qualified = staging.qualify_ordinary_regular_metadata();
        if (!target_qualified.value() || !*target_qualified.value())
            return review<bool>("regular_metadata.target_changed_before_publication");
    }
    return Observation<bool>::available(true);
}
} // namespace ck::files
