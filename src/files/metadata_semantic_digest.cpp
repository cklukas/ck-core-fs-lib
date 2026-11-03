// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "metadata_semantic_digest.hpp"
#include "metadata_capture_job.hpp"
#include "sha256.hpp"
#include "windows_acl_semantics.hpp"
#include <algorithm>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif
namespace ck::files {
namespace {
struct NativeFailure {UnavailableObservation detail;};
[[noreturn]]void native_fail(const char* op,ObservationState state=ObservationState::Changed,AdapterError code=AdapterError::MetadataChanged){throw NativeFailure{{state,{ErrorDomain::Adapter,static_cast<std::int64_t>(code),op}}};}
template<class T>T native_value(Observation<T>o){if(!o.value())throw NativeFailure{*o.unavailable_detail()};return std::move(o).take_value();}
using Wire=std::vector<std::byte>;
void number(Wire& b,std::uint64_t n) {for(unsigned i=0;i<8;++i)b.push_back(std::byte((n>>(i*8))&255));}
void blob(Wire& b,std::span<const std::byte> v) {number(b,v.size());b.insert(b.end(),v.begin(),v.end());}
std::array<std::byte,32> hashed(std::span<const std::byte> b) {Sha256 h;h.update(b);return h.digest();}
Wire identifier(const NativeFeatureIdentifier& id) {
    Wire b; number(b,static_cast<unsigned>(id.encoding()));
    if(auto* p=id.posix_bytes()) blob(b,std::as_bytes(std::span(*p)));
    else if(auto* w=id.windows_units()) { number(b,w->size()); for(auto u:*w) { b.push_back(std::byte(u&255));b.push_back(std::byte(u>>8)); } }
    else if(auto* e=id.windows_ea_bytes()) blob(b,std::as_bytes(std::span(*e)));
    else native_fail("sync_session.metadata_identifier",ObservationState::Unsupported);
    return b;
}
template<class T> void scalar(Wire& b,const Observation<T>& o) {
    number(b,static_cast<unsigned>(o.state())); if(o.value()) number(b,*o.value());
}
void timestamp(Wire& b,const Observation<FileTimestamp>& o) {
    number(b,static_cast<unsigned>(o.state())); if(o.value()) { number(b,o.value()->seconds());number(b,o.value()->nanoseconds()); }
}
#ifdef _WIN32
void sid_semantics(Wire& b,PSID sid) {
    if(!sid) { number(b,0); return; }
    if(!IsValidSid(sid)) native_fail("sync_session.metadata_sid",ObservationState::Unsupported);
    blob(b,std::as_bytes(std::span(static_cast<const std::byte*>(sid),GetLengthSid(sid))));
}
void acl_semantics(Wire& b,PACL acl) {
    if(!acl) { number(b,0); return; }
    if(!IsValidAcl(acl)) native_fail("sync_session.metadata_acl",ObservationState::Unsupported);
    number(b,1);
    blob(b,native_value(detail::canonical_windows_acl(
        std::span(reinterpret_cast<const std::byte*>(acl),acl->AclSize))));
}
#endif
Wire security_semantics(const NativeSecurityValue& s,MetadataOwnership ownership) {
    Wire b;number(b,static_cast<unsigned>(s.part));number(b,static_cast<unsigned>(s.presence));
    number(b,static_cast<unsigned>(s.encoding));number(b,s.native_query_mask);
    if(s.presence==SecurityPresence::Absent) return b;
    if(s.presence!=SecurityPresence::Present) native_fail("sync_session.unknown_security",ObservationState::Unsupported);
    if(s.encoding==SecurityEncoding::LinuxPosixAclXattrV2) {
        native_value(detail::validate_linux_acl(s.bytes,{})); blob(b,s.bytes); return b;
    }
#ifdef _WIN32
    if(s.encoding==SecurityEncoding::WindowsRelativeDescriptor) {
        native_value(detail::validate_windows_descriptor(s.bytes,{}));
        auto* sd=reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(s.bytes.data()));
        SECURITY_DESCRIPTOR_CONTROL control{};DWORD revision=0;
        if(!GetSecurityDescriptorControl(sd,&control,&revision)) native_fail("sync_session.metadata_sd_control",ObservationState::Unsupported);
        number(b,revision);number(b,control & ~SE_SELF_RELATIVE);
        PSID owner=nullptr,group=nullptr;BOOL defaulted=FALSE;
        if(!GetSecurityDescriptorOwner(sd,&owner,&defaulted) || !GetSecurityDescriptorGroup(sd,&group,&defaulted))
            native_fail("sync_session.metadata_sd_owner",ObservationState::Unsupported);
        if(ownership==MetadataOwnership::Original) { sid_semantics(b,owner);sid_semantics(b,group); }
        PACL acl=nullptr;BOOL present=FALSE;
        if(!GetSecurityDescriptorDacl(sd,&present,&acl,&defaulted)) native_fail("sync_session.metadata_sd_dacl",ObservationState::Unsupported);
        number(b,present);if(present) acl_semantics(b,acl);
        if(!GetSecurityDescriptorSacl(sd,&present,&acl,&defaulted)) native_fail("sync_session.metadata_sd_sacl",ObservationState::Unsupported);
        number(b,present);if(present) acl_semantics(b,acl); return b;
    }
#else
    (void)ownership;
#endif
    // Darwin opaque external ACL serialization is not a canonical semantic
    // encoding. Absent ACLs are supported; present ACLs need a native normalizer.
    native_fail("sync_session.security_semantics_unqualified",ObservationState::Unsupported);
}
Wire channel_manifest(const MetadataReplaySnapshot& s) {
    Wire out;number(out,1);number(out,static_cast<unsigned>(s.channel_coverage));
    std::vector<Wire> records;records.reserve(s.channels.size());
    for(const auto& c:s.channels) {
        if(c.identifier.encoding()!=NameEncoding::WindowsUtf16)
            native_fail("native_sync.channel_identifier",ObservationState::Unsupported,AdapterError::InvalidIdentifier);
        Wire record=identifier(c.identifier);number(record,c.logical_size);blob(record,c.digest);records.push_back(std::move(record));
    }
    std::sort(records.begin(),records.end());
    if(std::adjacent_find(records.begin(),records.end())!=records.end())native_fail("native_sync.duplicate_channel");
    number(out,records.size());for(const auto& record:records)blob(out,record);return out;
}
std::array<std::byte,32> metadata_digest(const MetadataReplaySnapshot& s) {
    Wire b; number(b,metadata_semantic_digest_version);number(b,s.policy.version);number(b,static_cast<unsigned>(s.policy.scope));number(b,static_cast<unsigned>(s.policy.ownership));
    scalar(b,s.basic.posix_permissions);scalar(b,s.basic.bsd_flags);scalar(b,s.basic.windows_attributes);
    timestamp(b,s.basic.modified);
    if(s.policy.scope==RegularMetadataScope::CompleteMetadataV1) timestamp(b,s.basic.created);
    if(s.policy.ownership==MetadataOwnership::Original) { scalar(b,s.basic.posix_uid);scalar(b,s.basic.posix_gid); }
    number(b,static_cast<unsigned>(s.attribute_coverage));
    number(b,static_cast<unsigned>(s.security_coverage?s.security_coverage->family():MetadataSecurityCoverage::Unknown));
    std::vector<Wire> attributes,security;
    for(const auto& a:s.attributes) { auto bytes=identifier(a.identifier);scalar(bytes,a.native_flags);blob(bytes,a.bytes);attributes.push_back(std::move(bytes)); }
    for(const auto& v:s.security) security.push_back(security_semantics(v,s.policy.ownership));
    std::sort(attributes.begin(),attributes.end());std::sort(security.begin(),security.end());
    number(b,attributes.size());for(const auto& a:attributes) blob(b,a);
    number(b,security.size());for(const auto& v:security) blob(b,v);
    blob(b,channel_manifest(s));return hashed(b);
}
}
Observation<std::array<std::byte,32>> detail::metadata_snapshot_semantic_digest(const MetadataReplaySnapshot& snapshot,std::stop_token stop){
    using R=Observation<std::array<std::byte,32>>;
    try {if(stop.stop_requested())native_fail("metadata_semantics.cancelled",ObservationState::Unknown,AdapterError::InterruptedRead);
        if(!snapshot.policy.valid())native_fail("metadata_semantics.policy",ObservationState::Failed,AdapterError::InvalidIdentifier);
        auto digest=metadata_digest(snapshot);
        if(stop.stop_requested())native_fail("metadata_semantics.cancelled",ObservationState::Unknown,AdapterError::InterruptedRead);
        return R::available(digest);
    }catch(const NativeFailure&e){return R::unavailable(e.detail.state,e.detail.error);}
}
Observation<std::array<std::byte,32>> native_metadata_proof_digest(const NativeMetadataProof& proof,std::stop_token stop){
    if(auto e=proof.cleanup_error())return Observation<std::array<std::byte,32>>::unavailable(e->state,{e->domain,e->code,e->operation});
    if(proof.progress().phase!=MetadataCapturePhase::Complete)return Observation<std::array<std::byte,32>>::unavailable(
        ObservationState::Unknown,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"metadata_semantics.unfinished_proof"});
    return detail::metadata_snapshot_semantic_digest(proof.snapshot(),stop);
}
}
