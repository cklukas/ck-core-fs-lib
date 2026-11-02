// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_fs_session.h"
#include "sync_session.hpp"
#include "native_filesystem.hpp"
#include "held_child.hpp"
#include "metadata_replay.hpp"
#include "sha256.hpp"
#include <set>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#endif
#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
using namespace ck::files;
struct ckfss_session {
    std::unique_ptr<SyncSession> core;
    SyncBaselineLimits limits;
    std::vector<std::string> pending;
    std::atomic<bool> cancelled{false};
    NativeFileSystem filesystem;
    std::optional<NativeAbsolutePath> left_address,right_address;
    std::optional<ckfss_metadata_policy> metadata_policy;
    std::shared_ptr<const int> receipt_owner=std::make_shared<const int>(0);
};
namespace {
void require(bool b) { if(!b) throw std::invalid_argument("sync_session.argument"); }
template<class F> ckfss_status boundary(F&& f) noexcept {
    try { return f(); } catch(const std::bad_alloc&) { return CKFSS_OUT_OF_MEMORY; }
    catch(const std::invalid_argument&) { return CKFSS_INVALID_ARGUMENT; }
    catch(...) { return CKFSS_EXCEPTION; }
}
void clear(ckfss_error* e) { if(e) *e={}; }
template<class T> ckfss_status unavailable(const Observation<T>& o,ckfss_error* e) {
    if(e) {
        const auto& d=*o.unavailable_detail(); e->observation=static_cast<uint32_t>(d.state);
        e->domain=static_cast<uint32_t>(d.error.domain); e->code=d.error.code;
        std::memcpy(e->operation,d.error.operation.data(),std::min(d.error.operation.size(),sizeof(e->operation)-1));
    }
    return CKFSS_UNAVAILABLE;
}
SyncDigest digest(const uint8_t* p) { SyncDigest d; std::memcpy(d.data(),p,32); return d; }
void digest(uint8_t* p,const SyncDigest& d) { std::memcpy(p,d.data(),32); }
NativeAbsolutePath path(const ckfss_native_path& p) {
    require(p.data && p.units && !p.reserved && p.encoding<=CKFSS_WINDOWS_UTF16);
    require(p.units<=NativePathLimits::hard_native_bytes);
    if(p.encoding==CKFSS_POSIX_BYTES) {
        auto r=NativeAbsolutePath::from_posix({static_cast<const char*>(p.data),static_cast<std::size_t>(p.units)});
        require(r.value()); return std::move(r).take_value();
    }
    require(p.units<=NativePathLimits::hard_native_bytes/2);
    std::u16string s(static_cast<std::size_t>(p.units),u'\0'); std::memcpy(s.data(),p.data,s.size()*2);
    auto r=NativeAbsolutePath::from_windows(s); require(r.value()); return std::move(r).take_value();
}
SyncBaselineLimits limits(const ckfss_limits& l) {
    require(l.max_rows && l.max_rows<=SyncBaselineLimits::hard_max_rows &&
        l.max_path_bytes && l.max_path_bytes<=SyncBaselineLimits::hard_max_path_bytes &&
        l.max_total_path_bytes && l.max_total_path_bytes<=SyncBaselineLimits::hard_max_total_path_bytes &&
        l.max_wire_bytes>=96 && l.max_wire_bytes<=SyncBaselineLimits::hard_max_wire_bytes);
    return {static_cast<std::size_t>(l.max_rows),static_cast<std::size_t>(l.max_path_bytes),
        static_cast<std::size_t>(l.max_total_path_bytes),static_cast<std::size_t>(l.max_wire_bytes)};
}
SyncEntryStatus status(const ckfss_entry_status& s) {
    require(s.presence<=CKFSS_PRESENT && s.kind<=CKFSS_OTHER);
    return {static_cast<SyncPresence>(s.presence),static_cast<SyncKind>(s.kind),
        digest(s.content_digest),digest(s.required_metadata_digest)};
}
ckfss_entry_status status(const SyncEntryStatus& s) {
    ckfss_entry_status out{}; out.presence=static_cast<uint32_t>(s.presence); out.kind=static_cast<uint32_t>(s.kind);
    digest(out.content_digest,s.content_digest); digest(out.required_metadata_digest,s.required_metadata_digest); return out;
}
void snapshot(const ckfss_session& s,ckfss_snapshot& out) {
    const auto& in=s.core->snapshot(); out={}; out.version=CKFSS_VERSION; out.struct_size=sizeof(out);
    out.state=static_cast<uint32_t>(in.state); out.generation=in.generation;
    out.has_baseline=in.baseline.has_value(); out.has_previous=in.previous.has_value();
    out.rows=in.baseline ? in.baseline->rows.size():0; out.previous_rows=in.previous ? in.previous->rows.size():0;
    out.pending_rows=s.pending.size(); const auto& id=s.core->identity();
    digest(out.left_root,id.left_root); digest(out.right_root,id.right_root);
    digest(out.bound_policy,id.policy); digest(out.pair,id.pair);
}
ckfss_status copy_key(const std::string& in,void* key,uint64_t capacity,uint64_t* required) {
    require(required && (key || !capacity)); *required=in.size();
    if(capacity<in.size()) return CKFSS_BUFFER_TOO_SMALL;
    if(!in.empty()) std::memcpy(key,in.data(),in.size()); return CKFSS_OK;
}
}
extern "C" {
void ckfss_options_init(ckfss_options* o) noexcept {
    if(!o) return; *o={}; o->version=CKFSS_VERSION; o->struct_size=sizeof(*o);
    SyncBaselineLimits l; o->limits={l.max_rows,l.max_path_bytes,l.max_total_path_bytes,l.max_wire_bytes};
}
void ckfss_update_init(ckfss_update* o) noexcept {
    if(!o) return; *o={}; o->version=CKFSS_VERSION; o->struct_size=sizeof(*o);
}
ckfss_status ckfss_session_open(const ckfss_options* o,ckfss_session** out,ckfss_error* e) noexcept {
    if(out) *out=nullptr; clear(e);
    return boundary([&]()->ckfss_status {
        require(o && out && o->version==CKFSS_VERSION && o->struct_size==sizeof(*o));
        for(auto v:o->reserved) require(!v);
        auto l=limits(o->limits); auto coordinator=path(o->coordinator),left=path(o->left),right=path(o->right);
        auto b=open_native_sync_session_backend(coordinator,left,right);
        if(!b.value()) return unavailable(b,e);
        auto core=SyncSession::open(std::move(b).take_value(),digest(o->policy_fingerprint),l);
        if(!core.value()) return unavailable(core,e);
        auto s=std::make_unique<ckfss_session>(); s->limits=l; s->core=std::move(core).take_value();
        s->left_address=left; s->right_address=right;
        *out=s.release(); return CKFSS_OK;
    });
}
void ckfss_session_destroy(ckfss_session* s) noexcept { delete s; }
ckfss_status ckfss_session_get_snapshot(const ckfss_session* s,ckfss_snapshot* out) noexcept {
    if(out) *out={}; return boundary([&]()->ckfss_status { require(s && out); snapshot(*s,*out); return CKFSS_OK; });
}
ckfss_status ckfss_session_refresh(ckfss_session* s,ckfss_error* e) noexcept {
    clear(e); return boundary([&]()->ckfss_status {
        require(s); auto r=s->core->refresh(); if(!r.value()) return unavailable(r,e);
        s->pending.clear(); return CKFSS_OK;
    });
}
ckfss_status ckfss_session_revalidate(ckfss_session* s,ckfss_error* e) noexcept {
    clear(e); return boundary([&]()->ckfss_status {
        require(s); auto r=s->core->revalidate(); return r.value()?CKFSS_OK:unavailable(r,e);
    });
}
ckfss_status ckfss_session_commit(ckfss_session* s,uint64_t expected,const ckfss_update* input,
    uint64_t count,uint32_t approve,ckfss_snapshot* out,ckfss_error* e) noexcept {
    if(out) *out={}; clear(e);
    return boundary([&]()->ckfss_status {
        require(s && out && approve<=1 && count<=s->limits.max_rows && (input || !count));
        std::vector<SyncBaselineUpdate> updates; updates.reserve(static_cast<std::size_t>(count));
        std::size_t total=0;
        for(uint64_t i=0;i<count;++i) {
            const auto& u=input[i]; require(u.version==CKFSS_VERSION && u.struct_size==sizeof(u) &&
                u.state<=CKFSS_CONFIRMED_EQUAL && !u.reserved && u.relative_key && u.relative_key_bytes &&
                u.relative_key_bytes<=s->limits.max_path_bytes && u.relative_key_bytes<=s->limits.max_total_path_bytes-total);
            total+=static_cast<std::size_t>(u.relative_key_bytes);
            std::string key(static_cast<const char*>(u.relative_key),static_cast<std::size_t>(u.relative_key_bytes));
            updates.push_back({{std::move(key),status(u.left),status(u.right)},static_cast<SyncBaselineUpdateState>(u.state)});
        }
        // There is deliberately NO call to SyncSession::commit here. Native C
        // callers cannot manufacture convergence authority by supplying digest
        // bytes or ConfirmedEqual. The reviewed executor does not yet issue a
        // session-bound, held-root post-verification receipt. Until that bridge
        // exists this boundary is read/recovery-only and fails explicitly.
        auto valid=s->core->revalidate(); if(!valid.value()) return unavailable(valid,e);
        const auto& current=s->core->snapshot();
        if(expected!=current.generation || (current.state==SyncSessionState::ReviewRequired || current.state==SyncSessionState::HistoryChanged) ||
            (current.state==SyncSessionState::FirstRun && !approve) || s->cancelled.load(std::memory_order_relaxed)) {
            auto r=Observation<bool>::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,
                static_cast<int64_t>(AdapterError::ProviderReviewRequired),"sync_session.native_commit_precondition"});
            return unavailable(r,e);
        }
        auto r=Observation<bool>::unavailable(ObservationState::Unsupported,{ErrorDomain::Adapter,
            static_cast<int64_t>(AdapterError::UnsupportedQuery),"sync_session.native_verified_receipt_unavailable"});
        return unavailable(r,e);
    });
}
void ckfss_session_request_cancel(ckfss_session* s) noexcept { if(s) s->cancelled.store(true,std::memory_order_relaxed); }
void ckfss_session_clear_cancel(ckfss_session* s) noexcept { if(s) s->cancelled.store(false,std::memory_order_relaxed); }
ckfss_status ckfss_session_get_row(const ckfss_session* s,uint32_t previous,uint64_t index,
    ckfss_row* out,void* key,uint64_t capacity,uint64_t* required) noexcept {
    if(out) *out={}; if(required) *required=0;
    return boundary([&]()->ckfss_status {
        require(s && out && required && previous<=1 && (key || !capacity));
        const auto& b=previous?s->core->snapshot().previous:s->core->snapshot().baseline;
        require(b && index<b->rows.size()); const auto& row=b->rows[static_cast<std::size_t>(index)];
        auto r=copy_key(row.relative_path,key,capacity,required); if(r!=CKFSS_OK) return r;
        out->relative_key_bytes=row.relative_path.size(); out->left=status(row.left); out->right=status(row.right); return CKFSS_OK;
    });
}
ckfss_status ckfss_session_get_pending_key(const ckfss_session* s,uint64_t index,void* key,uint64_t capacity,uint64_t* required) noexcept {
    if(required) *required=0;
    return boundary([&]()->ckfss_status { require(s && index<s->pending.size());
        return copy_key(s->pending[static_cast<std::size_t>(index)],key,capacity,required); });
}
} // extern C

namespace {
struct NativeFailure { UnavailableObservation detail; };
[[noreturn]] void native_fail(const char* op,ObservationState state=ObservationState::Changed,
    AdapterError code=AdapterError::MetadataChanged) {
    throw NativeFailure{{state,{ErrorDomain::Adapter,static_cast<int64_t>(code),op}}};
}
template<class T> T native_value(Observation<T> r) {
    if(!r.value()) throw NativeFailure{*r.unavailable_detail()};
    return std::move(r).take_value();
}
template<class F> ckfss_status native_boundary(ckfss_error* e,F&& f) noexcept {
    return boundary([&]()->ckfss_status {
        try { return f(); } catch(const NativeFailure& failure) {
            auto r=Observation<bool>::unavailable(failure.detail.state,failure.detail.error); return unavailable(r,e);
        }
    });
}
void cancelled(const ckfss_session& s) {
    if(s.cancelled.load(std::memory_order_relaxed)) native_fail("sync_session.verify_cancelled",ObservationState::Changed,AdapterError::InterruptedRead);
}
template<class T> bool field_equal(const Observation<T>& a,const Observation<T>& b) {
    return a.value() && b.value() ? *a.value()==*b.value() : !a.value() && !b.value() && a.state()==b.state();
}
bool same_version(const BasicMetadata& a,const BasicMetadata& b) {
    return a.identity.value() && b.identity.value() &&
        compare_identity(*a.identity.value(),*b.identity.value())==IdentityComparison::Same &&
        a.changed.value() && b.changed.value() && a.modified.value() && b.modified.value() &&
        field_equal(a.kind,b.kind) && field_equal(a.logical_size,b.logical_size) &&
        field_equal(a.link_count,b.link_count) && field_equal(a.changed,b.changed) &&
        field_equal(a.modified,b.modified) && field_equal(a.created,b.created) &&
        field_equal(a.posix_uid,b.posix_uid) && field_equal(a.posix_gid,b.posix_gid) &&
        field_equal(a.posix_permissions,b.posix_permissions) && field_equal(a.bsd_flags,b.bsd_flags) &&
        field_equal(a.windows_attributes,b.windows_attributes);
}
void validate_policy(const ckfss_metadata_policy& p) {
    require(p.version==CKFSS_VERSION && p.struct_size==sizeof(p) && p.scope<=CKFSS_METADATA_ORDINARY_V1 &&
        p.ownership<=CKFSS_OWNER_CURRENT_CALLER && p.allow_privilege_metadata<=1 && !p.reserved &&
        p.max_file_bytes && p.max_file_bytes<=UINT64_C(4)*1024*1024*1024 &&
        p.max_total_bytes && p.max_total_bytes<=UINT64_C(16)*1024*1024*1024 &&
        p.max_metadata_bytes && p.max_metadata_bytes<=InventoryLimits::hard_native_bytes &&
        p.max_metadata_records && p.max_metadata_records<=InventoryLimits::hard_records &&
        p.max_total_metadata_bytes && p.max_total_metadata_bytes<=UINT64_C(64)*1024*1024 &&
        p.max_parent_entries && p.max_parent_entries<=1'000'000 &&
        p.max_components_per_path && p.max_components_per_path<=1024);
}
bool same_policy(const ckfss_metadata_policy& a,const ckfss_metadata_policy& b) {
    return a.version==b.version && a.struct_size==b.struct_size && a.scope==b.scope && a.ownership==b.ownership &&
        a.allow_privilege_metadata==b.allow_privilege_metadata && a.max_file_bytes==b.max_file_bytes &&
        a.max_total_bytes==b.max_total_bytes && a.max_metadata_bytes==b.max_metadata_bytes &&
        a.max_metadata_records==b.max_metadata_records && a.max_total_metadata_bytes==b.max_total_metadata_bytes &&
        a.max_parent_entries==b.max_parent_entries && a.max_components_per_path==b.max_components_per_path;
}
using Wire=std::vector<std::byte>;
void number(Wire& b,std::uint64_t n) { for(unsigned i=0;i<8;++i) b.push_back(std::byte((n>>(8*i))&255)); }
void blob(Wire& b,std::span<const std::byte> bytes) { number(b,bytes.size()); b.insert(b.end(),bytes.begin(),bytes.end()); }
SyncDigest hashed(std::span<const std::byte> b) { Sha256 h;h.update(b);return h.digest(); }
SyncDigest policy_binding(const ckfss_options& o,const ckfss_metadata_policy& p) {
    Wire b; number(b,0x31534d4553534643ULL); // C-session semantic metadata schema 1
    blob(b,std::as_bytes(std::span(o.policy_fingerprint))); number(b,p.scope);
    number(b,p.ownership); number(b,p.allow_privilege_metadata); return hashed(b);
}
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
    number(b,1); number(b,acl->AceCount);
    for(DWORD i=0;i<acl->AceCount;++i) {
        void* raw=nullptr; if(!GetAce(acl,i,&raw)) native_fail("sync_session.metadata_ace",ObservationState::Unsupported);
        const auto* ace=static_cast<ACCESS_ALLOWED_ACE*>(raw);
        if(ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE && ace->Header.AceType!=ACCESS_DENIED_ACE_TYPE &&
            ace->Header.AceType!=SYSTEM_AUDIT_ACE_TYPE && ace->Header.AceType!=SYSTEM_MANDATORY_LABEL_ACE_TYPE)
            native_fail("sync_session.metadata_complex_ace",ObservationState::Unsupported);
        if(ace->Header.AceSize<sizeof(ACCESS_ALLOWED_ACE)) native_fail("sync_session.metadata_ace_size",ObservationState::Unsupported);
        number(b,ace->Header.AceType);number(b,ace->Header.AceFlags);number(b,ace->Mask);
        auto* sid=reinterpret_cast<PSID>(const_cast<DWORD*>(&ace->SidStart));
        if(!IsValidSid(sid) || GetLengthSid(sid)>ace->Header.AceSize- offsetof(ACCESS_ALLOWED_ACE,SidStart))
            native_fail("sync_session.metadata_ace_sid",ObservationState::Unsupported);
        sid_semantics(b,sid);
    }
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
        number(b,control & ~SE_SELF_RELATIVE);
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
SyncDigest metadata_digest(const MetadataReplaySnapshot& s) {
    Wire b; number(b,1);number(b,static_cast<unsigned>(s.policy.scope));number(b,static_cast<unsigned>(s.policy.ownership));
    scalar(b,s.basic.posix_permissions);scalar(b,s.basic.bsd_flags);scalar(b,s.basic.windows_attributes);
    timestamp(b,s.basic.modified);
    if(s.policy.scope==RegularMetadataScope::CompleteMetadataV1) timestamp(b,s.basic.created);
    if(s.policy.ownership==MetadataOwnership::Original) { scalar(b,s.basic.posix_uid);scalar(b,s.basic.posix_gid); }
    number(b,static_cast<unsigned>(s.attribute_coverage));
    std::vector<Wire> attributes,security;
    for(const auto& a:s.attributes) { auto bytes=identifier(a.identifier);scalar(bytes,a.native_flags);blob(bytes,a.bytes);attributes.push_back(std::move(bytes)); }
    for(const auto& v:s.security) security.push_back(security_semantics(v,s.policy.ownership));
    std::sort(attributes.begin(),attributes.end());std::sort(security.begin(),security.end());
    number(b,attributes.size());for(const auto& a:attributes) blob(b,a);
    number(b,security.size());for(const auto& v:security) blob(b,v);return hashed(b);
}
struct ParentProof { std::shared_ptr<DirectoryCursor> cursor; BasicMetadata before; };
struct SideProof {
    SyncEntryStatus status;
    std::vector<ParentProof> parents;
    HeldChild::Pointer file;
    std::optional<MetadataReplaySnapshot> metadata;
};
struct PathProof {
    std::vector<NativeName> components;
    std::string key;
    bool skipped=false;
    SideProof left,right;
};
struct Budget { std::uint64_t content=0,metadata=0,parents=0,handles=0; };
void charge(std::uint64_t& used,std::uint64_t n,std::uint64_t max,const char* op) {
    if(n>max-used) native_fail(op,ObservationState::Unknown,AdapterError::InventoryLimit); used+=n;
}
// Windows' native cursor contains a 128 KiB enumeration buffer; reserve that
// audited upper bound plus owner bookkeeping on every platform. Charge BEFORE
// opening each retained cursor, including absence-only paths and shared roots
// reopened for another requested path. No leaf-only accounting shortcut.
void reserve_parent(Budget& budget,const ckfss_metadata_policy& policy) {
    charge(budget.handles,1,policy.max_parent_entries,"sync_session.aggregate_handle_limit");
    charge(budget.metadata,sizeof(ParentProof)+128*1024+4096,policy.max_total_metadata_bytes,
        "sync_session.parent_proof_limit");
}
std::string exact_key(const std::vector<NativeName>& names) {
    std::string out; constexpr char hex[]="0123456789abcdef";
    auto byte=[&](unsigned n) { out+=hex[n>>4];out+=hex[n&15]; };
    for(const auto& n:names) {
        if(!out.empty()) out+='/';
        if(auto* p=n.posix_bytes()) { out+='p';for(unsigned char c:*p) byte(c); }
        else if(auto* w=n.windows_units()) { out+='w';for(auto u:*w) { byte(u&255);byte(u>>8); } }
        else native_fail("sync_session.component_encoding",ObservationState::Unsupported);
    } return out;
}
NativeName component(const ckfss_native_path& p) {
    require(p.data && p.units && !p.reserved && p.encoding<=CKFSS_WINDOWS_UTF16 && p.units<=65536);
#ifdef _WIN32
    if(p.encoding!=CKFSS_WINDOWS_UTF16) native_fail("sync_session.native_component_encoding",ObservationState::Unsupported);
#else
    if(p.encoding!=CKFSS_POSIX_BYTES) native_fail("sync_session.native_component_encoding",ObservationState::Unsupported);
#endif
    if(p.encoding==CKFSS_POSIX_BYTES) {
        auto name=NativeName::from_posix(std::string(static_cast<const char*>(p.data),static_cast<std::size_t>(p.units)));
        require(name.has_value());return std::move(*name);
    }
    std::u16string units(static_cast<std::size_t>(p.units),u'\0');std::memcpy(units.data(),p.data,units.size()*2);
    require(units.find(u':')==units.npos);auto name=NativeName::from_windows(std::move(units));require(name.has_value());return std::move(*name);
}
void root_binding(const ckfss_session& s,const DirectoryCursor& root,bool right) {
    auto now=native_value(root.inspect_basic());
    if(!now.identity.value() || !now.kind.value() || *now.kind.value()!=ObjectKind::Directory)
        native_fail("sync_session.cursor_root_identity");
    const auto& id=*now.identity.value();const auto handle=s.core->root_handle(right);
#ifdef _WIN32
    FILE_ID_INFO raw{};
    if(!GetFileInformationByHandleEx(reinterpret_cast<HANDLE>(handle),FileIdInfo,&raw,sizeof(raw)))
        native_fail("sync_session.held_root_id",ObservationState::Unsupported);
    NativeIdentifier object;std::memcpy(object.bytes.data(),raw.FileId.Identifier,16);
    if(id.scheme!=IdentityScheme::WindowsFileId128 || id.volume!=NativeIdentifier::from_u64(raw.VolumeSerialNumber) || id.object!=object)
        native_fail("sync_session.cursor_root_mismatch");
#else
    struct stat raw{};if(fstat(static_cast<int>(handle),&raw)) native_fail("sync_session.held_root_id");
    if(id.scheme!=IdentityScheme::PosixDeviceInode || id.volume!=NativeIdentifier::from_u64(raw.st_dev) || id.object!=NativeIdentifier::from_u64(raw.st_ino))
        native_fail("sync_session.cursor_root_mismatch");
#endif
}
std::shared_ptr<DirectoryCursor> root_cursor(ckfss_session& s,bool right) {
    auto cursor=std::shared_ptr<DirectoryCursor>(native_value(s.filesystem.open_native_directory(*(right?s.right_address:s.left_address))));
    root_binding(s,*cursor,right);return cursor;
}
void check_parents(const std::vector<ParentProof>& parents,const std::vector<NativeName>& components) {
    for(std::size_t i=0;i<parents.size();++i) {
        auto now=native_value(parents[i].cursor->inspect_basic());
        if(!same_version(parents[i].before,now)) native_fail("sync_session.parent_changed");
        if(i+1<parents.size()) {
            auto child=native_value(parents[i].cursor->open_directory_child(components[i]));
            auto child_now=native_value(child->inspect_basic());
            if(!same_version(parents[i+1].before,child_now)) native_fail("sync_session.parent_membership_changed");
        }
    }
}
SideProof observe_side(ckfss_session& s,const std::vector<NativeName>& names,bool right,Budget& budget) {
    cancelled(s);const auto& p=*s.metadata_policy;SideProof out;
    reserve_parent(budget,p);auto cursor=root_cursor(s,right);
    for(std::size_t i=0;i<names.size();++i) {
        auto before=native_value(cursor->inspect_basic());
        if(!before.identity.value() || !before.kind.value() || *before.kind.value()!=ObjectKind::Directory ||
            !before.changed.value() || !before.modified.value()) native_fail("sync_session.parent_version_unknown",ObservationState::Unsupported);
        out.parents.push_back({cursor,before});
        auto lookup=native_value(cursor->lookup_child(names[i],ChildLookupMode::NativeDefault));
        if(lookup.state()==ChildLookupState::Missing) {
            if(i+1!=names.size() || !lookup.missing_witness()) native_fail("sync_session.missing_intermediate_parent",ObservationState::Unsupported);
            // A fresh cursor is enumerated completely under a version bracket.
            // End on a reused cursor is never accepted as new inventory proof.
            for(;;) {
                cancelled(s);auto batch=cursor->read(256);
                charge(budget.parents,std::max<std::size_t>(1,batch.names.size()),p.max_parent_entries,"sync_session.absence_inventory_limit");
                if(std::find(batch.names.begin(),batch.names.end(),names[i])!=batch.names.end()) native_fail("sync_session.absence_name_appeared");
                if(batch.state==DirectoryReadState::Error) throw NativeFailure{*batch.error};
                if(batch.state==DirectoryReadState::Cancelled) native_fail("sync_session.absence_cancelled");
                if(batch.state==DirectoryReadState::End) break;
            }
            auto again=native_value(cursor->lookup_child(names[i],ChildLookupMode::NativeDefault));
            if(again.state()!=ChildLookupState::Missing || !again.missing_witness()) native_fail("sync_session.absence_changed");
            check_parents(out.parents,names);root_binding(s,*out.parents.front().cursor,right);
            out.status.presence=SyncPresence::Absent;return out;
        }
        if(lookup.state()!=ChildLookupState::Found || !lookup.entry()) native_fail("sync_session.lookup_unknown",ObservationState::Unsupported);
        // Native-default lookup may resolve an alias on a folding filesystem.
        // Certify the exact requested native spelling in this held parent;
        // never turn a different spelling into a second durable baseline key.
        bool exact_member=false;
        for(;;) {
            cancelled(s);auto batch=cursor->read(256);
            charge(budget.parents,std::max<std::size_t>(1,batch.names.size()),p.max_parent_entries,"sync_session.exact_inventory_limit");
            exact_member=std::find(batch.names.begin(),batch.names.end(),names[i])!=batch.names.end();
            if(batch.state==DirectoryReadState::Error) throw NativeFailure{*batch.error};
            if(batch.state==DirectoryReadState::Cancelled) native_fail("sync_session.exact_inventory_cancelled");
            if(exact_member || batch.state==DirectoryReadState::End) break;
        }
        if(!exact_member) native_fail("sync_session.native_spelling_alias",ObservationState::Unsupported);
        const auto basic=native_value(lookup.entry()->inspect_basic());
        if(!basic.kind.value()) native_fail("sync_session.path_kind_unknown",ObservationState::Unsupported);
        if(i+1<names.size()) {
            if(*basic.kind.value()!=ObjectKind::Directory) native_fail("sync_session.path_parent_kind",ObservationState::Unsupported);
            reserve_parent(budget,p);
            auto next=native_value(cursor->open_directory_child(names[i]));
            auto opened=native_value(next->inspect_basic());
            if(!same_version(basic,opened)) native_fail("sync_session.directory_open_changed");
            cursor=std::shared_ptr<DirectoryCursor>(std::move(next));continue;
        }
        if(*basic.kind.value()!=ObjectKind::RegularFile) native_fail("sync_session.regular_paths_only",ObservationState::Unsupported);
        auto access=EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity;
        if(p.scope==CKFSS_METADATA_COMPLETE_V1) access=access|EntryAccess::MetadataAndFullSecurity;
        out.file=native_value(HeldChild::observe_with_access(cursor,names[i],access));
        if(!same_version(basic,out.file->metadata())) native_fail("sync_session.file_open_changed");
        MetadataReplayPolicy policy;policy.scope=static_cast<RegularMetadataScope>(p.scope);
        policy.ownership=static_cast<MetadataOwnership>(p.ownership);policy.allow_privilege_metadata=p.allow_privilege_metadata!=0;
        policy.limits={static_cast<std::size_t>(p.max_metadata_bytes),static_cast<std::size_t>(p.max_metadata_records)};
        out.metadata=native_value(out.file->capture_metadata(policy));
        if(!same_version(out.file->metadata(),out.metadata->basic)) native_fail("sync_session.metadata_open_changed");
        std::uint64_t metadata_bytes=sizeof(MetadataReplaySnapshot);
        for(const auto& a:out.metadata->attributes) metadata_bytes+=a.bytes.size()+identifier(a.identifier).size()+sizeof(AttributeValue);
        for(const auto& v:out.metadata->security) metadata_bytes+=v.bytes.size()+sizeof(NativeSecurityValue);
        charge(budget.metadata,metadata_bytes,p.max_total_metadata_bytes,"sync_session.aggregate_metadata_limit");
        const auto* size=out.metadata->basic.logical_size.value();
        if(!size || *size>p.max_file_bytes) native_fail("sync_session.file_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        charge(budget.content,*size,p.max_total_bytes,"sync_session.total_content_limit");
        Sha256 hash;std::uint64_t offset=0;
        for(;;) {
            cancelled(s);auto data=native_value(out.file->read_content({64*1024},offset));
            if(offset>*size || data.bytes.size()>*size-offset || (data.bytes.empty()&&!data.complete)) native_fail("sync_session.hash_length_changed");
            hash.update(data.bytes);offset+=data.bytes.size();if(data.complete) break;
        }
        if(offset!=*size) native_fail("sync_session.hash_incomplete");
        native_value(out.file->verify_metadata_source(*out.metadata));
        auto member=native_value(out.file->refresh());
        if(!member->continues(*out.file) || !same_version(out.metadata->basic,member->metadata())) native_fail("sync_session.file_membership_changed");
        check_parents(out.parents,names);root_binding(s,*out.parents.front().cursor,right);
        out.status={SyncPresence::Present,SyncKind::File,hash.digest(),metadata_digest(*out.metadata)};return out;
    }
    native_fail("sync_session.empty_path",ObservationState::Failed,AdapterError::InvalidPath);
}
bool same_side_version(const SideProof& a,const SideProof& b) {
    if(a.status!=b.status || a.parents.size()!=b.parents.size()) return false;
    for(std::size_t i=0;i<a.parents.size();++i) if(!same_version(a.parents[i].before,b.parents[i].before)) return false;
    return !a.file && !b.file ? true : a.file && b.file && same_version(a.metadata->basic,b.metadata->basic);
}
bool owners_equal(const SideProof& a,const SideProof& b) {
    if(!a.metadata || !b.metadata) return true;
    if(!field_equal(a.metadata->basic.posix_uid,b.metadata->basic.posix_uid) || !field_equal(a.metadata->basic.posix_gid,b.metadata->basic.posix_gid)) return false;
#ifdef _WIN32
    for(const auto& x:a.metadata->security) for(const auto& y:b.metadata->security) if(x.part==y.part) {
        // Compare actual owner/group semantics separately when excluded from
        // CurrentCaller hashes. Observation owner identity is never serialized.
        Wire left,right;
        for(const auto* v:{&x,&y}) {
            auto* sd=reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(v->bytes.data()));
            if(v->presence!=SecurityPresence::Present) continue;
            PSID owner=nullptr,group=nullptr;BOOL def=FALSE;
            if(!GetSecurityDescriptorOwner(sd,&owner,&def)||!GetSecurityDescriptorGroup(sd,&group,&def)) return false;
            auto& wire=v==&x?left:right;sid_semantics(wire,owner);sid_semantics(wire,group);
        }
        if(left!=right) return false;
    }
#endif
    return true;
}
}
struct ckfss_receipt {
    std::shared_ptr<const int> owner;
    SyncSessionIdentity identity;
    std::uint64_t generation=0;
    std::vector<PathProof> paths;
    std::vector<SyncBaselineUpdate> updates;
    Budget retained_budget;
    bool consumed=false;
};
extern "C" {
void ckfss_metadata_policy_init(ckfss_metadata_policy* p) noexcept {
    if(!p) return;*p={};p->version=CKFSS_VERSION;p->struct_size=sizeof(*p);
    p->scope=CKFSS_METADATA_COMPLETE_V1;p->ownership=CKFSS_OWNER_ORIGINAL;
    p->max_file_bytes=128*1024*1024;p->max_total_bytes=512*1024*1024;
    p->max_metadata_bytes=1024*1024;p->max_metadata_records=16384;p->max_total_metadata_bytes=16*1024*1024;
    p->max_parent_entries=100'000;p->max_components_per_path=64;
}
ckfss_status ckfss_session_open_verified(const ckfss_options* o,const ckfss_metadata_policy* policy,
    ckfss_session** out,ckfss_error* e) noexcept {
    if(out) *out=nullptr;clear(e);
    return native_boundary(e,[&]()->ckfss_status {
        require(o && policy && out);validate_policy(*policy);
        auto options=*o;digest(options.policy_fingerprint,policy_binding(*o,*policy));
        ckfss_session* raw=nullptr;auto result=ckfss_session_open(&options,&raw,e);
        if(result!=CKFSS_OK) return result;
        std::unique_ptr<ckfss_session> s(raw);s->metadata_policy=*policy;*out=s.release();return CKFSS_OK;
    });
}
ckfss_status ckfss_session_verify_exact_paths(ckfss_session* s,const ckfss_exact_path* paths,
    uint64_t count,const ckfss_metadata_policy* policy,ckfss_receipt** out,ckfss_error* e) noexcept {
    if(out) *out=nullptr;clear(e);
    return native_boundary(e,[&]()->ckfss_status {
        require(s && policy && out && (paths || !count) && count<=s->limits.max_rows);validate_policy(*policy);
        if(!s->metadata_policy) native_fail("sync_session.verified_open_required",ObservationState::Unsupported);
        require(same_policy(*policy,*s->metadata_policy));cancelled(*s);native_value(s->core->revalidate());
        if((s->core->snapshot().state==SyncSessionState::ReviewRequired || s->core->snapshot().state==SyncSessionState::HistoryChanged)) native_fail("sync_session.baseline_review_required");
        auto receipt=std::make_unique<ckfss_receipt>();receipt->owner=s->receipt_owner;
        receipt->identity=s->core->identity();receipt->generation=s->core->snapshot().generation;
        std::uint64_t total=0;Budget budget;
        for(uint64_t i=0;i<count;++i) {
            const auto& in=paths[i];require(in.components && in.component_count && in.component_count<=policy->max_components_per_path &&
                in.disposition<=CKFSS_SKIP_PATH && !in.reserved);
            PathProof p;p.skipped=in.disposition==CKFSS_SKIP_PATH;
            for(uint64_t j=0;j<in.component_count;++j) p.components.push_back(component(in.components[j]));
            p.key=exact_key(p.components);require(p.key.size()<=s->limits.max_path_bytes);
            charge(total,p.key.size(),s->limits.max_total_path_bytes,"sync_session.exact_key_limit");
            if(!p.skipped) { p.left=observe_side(*s,p.components,false,budget);p.right=observe_side(*s,p.components,true,budget); }
            receipt->paths.push_back(std::move(p));
        }
        std::sort(receipt->paths.begin(),receipt->paths.end(),[](const auto& a,const auto& b){return a.key<b.key;});
        for(std::size_t i=0;i<receipt->paths.size();++i) {
            const auto& p=receipt->paths[i];require(!i || receipt->paths[i-1].key!=p.key);
            const bool equal=!p.skipped && p.left.status==p.right.status &&
                (policy->ownership!=CKFSS_OWNER_CURRENT_CALLER || owners_equal(p.left,p.right));
            receipt->updates.push_back({{p.key,p.left.status,p.right.status},equal?SyncBaselineUpdateState::ConfirmedEqual:SyncBaselineUpdateState::Pending});
        }
        cancelled(*s);native_value(s->core->revalidate());receipt->retained_budget=budget;*out=receipt.release();return CKFSS_OK;
    });
}
void ckfss_receipt_destroy(ckfss_receipt* r) noexcept { delete r; }
ckfss_status ckfss_receipt_get_counts(const ckfss_receipt* r,uint64_t* confirmed,uint64_t* pending) noexcept {
    if(confirmed) *confirmed=0;if(pending) *pending=0;
    return boundary([&]()->ckfss_status { require(r && confirmed && pending);
        for(const auto& u:r->updates) if(u.state==SyncBaselineUpdateState::ConfirmedEqual) ++*confirmed;else ++*pending;
        return CKFSS_OK;
    });
}
ckfss_status ckfss_session_commit_verified(ckfss_session* s,ckfss_receipt* r,uint32_t approve,
    ckfss_snapshot* out,ckfss_error* e) noexcept {
    if(out) *out={};clear(e);
    return native_boundary(e,[&]()->ckfss_status {
        require(s && r && out && approve<=1);
        if(!s->metadata_policy || r->owner!=s->receipt_owner || r->consumed || r->identity.pair!=s->core->identity().pair ||
            r->identity.policy!=s->core->identity().policy || r->generation!=s->core->snapshot().generation)
            native_fail("sync_session.foreign_stale_receipt");
        cancelled(*s);native_value(s->core->revalidate());Budget budget;
        budget.metadata=r->retained_budget.metadata;budget.handles=r->retained_budget.handles;
        for(const auto& p:r->paths) if(!p.skipped) {
            // Keep the original native objects alive while proving the exact
            // paths still name the same versions and freshly hashing both sides.
            auto left=observe_side(*s,p.components,false,budget);auto right=observe_side(*s,p.components,true,budget);
            if(!same_side_version(p.left,left) || !same_side_version(p.right,right)) native_fail("sync_session.receipt_version_changed");
            if(p.left.file) native_value(p.left.file->verify_metadata_source(*p.left.metadata));
            if(p.right.file) native_value(p.right.file->verify_metadata_source(*p.right.metadata));
        }
        cancelled(*s);native_value(s->core->revalidate());r->consumed=true;
        auto advance=s->core->commit(r->generation,r->updates,approve!=0,[s]{return s->cancelled.load(std::memory_order_relaxed);});
        if(!advance.value()) return unavailable(advance,e);
        s->pending=std::move(advance).take_value().pending_paths;snapshot(*s,*out);return CKFSS_OK;
    });
}
}

extern "C" ckfss_status ckfss_session_get_capabilities(const ckfss_session* s,uint64_t* supported,uint64_t* conditional) noexcept {
    if(supported) *supported=0;if(conditional) *conditional=0;
    return boundary([&]()->ckfss_status { require(s && supported && conditional);
        *supported=CKFSS_CAP_OVERLAP_SESSION_LOCKS|CKFSS_CAP_DURABLE_BASELINE;
        if(s->metadata_policy) *conditional=CKFSS_CAP_REGULAR_RECEIPT|CKFSS_CAP_FINAL_ABSENCE_RECEIPT;
        return CKFSS_OK;
    });
}
