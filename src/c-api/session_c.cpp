// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_fs_session.h"
#include "journal_root_handles.hpp"
#include "sync_session.hpp"
#include "native_sync_coordinator.hpp"
#include "native_sync_observation.hpp"
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
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
using namespace ck::files;
struct ckfss_session {
    std::unique_ptr<SyncSession> core;
    SyncBaselineLimits limits;
    std::vector<std::string> pending;
    std::atomic<bool> cancelled{false};
    std::mutex cancel_mutex;
    std::stop_source active_cancel{std::nostopstate};
    NativeFileSystem filesystem;
    std::optional<NativeAbsolutePath> coordinator_address,left_address,right_address;
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
static ckfss_status session_open_impl(const ckfss_options* o,PreparedJournalRoot::Pointer owner,ckfss_session** out,ckfss_error* e) noexcept {
    if(out) *out=nullptr; clear(e);
    return boundary([&]()->ckfss_status {
        require(o && out && o->version==CKFSS_VERSION && o->struct_size==sizeof(*o));
        for(auto v:o->reserved) require(!v);
        auto l=limits(o->limits); auto left=path(o->left),right=path(o->right);
        std::optional<NativeAbsolutePath> coordinator;
        if(!owner)coordinator=path(o->coordinator);
        auto b=owner?open_native_sync_session_backend(std::move(owner),left,right):
            open_native_sync_session_backend(*coordinator,left,right);
        if(!b.value()) return unavailable(b,e);
        auto core=SyncSession::open(std::move(b).take_value(),digest(o->policy_fingerprint),l);
        if(!core.value()) return unavailable(core,e);
        auto s=std::make_unique<ckfss_session>(); s->limits=l; s->core=std::move(core).take_value();
        s->coordinator_address=coordinator; s->left_address=left; s->right_address=right;
        *out=s.release(); return CKFSS_OK;
    });
}
ckfss_status ckfss_session_open(const ckfss_options* o,ckfss_session** out,ckfss_error* e) noexcept {
    return session_open_impl(o,{},out,e);
}
ckfss_status ckfss_session_open_with_journal_root(const ckfss_options* o,const ckfjr_root* root,ckfss_session** out,ckfss_error* e) noexcept {
    if(out)*out=nullptr;clear(e);
    return boundary([&]()->ckfss_status {require(root&&out);auto owner=retain_prepared_journal_root(root);
        if(!owner.value())return unavailable(owner,e);
        return session_open_impl(o,std::move(owner).take_value(),out,e);});
}
ckfss_status ckfss_session_finish_io(ckfss_session* s,ckfss_error* error) noexcept {
    clear(error);return boundary([&]()->ckfss_status {require(s);ckfss_session_request_cancel(s);s->receipt_owner.reset();
        auto result=s->core->finish_io();
        if(result.value()&&*result.value())return CKFSS_OK;
        if(result.value())result=Observation<bool>::unavailable(ObservationState::Unknown,{ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"sync_session.finish_false"});
        return unavailable(result,error);});
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
        // bytes or ConfirmedEqual. Native receipts and the two-way worker are
        // separate authority-producing paths; this raw-fact entry point refuses.
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
void ckfss_session_request_cancel(ckfss_session* s) noexcept {
    if(!s)return;
    s->cancelled.store(true);
    std::stop_source active(std::nostopstate);
    {std::lock_guard lock(s->cancel_mutex);active=s->active_cancel;}
    active.request_stop();
}
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
// Once a coordinator ledger adopts either held root, only its complete
// plan/rules/intent protocol may advance that baseline. Legacy per-path native
// receipts remain inspection-compatible but cannot bypass partial execution,
// protected-artifact catalogs, or a related pair's history review.
void unmanaged_receipt_storage(const ckfss_session& s) {
    auto owner=s.core->storage_root();
    if(!owner)native_fail("sync_session.storage_owner_unknown",ObservationState::Unsupported);
    const auto ledgers=native_value(load_native_sync_ledgers(std::move(owner)));
    const auto& live=s.core->identity();
    for(const auto& ledger:ledgers) {
        const auto& old=ledger.evidence.session;
        if(old.left_root==live.left_root||old.left_root==live.right_root||old.right_root==live.left_root||old.right_root==live.right_root)
            native_fail("sync_session.coordinator_managed_baseline",ObservationState::Changed,AdapterError::ProviderReviewRequired);
    }
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
#ifdef _WIN32
using Wire=std::vector<std::byte>;
void number(Wire& b,std::uint64_t n) { for(unsigned i=0;i<8;++i) b.push_back(std::byte((n>>(8*i))&255)); }
void blob(Wire& b,std::span<const std::byte> bytes) { number(b,bytes.size()); b.insert(b.end(),bytes.begin(),bytes.end()); }
#endif
SyncDigest policy_binding(const ckfss_options& o,const ckfss_metadata_policy& p) {
    MetadataReplayPolicy metadata;
    metadata.scope=static_cast<RegularMetadataScope>(p.scope);
    metadata.ownership=static_cast<MetadataOwnership>(p.ownership);
    metadata.allow_privilege_metadata=p.allow_privilege_metadata!=0;
    return native_sync_policy_binding(digest(o.policy_fingerprint),metadata);
}
#ifdef _WIN32
void sid_semantics(Wire& b,PSID sid) {
    if(!sid) { number(b,0); return; }
    if(!IsValidSid(sid)) native_fail("sync_session.metadata_sid",ObservationState::Unsupported);
    blob(b,std::as_bytes(std::span(static_cast<const std::byte*>(sid),GetLengthSid(sid))));
}
#endif
struct ParentProof { std::shared_ptr<DirectoryCursor> cursor; BasicMetadata before; };
struct SideProof {
    SyncEntryStatus status;
    std::vector<ParentProof> parents;
    HeldChild::Pointer file;
    std::shared_ptr<const OpenedEntry> native_source;
    std::optional<MetadataReplaySnapshot> metadata;
};
struct PathProof {
    std::vector<NativeName> components;
    std::string key;
    bool skipped=false;
    SideProof left,right;
};
struct Budget { std::uint64_t content=0,metadata=0,parents=0,handles=0; };
// Only request_cancel may race this worker. Publish a shared cancellation owner
// before checking the sticky flag, so cancellation during native stream hashing
// cannot fall between the caller's flag and the provider's stop token. Clear
// never races an active proof; request_cancel's copy keeps its source alive.
struct NativeCancelScope final {
    ckfss_session& session;
    std::stop_source source;
    explicit NativeCancelScope(ckfss_session& s):session(s) {
        {std::lock_guard lock(session.cancel_mutex);session.active_cancel=source;}
        if(session.cancelled.load())source.request_stop();
    }
    ~NativeCancelScope(){std::lock_guard lock(session.cancel_mutex);session.active_cancel=std::stop_source(std::nostopstate);}
    NativeCancelScope(const NativeCancelScope&)=delete;
    NativeCancelScope& operator=(const NativeCancelScope&)=delete;
};
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
        MetadataReplayPolicy policy;policy.scope=static_cast<RegularMetadataScope>(p.scope);
        policy.ownership=static_cast<MetadataOwnership>(p.ownership);policy.allow_privilege_metadata=p.allow_privilege_metadata!=0;
        policy.limits={static_cast<std::size_t>(p.max_metadata_bytes),static_cast<std::size_t>(p.max_metadata_records)};
        charge(budget.handles,2,p.max_parent_entries,"sync_session.aggregate_file_handle_limit");
        charge(budget.metadata,sizeof(NativeCancelScope)+512,p.max_total_metadata_bytes,"sync_session.cancel_proof_limit");
        NativeSyncProofLimits limits;
        limits.max_file_bytes=p.max_file_bytes;limits.max_total_bytes=p.max_total_bytes;
        limits.max_metadata_bytes=static_cast<std::size_t>(p.max_total_metadata_bytes);limits.max_entries=1;
        NativeSyncProofBudget native_budget{budget.content,budget.metadata,0};
        NativeCancelScope cancellation(s);
        auto proof=native_value(observe_native_sync_file(cursor,names[i],policy,limits,native_budget,cancellation.source.get_token()));
        if(!same_version(basic,proof.metadata.basic))native_fail("sync_session.file_open_changed");
        budget.content=native_budget.bytes;budget.metadata=native_budget.metadata;
        out.file=std::move(proof.held);out.native_source=std::move(proof.native_source);
        out.metadata=std::move(proof.metadata);out.status=proof.status;
        cancelled(s);
        check_parents(out.parents,names);root_binding(s,*out.parents.front().cursor,right);
        return out;
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
ckfss_status ckfss_session_open_verified_with_journal_root(const ckfss_options* o,const ckfss_metadata_policy* policy,
    const ckfjr_root* root,ckfss_session** out,ckfss_error* e) noexcept {
    if(out)*out=nullptr;clear(e);
    return native_boundary(e,[&]()->ckfss_status {
        require(o&&policy&&root&&out);validate_policy(*policy);
        auto options=*o;digest(options.policy_fingerprint,policy_binding(*o,*policy));
        ckfss_session* raw=nullptr;auto result=ckfss_session_open_with_journal_root(&options,root,&raw,e);
        if(result!=CKFSS_OK)return result;
        std::unique_ptr<ckfss_session> s(raw);s->metadata_policy=*policy;*out=s.release();return CKFSS_OK;
    });
}
ckfss_status ckfss_session_verify_exact_paths(ckfss_session* s,const ckfss_exact_path* paths,
    uint64_t count,const ckfss_metadata_policy* policy,ckfss_receipt** out,ckfss_error* e) noexcept {
    if(out) *out=nullptr;clear(e);
    return native_boundary(e,[&]()->ckfss_status {
        require(s && policy && out && (paths || !count) && count<=s->limits.max_rows);validate_policy(*policy);
        if(!s->metadata_policy) native_fail("sync_session.verified_open_required",ObservationState::Unsupported);
        require(same_policy(*policy,*s->metadata_policy));cancelled(*s);native_value(s->core->revalidate());unmanaged_receipt_storage(*s);
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
        cancelled(*s);native_value(s->core->revalidate());unmanaged_receipt_storage(*s);Budget budget;
        budget.metadata=r->retained_budget.metadata;budget.handles=r->retained_budget.handles;
        for(const auto& p:r->paths) if(!p.skipped) {
            // Keep the original native objects alive while proving the exact
            // paths still name the same versions and freshly hashing both sides.
            auto left=observe_side(*s,p.components,false,budget);auto right=observe_side(*s,p.components,true,budget);
            if(!same_side_version(p.left,left) || !same_side_version(p.right,right)) native_fail("sync_session.receipt_version_changed");
            if(p.left.file) native_value(p.left.file->verify_metadata_source(*p.left.metadata));
            if(p.right.file) native_value(p.right.file->verify_metadata_source(*p.right.metadata));
        }
        cancelled(*s);native_value(s->core->revalidate());unmanaged_receipt_storage(*s);r->consumed=true;
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

static_assert(static_cast<unsigned>(SyncAction::Blocked)==CKFSS_TW_BLOCKED);
static_assert(static_cast<unsigned>(SyncReason::DeletionGuard)==CKFSS_TW_REASON_DELETION_GUARD);
static_assert(static_cast<unsigned>(NativeSyncCoordinatorState::NeedsReview)==CKFSS_TW_NEEDS_REVIEW);
struct ckfss_two_way {
    NativeSyncCoordinator::Pointer core;
    std::stop_source stop;
};
namespace {
void tw_error(const UnavailableObservation& detail,ckfss_error& out) {
    out={};out.observation=static_cast<uint32_t>(detail.state);out.domain=static_cast<uint32_t>(detail.error.domain);out.code=detail.error.code;
    std::memcpy(out.operation,detail.error.operation.data(),std::min(detail.error.operation.size(),sizeof(out.operation)-1));
}
void tw_info(const ckfss_two_way& worker,ckfss_two_way_info& out) {
    out={};out.version=CKFSS_VERSION;out.struct_size=sizeof(out);const auto& r=worker.core->result();
    out.state=static_cast<uint32_t>(r.state);out.generation=r.generation;out.rows=worker.core->rows().size();
    out.protected_artifacts=worker.core->protected_artifacts().size();out.completed_operations=r.completed_operations;out.pending_rows=r.pending_keys.size();
    if(r.failure){out.has_failure=1;tw_error(*r.failure,out.failure);}
}
ckfss_status tw_component(const std::vector<NativeName>& names,uint64_t index,uint32_t* encoding,
    void* buffer,uint64_t capacity,uint64_t* required) {
    require(encoding&&required&&(buffer||!capacity)&&index<names.size());*required=0;*encoding=0;
    const auto& name=names[static_cast<std::size_t>(index)];
    if(const auto* p=name.posix_bytes()) {
        *encoding=CKFSS_POSIX_BYTES;*required=p->size();if(capacity<p->size())return CKFSS_BUFFER_TOO_SMALL;
        if(!p->empty())std::memcpy(buffer,p->data(),p->size());return CKFSS_OK;
    }
    const auto* w=name.windows_units();require(w);*encoding=CKFSS_WINDOWS_UTF16;*required=w->size();
    if(capacity<w->size())return CKFSS_BUFFER_TOO_SMALL;
    if(!w->empty())std::memcpy(buffer,w->data(),w->size()*sizeof(char16_t));return CKFSS_OK;
}
ckfss_durable_identity tw_identity(const NativeDurableIdentity& id) {
    ckfss_durable_identity out{};out.scheme=static_cast<uint32_t>(id.scheme);out.has_generation=id.generation.has_value();out.generation=id.generation.value_or(0);
    std::memcpy(out.volume,id.volume.bytes.data(),sizeof(out.volume));std::memcpy(out.object,id.object.bytes.data(),sizeof(out.object));return out;
}
}
extern "C" {
void ckfss_two_way_policy_init(ckfss_two_way_policy* p) noexcept {
    if(!p)return;*p={};p->version=CKFSS_VERSION;p->struct_size=sizeof(*p);NativeSyncProofLimits proof;NativeSyncLedgerLimits ledger;
    p->max_entries=proof.max_entries;p->chunk_bytes=proof.chunk_bytes;p->max_ledger_files=ledger.max_ledgers;
    p->max_ledger_bytes=ledger.max_total_wire_bytes;p->max_retained_artifacts=ledger.max_artifacts;
}
static ckfss_status two_way_open_impl(const ckfss_options* o,const ckfss_metadata_policy* metadata,const ckfss_two_way_policy* execution,
    PreparedJournalRoot::Pointer owner,ckfss_two_way** out,ckfss_error* error) noexcept {
    if(out)*out=nullptr;clear(error);
    return boundary([&]()->ckfss_status {
        require(o&&metadata&&execution&&out&&o->version==CKFSS_VERSION&&o->struct_size==sizeof(*o));
        for(auto reserved:o->reserved)require(!reserved);validate_policy(*metadata);
        const auto& p=*execution;
        require(p.version==CKFSS_VERSION&&p.struct_size==sizeof(p)&&!p.reserved&&p.max_entries&&p.max_entries<=1'000'000&&
            p.chunk_bytes&&p.chunk_bytes<=ContentReadLimits::hard_max_bytes&&p.max_ledger_files&&p.max_ledger_files<=4096&&
            p.max_ledger_bytes&&p.max_ledger_bytes<=OperationJournalLimits::hard_max_evidence_bytes&&
            p.max_retained_artifacts<=1'000'000&&p.max_deletions<=1'000'000&&p.max_delete_basis_points<=10000);
        NativeSyncCoordinatorRequest request{owner?std::optional<NativeAbsolutePath>{}:path(o->coordinator),path(o->left),path(o->right),digest(o->policy_fingerprint),{},{},{},{},{},{}};
        request.prepared_journal_root=std::move(owner);
        request.metadata.scope=static_cast<RegularMetadataScope>(metadata->scope);request.metadata.ownership=static_cast<MetadataOwnership>(metadata->ownership);
        request.metadata.allow_privilege_metadata=metadata->allow_privilege_metadata!=0;
        request.metadata.limits={static_cast<std::size_t>(metadata->max_metadata_bytes),static_cast<std::size_t>(metadata->max_metadata_records)};
        request.proof_limits={metadata->max_file_bytes,metadata->max_total_bytes,static_cast<std::size_t>(p.max_entries),
            static_cast<std::size_t>(metadata->max_total_metadata_bytes),static_cast<std::size_t>(p.chunk_bytes),limits(o->limits)};
        request.ledger_limits={static_cast<std::size_t>(p.max_ledger_files),static_cast<std::size_t>(p.max_ledger_bytes),
            static_cast<std::size_t>(p.max_retained_artifacts),request.proof_limits.baseline};
        request.deletion_guard={static_cast<std::size_t>(p.max_deletions),p.max_delete_basis_points};
        auto core=NativeSyncCoordinator::open(std::move(request));if(!core.value())return unavailable(core,error);
        auto worker=std::make_unique<ckfss_two_way>();worker->core=std::move(core).take_value();*out=worker.release();return CKFSS_OK;
    });
}
ckfss_status ckfss_two_way_open(const ckfss_options* o,const ckfss_metadata_policy* metadata,const ckfss_two_way_policy* execution,
    ckfss_two_way** out,ckfss_error* error) noexcept {return two_way_open_impl(o,metadata,execution,{},out,error);}
ckfss_status ckfss_two_way_open_with_journal_root(const ckfss_options* o,const ckfss_metadata_policy* metadata,const ckfss_two_way_policy* execution,
    const ckfjr_root* root,ckfss_two_way** out,ckfss_error* error) noexcept {
    if(out)*out=nullptr;clear(error);
    return boundary([&]()->ckfss_status {require(root&&out);auto owner=retain_prepared_journal_root(root);
        if(!owner.value())return unavailable(owner,error);
        return two_way_open_impl(o,metadata,execution,std::move(owner).take_value(),out,error);});
}
ckfss_status ckfss_two_way_finish_io(ckfss_two_way* worker,ckfss_error* error) noexcept {
    clear(error);return boundary([&]()->ckfss_status {require(worker);worker->stop.request_stop();
        auto result=worker->core->finish_io();
        if(result.value()&&*result.value())return CKFSS_OK;
        if(result.value())result=Observation<bool>::unavailable(ObservationState::Unknown,{ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"native_sync.finish_false"});
        return unavailable(result,error);});
}
void ckfss_two_way_destroy(ckfss_two_way* worker) noexcept {delete worker;}
ckfss_status ckfss_two_way_get_info(const ckfss_two_way* worker,ckfss_two_way_info* out) noexcept {
    if(out)*out={};return boundary([&]()->ckfss_status {require(worker&&out);tw_info(*worker,*out);return CKFSS_OK;});
}
ckfss_status ckfss_two_way_get_capabilities(const ckfss_two_way* worker,uint64_t* supported,uint64_t* conditional) noexcept {
    if(supported)*supported=0;if(conditional)*conditional=0;
    return boundary([&]()->ckfss_status {require(worker&&supported&&conditional);*supported=CKFSS_CAP_OVERLAP_SESSION_LOCKS|CKFSS_CAP_DURABLE_BASELINE;
        *conditional=CKFSS_CAP_REGULAR_RECEIPT|CKFSS_CAP_FINAL_ABSENCE_RECEIPT|CKFSS_CAP_TWO_WAY_EXECUTION;return CKFSS_OK;});
}
ckfss_status ckfss_two_way_get_row(const ckfss_two_way* worker,uint64_t index,ckfss_two_way_row* out,
    void* key,uint64_t capacity,uint64_t* required) noexcept {
    if(out)*out={};if(required)*required=0;
    return boundary([&]()->ckfss_status {
        require(worker&&out&&index<worker->core->rows().size());const auto& row=worker->core->rows()[static_cast<std::size_t>(index)];
        out->left=status(row.left);out->right=status(row.right);out->proposed_action=static_cast<uint32_t>(row.proposal);out->reason=static_cast<uint32_t>(row.reason);
        out->relative_key_bytes=row.exact_key.size();out->component_count=worker->core->components(static_cast<std::size_t>(index)).size();
        return copy_key(row.exact_key,key,capacity,required);
    });
}
ckfss_status ckfss_two_way_get_component(const ckfss_two_way* worker,uint64_t row,uint64_t component,
    uint32_t* encoding,void* units,uint64_t capacity,uint64_t* required) noexcept {
    if(encoding)*encoding=0;if(required)*required=0;
    return boundary([&]()->ckfss_status {require(worker&&row<worker->core->rows().size());return tw_component(worker->core->components(static_cast<std::size_t>(row)),component,encoding,units,capacity,required);});
}
ckfss_status ckfss_two_way_get_retained(const ckfss_two_way* worker,uint64_t index,ckfss_two_way_retained* out) noexcept {
    if(out)*out={};return boundary([&]()->ckfss_status {
        require(worker&&out&&index<worker->core->protected_artifacts().size());const auto& artifact=worker->core->protected_artifacts()[static_cast<std::size_t>(index)].artifact;
        out->kind=static_cast<uint32_t>(artifact.kind);out->protection=CKFSS_TW_PROTECTED;out->right_side=artifact.right;
        out->component_count=artifact.components.size();out->parent=tw_identity(artifact.parent);out->object=tw_identity(artifact.object);out->observed=status(artifact.status);return CKFSS_OK;
    });
}
ckfss_status ckfss_two_way_get_retained_component(const ckfss_two_way* worker,uint64_t artifact,uint64_t component,
    uint32_t* encoding,void* units,uint64_t capacity,uint64_t* required) noexcept {
    if(encoding)*encoding=0;if(required)*required=0;
    return boundary([&]()->ckfss_status {require(worker&&artifact<worker->core->protected_artifacts().size());return tw_component(worker->core->protected_artifacts()[static_cast<std::size_t>(artifact)].artifact.components,component,encoding,units,capacity,required);});
}
ckfss_status ckfss_two_way_approve(ckfss_two_way* worker,const ckfss_two_way_decision* decisions,uint64_t count,uint32_t first,ckfss_error* error) noexcept {
    clear(error);return boundary([&]()->ckfss_status {
        require(worker&&(decisions||!count)&&first<=1&&count==worker->core->rows().size());
        std::vector<NativeSyncDecision> native;native.reserve(static_cast<std::size_t>(count));std::set<uint64_t> seen;
        for(uint64_t i=0;i<count;++i) {const auto& d=decisions[i];require(d.row_index<count&&d.choice<=CKFSS_TW_RIGHT_WINS&&!d.reserved&&seen.insert(d.row_index).second);
            native.push_back({worker->core->rows()[static_cast<std::size_t>(d.row_index)].exact_key,static_cast<NativeSyncChoice>(d.choice)});}
        auto approved=worker->core->approve(native,first!=0);return approved.value()?CKFSS_OK:unavailable(approved,error);
    });
}
ckfss_status ckfss_two_way_advance(ckfss_two_way* worker,ckfss_two_way_info* out,ckfss_error* error) noexcept {
    if(out)*out={};clear(error);return boundary([&]()->ckfss_status {
        require(worker&&out);worker->core->advance(worker->stop.get_token());tw_info(*worker,*out);
        if(out->has_failure){if(error)*error=out->failure;return CKFSS_UNAVAILABLE;}return CKFSS_OK;
    });
}
void ckfss_two_way_request_cancel(ckfss_two_way* worker) noexcept {if(worker)worker->stop.request_stop();}
ckfss_status ckfss_two_way_get_pending_key(const ckfss_two_way* worker,uint64_t index,void* key,uint64_t capacity,uint64_t* required) noexcept {
    if(required)*required=0;return boundary([&]()->ckfss_status {require(worker&&index<worker->core->result().pending_keys.size());return copy_key(worker->core->result().pending_keys[static_cast<std::size_t>(index)],key,capacity,required);});
}
} // extern C

struct ckfss_two_way_review {
    NativeSyncRuleAssessment::Pointer core;
    uint64_t generation=0;
};
namespace {
ckfss_two_way_observed tw_observed(const NativeSyncObservedFacts& f) {
    ckfss_two_way_observed out{};out.status=status(f.status);
    if(f.kind){out.known_fields|=CKFSS_FACT_KIND;out.kind=static_cast<uint32_t>(*f.kind);}
    if(f.size){out.known_fields|=CKFSS_FACT_SIZE;out.size=*f.size;}
    if(f.modified){out.known_fields|=CKFSS_FACT_MODIFIED;out.modified_seconds=f.modified->seconds();out.modified_nanoseconds=f.modified->nanoseconds();}
    if(f.status.presence!=SyncPresence::Unknown)out.known_fields|=CKFSS_FACT_REQUIRED_METADATA;return out;
}
}
extern "C" {
void ckfss_two_way_rule_init(ckfss_two_way_rule* rule) noexcept {
    if(!rule)return;*rule={};rule->version=CKFSS_VERSION;rule->struct_size=sizeof(*rule);rule->scope=CKFSS_SCOPE_JOB;rule->protect_nonempty=1;rule->retain_replaced=1;
}
ckfss_status ckfss_two_way_get_facts(ckfss_two_way* worker,uint64_t index,ckfss_two_way_raw_facts* out,ckfss_error* error) noexcept {
    if(out)*out={};clear(error);return boundary([&]()->ckfss_status {
        require(worker&&out&&index<worker->core->rows().size());auto facts=worker->core->facts(static_cast<std::size_t>(index));if(!facts.value())return unavailable(facts,error);
        const auto& f=*facts.value();out->version=CKFSS_VERSION;out->struct_size=sizeof(*out);out->row_index=index;out->generation=worker->core->result().generation;
        out->relation=static_cast<uint32_t>(f.relation);out->conflict_class=static_cast<uint32_t>(f.conflict_class);out->left=tw_observed(f.left);out->right=tw_observed(f.right);out->allowed_choices=f.allowed_choices;
        out->left_retention_state=static_cast<uint32_t>(f.left_retention.state());out->right_retention_state=static_cast<uint32_t>(f.right_retention.state());
        if(f.left_retention.value())out->left_retention_available=*f.left_retention.value();else tw_error(*f.left_retention.unavailable_detail(),out->left_retention_failure);
        if(f.right_retention.value())out->right_retention_available=*f.right_retention.value();else tw_error(*f.right_retention.unavailable_detail(),out->right_retention_failure);return CKFSS_OK;
    });
}
ckfss_status ckfss_two_way_assess_rules(ckfss_two_way* worker,const ckfss_two_way_rule* rules,uint64_t count,uint64_t quantum,
    ckfss_two_way_review** out,ckfss_error* error) noexcept {
    if(out)*out=nullptr;clear(error);return boundary([&]()->ckfss_status {
        require(worker);worker->core->invalidate_rule_receipts();
        require(out&&(rules||!count)&&count<=4096);
        if(worker->stop.stop_requested())return unavailable(Observation<bool>::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::InterruptedRead),"native_sync.cancelled"}),error);
        const auto row_count=worker->core->rows().size();
        auto identity=worker->core->rule_plan_identity();if(!identity.value())return unavailable(identity,error);
        std::vector<ConflictRule> native;native.reserve(static_cast<std::size_t>(count));uint64_t selected_total=0,keys_total=0;
        for(uint64_t i=0;i<count;++i) {
            const auto& r=rules[i];
            if(r.expected_generation!=worker->core->result().generation)return unavailable(Observation<bool>::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::PlanDecisionStale),"native_sync.rule_generation_stale"}),error);
            require(r.version==CKFSS_VERSION&&r.struct_size==sizeof(r)&&!r.reserved&&r.kind<=CKFSS_CONFLICT_CAPACITY&&
                r.choice<=CKFSS_RULE_DELETE_EDITED&&r.tie<=CKFSS_RULE_DELETE_EDITED&&r.scope<=CKFSS_SCOPE_JOB&&r.direction<=CKFSS_DIRECTION_RIGHT_TO_LEFT&&
                r.protect_nonempty<=1&&r.retain_replaced<=1&&
                r.selected_count<=row_count&&r.selected_count<=1000000-selected_total&&(r.selected_rows||!r.selected_count)&&
                r.subtree_key_bytes<=65536&&r.subtree_key_bytes<=16777216-keys_total&&(r.subtree_key||!r.subtree_key_bytes));
            selected_total+=r.selected_count;keys_total+=r.subtree_key_bytes;
            ConflictRule n;n.plan=*identity.value();n.kind=static_cast<ConflictClass>(r.kind);n.choice=static_cast<ConflictChoice>(r.choice);n.tie=static_cast<ConflictChoice>(r.tie);
            n.scope=static_cast<ConflictScope>(r.scope);n.direction=static_cast<ConflictDirection>(r.direction);n.protect_nonempty=r.protect_nonempty!=0;n.retain_replaced=r.retain_replaced!=0;
            for(uint64_t j=0;j<r.selected_count;++j){require(r.selected_rows[j]<row_count);n.selected_rows.push_back(r.selected_rows[j]+1);}
            if(r.subtree_key_bytes)n.subtree.assign(static_cast<const char*>(r.subtree_key),static_cast<std::size_t>(r.subtree_key_bytes));native.push_back(std::move(n));
        }
        auto assessed=worker->core->assess_rules(native,quantum,worker->stop.get_token());if(!assessed.value())return unavailable(assessed,error);
        auto review=std::make_unique<ckfss_two_way_review>();review->core=std::move(assessed).take_value();review->generation=worker->core->result().generation;*out=review.release();return CKFSS_OK;
    });
}
void ckfss_two_way_review_destroy(ckfss_two_way_review* review) noexcept {delete review;}
ckfss_status ckfss_two_way_review_get_info(const ckfss_two_way_review* review,ckfss_two_way_review_info* out) noexcept {
    if(out)*out={};return boundary([&]()->ckfss_status {
        require(review&&out);out->version=CKFSS_VERSION;out->struct_size=sizeof(*out);out->generation=review->generation;out->consumed=review->core->consumed();out->rows=review->core->rows().size();
        for(const auto& row:review->core->rows()) {
            if(row.decision.rule_index)++out->matched_rows;
            if(row.decision.state==ConflictRuleState::Apply)++out->applied_rows;
            else if(row.decision.state!=ConflictRuleState::NoMatch)++out->unresolved_rows;
            if(row.decision.state==ConflictRuleState::Apply&&row.selected.choice==NativeSyncChoice::Skip)++out->skipped_rows;
        }return CKFSS_OK;
    });
}
ckfss_status ckfss_two_way_review_get_row(const ckfss_two_way_review* review,uint64_t index,ckfss_two_way_rule_result* out) noexcept {
    if(out)*out={};return boundary([&]()->ckfss_status {
        require(review&&out&&index<review->core->rows().size());const auto& row=review->core->rows()[static_cast<std::size_t>(index)];out->state=static_cast<uint32_t>(row.decision.state);
        out->choice=static_cast<uint32_t>(row.decision.choice);out->reason=static_cast<uint32_t>(row.decision.reason);out->selected_choice=static_cast<uint32_t>(row.selected.choice);
        out->used_fallback=row.decision.used_fallback;out->retain_replaced=row.decision.retain_replaced;out->has_rule_index=row.decision.rule_index.has_value();out->rule_index=row.decision.rule_index.value_or(0);return CKFSS_OK;
    });
}
ckfss_status ckfss_two_way_approve_review(ckfss_two_way* worker,ckfss_two_way_review* review,uint32_t first,ckfss_error* error) noexcept {
    clear(error);return boundary([&]()->ckfss_status {require(worker&&review&&first<=1);auto approved=worker->core->approve_rules(*review->core,first!=0,worker->stop.get_token());return approved.value()?CKFSS_OK:unavailable(approved,error);});
}
} // extern C

#include "native_sync_resolution.hpp"
struct ckfss_resolution_job { NativeSyncResolution::Pointer core;std::stop_source stop; };
struct ckfss_resolution_review { NativeSyncResolutionReceipt::Pointer core; };
namespace {
NativeName resolution_name(const ckfss_native_path& p) {
    require(p.data&&p.units&&!p.reserved&&p.units<=4096);
    if(p.encoding==CKFSS_POSIX_BYTES){auto n=NativeName::from_posix({static_cast<const char*>(p.data),static_cast<std::size_t>(p.units)});require(n.has_value());return *n;}
    require(p.encoding==CKFSS_WINDOWS_UTF16);std::u16string units(static_cast<std::size_t>(p.units),u'\0');std::memcpy(units.data(),p.data,units.size()*2);auto n=NativeName::from_windows(std::move(units));require(n.has_value());return *n;
}
void resolution_info(const ckfss_resolution_job& worker,ckfss_two_way_info& out){out={};out.version=CKFSS_VERSION;out.struct_size=sizeof(out);const auto& r=worker.core->result();out.state=static_cast<uint32_t>(r.state);out.generation=r.generation;out.rows=worker.core->rows().size();out.protected_artifacts=worker.core->protected_originals().size();out.completed_operations=r.completed_operations;out.pending_rows=r.pending_keys.size();if(r.failure){out.has_failure=1;tw_error(*r.failure,out.failure);}}
ckfss_status resolution_open(const ckfss_options* o,const ckfss_metadata_policy* metadata,const ckfss_two_way_policy* execution,
    const ckfss_resolution_limits_v1* configured,PreparedJournalRoot::Pointer owner,ckfss_resolution_job** out,ckfss_error* error) noexcept {
    if(out)*out=nullptr;clear(error);return boundary([&]()->ckfss_status {
        require(o&&metadata&&execution&&configured&&out&&o->version==CKFSS_VERSION&&o->struct_size==sizeof(*o));for(auto v:o->reserved)require(!v);validate_policy(*metadata);
        const auto& p=*execution;require(p.version==CKFSS_VERSION&&p.struct_size==sizeof(p)&&!p.reserved&&p.max_entries&&p.max_entries<=1'000'000&&p.chunk_bytes&&p.chunk_bytes<=ContentReadLimits::hard_max_bytes&&p.max_ledger_files&&p.max_ledger_files<=4096&&p.max_ledger_bytes&&p.max_ledger_bytes<=OperationJournalLimits::hard_max_evidence_bytes&&p.max_retained_artifacts<=1'000'000&&p.max_deletions<=1'000'000&&p.max_delete_basis_points<=10000);
        const auto& l=*configured;require(l.version==1&&l.struct_size==sizeof(l)&&l.max_resolutions&&l.max_resolutions<=128&&l.max_added_paths&&l.max_added_paths<=256&&l.max_protected_objects&&l.max_protected_objects<=256&&l.max_name_bytes&&l.max_name_bytes<=1024*1024&&l.max_transfer_bytes&&l.max_proof_bytes);for(auto v:l.reserved)require(!v);
        NativeSyncCoordinatorRequest r{owner?std::optional<NativeAbsolutePath>{}:path(o->coordinator),path(o->left),path(o->right),digest(o->policy_fingerprint),{},{},{},{},{},{}};r.prepared_journal_root=std::move(owner);
        r.metadata.scope=static_cast<RegularMetadataScope>(metadata->scope);r.metadata.ownership=static_cast<MetadataOwnership>(metadata->ownership);r.metadata.allow_privilege_metadata=metadata->allow_privilege_metadata!=0;r.metadata.limits={static_cast<std::size_t>(metadata->max_metadata_bytes),static_cast<std::size_t>(metadata->max_metadata_records)};
        r.proof_limits={metadata->max_file_bytes,metadata->max_total_bytes,static_cast<std::size_t>(p.max_entries),static_cast<std::size_t>(metadata->max_total_metadata_bytes),static_cast<std::size_t>(p.chunk_bytes),limits(o->limits)};r.ledger_limits={static_cast<std::size_t>(p.max_ledger_files),static_cast<std::size_t>(p.max_ledger_bytes),static_cast<std::size_t>(p.max_retained_artifacts),r.proof_limits.baseline};
        NativeSyncResolutionLimits bounds{static_cast<std::size_t>(l.max_resolutions),static_cast<std::size_t>(l.max_added_paths),static_cast<std::size_t>(l.max_protected_objects),l.max_name_bytes,l.max_transfer_bytes,l.max_proof_bytes};
        auto core=NativeSyncResolution::open(std::move(r),bounds);if(!core.value())return unavailable(core,error);auto worker=std::make_unique<ckfss_resolution_job>();worker->core=std::move(core).take_value();*out=worker.release();return CKFSS_OK;
    });
}
}
extern "C" {
void ckfss_named_resolution_init_v1(ckfss_named_resolution_v1* out) noexcept {if(out){*out={};out->version=1;out->struct_size=sizeof(*out);out->mode=CKFSS_RESOLVE_KEEP_BOTH_NAMED;}}
void ckfss_resolution_limits_init_v1(ckfss_resolution_limits_v1* out) noexcept {if(out){*out={};out->version=1;out->struct_size=sizeof(*out);NativeSyncResolutionLimits l;out->max_resolutions=l.max_resolutions;out->max_added_paths=l.max_added_paths;out->max_protected_objects=l.max_protected_objects;out->max_name_bytes=l.max_name_bytes;out->max_transfer_bytes=l.max_transfer_bytes;out->max_proof_bytes=l.max_proof_bytes;}}
ckfss_status ckfss_resolution_open_v1(const ckfss_options* o,const ckfss_metadata_policy* m,const ckfss_two_way_policy* e,const ckfss_resolution_limits_v1* l,ckfss_resolution_job** out,ckfss_error* error) noexcept {return resolution_open(o,m,e,l,{},out,error);}
ckfss_status ckfss_resolution_open_with_journal_root_v1(const ckfss_options* o,const ckfss_metadata_policy* m,const ckfss_two_way_policy* e,const ckfss_resolution_limits_v1* l,const ckfjr_root* root,ckfss_resolution_job** out,ckfss_error* error) noexcept {
    if(out)*out=nullptr;clear(error);return boundary([&]()->ckfss_status {require(root);auto owner=retain_prepared_journal_root(root);if(!owner.value())return unavailable(owner,error);return resolution_open(o,m,e,l,std::move(owner).take_value(),out,error);});}
ckfss_status ckfss_resolution_get_info_v1(const ckfss_resolution_job* w,ckfss_two_way_info* out) noexcept {if(out)*out={};return boundary([&]()->ckfss_status {require(w&&out);resolution_info(*w,*out);return CKFSS_OK;});}
ckfss_status ckfss_resolution_get_row_v1(const ckfss_resolution_job* w,uint64_t index,ckfss_two_way_row* out,void* key,uint64_t capacity,uint64_t* required) noexcept {
    if(out)*out={};if(required)*required=0;return boundary([&]()->ckfss_status {require(w&&out&&index<w->core->rows().size());const auto& row=w->core->rows()[static_cast<std::size_t>(index)];out->left=status(row.left);out->right=status(row.right);out->proposed_action=static_cast<uint32_t>(row.proposal);out->reason=static_cast<uint32_t>(row.reason);out->relative_key_bytes=row.exact_key.size();out->component_count=w->core->components(static_cast<std::size_t>(index)).size();return copy_key(row.exact_key,key,capacity,required);});}
ckfss_status ckfss_resolution_get_component_v1(const ckfss_resolution_job* w,uint64_t row,uint64_t component,uint32_t* encoding,void* units,uint64_t capacity,uint64_t* required) noexcept {
    if(encoding)*encoding=0;if(required)*required=0;return boundary([&]()->ckfss_status {require(w&&row<w->core->rows().size());return tw_component(w->core->components(static_cast<std::size_t>(row)),component,encoding,units,capacity,required);});}
ckfss_status ckfss_resolution_assess_v1(ckfss_resolution_job* w,const ckfss_named_resolution_v1* choices,uint64_t count,ckfss_resolution_review** out,ckfss_error* error) noexcept {
    if(out)*out=nullptr;clear(error);return boundary([&]()->ckfss_status {require(w&&out&&choices&&count&&count<=128);std::vector<NativeSyncNamedResolution> requests;requests.reserve(static_cast<std::size_t>(count));for(uint64_t i=0;i<count;++i){const auto& c=choices[i];require(c.version==1&&c.struct_size==sizeof(c)&&c.mode==CKFSS_RESOLVE_KEEP_BOTH_NAMED&&!c.reserved&&c.row_index<w->core->rows().size());requests.push_back({static_cast<std::size_t>(c.row_index),resolution_name(c.left_version_name),resolution_name(c.right_version_name)});}auto r=w->core->assess(requests,w->stop.get_token());if(!r.value())return unavailable(r,error);auto review=std::make_unique<ckfss_resolution_review>();review->core=std::move(r).take_value();*out=review.release();return CKFSS_OK;});}
ckfss_status ckfss_resolution_review_get_count_v1(const ckfss_resolution_review* r,uint64_t* count) noexcept {if(count)*count=0;return boundary([&]()->ckfss_status {require(r&&count);*count=r->core->operations().size();return CKFSS_OK;});}
ckfss_status ckfss_resolution_review_get_operation_v1(const ckfss_resolution_review* r,uint64_t index,ckfss_resolution_operation_v1* out) noexcept {
    if(out)*out={};return boundary([&]()->ckfss_status {require(r&&out&&index<r->core->operations().size());const auto& op=r->core->operations()[static_cast<std::size_t>(index)];out->version=1;out->struct_size=sizeof(*out);out->operation=static_cast<uint32_t>(op.kind);out->destination_right=op.destination_right;out->source_row=op.source_row;out->source_right=op.source_right;out->original_protected=op.kind==NativeSyncResolutionOperationKind::ProtectOriginal;out->component_count=op.components.size();out->main_data_bytes=op.main_data_bytes;return CKFSS_OK;});}
ckfss_status ckfss_resolution_review_get_component_v1(const ckfss_resolution_review* r,uint64_t index,uint64_t component,uint32_t* encoding,void* units,uint64_t capacity,uint64_t* required) noexcept {
    if(encoding)*encoding=0;if(required)*required=0;return boundary([&]()->ckfss_status {require(r&&index<r->core->operations().size());return tw_component(r->core->operations()[static_cast<std::size_t>(index)].components,component,encoding,units,capacity,required);});}
void ckfss_resolution_review_destroy_v1(ckfss_resolution_review* r) noexcept {delete r;}
ckfss_status ckfss_resolution_approve_v1(ckfss_resolution_job* w,const ckfss_resolution_review* r,uint32_t first,ckfss_error* error) noexcept {clear(error);return boundary([&]()->ckfss_status {require(w&&r&&first<=1);auto approved=w->core->approve(*r->core,first!=0,w->stop.get_token());return approved.value()?static_cast<ckfss_status>(CKFSS_OK):unavailable(approved,error);});}
ckfss_status ckfss_resolution_advance_v1(ckfss_resolution_job* w,ckfss_two_way_info* out,ckfss_error* error) noexcept {if(out)*out={};clear(error);return boundary([&]()->ckfss_status {require(w&&out);w->core->advance(w->stop.get_token());resolution_info(*w,*out);if(out->has_failure){if(error)*error=out->failure;return CKFSS_UNAVAILABLE;}return CKFSS_OK;});}
ckfss_status ckfss_resolution_get_protected_v1(const ckfss_resolution_job* w,uint64_t index,ckfss_two_way_retained* out) noexcept {if(out)*out={};return boundary([&]()->ckfss_status {require(w&&out&&index<w->core->protected_originals().size());const auto& a=w->core->protected_originals()[static_cast<std::size_t>(index)].artifact;out->kind=static_cast<uint32_t>(a.kind);out->protection=CKFSS_TW_PROTECTED;out->right_side=a.right;out->component_count=a.components.size();out->parent=tw_identity(a.parent);out->object=tw_identity(a.object);out->observed=status(a.status);return CKFSS_OK;});}
ckfss_status ckfss_resolution_get_protected_component_v1(const ckfss_resolution_job* w,uint64_t index,uint64_t component,uint32_t* encoding,void* units,uint64_t capacity,uint64_t* required) noexcept {if(encoding)*encoding=0;if(required)*required=0;return boundary([&]()->ckfss_status {require(w&&index<w->core->protected_originals().size());return tw_component(w->core->protected_originals()[static_cast<std::size_t>(index)].artifact.components,component,encoding,units,capacity,required);});}
ckfss_status ckfss_resolution_get_pending_key_v1(const ckfss_resolution_job* w,uint64_t index,void* key,uint64_t capacity,uint64_t* required) noexcept {if(required)*required=0;return boundary([&]()->ckfss_status {require(w&&index<w->core->result().pending_keys.size());return copy_key(w->core->result().pending_keys[static_cast<std::size_t>(index)],key,capacity,required);});}
void ckfss_resolution_request_cancel_v1(ckfss_resolution_job* w) noexcept {if(w)w->stop.request_stop();}
ckfss_status ckfss_resolution_finish_io_v1(ckfss_resolution_job* w,ckfss_error* error) noexcept {clear(error);return boundary([&]()->ckfss_status {require(w);w->stop.request_stop();auto r=w->core->finish_io();if(r.value()&&*r.value())return CKFSS_OK;if(!r.value())return unavailable(r,error);return CKFSS_EXCEPTION;});}
void ckfss_resolution_destroy_v1(ckfss_resolution_job* w) noexcept {delete w;}
}
