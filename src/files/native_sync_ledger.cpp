// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_sync_ledger.hpp"
#include "native_sync_observation.hpp"
#include "native_sync_internal.hpp"
#include "prepared_journal_directory.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "sha256.hpp"
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif
#if defined(__linux__) || defined(__APPLE__)
#include <cerrno>
#include <fcntl.h>
#include <utility>
#endif
#ifdef __linux__
#include "platform/linux_anonymous_staging.hpp"
#include <poll.h>
#include <sys/inotify.h>
#elif defined(__APPLE__)
#include <sys/event.h>
#endif
#include <algorithm>
#include <limits>
#include <set>
namespace ck::files {
namespace {
using namespace sync_detail;
using Wire=std::vector<std::byte>;
#if defined(__linux__) || defined(__APPLE__)
[[noreturn]] void ledger_watch_error(int code, const char* operation) {
    auto state = ObservationState::Failed;
    if (code == EACCES || code == EPERM)
        state = ObservationState::Denied;
    if (code == ENOSYS || code == EOPNOTSUPP)
        state = ObservationState::Unsupported;
    throw Failure{{state, {ErrorDomain::Posix, code, operation}}};
}

class LedgerWatchFd final {
public:
    LedgerWatchFd(PreparedJournalRoot& root, int fd) noexcept : root_(root), fd_(fd) {}
    LedgerWatchFd(const LedgerWatchFd&) = delete;
    LedgerWatchFd& operator=(const LedgerWatchFd&) = delete;
    ~LedgerWatchFd() { (void)consume(); }
    int get() const noexcept { return fd_; }
    int release() noexcept { return std::exchange(fd_, -1); }
    void finish() {
        if (const int error = consume())
            ledger_watch_error(error, "native_sync.ledger_watch_close");
    }
private:
    int consume() noexcept {
        const int fd = release();
        if (fd < 0 || ::close(fd) == 0)
            return 0;
        const int error = errno;
        detail::record_prepared_journal_consumer_failure(root_, ObservationState::Unknown,
            ErrorDomain::Posix, error, "native_sync.ledger_watch_close");
        return error;
    }
    PreparedJournalRoot& root_;
    int fd_;
};
#endif

#ifdef __linux__
int start_linux_ledger_watch(PreparedJournalRoot& root) {
    LedgerWatchFd directory(root, value(detail::duplicate_prepared_journal_directory(root)));
    LedgerWatchFd proc(root, value(detail::open_linux_thread_fd_directory()));
    const auto component = std::to_string(directory.get());
    struct stat held{}, kernel_link{}, target{};
    if (::fstat(directory.get(), &held) != 0 ||
        ::fstatat(proc.get(), component.c_str(), &kernel_link, AT_SYMLINK_NOFOLLOW) != 0 ||
        ::fstatat(proc.get(), component.c_str(), &target, 0) != 0)
        ledger_watch_error(errno, "native_sync.ledger_watch_identity");
    if (!S_ISLNK(kernel_link.st_mode) || !S_ISDIR(held.st_mode) || !S_ISDIR(target.st_mode) ||
        held.st_dev != target.st_dev || held.st_ino != target.st_ino)
        fail("native_sync.ledger_watch_identity");

    // inotify takes a pathname. This kernel-owned procfs alias starts at the
    // verified thread fd table and follows the retained directory descriptor.
    // Neither the original directory name nor the recovery hint is used.
    const auto alias = "/proc/thread-self/fd/" + std::to_string(proc.get()) + "/" + component;
    LedgerWatchFd watch(root, ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC));
    if (watch.get() < 0)
        ledger_watch_error(errno, "native_sync.ledger_watch_create");
    // Ledger verification opens an existing file with write access for its
    // shared I/O protocol. IN_CLOSE_WRITE would report that read-only use.
    constexpr std::uint32_t events = IN_ONLYDIR | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO |
        IN_ATTRIB | IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF;
    if (::inotify_add_watch(watch.get(), alias.c_str(), events) < 0)
        ledger_watch_error(errno, "native_sync.ledger_watch_bind");
    proc.finish();
    directory.finish();
    return watch.release();
}

void finish_linux_ledger_watch(LedgerWatchFd& watch, std::stop_token token) {
    for (;;) {
        stop(token);
        pollfd event{watch.get(), POLLIN, 0};
        const int ready = ::poll(&event, 1, 0);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready < 0)
            ledger_watch_error(errno, "native_sync.ledger_watch_poll");
        // Any queued notification, including overflow or watch loss,
        // invalidates this inventory. Read-only enumeration is unsubscribed.
        if (ready > 0 && (event.revents & POLLIN))
            fail("native_sync.ledger_namespace_changed");
        if (ready != 0)
            fail("native_sync.ledger_watch_unavailable", ObservationState::Unknown,
                 AdapterError::InvalidNativeResult);
        watch.finish();
        return;
    }
}
#elif defined(__APPLE__)
class MacLedgerDirectoryWatch final {
public:
    explicit MacLedgerDirectoryWatch(PreparedJournalRoot& root)
        : directory_(root, value(detail::duplicate_prepared_journal_directory(root))),
          queue_(root, ::kqueue()) {
        if (queue_.get() < 0)
            ledger_watch_error(errno, "native_sync.ledger_watch_create");
        if (::fcntl(queue_.get(), F_SETFD, FD_CLOEXEC) < 0)
            ledger_watch_error(errno, "native_sync.ledger_watch_cloexec");

        struct kevent watch{};
        constexpr unsigned events = NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_LINK |
            NOTE_RENAME | NOTE_DELETE | NOTE_REVOKE;
        EV_SET(&watch, static_cast<std::uintptr_t>(directory_.get()), EVFILT_VNODE,
               EV_ADD | EV_CLEAR, events, 0, nullptr);
        const timespec now{};
        if (::kevent(queue_.get(), &watch, 1, nullptr, 0, &now) < 0)
            ledger_watch_error(errno, "native_sync.ledger_watch_bind");
    }

    void finish(std::stop_token token) {
        for (;;) {
            stop(token);
            struct kevent event{};
            const timespec now{};
            const int ready = ::kevent(queue_.get(), nullptr, 0, &event, 1, &now);
            if (ready < 0 && errno == EINTR)
                continue;
            if (ready < 0)
                ledger_watch_error(errno, "native_sync.ledger_watch_poll");
            // This queue has one registration, for the retained directory.
            // Any event (including revocation or an error) refuses the scan.
            if (ready > 0)
                fail("native_sync.ledger_namespace_changed");
            queue_.finish();
            directory_.finish();
            return;
        }
    }
private:
    LedgerWatchFd directory_;
    LedgerWatchFd queue_;
};
#endif

// Native observations of the SAME provider-owned directory; never an address
// or injected cursor. Enumeration changes access time, so only namespace/version
// fields participate. This does not claim exclusion of unrelated writers.
SyncDigest directory_version(PreparedJournalRoot& root) {
    auto duplicate=value(detail::duplicate_prepared_journal_directory(root));
    struct Owner {
#ifdef _WIN32
        void* handle;~Owner(){if(handle)CloseHandle(handle);}
#else
        int handle;~Owner(){if(handle>=0)::close(handle);}
#endif
    } owned{duplicate};
    Sha256 hash;auto put=[&](std::uint64_t number){std::array<std::byte,8> bytes{};for(unsigned i=0;i<8;++i)bytes[i]=std::byte((number>>(8*i))&255);hash.update(bytes);};
    auto io_failure=[&](std::int64_t code,const char* operation) {
#ifdef _WIN32
        throw Failure{{ObservationState::Failed,{ErrorDomain::Win32,code,operation}}};
#else
        throw Failure{{ObservationState::Failed,{ErrorDomain::Posix,code,operation}}};
#endif
    };
#ifdef _WIN32
    FILE_ID_INFO id{};FILE_BASIC_INFO basic{};FILE_STANDARD_INFO standard{};
    if(!GetFileInformationByHandleEx(owned.handle,FileIdInfo,&id,sizeof(id))||
       !GetFileInformationByHandleEx(owned.handle,FileBasicInfo,&basic,sizeof(basic))||
       !GetFileInformationByHandleEx(owned.handle,FileStandardInfo,&standard,sizeof(standard)))
        io_failure(GetLastError(),"native_sync.storage_version");
    put(id.VolumeSerialNumber);hash.update(std::as_bytes(std::span(id.FileId.Identifier)));
    put(basic.CreationTime.QuadPart);put(basic.LastWriteTime.QuadPart);put(basic.ChangeTime.QuadPart);
    put(basic.FileAttributes);put(standard.EndOfFile.QuadPart);put(standard.NumberOfLinks);put(standard.DeletePending);
    auto handle=owned.handle;owned.handle=nullptr;if(!CloseHandle(handle))io_failure(GetLastError(),"native_sync.storage_version_close");
#else
    struct stat basic{};if(fstat(owned.handle,&basic))io_failure(errno,"native_sync.storage_version");
    put(basic.st_dev);put(basic.st_ino);put(basic.st_mode);put(basic.st_uid);put(basic.st_gid);put(basic.st_size);put(basic.st_nlink);
#ifdef __APPLE__
    put(basic.st_mtimespec.tv_sec);put(basic.st_mtimespec.tv_nsec);put(basic.st_ctimespec.tv_sec);put(basic.st_ctimespec.tv_nsec);
#else
    put(basic.st_mtim.tv_sec);put(basic.st_mtim.tv_nsec);put(basic.st_ctim.tv_sec);put(basic.st_ctim.tv_nsec);
#endif
    auto descriptor=owned.handle;owned.handle=-1;if(::close(descriptor))io_failure(errno,"native_sync.storage_version_close");
#endif
    require(root.revalidate());return hash.digest();
}
constexpr std::uint64_t magic=0x3147524c534b4343ULL;
constexpr std::uint64_t hierarchy_magic=0x3347524c534b4343ULL;
Observation<Wire> encode_ledger(const NativeSyncLedgerEvidence&,NativeSyncLedgerLimits,bool);
bool hierarchy_payload(std::span<const std::byte> bytes){
    if(bytes.size()<8)fail("native_sync.ledger_truncated",ObservationState::Failed,AdapterError::InvalidNativeResult);
    std::uint64_t tag=0;for(unsigned i=0;i<8;++i)tag|=std::uint64_t(std::to_integer<unsigned>(bytes[i]))<<(8*i);
    if(tag!=magic&&tag!=hierarchy_magic)fail("native_sync.ledger_magic",ObservationState::Failed,AdapterError::InvalidNativeResult);
    return tag==hierarchy_magic;
}
constexpr std::string_view prefix=".ck-sync-ledger-";
void put(Wire& b,std::uint64_t n) {for(unsigned i=0;i<8;++i)b.push_back(std::byte((n>>(8*i))&255));}
void blob(Wire& b,std::span<const std::byte> s) {put(b,s.size());b.insert(b.end(),s.begin(),s.end());}
void identity(Wire& b,const NativeDurableIdentity& id) {
    if(id.scheme==IdentityScheme::Unknown||static_cast<unsigned>(id.scheme)>static_cast<unsigned>(IdentityScheme::WindowsFileIndex64))
        fail("native_sync.ledger_identity",ObservationState::Failed,AdapterError::UnqualifiedIdentity);
    put(b,static_cast<unsigned>(id.scheme));b.insert(b.end(),id.volume.bytes.begin(),id.volume.bytes.end());
    b.insert(b.end(),id.object.bytes.begin(),id.object.bytes.end());put(b,id.generation.has_value());if(id.generation)put(b,*id.generation);
}
struct Reader {
    std::span<const std::byte> bytes;std::size_t offset=0;
    std::span<const std::byte> take(std::size_t n) {
        if(n>bytes.size()-offset)fail("native_sync.ledger_truncated",ObservationState::Failed,AdapterError::InvalidNativeResult);
        auto s=bytes.subspan(offset,n);offset+=n;return s;
    }
    std::uint64_t number() {auto s=take(8);std::uint64_t n=0;for(unsigned i=0;i<8;++i)n|=std::uint64_t(std::to_integer<unsigned>(s[i]))<<(i*8);return n;}
    std::span<const std::byte> blob(std::size_t max) {auto n=number();if(n>max)fail("native_sync.ledger_limit",ObservationState::Unknown,AdapterError::InventoryLimit);return take(static_cast<std::size_t>(n));}
    SyncDigest digest() {SyncDigest d;auto s=take(d.size());std::copy(s.begin(),s.end(),d.begin());return d;}
    NativeDurableIdentity identity() {
        NativeDurableIdentity id;auto scheme=number();if(!scheme||scheme>static_cast<unsigned>(IdentityScheme::WindowsFileIndex64))
            fail("native_sync.ledger_identity",ObservationState::Failed,AdapterError::UnqualifiedIdentity);
        id.scheme=static_cast<IdentityScheme>(scheme);auto v=take(16);std::copy(v.begin(),v.end(),id.volume.bytes.begin());
        auto o=take(16);std::copy(o.begin(),o.end(),id.object.bytes.begin());auto g=number();
        if(g>1)fail("native_sync.ledger_generation_flag",ObservationState::Failed,AdapterError::InvalidNativeResult);
        if(g)id.generation=number();return id;
    }
};
std::size_t component_bytes(const NativeName& name){
    if(!name.is_valid())fail("native_sync.ledger_native_component",ObservationState::Failed,AdapterError::InvalidIdentifier);
    if(const auto* p=name.posix_bytes())return p->size();
    if(const auto* w=name.windows_units()){
        if(w->size()>std::numeric_limits<std::size_t>::max()/2)fail("native_sync.ledger_component_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        return w->size()*2;
    }
    fail("native_sync.ledger_component_encoding",ObservationState::Failed,AdapterError::InvalidIdentifier);
}
void components(Wire& out,std::span<const NativeName> names,NativeSyncLedgerLimits limits,bool hierarchical) {
    if(names.empty()||names.size()>(hierarchical?1024U:1U))fail("native_sync.ledger_component_count",ObservationState::Unsupported,AdapterError::UnsupportedQuery);
    std::size_t key_bytes=0;put(out,names.size());
    for(const auto& name:names) {
        const auto bytes=component_bytes(name);
        if(bytes>(limits.baseline.max_path_bytes-std::min(key_bytes,limits.baseline.max_path_bytes))/2||key_bytes>limits.baseline.max_path_bytes||
           2*bytes+1+(key_bytes?1:0)>limits.baseline.max_path_bytes-key_bytes)
            fail("native_sync.ledger_component_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        key_bytes+=2*bytes+1+(key_bytes?1:0);
        if(name.encoding()!=names.front().encoding())fail("native_sync.ledger_mixed_native_chain",ObservationState::Failed,AdapterError::InvalidIdentifier);
        if(auto* p=name.posix_bytes()) {put(out,1);blob(out,std::as_bytes(std::span(*p)));}
        else if(auto* w=name.windows_units()) {put(out,2);put(out,bytes);for(auto c:*w){out.push_back(std::byte(c&255));out.push_back(std::byte(c>>8));}}
    }
}
std::vector<NativeName> components(Reader& r,NativeSyncLedgerLimits limits,bool hierarchical) {
    const auto count=r.number();if(!count||count>(hierarchical?1024U:1U))fail("native_sync.ledger_component_count",ObservationState::Unsupported,AdapterError::UnsupportedQuery);
    std::vector<NativeName> result(std::initializer_list<NativeName>{});std::size_t key_bytes=0;
    for(std::uint64_t index=0;index<count;++index){
        const auto encoding=r.number();const auto bytes=r.blob(limits.baseline.max_path_bytes);
        if(key_bytes>limits.baseline.max_path_bytes||bytes.size()>(limits.baseline.max_path_bytes-key_bytes)/2||
           bytes.size()*2+1+(index?1:0)>limits.baseline.max_path_bytes-key_bytes)
            fail("native_sync.ledger_component_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        key_bytes+=bytes.size()*2+1+(index?1:0);std::optional<NativeName> name;
        if(encoding==1)name=NativeName::from_posix({reinterpret_cast<const char*>(bytes.data()),bytes.size()});
        else if(encoding==2){
            if(bytes.size()%2)fail("native_sync.ledger_utf16",ObservationState::Failed,AdapterError::InvalidIdentifier);
            std::u16string units;units.reserve(bytes.size()/2);for(std::size_t i=0;i<bytes.size();i+=2)units+=char16_t(std::to_integer<unsigned>(bytes[i])|(std::to_integer<unsigned>(bytes[i+1])<<8));
            name=NativeName::from_windows(std::move(units));
        }
        if(!name)fail("native_sync.ledger_native_component",ObservationState::Failed,AdapterError::InvalidIdentifier);
        if(!result.empty()&&name->encoding()!=result.front().encoding())fail("native_sync.ledger_mixed_native_chain",ObservationState::Failed,AdapterError::InvalidIdentifier);
        result.push_back(std::move(*name));
    }
    return result;
}
void path_side(Wire& bytes,const SyncEntryStatus& status,const std::optional<NativeDurableIdentity>& object,bool hierarchical) {
    if((status.presence!=SyncPresence::Present&&status.presence!=SyncPresence::Absent)||
        (status.presence==SyncPresence::Present&&((status.kind!=SyncKind::File&&(!hierarchical||status.kind!=SyncKind::Directory))||!object))||
        (status.presence==SyncPresence::Absent&&(status.kind!=SyncKind::Unknown||object||status.content_digest!=SyncDigest{}||status.required_metadata_digest!=SyncDigest{})))
        fail("native_sync.ledger_side_status",ObservationState::Failed,AdapterError::PlanInvalid);
    put(bytes,static_cast<unsigned>(status.presence));if(hierarchical)put(bytes,static_cast<unsigned>(status.kind));
    bytes.insert(bytes.end(),status.content_digest.begin(),status.content_digest.end());bytes.insert(bytes.end(),status.required_metadata_digest.begin(),status.required_metadata_digest.end());if(object)identity(bytes,*object);
}
std::pair<SyncEntryStatus,std::optional<NativeDurableIdentity>> path_side(Reader& reader,bool hierarchical) {
    const auto presence=reader.number();if(presence!=static_cast<unsigned>(SyncPresence::Present)&&presence!=static_cast<unsigned>(SyncPresence::Absent))
        fail("native_sync.ledger_side_presence",ObservationState::Failed,AdapterError::InvalidNativeResult);
    const auto kind=hierarchical?reader.number():presence==static_cast<unsigned>(SyncPresence::Present)?static_cast<unsigned>(SyncKind::File):static_cast<unsigned>(SyncKind::Unknown);
    if(kind>static_cast<unsigned>(SyncKind::Directory))fail("native_sync.ledger_side_kind",ObservationState::Failed,AdapterError::InvalidNativeResult);
    SyncEntryStatus status{static_cast<SyncPresence>(presence),static_cast<SyncKind>(kind),reader.digest(),reader.digest()};
    std::optional<NativeDurableIdentity> object;if(status.presence==SyncPresence::Present)object=reader.identity();return {status,object};
}
std::size_t admit_ledger_wire(const NativeSyncLedgerEvidence& e,NativeSyncLedgerLimits l,bool hierarchical,std::size_t baseline_bytes){
    if(!l.baseline.max_path_bytes||l.baseline.max_path_bytes>SyncBaselineLimits::hard_max_path_bytes||
        !l.baseline.max_total_path_bytes||l.baseline.max_total_path_bytes>SyncBaselineLimits::hard_max_total_path_bytes||
        !l.baseline.max_rows||l.baseline.max_rows>SyncBaselineLimits::hard_max_rows||e.paths.size()>l.baseline.max_rows)
        fail("native_sync.ledger_limits",ObservationState::Failed,AdapterError::InvalidLimit);
    std::size_t used=0;const auto add=[&](std::size_t n){if(used>l.max_total_wire_bytes||n>l.max_total_wire_bytes-used)fail("native_sync.ledger_wire_limit",ObservationState::Unknown,AdapterError::InventoryLimit);used+=n;};
    const auto durable=[&](const NativeDurableIdentity& id){add(48);if(id.generation)add(8);};
    const auto names=[&](std::span<const NativeName> chain){
        if(chain.empty()||chain.size()>(hierarchical?1024U:1U))fail("native_sync.ledger_component_count",ObservationState::Unsupported,AdapterError::UnsupportedQuery);
        add(8);std::size_t key_bytes=0;
        for(const auto& name:chain){const auto bytes=component_bytes(name);
            if(key_bytes>l.baseline.max_path_bytes||bytes>(l.baseline.max_path_bytes-key_bytes)/2||
                bytes*2+1+(key_bytes?1:0)>l.baseline.max_path_bytes-key_bytes)
                fail("native_sync.ledger_component_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
            key_bytes+=bytes*2+1+(key_bytes?1:0);add(16);add(bytes);
        }
    };
    add(200);
    std::size_t total_paths=0;
    for(const auto& path:e.paths){
        if(path.opaque_key.empty()||path.opaque_key.size()>l.baseline.max_path_bytes||total_paths>l.baseline.max_total_path_bytes||path.opaque_key.size()>l.baseline.max_total_path_bytes-total_paths)
            fail("native_sync.ledger_path_label",ObservationState::Failed,AdapterError::PlanInvalid);
        total_paths+=path.opaque_key.size();add(8);add(path.opaque_key.size());names(path.components);
        add(hierarchical?160:144);if(path.left_object)durable(*path.left_object);if(path.right_object)durable(*path.right_object);add(16);
    }
    for(const auto& artifact:e.artifacts){add(16);names(artifact.components);durable(artifact.parent);durable(artifact.object);add(64);}
    if(e.proposed_baseline){add(8);add(baseline_bytes);}return used;
}
void hierarchy_parent_closure(const NativeSyncLedgerEvidence& e){
    std::map<std::string,const NativeSyncPathRecord*> paths(std::initializer_list<std::pair<const std::string,const NativeSyncPathRecord*>>{});
    for(const auto& p:e.paths)if(p.opaque_key!=native_sync_key(p.components)||!paths.emplace(p.opaque_key,&p).second)
        fail("native_sync.hierarchy_ledger_native_key",ObservationState::Failed,AdapterError::PlanInvalid);
    for(const auto& p:e.paths)for(unsigned side=0;side<2;++side){
        const auto& status=side?p.right:p.left;const auto& object=side?p.right_object:p.left_object;
        for(std::size_t depth=1;depth<p.components.size();++depth){
            const auto found=paths.find(native_sync_key(std::span(p.components).first(depth)));
            if(found==paths.end())fail("native_sync.hierarchy_ledger_parent_missing",ObservationState::Failed,AdapterError::PlanInvalid);
            const auto& parent=side?found->second->right:found->second->left;const auto& parent_id=side?found->second->right_object:found->second->left_object;
            if(status.presence==SyncPresence::Present&&(parent.presence!=SyncPresence::Present||parent.kind!=SyncKind::Directory||!parent_id||!object||
                parent_id->scheme!=object->scheme||parent_id->volume!=object->volume||parent_id->object==object->object))
                fail("native_sync.hierarchy_ledger_parent_binding",ObservationState::Failed,AdapterError::PlanInvalid);
        }
    }
    for(const auto& a:e.artifacts)if(a.components.size()>1){
        const auto found=paths.find(native_sync_key(std::span(a.components).first(a.components.size()-1)));
        if(found==paths.end())fail("native_sync.hierarchy_ledger_artifact_parent_missing",ObservationState::Failed,AdapterError::PlanInvalid);
        const auto& parent=a.right?found->second->right:found->second->left;const auto& id=a.right?found->second->right_object:found->second->left_object;
        if(parent.presence!=SyncPresence::Present||parent.kind!=SyncKind::Directory||!id||*id!=a.parent)
            fail("native_sync.hierarchy_ledger_artifact_parent_binding",ObservationState::Failed,AdapterError::PlanInvalid);
    }
}
OperationJournalLimits journal_limits(NativeSyncLedgerLimits l) {return {1,16,l.max_total_wire_bytes};}
OperationJournalCodecLimits codec_limits(NativeSyncLedgerLimits l) {return {l.max_total_wire_bytes};}
bool reserved(const NativeName& n) {
    if(auto* p=n.posix_bytes())return p->starts_with(prefix);
    if(auto* w=n.windows_units())return w->size()>=prefix.size()&&std::equal(prefix.begin(),prefix.end(),w->begin());
    return false;
}
NativeSyncLedgerEvidence evidence(const OperationJournal& j,NativeSyncLedgerLimits limits) {
    if(j.operation()!=FileOperation::Copy||j.records().empty())fail("native_sync.ledger_protocol",ObservationState::Failed,AdapterError::InvalidNativeResult);
    std::optional<NativeSyncLedgerEvidence> first,last;
    for(const auto& record:j.records()) {
        if(record.item!=0)fail("native_sync.ledger_item",ObservationState::Failed,AdapterError::InvalidNativeResult);
        auto decoded=value(decode_native_sync_ledger(record.evidence,limits));
        const bool hierarchical=hierarchy_payload(record.evidence);
        if(hierarchy_payload(j.records().front().evidence)!=hierarchical)fail("native_sync.ledger_schema_changed",ObservationState::Failed,AdapterError::InvalidNativeResult);
        if(!first)first=decoded;
        if(decoded.session.pair!=first->session.pair||decoded.session.policy!=first->session.policy||
            decoded.session.left_root!=first->session.left_root||decoded.session.right_root!=first->session.right_root||
            decoded.expected_generation!=first->expected_generation||decoded.reviewed_plan!=first->reviewed_plan)
            fail("native_sync.ledger_binding_changed",ObservationState::Failed,AdapterError::InvalidNativeResult);
        auto invariant=decoded;invariant.proposed_baseline.reset();auto planned=*first;planned.proposed_baseline.reset();
        if(value(encode_ledger(invariant,limits,hierarchical))!=value(encode_ledger(planned,limits,hierarchical)))
            fail("native_sync.ledger_plan_changed",ObservationState::Failed,AdapterError::InvalidNativeResult);
        if((record.state==OperationJournalState::Copied||record.state==OperationJournalState::Verified||record.state==OperationJournalState::CommitIntended||
            record.state==OperationJournalState::DestinationCommitted||record.state==OperationJournalState::Complete)&&!decoded.proposed_baseline)
            fail("native_sync.ledger_missing_baseline",ObservationState::Failed,AdapterError::InvalidNativeResult);
        if(last&&last->proposed_baseline&&last->proposed_baseline!=decoded.proposed_baseline)
            fail("native_sync.ledger_baseline_changed",ObservationState::Failed,AdapterError::InvalidNativeResult);
        last=std::move(decoded);
    }
    return std::move(*last);
}
}
namespace {
Observation<Wire> encode_ledger(const NativeSyncLedgerEvidence& e,NativeSyncLedgerLimits l,bool hierarchical) {
    return attempt<Wire>([&]{
        if(!l.max_ledgers||!l.max_total_wire_bytes||l.max_total_wire_bytes>OperationJournalLimits::hard_max_evidence_bytes||
            e.artifacts.size()>l.max_artifacts||e.expected_generation==std::numeric_limits<std::uint64_t>::max())
            fail("native_sync.ledger_limits",ObservationState::Failed,AdapterError::InvalidLimit);
        std::optional<Wire> baseline_payload;
        if(e.proposed_baseline){if(e.proposed_baseline->policy_fingerprint!=e.session.policy)fail("native_sync.ledger_baseline_policy",ObservationState::Failed,AdapterError::PlanInvalid);baseline_payload=value(encode_sync_baseline(*e.proposed_baseline,l.baseline));}
        const auto wire_size=admit_ledger_wire(e,l,hierarchical,baseline_payload?baseline_payload->size():0);
        if(hierarchical)hierarchy_parent_closure(e);
        Wire b(std::initializer_list<std::byte>{});b.reserve(wire_size);put(b,hierarchical?hierarchy_magic:magic);for(const auto* d:{&e.session.left_root,&e.session.right_root,&e.session.policy,&e.session.pair})b.insert(b.end(),d->begin(),d->end());
        put(b,e.expected_generation);b.insert(b.end(),e.reviewed_plan.begin(),e.reviewed_plan.end());
        if(e.paths.size()>l.baseline.max_rows)fail("native_sync.ledger_path_count",ObservationState::Unknown,AdapterError::InventoryLimit);
        put(b,e.paths.size());std::set<std::string> path_keys(std::initializer_list<std::string>{});std::size_t path_bytes=0;
        for(const auto& path:e.paths) {
            if(path.opaque_key.empty()||path.opaque_key.size()>l.baseline.max_path_bytes||!path_keys.insert(path.opaque_key).second||
                path.opaque_key.size()>l.baseline.max_total_path_bytes-path_bytes)
                fail("native_sync.ledger_path_label",ObservationState::Failed,AdapterError::PlanInvalid);
            path_bytes+=path.opaque_key.size();blob(b,std::as_bytes(std::span(path.opaque_key)));components(b,path.components,l,hierarchical);
            path_side(b,path.left,path.left_object,hierarchical);path_side(b,path.right,path.right_object,hierarchical);
            if(static_cast<unsigned>(path.action)>static_cast<unsigned>(SyncAction::Blocked))fail("native_sync.ledger_action",ObservationState::Failed,AdapterError::PlanInvalid);
            put(b,static_cast<unsigned>(path.action));put(b,path.skipped);
        }
        put(b,e.artifacts.size());std::set<std::pair<bool,std::string>> seen(std::initializer_list<std::pair<bool,std::string>>{});
        for(const auto& a:e.artifacts) {
            if((a.components.empty()||a.components.size()>(hierarchical?1024U:1U))||a.kind!=NativeSyncArtifactKind::RetainedOriginal||a.status.presence!=SyncPresence::Present||a.status.kind!=SyncKind::File)
                fail("native_sync.ledger_artifact",ObservationState::Failed,AdapterError::PlanInvalid);
            auto key=native_sync_key(a.components);if(key.size()>l.baseline.max_path_bytes||!seen.emplace(a.right,key).second)
                fail("native_sync.ledger_artifact_key",ObservationState::Failed,AdapterError::PlanInvalid);
            put(b,a.right);put(b,static_cast<unsigned>(a.kind));components(b,a.components,l,hierarchical);identity(b,a.parent);identity(b,a.object);
            b.insert(b.end(),a.status.content_digest.begin(),a.status.content_digest.end());
            b.insert(b.end(),a.status.required_metadata_digest.begin(),a.status.required_metadata_digest.end());
        }
        put(b,e.proposed_baseline.has_value());if(e.proposed_baseline) {
            if(e.proposed_baseline->policy_fingerprint!=e.session.policy)fail("native_sync.ledger_baseline_policy",ObservationState::Failed,AdapterError::PlanInvalid);
            for(const auto& row:e.proposed_baseline->rows)if(!path_keys.contains(row.relative_path))fail("native_sync.ledger_baseline_native_record",ObservationState::Failed,AdapterError::PlanInvalid);
            blob(b,*baseline_payload);
        }
        if(b.size()!=wire_size)fail("native_sync.ledger_wire_admission_mismatch",ObservationState::Failed,AdapterError::InvalidNativeResult);
        if(b.size()>l.max_total_wire_bytes)fail("native_sync.ledger_wire_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        return b;
    });
}
} // namespace
Observation<Wire> encode_native_sync_ledger(const NativeSyncLedgerEvidence& e,NativeSyncLedgerLimits l){return encode_ledger(e,l,false);}
Observation<Wire> encode_native_sync_hierarchy_ledger(const NativeSyncLedgerEvidence& e,NativeSyncLedgerLimits l){return encode_ledger(e,l,true);}
Observation<NativeSyncLedgerEvidence> decode_native_sync_ledger(std::span<const std::byte> bytes,NativeSyncLedgerLimits l) {
    return attempt<NativeSyncLedgerEvidence>([&]{
        if(bytes.size()>l.max_total_wire_bytes)fail("native_sync.ledger_wire_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        const bool hierarchical=hierarchy_payload(bytes);Reader r{bytes};(void)r.number();
        NativeSyncLedgerEvidence e;e.session.left_root=r.digest();e.session.right_root=r.digest();e.session.policy=r.digest();e.session.pair=r.digest();
        e.expected_generation=r.number();e.reviewed_plan=r.digest();auto paths=r.number();
        if(paths>l.baseline.max_rows)fail("native_sync.ledger_path_count",ObservationState::Unknown,AdapterError::InventoryLimit);
        for(std::uint64_t i=0;i<paths;++i) {auto label=r.blob(l.baseline.max_path_bytes);std::string key(reinterpret_cast<const char*>(label.data()),label.size());
            NativeSyncPathRecord path;path.opaque_key=std::move(key);path.components=components(r,l,hierarchical);auto left=path_side(r,hierarchical),right=path_side(r,hierarchical);
            path.left=left.first;path.left_object=left.second;path.right=right.first;path.right_object=right.second;
            auto action=r.number(),skipped=r.number();if(action>static_cast<unsigned>(SyncAction::Blocked)||skipped>1)
                fail("native_sync.ledger_path_choice",ObservationState::Failed,AdapterError::InvalidNativeResult);
            path.action=static_cast<SyncAction>(action);path.skipped=skipped!=0;e.paths.push_back(std::move(path));}
        auto count=r.number();if(count>l.max_artifacts)fail("native_sync.ledger_artifact_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        for(std::uint64_t i=0;i<count;++i) {
            NativeSyncArtifact a;auto side=r.number();auto kind=r.number();if(side>1||kind!=1)fail("native_sync.ledger_artifact_enum",ObservationState::Failed,AdapterError::InvalidNativeResult);
            a.right=side!=0;a.components=components(r,l,hierarchical);
            a.parent=r.identity();a.object=r.identity();a.status={SyncPresence::Present,SyncKind::File,r.digest(),r.digest()};e.artifacts.push_back(std::move(a));
        }
        auto baseline=r.number();if(baseline>1)fail("native_sync.ledger_baseline_flag",ObservationState::Failed,AdapterError::InvalidNativeResult);
        if(baseline)e.proposed_baseline=value(decode_sync_baseline(r.blob(l.baseline.max_wire_bytes),l.baseline));
        if(r.offset!=bytes.size()||value(encode_ledger(e,l,hierarchical))!=Wire(bytes.begin(),bytes.end()))
            fail("native_sync.ledger_noncanonical",ObservationState::Failed,AdapterError::InvalidNativeResult);
        return e;
    });
}
Observation<std::unique_ptr<NativeSyncLedger>> NativeSyncLedger::create(PreparedJournalRoot::Pointer root,NativeName name,
    OperationJournalId id,const NativeSyncLedgerEvidence& e,NativeSyncLedgerLimits limits) {
    return attempt<std::unique_ptr<NativeSyncLedger>>([&]{
        if(!root)fail("native_sync.null_storage_owner",ObservationState::Failed,AdapterError::InvalidAccess);
        // Validate the actual provider before trusting any virtual open method.
        auto native=value(open_prepared_journal_directory(root));require(native->finish_io());
        if(!reserved(name))fail("native_sync.ledger_name",ObservationState::Failed,AdapterError::PlanInvalid);
        auto check=value(OperationJournal::create(FileOperation::Copy,id,journal_limits(limits)));
        (void)value(encode_operation_journal_frame(*check,{1,0,OperationJournalState::Planned,value(encode_native_sync_ledger(e,limits))},codec_limits(limits)));
        auto f=value(open_prepared_operation_journal_file(*root,name,true));
        return value(create_on_file(std::move(f),id,e,limits));
    });
}
Observation<std::unique_ptr<NativeSyncLedger>> NativeSyncLedger::create_hierarchy(PreparedJournalRoot::Pointer root,NativeName name,
    OperationJournalId id,const NativeSyncLedgerEvidence& e,NativeSyncLedgerLimits limits){
    return attempt<std::unique_ptr<NativeSyncLedger>>([&]{
        if(!root||!reserved(name)||e.proposed_baseline)fail("native_sync.hierarchy_ledger_request",ObservationState::Failed,AdapterError::PlanInvalid);
        auto payload=value(encode_ledger(e,limits,true));auto journal=value(OperationJournal::create(FileOperation::Copy,id,journal_limits(limits)));
        OperationJournalRecord record{1,0,OperationJournalState::Planned,std::move(payload)};
        (void)value(encode_operation_journal_frame(*journal,record,codec_limits(limits)));
        auto native=value(open_prepared_journal_directory(root));require(native->finish_io());
        auto file=value(open_prepared_operation_journal_file(*root,name,true));
        require(append_operation_journal_file(*file,*journal,std::move(record),codec_limits(limits)));
        return std::unique_ptr<NativeSyncLedger>(new NativeSyncLedger(std::move(file),std::move(journal),limits));
    });
}
Observation<std::unique_ptr<NativeSyncLedger>> NativeSyncLedger::create_on_file(std::unique_ptr<OperationJournalFile> file,
    OperationJournalId id,const NativeSyncLedgerEvidence& e,NativeSyncLedgerLimits limits) {
    return attempt<std::unique_ptr<NativeSyncLedger>>([&]{
        if(!file||value(file->size())!=0)fail("native_sync.ledger_nonempty",ObservationState::Failed,AdapterError::PlanInvalid);
        auto j=value(OperationJournal::create(FileOperation::Copy,id,journal_limits(limits)));
        auto out=std::unique_ptr<NativeSyncLedger>(new NativeSyncLedger(std::move(file),std::move(j),limits));
        require(out->append(OperationJournalState::Planned,e));return out;
    });
}
Observation<std::unique_ptr<NativeSyncLedger>> NativeSyncLedger::reopen(PreparedJournalRoot::Pointer root,NativeName name,
    OperationJournalId id,NativeSyncLedgerLimits limits) {
    return attempt<std::unique_ptr<NativeSyncLedger>>([&]{
        if(!root)fail("native_sync.null_storage_owner",ObservationState::Failed,AdapterError::InvalidAccess);
        auto native=value(open_prepared_journal_directory(root));require(native->finish_io());
        auto f=value(open_prepared_operation_journal_file(*root,name,false));auto loaded=value(load_operation_journal(*f,journal_limits(limits),codec_limits(limits)));
        if(loaded.tail||!loaded.journal||loaded.journal->id()!=id)fail("native_sync.ledger_reopen",ObservationState::Changed,AdapterError::PlanDecisionStale);
        (void)evidence(*loaded.journal,limits);
        return std::unique_ptr<NativeSyncLedger>(new NativeSyncLedger(std::move(f),std::move(loaded.journal),limits));
    });
}
Observation<bool> NativeSyncLedger::append(OperationJournalState state,const NativeSyncLedgerEvidence& e) {
    return attempt<bool>([&]{if(!file_||closed_)fail("native_sync.closed_ledger",ObservationState::Failed,AdapterError::PlanInvalid);
        const bool hierarchical=!journal_->records().empty()&&hierarchy_payload(journal_->records().front().evidence);
        auto bytes=value(encode_ledger(e,limits_,hierarchical));
        if((state==OperationJournalState::Planned||state==OperationJournalState::Prepared)&&e.proposed_baseline)
            fail("native_sync.early_baseline_assertion",ObservationState::Failed,AdapterError::PlanInvalid);
        if((state==OperationJournalState::Copied||state==OperationJournalState::Verified||state==OperationJournalState::CommitIntended||
            state==OperationJournalState::DestinationCommitted||state==OperationJournalState::Complete)&&!e.proposed_baseline)
            fail("native_sync.missing_baseline_proposal",ObservationState::Failed,AdapterError::PlanInvalid);
        if(!journal_->records().empty()) {
            auto previous=evidence(*journal_,limits_);auto invariant=e;invariant.proposed_baseline.reset();auto fixed=previous;fixed.proposed_baseline.reset();
            if(value(encode_ledger(invariant,limits_,hierarchical))!=value(encode_ledger(fixed,limits_,hierarchical))||
                (previous.proposed_baseline&&previous.proposed_baseline!=e.proposed_baseline))
                fail("native_sync.changed_ledger_receipt",ObservationState::Changed,AdapterError::PlanDecisionStale);
        }
        require(append_operation_journal_file(*file_,*journal_,
            {journal_->records().size()+1,0,state,std::move(bytes)},codec_limits(limits_)));return true;});
}
Observation<bool> NativeSyncLedger::finish_io() {
    if(closed_)return close_failure_?Observation<bool>::unavailable(close_failure_->state,close_failure_->error):Observation<bool>::available(true);
    // Install failure BEFORE starting or surrendering native I/O. If this
    // allocation throws, no finalizer ran and a retry is still safe. Once
    // closed_ is set, a throwing finalizer/failure copy must remain failure.
    close_failure_=UnavailableObservation{ObservationState::Unknown,{ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"native_sync.ledger_finish_incomplete"}};
    closed_=true;auto file=std::move(file_);auto finished=file->finish_io();
    if(!finished.value())close_failure_=*finished.unavailable_detail();
    else if(!*finished.value())close_failure_=UnavailableObservation{ObservationState::Unknown,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"native_sync.ledger_close_false"}};
    else close_failure_.reset(); // Only a completed, successful finalizer clears the guard.
    return close_failure_?Observation<bool>::unavailable(close_failure_->state,close_failure_->error):Observation<bool>::available(true);
}
Observation<std::vector<NativeSyncLoadedLedger>> load_native_sync_ledgers(PreparedJournalRoot::Pointer root,NativeSyncLedgerLimits limits,std::stop_token token) {
    return attempt<std::vector<NativeSyncLoadedLedger>>([&]{
        if(!root)fail("native_sync.null_storage_owner",ObservationState::Failed,AdapterError::InvalidAccess);
#ifdef __linux__
        stop(token);
        LedgerWatchFd watch(*root, start_linux_ledger_watch(*root));
#elif defined(__APPLE__)
        stop(token);
        MacLedgerDirectoryWatch watch(*root);
#endif
        auto before=directory_version(*root);auto cursor=value(open_prepared_journal_directory(root));
        std::vector<NativeSyncLoadedLedger> out;std::size_t total=0,all_names=0;
        for(;;) {stop(token);auto batch=cursor->read(128,token);
            if(batch.state==DirectoryReadState::Error)throw Failure{*batch.error};
            if(batch.state==DirectoryReadState::Cancelled)fail("native_sync.ledger_enumeration_cancelled");
            for(const auto& name:batch.names) {
                if(++all_names>8192)fail("native_sync.coordinator_entry_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
                if(!reserved(name))continue;
                if(out.size()==limits.max_ledgers)fail("native_sync.ledger_count",ObservationState::Unknown,AdapterError::InventoryLimit);
                auto f=value(open_prepared_operation_journal_file(*root,name,false));auto size=value(f->size());
                if(size>limits.max_total_wire_bytes-total)fail("native_sync.ledger_total_wire",ObservationState::Unknown,AdapterError::InventoryLimit);
                total+=static_cast<std::size_t>(size);auto loaded=value(load_operation_journal(*f,journal_limits(limits),codec_limits(limits)));
                if(loaded.tail||!loaded.journal)fail("native_sync.ledger_tail",ObservationState::Changed,AdapterError::ProviderReviewRequired);
                auto e=evidence(*loaded.journal,limits);require(f->finish_io());out.push_back({name,std::move(loaded.journal),std::move(e),static_cast<std::size_t>(size)});
            }
            if(batch.state==DirectoryReadState::End)break;
        }
        auto after=directory_version(*root);if(before!=after)fail("native_sync.ledger_namespace_changed");
        require(cursor->finish_io());require(root->revalidate());
#ifdef __linux__
        finish_linux_ledger_watch(watch, token);
#elif defined(__APPLE__)
        watch.finish(token);
#endif
        return out;
    });
}
Observation<std::unique_ptr<NativeSyncLedger>> NativeSyncLedger::create(const NativeAbsolutePath& address,NativeName name,
    OperationJournalId id,const NativeSyncLedgerEvidence& evidence,NativeSyncLedgerLimits limits) {
    return attempt<std::unique_ptr<NativeSyncLedger>>([&]{return value(create(value(acquire_native_sync_storage_root(address)),std::move(name),id,evidence,limits));});
}
Observation<std::unique_ptr<NativeSyncLedger>> NativeSyncLedger::reopen(const NativeAbsolutePath& address,NativeName name,
    OperationJournalId id,NativeSyncLedgerLimits limits) {
    return attempt<std::unique_ptr<NativeSyncLedger>>([&]{return value(reopen(value(acquire_native_sync_storage_root(address)),std::move(name),id,limits));});
}
Observation<std::vector<NativeSyncLoadedLedger>> load_native_sync_ledgers(const NativeAbsolutePath& address,NativeSyncLedgerLimits limits,std::stop_token stop) {
    return attempt<std::vector<NativeSyncLoadedLedger>>([&]{return value(load_native_sync_ledgers(value(acquire_native_sync_storage_root(address)),limits,stop));});
}
} // namespace ck::files
