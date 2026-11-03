// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "../sync_session.hpp"
#include "../sha256.hpp"
#include "posix_private_storage.hpp"
#include "prepared_journal_root_bridge.hpp"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <map>
#include <utility>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/attr.h>
#include <sys/mount.h>
#else
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <sstream>
#endif

namespace ck::files {
namespace {
struct Fd {
    int fd=-1;
    PreparedJournalRoot::Pointer owner;
    explicit Fd(int v=-1,PreparedJournalRoot::Pointer keep={}):fd(v),owner(std::move(keep)) {}
    int close_native() noexcept {
        const int current=std::exchange(fd,-1);int code=0;
        if(current>=0 && ::close(current))code=errno;
        if(code&&owner)detail::record_prepared_journal_consumer_failure(*owner,ObservationState::Failed,ErrorDomain::Posix,code,"sync_session.directory_close");
        owner.reset();return code;
    }
    ~Fd() { (void)close_native(); }
    Fd(Fd&& v) noexcept:fd(std::exchange(v.fd,-1)),owner(std::move(v.owner)) {}
    Fd& operator=(Fd&& v) noexcept { if(this!=&v) { (void)close_native();fd=std::exchange(v.fd,-1);owner=std::move(v.owner); } return *this; }
    Fd(const Fd&)=delete; Fd& operator=(const Fd&)=delete;
};
template<class T> Observation<T> failure(int e,const char* op) {
    auto state=ObservationState::Failed;
    if(e==ENOENT || e==ENOTDIR) state=ObservationState::Gone;
    if(e==EACCES || e==EPERM) state=ObservationState::Denied;
    if(e==EWOULDBLOCK || e==EAGAIN) state=ObservationState::Changed;
    if(e==ENOTSUP || e==ENOSYS) state=ObservationState::Unsupported;
    return Observation<T>::unavailable(state,{ErrorDomain::Posix,e,op});
}
template<class T> Observation<T> reject(const char* op,ObservationState s=ObservationState::Changed) {
    return Observation<T>::unavailable(s,{ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity),op});
}
template<class T,class U> Observation<T> propagate(const Observation<U>& r) {
    return Observation<T>::unavailable(r.state(),r.unavailable_detail()->error);
}
void put(Sha256& h,std::uint64_t n) {
    std::array<std::byte,8> b; for(unsigned i=0;i<8;++i) b[i]=std::byte((n>>(i*8))&255); h.update(b);
}
Observation<SyncDigest> identity(int fd) {
    struct stat s{};
    if(fstat(fd,&s)) return failure<SyncDigest>(errno,"sync_session.root_stat");
    if(!S_ISDIR(s.st_mode) || !s.st_nlink) return reject<SyncDigest>("sync_session.root_kind");
    Sha256 h;
#ifdef __APPLE__
    struct statfs fs{};
    if(fstatfs(fd,&fs)) return failure<SyncDigest>(errno,"sync_session.root_fs");
    if(!(fs.f_flags&MNT_LOCAL) || (std::strcmp(fs.f_fstypename,"apfs") && std::strcmp(fs.f_fstypename,"hfs")))
        return reject<SyncDigest>("sync_session.local_durable_identity",ObservationState::Unsupported);
    struct attrlist attrs{}; attrs.bitmapcount=ATTR_BIT_MAP_COUNT; attrs.volattr=ATTR_VOL_INFO|ATTR_VOL_UUID;
    struct { std::uint32_t length; unsigned char uuid[16]; } volume{};
    if(fgetattrlist(fd,&attrs,&volume,sizeof(volume),0))
        return failure<SyncDigest>(errno,"sync_session.volume_uuid");
    if(volume.length!=sizeof(volume) || std::all_of(std::begin(volume.uuid),std::end(volume.uuid),[](auto v){return !v;}))
        return reject<SyncDigest>("sync_session.volume_uuid_missing",ObservationState::Unsupported);
    put(h,0x3158534f504b43ULL);
    h.update(std::as_bytes(std::span(volume.uuid)));
    put(h,s.st_ino); put(h,s.st_birthtimespec.tv_sec); put(h,s.st_birthtimespec.tv_nsec);
#else
#if defined(__linux__) && defined(STATX_BTIME)
    struct statfs fs{};
    if(fstatfs(fd,&fs)) return failure<SyncDigest>(errno,"sync_session.root_fs");
    // ext4, XFS and Btrfs expose local stable fsids. Overlay/network and
    // providers without creation-time identity are deliberately unsupported.
    if(fs.f_type!=0xef53 && fs.f_type!=0x58465342 && fs.f_type!=0x9123683e)
        return reject<SyncDigest>("sync_session.local_durable_identity",ObservationState::Unsupported);
    struct statx x{};
    if(statx(fd,"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,STATX_INO|STATX_BTIME,&x))
        return failure<SyncDigest>(errno,"sync_session.statx_identity");
    if((x.stx_mask&(STATX_INO|STATX_BTIME))!=(STATX_INO|STATX_BTIME))
        return reject<SyncDigest>("sync_session.birth_identity",ObservationState::Unsupported);
    put(h,0x31584e494c4b43ULL); h.update(std::as_bytes(std::span(&fs.f_fsid,1)));
    put(h,x.stx_ino); put(h,x.stx_btime.tv_sec); put(h,x.stx_btime.tv_nsec);
#else
    return reject<SyncDigest>("sync_session.durable_identity",ObservationState::Unsupported);
#endif
#endif
    return Observation<SyncDigest>::available(h.digest());
}
struct Node { Fd fd; std::string name; SyncDigest id; dev_t dev; ino_t ino; };
using Chain=std::vector<Node>;
Observation<Chain> chain(const NativeAbsolutePath& p) {
    if(!p.posix_bytes() || !p.is_valid()) return reject<Chain>("sync_session.posix_path",ObservationState::Unsupported);
    const auto& path=*p.posix_bytes();
    if(path.empty() || path[0]!='/' || (path.size()>1 && path.back()=='/'))
        return reject<Chain>("sync_session.exact_path",ObservationState::Failed);
    Chain out;
    auto add=[&](Fd fd,std::string name)->Observation<bool> {
        if(fd.fd<0) return failure<bool>(errno,"sync_session.open_directory");
        auto id=identity(fd.fd); if(!id.value()) return propagate<bool>(id);
        struct stat s{}; if(fstat(fd.fd,&s)) return failure<bool>(errno,"sync_session.chain_stat");
#ifdef __APPLE__
        // Firmlinks can enter a mounted volume BELOW its root, hiding native
        // ancestors (e.g. /Users versus /System/Volumes/Data). Only accept a
        // cross-volume edge when it lands on that volume's actual mount root.
        if(!out.empty() && out.back().dev!=s.st_dev) {
            struct statfs fs{}; if(fstatfs(fd.fd,&fs)) return failure<bool>(errno,"sync_session.mount_scope");
            Fd mount_root(open(fs.f_mntonname,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW));
            if(mount_root.fd<0) return failure<bool>(errno,"sync_session.mount_root");
            struct stat root{}; if(fstat(mount_root.fd,&root)) return failure<bool>(errno,"sync_session.mount_root_stat");
            if(root.st_dev!=s.st_dev || root.st_ino!=s.st_ino)
                return reject<bool>("sync_session.hidden_native_ancestors",ObservationState::Unsupported);
        }
#endif
        out.push_back({std::move(fd),std::move(name),*id.value(),s.st_dev,s.st_ino});
        return Observation<bool>::available(true);
    };
    auto r=add(Fd(open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW)),{});
    if(!r.value()) return propagate<Chain>(r);
    std::size_t at=1;
    while(at<path.size()) {
        auto slash=path.find('/',at); auto part=path.substr(at,slash==path.npos ? path.npos : slash-at);
        if(part.empty() || part=="." || part=="..") return reject<Chain>("sync_session.exact_components",ObservationState::Failed);
        r=add(Fd(openat(out.back().fd.fd,part.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW)),part);
        if(!r.value()) return propagate<Chain>(r);
        if(out.size()>4096) return reject<Chain>("sync_session.ancestry_limit",ObservationState::Unsupported);
        if(slash==path.npos) break; at=slash+1;
    }
    return Observation<Chain>::available(std::move(out));
}
Observation<bool> validate(const Chain& c) {
    for(std::size_t i=0;i<c.size();++i) {
        auto id=identity(c[i].fd.fd); if(!id.value()) return propagate<bool>(id);
        if(*id.value()!=c[i].id) return reject<bool>("sync_session.held_identity");
        struct stat s{};
        const int rc=i ? fstatat(c[i-1].fd.fd,c[i].name.c_str(),&s,AT_SYMLINK_NOFOLLOW) : lstat("/",&s);
        if(rc) return failure<bool>(errno,"sync_session.held_edge");
        if(!S_ISDIR(s.st_mode) || s.st_dev!=c[i].dev || s.st_ino!=c[i].ino)
            return reject<bool>("sync_session.namespace_changed");
    }
    return Observation<bool>::available(true);
}
// Ascend from the provider-owned duplicate; no navigation address participates.
Observation<Chain> held_storage_chain(PreparedJournalRoot::Pointer owner) {
    auto duplicate=detail::duplicate_prepared_journal_directory(*owner);
    if(!duplicate.value())return propagate<Chain>(duplicate);
    Fd current(*duplicate.value(),owner);Chain out;
    for(;;) {
        if(out.size()>=256)return reject<Chain>("sync_session.storage_ancestor_limit",ObservationState::Unsupported);
        struct stat st{};if(fstat(current.fd,&st))return failure<Chain>(errno,"sync_session.storage_stat");
        auto id=identity(current.fd);if(!id.value())return propagate<Chain>(id);
        if(std::any_of(out.begin(),out.end(),[&](const auto& node){return node.id==*id.value();}))
            return reject<Chain>("sync_session.storage_ancestor_cycle",ObservationState::Unsupported);
        Fd parent(openat(current.fd,"..",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),owner);
        if(parent.fd<0)return failure<Chain>(errno,"sync_session.storage_parent");
        struct stat ps{};if(fstat(parent.fd,&ps))return failure<Chain>(errno,"sync_session.storage_parent_stat");
        out.push_back({std::move(current),{},*id.value(),st.st_dev,st.st_ino});
        if(st.st_dev==ps.st_dev&&st.st_ino==ps.st_ino)break;
        current=std::move(parent);
    }
    std::reverse(out.begin(),out.end());
    auto valid=owner->revalidate();if(!valid.value())return propagate<Chain>(valid);
    return Observation<Chain>::available(std::move(out));
}
Observation<bool> validate_storage(const Chain& chain,PreparedJournalRoot& owner) {
    auto checked=owner.revalidate();if(!checked.value())return checked;
    for(std::size_t i=0;i<chain.size();++i) {
        auto id=identity(chain[i].fd.fd);if(!id.value())return propagate<bool>(id);
        if(*id.value()!=chain[i].id)return reject<bool>("sync_session.storage_identity_changed");
        struct stat parent{};if(fstatat(chain[i].fd.fd,"..",&parent,AT_SYMLINK_NOFOLLOW))
            return failure<bool>(errno,"sync_session.storage_parent_check");
        const auto& expected=chain[i?i-1:0];
        if(parent.st_dev!=expected.dev||parent.st_ino!=expected.ino)return reject<bool>("sync_session.storage_ancestry_changed");
    }
    return owner.revalidate();
}
bool contains(const Chain& c,const SyncDigest& id) {
    return std::any_of(c.begin(),c.end(),[&](const auto& n){return n.id==id;});
}
bool valid_name(std::string_view n) {
    return !n.empty() && n.size()<128 && n.find_first_not_of("0123456789abcdefghijklmnopqrstuvwxyz.-") == n.npos &&
        n!="." && n!="..";
}
Observation<bool> private_file(int fd) {
    return detail::qualify_posix_private_storage(fd,detail::PosixPrivateStorageKind::RegularFile);
}
#ifndef __APPLE__
// Bind mounts can hide true ancestors from '..' traversal. Reject duplicate
// device mounts and mounted subdirectories, and pin the mount table snapshot.
Observation<std::string> mount_table() {
    Fd f(open("/proc/self/mountinfo",O_RDONLY|O_CLOEXEC));
    if(f.fd<0) return failure<std::string>(errno,"sync_session.mountinfo");
    std::string out; char b[4096];
    for(;;) { const auto n=::read(f.fd,b,sizeof(b));
        if(n<0) { if(errno==EINTR) continue; return failure<std::string>(errno,"sync_session.mount_read"); }
        if(!n) break; if(out.size()+n>4*1024*1024) return reject<std::string>("sync_session.mount_limit",ObservationState::Unsupported);
        out.append(b,n);
    }
    return Observation<std::string>::available(std::move(out));
}
Observation<bool> qualify_mounts(const std::string& text,const Chain& c) {
    std::map<std::pair<unsigned,unsigned>,std::vector<std::string>> roots;
    std::istringstream input(text); std::string line;
    while(std::getline(input,line)) {
        std::istringstream row(line); std::string id,parent,device,root;
        if(!(row>>id>>parent>>device>>root)) return reject<bool>("sync_session.mount_parse",ObservationState::Unsupported);
        unsigned ma=0,mi=0; char tail=0;
        if(std::sscanf(device.c_str(),"%u:%u%c",&ma,&mi,&tail)!=2) return reject<bool>("sync_session.mount_device",ObservationState::Unsupported);
        roots[{ma,mi}].push_back(root);
    }
    for(const auto& node:c) {
        const auto it=roots.find({major(node.dev),minor(node.dev)});
        if(it==roots.end() || it->second.size()!=1 || it->second.front()!="/")
            return reject<bool>("sync_session.ambiguous_mount_ancestry",ObservationState::Unsupported);
    }
    return Observation<bool>::available(true);
}
#endif
class PosixBackend final:public SyncSessionBackend {
public:
    // Destroy native duplicates/locks before releasing the lifecycle owner.
    PreparedJournalRoot::Pointer owner;
    Chain store,left,right;
    PreparedJournalRoot::Pointer storage_root() const noexcept override { return owner; }
    // Set only by this provider's legacy address factory. An externally
    // adopted shared root is NEVER finalized by a session consumer.
    bool owns_root_lifecycle=false,root_finished=false;
    bool closed=false;
    int close_error=0;
    void close_native() noexcept {
        if(closed)return;closed=true;
        for(auto* chain:{&store,&left,&right})for(auto& node:*chain) {
            if(node.fd.fd<0)continue;
            const int error=node.fd.close_native();if(error&&!close_error)close_error=error;
            try {if(faults.before&&!faults.before(SyncSessionIo::NativeHandleClose)&&!close_error)close_error=EIO;}
            catch(...) {if(!close_error)close_error=EIO;}
        }
        if(close_error&&owner)detail::record_prepared_journal_consumer_failure(*owner,ObservationState::Failed,ErrorDomain::Posix,close_error,"sync_session.directory_close");
    }
    ~PosixBackend() override {
        close_native();
        if(owns_root_lifecycle&&owner&&!root_finished)try{(void)finish_owned_root();}catch(...) {
            detail::record_prepared_journal_consumer_failure(*owner,ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"sync_session.root_finish_exception");
        }
    }
    Observation<bool> finish_owned_root() {
        if(!owns_root_lifecycle||root_finished)return Observation<bool>::available(true);
        auto result=owner->finish_io();
        if(result.value()) {
            if(*result.value())root_finished=true;
            else {
                detail::record_prepared_journal_consumer_failure(*owner,ObservationState::Unknown,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"sync_session.root_finish_false");
                return Observation<bool>::unavailable(ObservationState::Unknown,{ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"sync_session.root_finish_false"});
            }
        }
        return result;
    }
    Observation<bool> finish_io() override {
        close_native();
        auto root=finish_owned_root();if(!root.value())return root;
        detail::PreparedJournalConsumerFailure first;
        if(owner&&detail::read_prepared_journal_consumer_failure(*owner,first))
            return Observation<bool>::unavailable(first.state,{first.domain,first.code,first.operation.data()});
        return close_error?failure<bool>(close_error,"sync_session.directory_close"):Observation<bool>::available(true);
    }
    SyncSessionFaults faults;
#ifndef __APPLE__
    std::string mounts;
#endif
    const SyncDigest& left_identity() const noexcept override { return left.back().id; }
    const SyncDigest& right_identity() const noexcept override { return right.back().id; }
    std::intptr_t root_handle(bool r) const noexcept override { return closed?-1:(r?right:left).back().fd.fd; }
    Observation<bool> revalidate() override {
        if(closed)return reject<bool>("sync_session.finished");
#ifndef __APPLE__
        auto m=mount_table(); if(!m.value()) return propagate<bool>(m);
        if(*m.value()!=mounts) return reject<bool>("sync_session.mount_topology_changed");
#endif
        auto held=validate_storage(store,*owner);if(!held.value())return held;
        for(const auto* c:{&left,&right}) { auto r=validate(*c); if(!r.value()) return r; }
        return detail::qualify_posix_private_storage(store.back().fd.fd,detail::PosixPrivateStorageKind::Directory);
    }
    Observation<bool> before(SyncSessionIo io) {
        auto r=revalidate(); if(!r.value()) return r;
        if(faults.before && !faults.before(io)) return failure<bool>(EIO,"sync_session.injected");
        return Observation<bool>::available(true);
    }
    Observation<std::optional<std::vector<std::byte>>> read(std::string_view name,std::size_t limit) override {
        using T=std::optional<std::vector<std::byte>>;
        if(!valid_name(name)) return reject<T>("sync_session.basename",ObservationState::Failed);
        auto r=revalidate(); if(!r.value()) return propagate<T>(r);
        Fd f(openat(store.back().fd.fd,std::string(name).c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK));
        if(f.fd<0) { if(errno==ENOENT) return Observation<T>::available({}); return failure<T>(errno,"sync_session.read_open"); }
        r=private_file(f.fd); if(!r.value()) return propagate<T>(r);
        struct stat s{}; if(fstat(f.fd,&s)) return failure<T>(errno,"sync_session.read_stat");
        // Oversized storage is corruption to review, not an unbounded read.
        if(s.st_size<0 || std::uint64_t(s.st_size)>limit) return Observation<T>::available(std::vector<std::byte>{});
        std::vector<std::byte> bytes(static_cast<std::size_t>(s.st_size)); std::size_t at=0;
        while(at<bytes.size()) {
            const auto n=pread(f.fd,bytes.data()+at,bytes.size()-at,at);
            if(n<0) { if(errno==EINTR) continue; return failure<T>(errno,"sync_session.read"); }
            if(!n) return reject<T>("sync_session.short_read"); at+=n;
        }
        struct stat end{}; if(fstat(f.fd,&end)) return failure<T>(errno,"sync_session.read_end");
        if(end.st_size!=s.st_size || end.st_mtime!=s.st_mtime || end.st_ctime!=s.st_ctime || end.st_nlink!=1)
            return reject<T>("sync_session.read_changed");
        r=private_file(f.fd); if(!r.value()) return propagate<T>(r);
        return Observation<T>::available(std::move(bytes));
    }
    Observation<bool> stage(std::string_view name,std::span<const std::byte> bytes) override {
        if(!valid_name(name)) return reject<bool>("sync_session.basename",ObservationState::Failed);
        auto r=before(SyncSessionIo::Remove); if(!r.value()) return r;
        // Only stage names are replaceable here. Never truncate a named current
        // generation, nor a hardlinked/symlinked existing object.
        if(!name.ends_with(".next") && !name.ends_with(".intent-stage"))
            return reject<bool>("sync_session.stage_name",ObservationState::Failed);
        if(unlinkat(store.back().fd.fd,std::string(name).c_str(),0) && errno!=ENOENT)
            return failure<bool>(errno,"sync_session.stage_unlink");
        Fd f(openat(store.back().fd.fd,std::string(name).c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
        if(f.fd<0) return failure<bool>(errno,"sync_session.stage_create");
        r=private_file(f.fd); if(!r.value()) return r;
        std::size_t at=0;
        while(at<bytes.size()) {
            r=before(SyncSessionIo::Write); if(!r.value()) return r;
            const auto n=pwrite(f.fd,bytes.data()+at,std::min(bytes.size()-at,faults.max_write_bytes),at);
            if(n<0) { if(errno==EINTR) continue; return failure<bool>(errno,"sync_session.write"); }
            if(!n) return failure<bool>(EIO,"sync_session.zero_write"); at+=n;
        }
        r=before(SyncSessionIo::FileFlush); if(!r.value()) return r;
        r=private_file(f.fd); if(!r.value()) return r;
        if(fsync(f.fd)) return failure<bool>(errno,"sync_session.file_flush");
#ifdef __APPLE__
        if(fcntl(f.fd,F_FULLFSYNC)) return failure<bool>(errno,"sync_session.file_fullflush");
#endif
        r=before(SyncSessionIo::FileClose);if(!r.value()) return r;
        // Relinquish ownership BEFORE close. A delayed failure/EINTR must never
        // trigger a second close on a descriptor another thread could reuse.
        const auto descriptor=std::exchange(f.fd,-1);
        if(::close(descriptor)) return failure<bool>(errno,"sync_session.stage_close");
        return Observation<bool>::available(true);
    }
    Observation<bool> publish(std::string_view from,std::string_view to) override {
        if(!valid_name(from)||!valid_name(to)) return reject<bool>("sync_session.basename",ObservationState::Failed);
        auto r=before(SyncSessionIo::Publish); if(!r.value()) return r;
        Fd source(openat(store.back().fd.fd,std::string(from).c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK));
        if(source.fd<0) return failure<bool>(errno,"sync_session.publish_source");
        r=private_file(source.fd);if(!r.value()) return r;
        Fd destination(openat(store.back().fd.fd,std::string(to).c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK));
        if(destination.fd<0 && errno!=ENOENT) return failure<bool>(errno,"sync_session.publish_destination");
        if(destination.fd>=0) { r=private_file(destination.fd);if(!r.value()) return r; }
        if(renameat(store.back().fd.fd,std::string(from).c_str(),store.back().fd.fd,std::string(to).c_str()))
            return failure<bool>(errno,"sync_session.rename");
        return Observation<bool>::available(true);
    }
    Observation<bool> remove(std::string_view name) override {
        if(!valid_name(name)) return reject<bool>("sync_session.basename",ObservationState::Failed);
        auto r=before(SyncSessionIo::Remove); if(!r.value()) return r;
        if(unlinkat(store.back().fd.fd,std::string(name).c_str(),0) && errno!=ENOENT)
            return failure<bool>(errno,"sync_session.unlink");
        return Observation<bool>::available(true);
    }
    Observation<bool> flush_directory() override {
        auto r=before(SyncSessionIo::ParentFlush); if(!r.value()) return r;
        return owner->sync();
    }
};
}
Observation<std::unique_ptr<SyncSessionBackend>> open_native_sync_session_backend(
    const NativeAbsolutePath& coordinator,const NativeAbsolutePath& left,const NativeAbsolutePath& right,SyncSessionFaults faults) {
    using P=std::unique_ptr<SyncSessionBackend>;
    auto initial=chain(coordinator);if(!initial.value())return propagate<P>(initial);
    auto privacy=detail::qualify_posix_private_storage(initial.value()->back().fd.fd,detail::PosixPrivateStorageKind::Directory);
    if(!privacy.value())return propagate<P>(privacy);
    auto root=acquire_native_sync_storage_root(coordinator);if(!root.value())return propagate<P>(root);
    auto checked=validate(*initial.value());if(!checked.value())return propagate<P>(checked);
    auto acquired=held_storage_chain(*root.value());if(!acquired.value())return propagate<P>(acquired);
    if(acquired.value()->back().id!=initial.value()->back().id)return reject<P>("sync_session.initial_storage_changed");
    auto acquired_backend=open_native_sync_session_backend(std::move(root).take_value(),left,right,std::move(faults));
    if(acquired_backend.value())static_cast<PosixBackend*>(acquired_backend.value()->get())->owns_root_lifecycle=true;
    return acquired_backend;
}
Observation<std::unique_ptr<SyncSessionBackend>> open_native_sync_session_backend(
    PreparedJournalRoot::Pointer owner,const NativeAbsolutePath& left,const NativeAbsolutePath& right,SyncSessionFaults faults) {
    using P=std::unique_ptr<SyncSessionBackend>;
    if(!faults.max_write_bytes || faults.max_write_bytes>1024*1024)
        return reject<P>("sync_session.write_limit",ObservationState::Failed);
    if(!owner)return reject<P>("sync_session.null_storage_owner",ObservationState::Failed);
    auto s=held_storage_chain(owner); if(!s.value()) return propagate<P>(s);
    auto l=chain(left); if(!l.value()) return propagate<P>(l);
    auto r=chain(right); if(!r.value()) return propagate<P>(r);
    auto b=std::make_unique<PosixBackend>(); b->owner=std::move(owner); b->store=std::move(s).take_value();
    b->left=std::move(l).take_value(); b->right=std::move(r).take_value(); b->faults=std::move(faults);
    if(b->store.front().id!=b->left.front().id||b->store.front().id!=b->right.front().id)
        return reject<P>("sync_session.storage_namespace_unqualified",ObservationState::Unsupported);
    if(contains(b->left,b->right_identity()) || contains(b->right,b->left_identity()) ||
        contains(b->store,b->left_identity()) || contains(b->store,b->right_identity()))
        return reject<P>("sync_session.overlapping_pair_or_store",ObservationState::Failed);
#ifndef __APPLE__
    auto m=mount_table(); if(!m.value()) return propagate<P>(m); b->mounts=*m.value();
    for(const auto* c:{&b->store,&b->left,&b->right}) { auto q=qualify_mounts(b->mounts,*c); if(!q.value()) return propagate<P>(q); }
#endif
    // Deduplicate both roots' ancestor objects before flock: taking another
    // open-description lock for the same inode can conflict with ourselves.
    struct Lock { int fd; bool exclusive; };
    std::map<SyncDigest,Lock> locks;
    for(const auto* c:{&b->left,&b->right}) for(std::size_t i=0;i<c->size();++i) {
        const auto& n=(*c)[i]; auto [it,added]=locks.emplace(n.id,Lock{n.fd.fd,false});
        (void)added; it->second.exclusive |= i+1==c->size();
    }
    for(const auto& [id,lock]:locks) {
        (void)id;
        if(flock(lock.fd,(lock.exclusive?LOCK_EX:LOCK_SH)|LOCK_NB)) return failure<P>(errno,"sync_session.overlap_lock");
    }
    auto checked=b->revalidate(); if(!checked.value()) return propagate<P>(checked);
    // Establish parent-flush support before advertising durable storage.
    checked=b->flush_directory(); if(!checked.value()) return propagate<P>(checked);
    return Observation<P>::available(std::move(b));
}
} // namespace ck::files
