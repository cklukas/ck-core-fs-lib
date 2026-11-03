// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "../private_journal_membership.hpp"
#include "prepared_journal_root_bridge.hpp"
#include "native_journal_directory_bridge.hpp"
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <dirent.h>
#include <fcntl.h>
#include <new>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#else
#include <sys/mount.h>
#endif

namespace ck::files::detail {
namespace {
ObservationState state(int code) noexcept {
    if(code==EACCES||code==EPERM)return ObservationState::Denied;
    if(code==ENOENT||code==ENOTDIR)return ObservationState::Changed;
    if(code==ENOSYS||code==ENOTSUP)return ObservationState::Unsupported;
    return ObservationState::Failed;
}
void native_error(PrivateMembershipFailure& failure,int code,const char* op) noexcept {
    failure.record(state(code),ErrorDomain::Posix,code,op);
}
void closed(PreparedJournalRoot& root,PrivateMembershipFailure& failure,int code,const char* op) noexcept {
    if(!code)try {
        if(private_membership_test_fault) {
            if(auto fault=private_membership_test_fault(PrivateMembershipFaultPoint::Close))code=static_cast<int>(*fault);
        }
    } catch(...) {
        record_prepared_journal_consumer_failure(root,ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_membership.close_hook");
        failure.record(ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_membership.close_hook");
        return;
    }
    if(code) {
        // Fixed native failure publication precedes any string/copy/formatter.
        record_prepared_journal_consumer_failure(root,state(code),ErrorDomain::Posix,code,op);
        native_error(failure,code,op);
    }
}
struct Fd {
    int value=-1;PreparedJournalRoot* root=nullptr;PrivateMembershipFailure* failure=nullptr;
    Fd(int fd,PreparedJournalRoot& r,PrivateMembershipFailure& f) noexcept:value(fd),root(&r),failure(&f){}
    ~Fd(){reset();}
    Fd(const Fd&)=delete;Fd& operator=(const Fd&)=delete;
    void reset() noexcept {if(value>=0){const int fd=value;value=-1;const int rc=::close(fd);const int error=rc?errno:0;closed(*root,*failure,error,"journal_membership.fd_close");}}
    int release() noexcept {const int fd=value;value=-1;return fd;}
};
struct Stream {
    DIR* value=nullptr;PreparedJournalRoot* root=nullptr;PrivateMembershipFailure* failure=nullptr;
    Stream(DIR* d,PreparedJournalRoot& r,PrivateMembershipFailure& f) noexcept:value(d),root(&r),failure(&f){}
    Stream(Stream&& other) noexcept:value(other.value),root(other.root),failure(other.failure){other.value=nullptr;}
    Stream& operator=(Stream&&)=delete;Stream(const Stream&)=delete;
    ~Stream(){if(value){DIR* d=value;value=nullptr;const int rc=::closedir(d);const int error=rc?errno:0;closed(*root,*failure,error,"journal_membership.directory_close");}}
};
struct Snapshot {struct stat info{};std::uint64_t mount=0;};
bool identity_same(const Snapshot& a,const Snapshot& b) noexcept {
    return a.info.st_dev==b.info.st_dev&&a.info.st_ino==b.info.st_ino&&
        (a.info.st_mode&S_IFMT)==(b.info.st_mode&S_IFMT)&&a.mount==b.mount
#ifdef __APPLE__
        &&a.info.st_gen==b.info.st_gen
#endif
        ;
}
bool edge_same(const Snapshot& a,const Snapshot& b) noexcept {
    return identity_same(a,b)&&a.info.st_nlink==b.info.st_nlink;
}
bool directory_same(const Snapshot& a,const Snapshot& b) noexcept {
    return edge_same(a,b)&&a.info.st_mode==b.info.st_mode&&a.info.st_uid==b.info.st_uid&&
        a.info.st_gid==b.info.st_gid&&a.info.st_size==b.info.st_size&&
#ifdef __APPLE__
        a.info.st_mtimespec.tv_sec==b.info.st_mtimespec.tv_sec&&a.info.st_mtimespec.tv_nsec==b.info.st_mtimespec.tv_nsec&&
        a.info.st_ctimespec.tv_sec==b.info.st_ctimespec.tv_sec&&a.info.st_ctimespec.tv_nsec==b.info.st_ctimespec.tv_nsec;
#else
        a.info.st_mtim.tv_sec==b.info.st_mtim.tv_sec&&a.info.st_mtim.tv_nsec==b.info.st_mtim.tv_nsec&&
        a.info.st_ctim.tv_sec==b.info.st_ctim.tv_sec&&a.info.st_ctim.tv_nsec==b.info.st_ctim.tv_nsec;
#endif
}
bool snapshot(int parent,const char* name,Snapshot& out,PrivateMembershipFailure& failure) {
    const bool self=!name;
    const int rc=self?fstat(parent,&out.info):fstatat(parent,name,&out.info,AT_SYMLINK_NOFOLLOW);
    if(rc){native_error(failure,errno,"journal_membership.stat");return false;}
#ifdef __linux__
    struct statx sx{};
    if(syscall(SYS_statx,parent,self?"":name,AT_SYMLINK_NOFOLLOW|(self?AT_EMPTY_PATH:0),STATX_BASIC_STATS|STATX_MNT_ID,&sx)) {
        native_error(failure,errno,"journal_membership.statx");return false;
    }
    if((sx.stx_mask&(STATX_BASIC_STATS|STATX_MNT_ID))!=(STATX_BASIC_STATS|STATX_MNT_ID)) {
        failure.unsafe("journal_membership.mount_unknown");return false;
    }
    if(sx.stx_ino!=out.info.st_ino||makedev(sx.stx_dev_major,sx.stx_dev_minor)!=out.info.st_dev||
        sx.stx_mode!=out.info.st_mode||sx.stx_nlink!=out.info.st_nlink||
        sx.stx_ctime.tv_sec!=out.info.st_ctim.tv_sec||sx.stx_ctime.tv_nsec!=out.info.st_ctim.tv_nsec) {
        failure.changed("journal_membership.stat_changed");return false;
    }
    out.mount=sx.stx_mnt_id;
#elif defined(__APPLE__)
    out.mount=static_cast<std::uint64_t>(out.info.st_dev);
#else
    failure.unsafe("journal_membership.mount_unqualified");return false;
#endif
    return true;
}
bool filesystem(int fd,PrivateMembershipFailure& failure) {
    struct statfs fs{};
    if(fstatfs(fd,&fs)){native_error(failure,errno,"journal_membership.filesystem");return false;}
#ifdef __APPLE__
    const bool qualified=(fs.f_flags&MNT_LOCAL)&&!std::strcmp(fs.f_fstypename,"apfs");
#else
    const bool qualified=fs.f_type==0xef53||fs.f_type==0x58465342||fs.f_type==0x9123683e;
#endif
    if(!qualified)failure.unsafe("journal_membership.filesystem_unqualified");
    return qualified;
}
bool matches(const ObjectIdentity& id,const Snapshot& value) noexcept {
    if(id.scheme!=IdentityScheme::PosixDeviceInode||id.volume!=NativeIdentifier::from_u64(value.info.st_dev)||
        id.object!=NativeIdentifier::from_u64(value.info.st_ino))return false;
#ifdef __APPLE__
    return id.generation&&*id.generation==value.info.st_gen;
#else
    return !id.generation;
#endif
}
struct Node {
    Stream stream;Snapshot before;std::size_t depth,parent;std::string name;
    Node(Stream s,Snapshot v,std::size_t d,std::size_t p,std::string n)
        :stream(std::move(s)),before(v),depth(d),parent(p),name(std::move(n)){}
    Node(Node&&)=default;
};
struct Edge {std::size_t parent;std::string name;Snapshot before;};
struct Scan {
    PreparedJournalRoot& root;PrivateMembershipFailure& failure;const HeldChild& entry;
    const PrivateJournalMembershipLimits& limits;std::stop_token stop;
    std::vector<Node> nodes;std::vector<Edge> edges;std::size_t name_bytes=0;
    Scan(PreparedJournalRoot& r,PrivateMembershipFailure& f,const HeldChild& e,
        const PrivateJournalMembershipLimits& l,std::stop_token s):root(r),failure(f),entry(e),limits(l),stop(s){}
    bool running() {
        if(failure)return false;
        if(stop.stop_requested()){failure.record(ObservationState::Changed,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InterruptedRead),"journal_membership.cancelled");return false;}
        return true;
    }
    bool hook(PrivateMembershipFaultPoint point) {
        if(private_membership_test_fault)if(auto fault=private_membership_test_fault(point)) {
            native_error(failure,static_cast<int>(*fault),"journal_membership.read_hook");return false;
        }
        return running();
    }
    bool add_directory(Fd& owner,Snapshot value,std::size_t depth,std::size_t parent,std::string name) {
        if(nodes.size()>=limits.max_directories||depth>limits.max_depth) {
            failure.unsafe("journal_membership.directory_limit");return false;
        }
        for(const auto& old:nodes)if(identity_same(old.before,value)) {
            failure.unsafe("journal_membership.directory_alias");return false;
        }
        DIR* dir=fdopendir(owner.value);
        if(!dir){native_error(failure,errno,"journal_membership.fdopendir");return false;}
        owner.release();Stream stream(dir,root,failure);
        nodes.emplace_back(std::move(stream),value,depth,parent,std::move(name));return true;
    }
    void run() {
        // Dynamic native Root/cursor certification occurs before cross-scope
        // identity use. Raw input descriptors or DTO IDs are never accepted.
        auto duplicate=duplicate_prepared_journal_directory(root);
        if(!duplicate.value()){failure.record(*duplicate.unavailable_detail());return;}
        Fd original(*duplicate.value(),root,failure);
        auto parent_dup=duplicate_posix_journal_directory(*entry.parent());
        if(!parent_dup.value()){failure.record(*parent_dup.unavailable_detail());return;}
        Fd selected_parent(*parent_dup.value(),root,failure);
        if(!filesystem(original.value,failure)||!filesystem(selected_parent.value,failure))return;
        auto source=entry.inspect_basic();
        if(!source.value()){failure.record(*source.unavailable_detail());return;}
        if(!private_membership_entry_qualified(*source.value())){failure.unsafe("journal_membership.source_unqualified");return;}
        if(!private_membership_entry_same(entry.metadata(),*source.value())){failure.changed("journal_membership.source_changed");return;}
        if(!entry.name().posix_bytes()){failure.unsafe("journal_membership.source_name");return;}
        Snapshot selected{},parent_before{},root_before{};
        if(!snapshot(selected_parent.value,entry.name().posix_bytes()->c_str(),selected,failure)||
            !snapshot(selected_parent.value,nullptr,parent_before,failure)||!snapshot(original.value,nullptr,root_before,failure))return;
        if(!S_ISREG(selected.info.st_mode)||!matches(*source.value()->identity.value(),selected)||
            selected.mount!=parent_before.mount||selected.mount!=*source.value()->mount_id.value()||
            selected.info.st_nlink!=*source.value()->link_count.value()) {
            failure.changed("journal_membership.source_membership_changed");return;
        }
        Fd enumeration(openat(original.value,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),root,failure);
        if(enumeration.value<0){native_error(failure,errno,"journal_membership.root_self_open");return;}
        Snapshot opened{};if(!snapshot(enumeration.value,nullptr,opened,failure))return;
        if(!identity_same(root_before,opened)){failure.changed("journal_membership.root_changed");return;}
        original.reset();if(!running()||!add_directory(enumeration,opened,0,0,{}))return;
        for(std::size_t index=0;index<nodes.size()&&running();++index) {
            for(;;) {
                if(!running())return;
                errno=0;const auto* item=readdir(nodes[index].stream.value);const int error=errno;
                if(!item){if(error)native_error(failure,error,"journal_membership.readdir");break;}
                constexpr auto offset=offsetof(dirent,d_name);
                if(item->d_reclen<=offset||item->d_reclen>sizeof(dirent)) {failure.unsafe("journal_membership.name_record");return;}
                const auto bound=static_cast<std::size_t>(item->d_reclen)-offset;
                const auto length=strnlen(item->d_name,bound);
                if(!length||length==bound){failure.unsafe("journal_membership.name_extent");return;}
                if((length==1&&item->d_name[0]=='.')||(length==2&&item->d_name[0]=='.'&&item->d_name[1]=='.'))continue;
                if(edges.size()>=limits.max_records||length>limits.max_name_bytes-name_bytes) {
                    failure.unsafe("journal_membership.record_limit");return;
                }
                std::string name(item->d_name,length);name_bytes+=length;
                const int parent=dirfd(nodes[index].stream.value);Snapshot member{};
                if(!snapshot(parent,name.c_str(),member,failure))return;
                if(member.mount!=root_before.mount||member.info.st_dev!=root_before.info.st_dev||
                    (!S_ISREG(member.info.st_mode)&&!S_ISDIR(member.info.st_mode))) {
                    failure.unsafe("journal_membership.kind_or_mount");return;
                }
                if(S_ISREG(member.info.st_mode)&&matches(*source.value()->identity.value(),member)) {
                    failure.unsafe("journal_membership.private_alias");return;
                }
                edges.push_back({index,name,member});
                if(S_ISDIR(member.info.st_mode)) {
                    Fd child(openat(parent,name.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),root,failure);
                    if(child.value<0){native_error(failure,errno,"journal_membership.child_open");return;}
                    Snapshot held{},named{};
                    if(!snapshot(child.value,nullptr,held,failure)||!snapshot(parent,name.c_str(),named,failure))return;
                    if(!directory_same(member,held)||!directory_same(member,named)) {
                        failure.changed("journal_membership.child_changed");return;
                    }
                    const auto depth=nodes[index].depth+1;
                    if(!add_directory(child,held,depth,index,std::move(name)))return;
                }
            }
            if(!running()||!hook(PrivateMembershipFaultPoint::DirectoryReadComplete))return;
        }
        if(!running()||!hook(PrivateMembershipFaultPoint::BeforeFinalCheck))return;
        // Re-enumerate every pinned directory: additions/removals must not be
        // inferred solely from timestamp granularity. Both passes are bounded.
        std::vector<Edge> final_edges;std::size_t final_names=0;
        for(std::size_t index=0;index<nodes.size();++index) {
            rewinddir(nodes[index].stream.value);
            for(;;) {
                if(!running())return;
                errno=0;const auto* item=readdir(nodes[index].stream.value);const int error=errno;
                if(!item){if(error)native_error(failure,error,"journal_membership.readdir_final");break;}
                constexpr auto offset=offsetof(dirent,d_name);
                if(item->d_reclen<=offset||item->d_reclen>sizeof(dirent)){failure.unsafe("journal_membership.name_record");return;}
                const auto bound=static_cast<std::size_t>(item->d_reclen)-offset;
                const auto length=strnlen(item->d_name,bound);
                if(!length||length==bound){failure.unsafe("journal_membership.name_extent");return;}
                if((length==1&&item->d_name[0]=='.')||(length==2&&item->d_name[0]=='.'&&item->d_name[1]=='.'))continue;
                if(final_edges.size()>=limits.max_records||length>limits.max_name_bytes-final_names){failure.unsafe("journal_membership.record_limit");return;}
                std::string name(item->d_name,length);final_names+=length;Snapshot now{};
                if(!snapshot(dirfd(nodes[index].stream.value),name.c_str(),now,failure))return;
                if(now.mount!=root_before.mount||now.info.st_dev!=root_before.info.st_dev||
                    (!S_ISREG(now.info.st_mode)&&!S_ISDIR(now.info.st_mode))){failure.unsafe("journal_membership.kind_or_mount");return;}
                if(S_ISREG(now.info.st_mode)&&matches(*source.value()->identity.value(),now)){failure.unsafe("journal_membership.private_alias");return;}
                final_edges.push_back({index,std::move(name),now});
            }
            if(!running())return;
        }
        const auto less=[](const Edge& a,const Edge& b){return a.parent!=b.parent?a.parent<b.parent:a.name<b.name;};
        std::sort(edges.begin(),edges.end(),less);std::sort(final_edges.begin(),final_edges.end(),less);
        if(edges.size()!=final_edges.size()){failure.changed("journal_membership.namespace_changed");return;}
        for(std::size_t n=0;n<edges.size();++n)
            if(edges[n].parent!=final_edges[n].parent||edges[n].name!=final_edges[n].name||
                !edge_same(edges[n].before,final_edges[n].before)) {failure.changed("journal_membership.edge_changed");return;}
        // Keep every directory pinned until ALL namespace bookends have been
        // checked. No timestamp-keyed ID set survives this call.
        for(const auto& node:nodes) {
            if(!running())return;
            Snapshot now{};
            if(!snapshot(dirfd(node.stream.value),nullptr,now,failure))return;
            if(!directory_same(node.before,now)){failure.changed("journal_membership.namespace_changed");return;}
        }
        auto after=entry.inspect_basic();if(!after.value()){failure.record(*after.unavailable_detail());return;}
        Snapshot named{},parent_after{};
        if(!snapshot(selected_parent.value,entry.name().posix_bytes()->c_str(),named,failure)||
            !snapshot(selected_parent.value,nullptr,parent_after,failure))return;
        if(!private_membership_entry_same(*source.value(),*after.value())||!edge_same(selected,named)||
            !identity_same(parent_before,parent_after)) {failure.changed("journal_membership.source_changed");return;}
        auto valid=root.revalidate();
        if(!valid.value())failure.record(*valid.unavailable_detail());
        else if(!*valid.value())failure.unsafe("journal_membership.root_false");
    }
};
}
Observation<bool> native_private_journal_disjointness(PreparedJournalRoot& root,const HeldChild& entry,
    const PrivateJournalMembershipLimits& limits,std::stop_token stop) {
    PrivateMembershipFailure failure;
    try {Scan scan(root,failure,entry,limits,stop);scan.run();}
    catch(const std::bad_alloc&) {failure.record(ObservationState::Unknown,ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_membership.allocation");}
    catch(...) {failure.record(ObservationState::Unknown,ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_membership.exception");}
    return failure.result();
}
} // namespace ck::files::detail
