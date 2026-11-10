// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "private_journal_scope_native.hpp"
#include "native_journal_directory_bridge.hpp"
#include "prepared_journal_root_bridge.hpp"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include "legacy_native_fixture_posix.hpp"
#include <utility>
#ifdef __APPLE__
#include <sys/mount.h>
#else
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#endif
#include <unistd.h>
namespace ck::files::detail {
Observation<bool> certify_journal_scope_cursor(PreparedJournalRoot& root,const DirectoryCursor& cursor) {
    auto duplicate=duplicate_posix_journal_directory(cursor);
    if(!duplicate.value()) {const auto& e=*duplicate.unavailable_detail();return Observation<bool>::unavailable(e.state,e.error);}
    const int fd=std::move(duplicate).take_value();
    struct statfs filesystem{};
    const int queried=fstatfs(fd,&filesystem);
    const int query_error=queried?errno:0;
    bool direct=false;
    if(!queried) {
#ifdef __APPLE__
        // HFS directory hard links and stacked/network providers need their
        // own ancestry proof; a native cursor class alone is not provenance.
        direct=(filesystem.f_flags&MNT_LOCAL)&&!std::strcmp(filesystem.f_fstypename,"apfs");
#else
        direct=filesystem.f_type==0xef53||filesystem.f_type==0x58465342||filesystem.f_type==0x9123683e;
#endif
    }
    // Consume before close; EINTR and delayed errors never permit a retry.
    if(::close(fd)) {
        const int code=errno;
        record_prepared_journal_consumer_failure(root,ObservationState::Unknown,
            ErrorDomain::Posix,code,"journal_scope.cursor_close");
        return Observation<bool>::unavailable(ObservationState::Unknown,
            {ErrorDomain::Posix,code,"journal_scope.cursor_close"});
    }
    if(query_error)return Observation<bool>::unavailable(ObservationState::Failed,
        {ErrorDomain::Posix,query_error,"journal_scope.filesystem_query"});
    if(!direct)return Observation<bool>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe),
         "journal_scope.filesystem_provenance_unqualified"});
    return Observation<bool>::available(true);
}
namespace {
ObservationState scope_errno(int code) noexcept {
    if(code==EACCES||code==EPERM)return ObservationState::Denied;
    if(code==ENOENT||code==ENOTDIR)return ObservationState::Gone;
    if(code==ESTALE||code==EEXIST)return ObservationState::Changed;
    if(code==ENOSYS||code==ENOTSUP||code==EOPNOTSUPP)return ObservationState::Unsupported;
    return ObservationState::Failed;
}
template<class T> Observation<T> scope_error(int code,const char* operation) {
    return Observation<T>::unavailable(scope_errno(code),{ErrorDomain::Posix,code,operation});
}
template<class T> Observation<T> scope_unqualified(const char* operation) {
    return Observation<T>::unavailable(ObservationState::Unsupported,{ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe),operation});
}
class ScopeFd final {
public:
    ScopeFd(int fd,PreparedJournalRoot::Pointer root):root_(std::move(root)),fd_(fd){}
    ScopeFd(const ScopeFd&)=delete;
    ScopeFd& operator=(const ScopeFd&)=delete;
    ScopeFd(ScopeFd&& other) noexcept:root_(std::move(other.root_)),fd_(std::exchange(other.fd_,-1)){}
    ~ScopeFd() {
        const int value=std::exchange(fd_,-1);
        if(value>=0&&::close(value)) {const int code=errno;
            record_prepared_journal_consumer_failure(*root_,ObservationState::Unknown,
                ErrorDomain::Posix,code,"journal_scope.topology_close");}
    }
    int get() const noexcept{return fd_;}
    const PreparedJournalRoot::Pointer& root() const noexcept{return root_;}
private:
    PreparedJournalRoot::Pointer root_;
    int fd_;
};
class PosixScopeCursor final:public ScopeDirectoryCursor {
public:
    PosixScopeCursor(ScopeFd fd,AdapterScope scope):fd_(std::move(fd)),scope_(std::move(scope)){}
    Observation<ScopeDirectoryMetadata> inspect() const override {
        using R=Observation<ScopeDirectoryMetadata>;
#ifdef __APPLE__
        struct stat value{};
        if(::ck::files::detail::legacy_fstat(fd_.get(),&value,"legacy.private_journal_scope_posix.fstat.94"))return scope_error<ScopeDirectoryMetadata>(errno,"journal_scope.topology_fstat");
        if(!S_ISDIR(value.st_mode)||!value.st_nlink)return scope_unqualified<ScopeDirectoryMetadata>("journal_scope.topology_kind");
        const auto modified=FileTimestamp::from_unix(value.st_mtimespec.tv_sec,static_cast<std::uint32_t>(value.st_mtimespec.tv_nsec));
        const auto changed=FileTimestamp::from_unix(value.st_ctimespec.tv_sec,static_cast<std::uint32_t>(value.st_ctimespec.tv_nsec));
        if(!modified||!changed)return scope_unqualified<ScopeDirectoryMetadata>("journal_scope.topology_time");
        return R::available({{scope_,IdentityScheme::PosixDeviceInode,
            NativeIdentifier::from_u64(static_cast<std::uint64_t>(value.st_dev)),NativeIdentifier::from_u64(static_cast<std::uint64_t>(value.st_ino)),
            static_cast<std::uint64_t>(value.st_gen)},static_cast<std::uint64_t>(value.st_dev),
            static_cast<std::uint64_t>(value.st_nlink),*modified,*changed});
#else
#ifdef STATX_MNT_ID
        struct statx value{};
        constexpr unsigned required=STATX_TYPE|STATX_INO|STATX_NLINK|STATX_MTIME|STATX_CTIME|STATX_MNT_ID;
        if(statx(fd_.get(),"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT,required,&value))
            return scope_error<ScopeDirectoryMetadata>(errno,"journal_scope.topology_statx");
        if((value.stx_mask&required)!=required||!S_ISDIR(value.stx_mode)||!value.stx_nlink)
            return scope_unqualified<ScopeDirectoryMetadata>("journal_scope.topology_fields");
        const auto modified=FileTimestamp::from_unix(value.stx_mtime.tv_sec,value.stx_mtime.tv_nsec);
        const auto changed=FileTimestamp::from_unix(value.stx_ctime.tv_sec,value.stx_ctime.tv_nsec);
        if(!modified||!changed)return scope_unqualified<ScopeDirectoryMetadata>("journal_scope.topology_time");
        struct statx unique{};
        // Linux UAPI bit 0x4000 is STATX_MNT_ID_UNIQUE; keep this usable
        // with older libc headers while negotiating support through stx_mask.
        constexpr unsigned unique_required=STATX_TYPE|STATX_INO|STATX_NLINK|0x00004000U;
        if(statx(fd_.get(),"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT,unique_required,&unique))
            return scope_error<ScopeDirectoryMetadata>(errno,"journal_scope.topology_statx_unique");
        if((unique.stx_mask&unique_required)!=unique_required ||
            !S_ISDIR(unique.stx_mode)||!unique.stx_nlink ||
            unique.stx_mnt_id < (1ULL << 31) ||
            unique.stx_ino!=value.stx_ino || unique.stx_dev_major!=value.stx_dev_major ||
            unique.stx_dev_minor!=value.stx_dev_minor)
            return scope_unqualified<ScopeDirectoryMetadata>("journal_scope.topology_unique_fields");
        return R::available({{scope_,IdentityScheme::PosixDeviceInode,
            NativeIdentifier::from_u64(static_cast<std::uint64_t>(makedev(value.stx_dev_major,value.stx_dev_minor))),
            NativeIdentifier::from_u64(value.stx_ino),std::nullopt},value.stx_mnt_id,value.stx_nlink,
            *modified,*changed,unique.stx_mnt_id});
#else
        return scope_unqualified<ScopeDirectoryMetadata>("journal_scope.topology_mount_id_unavailable");
#endif
#endif
    }
    Observation<Pointer> open_parent() const override {
#ifdef __APPLE__
        constexpr int flags=O_EVTONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC;
#else
        constexpr int flags=O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC;
#endif
        const int raw=openat(fd_.get(),"..",flags);
        if(raw<0)return scope_error<Pointer>(errno,"journal_scope.topology_parent");
        ScopeFd owned(raw,fd_.root());
        return Observation<Pointer>::available(std::make_unique<PosixScopeCursor>(std::move(owned),scope_));
    }
private:
    ScopeFd fd_;
    AdapterScope scope_;
};
}
Observation<ScopeDirectoryCursor::Pointer> open_scope_directory_cursor(PreparedJournalRoot::Pointer root,
    std::shared_ptr<const DirectoryCursor> cursor) {
    using P=ScopeDirectoryCursor::Pointer;
    if(!root||!cursor)return scope_unqualified<P>("journal_scope.topology_inputs");
    auto duplicated=duplicate_posix_journal_directory(*cursor);
    if(!duplicated.value()) {const auto& error=*duplicated.unavailable_detail();return Observation<P>::unavailable(error.state,error.error);}
    ScopeFd fd(std::move(duplicated).take_value(),std::move(root));
    if(!cursor->identity().value())return scope_unqualified<P>("journal_scope.topology_identity");
    return Observation<P>::available(std::make_unique<PosixScopeCursor>(std::move(fd),cursor->identity().value()->scope));
}
}

#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
namespace ck::files::detail {
// Test instrumentation closure only, not native authority/async completion.
std::uint64_t legacy_native_scope_coverage()noexcept {
    return legacy_operation_bit(LegacyNativeOperation::Query);
}
}
#endif
