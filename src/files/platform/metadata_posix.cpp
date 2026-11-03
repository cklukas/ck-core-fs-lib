// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif
#include "native_filesystem.hpp"
#include "native_home.hpp"
#include "metadata_replay.hpp"
#include "metadata_capture_job.hpp"
#include "native_target_read_seed.hpp"
#include "native_target_read_budget.hpp"
#include "native_metadata_stream_target.hpp"
#include "linux_anonymous_staging.hpp"
#include "native_journal_directory_bridge.hpp"
#include "native_directory_reader.hpp"

#include <algorithm>
#include <atomic>
#include <iterator>
#include <set>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <cstdlib>
#include <iomanip>
#include <limits.h>
#include <memory>
#include <sstream>
#include <string_view>
#include <cstdint>
#include <limits>
#include <string>
#include <optional>
#include <utility>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#if defined(__APPLE__)
#include <sys/acl.h>
#include <libkern/OSByteOrder.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/stdio.h>
#endif
#if defined(__linux__)
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include "linux_ordinary_metadata.hpp"
#include <linux/fs.h>
#include <linux/capability.h>
#include <linux/nsfs.h>
#include <linux/openat2.h>
#include <sched.h>
#if __has_include(<linux/fscrypt.h>)
#include <linux/fscrypt.h>
#endif
#include <sys/ioctl.h>
#include <sys/statvfs.h>
#include <sys/fsuid.h>
#endif

namespace ck::files {
namespace {

class PosixTargetReadSeed;
#if defined(__linux__)
struct NativeTargetReadCloneState final {
    std::atomic<std::size_t> active_clones{0};
};
struct NativeTargetReadCloneLease final {
    explicit NativeTargetReadCloneLease(std::shared_ptr<NativeTargetReadCloneState> state)noexcept
        :state_(std::move(state)) { if(state_)state_->active_clones.fetch_add(1,std::memory_order_relaxed); }
    ~NativeTargetReadCloneLease() { if(state_)state_->active_clones.fetch_sub(1,std::memory_order_relaxed); }
    NativeTargetReadCloneLease(const NativeTargetReadCloneLease&)=delete;
    NativeTargetReadCloneLease& operator=(const NativeTargetReadCloneLease&)=delete;
private:
    std::shared_ptr<NativeTargetReadCloneState> state_;
};
#endif

NativeError adapter_error(AdapterError code, std::string operation) {
    return {ErrorDomain::Adapter, static_cast<std::int64_t>(code), std::move(operation)};
}

ObservationState errno_state(int code) noexcept {
    if (code == EACCES || code == EPERM) return ObservationState::Denied;
    if (code == ENOENT || code == ENOTDIR) return ObservationState::Gone;
    if (code == EEXIST) return ObservationState::Changed;
    if (code == ESTALE) return ObservationState::Changed;
    if (code == ENOSYS || code == ENOTSUP || code == EOPNOTSUPP) return ObservationState::Unsupported;
    return ObservationState::Failed;
}

Observation<std::uint64_t> descriptor_limit(int descriptor, int name, const char* operation) {
    errno = 0; const auto value = fpathconf(descriptor, name); const int code = errno;
    static_assert(sizeof(value) <= sizeof(std::int64_t));
    return detail::decode_posix_limit(static_cast<std::int64_t>(value), code == EINVAL ? ObservationState::Unknown : errno_state(code), {ErrorDomain::Posix, code, operation});
}

template <class T>
Observation<T> not_applicable(const char* operation) {
    return Observation<T>::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::NotApplicable, operation));
}

Observation<FileTimestamp> timestamp(std::int64_t seconds, std::int64_t nanos, const char* operation) {
    if (nanos < 0 || nanos >= 1'000'000'000)
        return Observation<FileTimestamp>::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidNativeResult, operation));
    return Observation<FileTimestamp>::available(*FileTimestamp::from_unix(seconds, static_cast<std::uint32_t>(nanos)));
}

ObjectKind kind(mode_t mode) noexcept {
    if (S_ISREG(mode)) return ObjectKind::RegularFile;
    if (S_ISDIR(mode)) return ObjectKind::Directory;
    if (S_ISLNK(mode)) return ObjectKind::SymbolicLink;
    if (S_ISFIFO(mode)) return ObjectKind::Fifo;
    if (S_ISSOCK(mode)) return ObjectKind::Socket;
    if (S_ISCHR(mode)) return ObjectKind::CharacterDevice;
    if (S_ISBLK(mode)) return ObjectKind::BlockDevice;
    return ObjectKind::Other;
}

void platform_fields(BasicMetadata& result) {
    result.windows_attributes = not_applicable<std::uint32_t>("windows_attributes");
    result.reparse_tag = not_applicable<std::uint32_t>("reparse_tag");
}

Observation<BasicMetadata> stat_metadata(int descriptor, const char* path, bool from_handle, const AdapterScope& scope, int path_flags = AT_SYMLINK_NOFOLLOW) {
    struct stat native{};
    if ((from_handle ? fstat(descriptor, &native) : fstatat(descriptor, path, &native, path_flags)) != 0) {
        const int code = errno;
        return Observation<BasicMetadata>::unavailable(errno_state(code), {ErrorDomain::Posix, code, from_handle ? "fstat" : "fstatat"});
    }
    BasicMetadata result;
    platform_fields(result);
    std::optional<std::uint64_t> generation;
#if defined(__APPLE__)
    generation = native.st_gen;
    result.bsd_flags = Observation<std::uint32_t>::available(native.st_flags);
    result.created = timestamp(native.st_birthtimespec.tv_sec, native.st_birthtimespec.tv_nsec, "stat.birth_time");
    result.accessed = timestamp(native.st_atimespec.tv_sec, native.st_atimespec.tv_nsec, "stat.access_time");
    result.modified = timestamp(native.st_mtimespec.tv_sec, native.st_mtimespec.tv_nsec, "stat.modified_time");
    result.changed = timestamp(native.st_ctimespec.tv_sec, native.st_ctimespec.tv_nsec, "stat.changed_time");
    result.linux_attributes = not_applicable<LinuxFileAttributes>("linux_attributes");
#else
    result.bsd_flags = not_applicable<std::uint32_t>("bsd_flags");
    result.created = Observation<FileTimestamp>::unavailable(ObservationState::Unsupported,
        adapter_error(AdapterError::UnsupportedQuery, "stat.birth_time"));
    result.accessed = timestamp(native.st_atim.tv_sec, native.st_atim.tv_nsec, "stat.access_time");
    result.modified = timestamp(native.st_mtim.tv_sec, native.st_mtim.tv_nsec, "stat.modified_time");
    result.changed = timestamp(native.st_ctim.tv_sec, native.st_ctim.tv_nsec, "stat.changed_time");
#endif
    result.identity = Observation<ObjectIdentity>::available({scope, IdentityScheme::PosixDeviceInode,
        NativeIdentifier::from_u64(static_cast<std::uint64_t>(native.st_dev)),
        NativeIdentifier::from_u64(static_cast<std::uint64_t>(native.st_ino)), generation});
    // st_dev is the portable POSIX mount/volume discriminator used by the
    // recursive inventory confinement check. Linux statx may provide the
    // finer mount-id below; this fallback keeps Darwin's native path honest.
    result.mount_id = Observation<std::uint64_t>::available(static_cast<std::uint64_t>(native.st_dev));
    result.kind = Observation<ObjectKind>::available(kind(native.st_mode));
    result.posix_permissions = Observation<std::uint32_t>::available(static_cast<std::uint32_t>(native.st_mode) & 07777U);
    result.posix_uid = Observation<std::uint64_t>::available(native.st_uid);
    result.posix_gid = Observation<std::uint64_t>::available(native.st_gid);
    result.link_count = Observation<std::uint64_t>::available(native.st_nlink);
    if (S_ISREG(native.st_mode)) {
        if (native.st_size >= 0)
            result.logical_size = Observation<std::uint64_t>::available(static_cast<std::uint64_t>(native.st_size));
        else
            result.logical_size = Observation<std::uint64_t>::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidNativeResult, "stat.size"));
        if (native.st_blocks >= 0 && static_cast<std::uint64_t>(native.st_blocks) <= std::numeric_limits<std::uint64_t>::max() / 512U)
            result.allocated_size = Observation<std::uint64_t>::available(static_cast<std::uint64_t>(native.st_blocks) * 512U);
        else
            result.allocated_size = Observation<std::uint64_t>::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidNativeResult, "stat.blocks"));
    } else {
        result.logical_size = not_applicable<std::uint64_t>("regular_file.size");
        result.allocated_size = not_applicable<std::uint64_t>("regular_file.allocation");
    }
    return Observation<BasicMetadata>::available(std::move(result));
}

#if defined(__linux__)
Observation<BasicMetadata> statx_metadata(int descriptor, const char* path, int flags, const AdapterScope& scope) {
    struct statx native{};
    unsigned int requested = STATX_BASIC_STATS | STATX_BTIME;
#ifdef STATX_MNT_ID
    requested |= STATX_MNT_ID;
#endif
    if (statx(descriptor, path, flags | AT_NO_AUTOMOUNT, requested, &native) != 0) {
        const int code = errno;
        // The older stat interface is a separate documented query, not a claim
        // that omitted statx-only fields were observed. Do not retry denial or
        // I/O failures through a different API and conceal the original error.
        if (code == ENOSYS) return stat_metadata(descriptor, path, (flags & AT_EMPTY_PATH) != 0, scope, flags & AT_SYMLINK_NOFOLLOW);
        return Observation<BasicMetadata>::unavailable(errno_state(code), {ErrorDomain::Posix, code, "statx"});
    }
    BasicMetadata result;
    platform_fields(result);
    result.bsd_flags = not_applicable<std::uint32_t>("bsd_flags");
    result.linux_attributes = Observation<LinuxFileAttributes>::available({native.stx_attributes, native.stx_attributes_mask});
    if ((native.stx_mask & STATX_INO) != 0) {
        result.identity = Observation<ObjectIdentity>::available({scope, IdentityScheme::PosixDeviceInode,
            NativeIdentifier::from_u64(static_cast<std::uint64_t>(makedev(native.stx_dev_major, native.stx_dev_minor))),
            NativeIdentifier::from_u64(native.stx_ino), std::nullopt});
    }
    if ((native.stx_mask & STATX_TYPE) != 0)
        result.kind = Observation<ObjectKind>::available(kind(native.stx_mode));
    if ((native.stx_mask & STATX_MODE) != 0)
        result.posix_permissions = Observation<std::uint32_t>::available(native.stx_mode & 07777U);
    if ((native.stx_mask & STATX_UID) != 0) result.posix_uid = Observation<std::uint64_t>::available(native.stx_uid);
    if ((native.stx_mask & STATX_GID) != 0) result.posix_gid = Observation<std::uint64_t>::available(native.stx_gid);
    if ((native.stx_mask & STATX_NLINK) != 0) result.link_count = Observation<std::uint64_t>::available(native.stx_nlink);
#ifdef STATX_MNT_ID
    if ((native.stx_mask & STATX_MNT_ID) != 0) result.mount_id = Observation<std::uint64_t>::available(native.stx_mnt_id);
#endif
    if ((native.stx_mask & STATX_ATIME) != 0) result.accessed = timestamp(native.stx_atime.tv_sec, native.stx_atime.tv_nsec, "statx.access_time");
    if ((native.stx_mask & STATX_MTIME) != 0) result.modified = timestamp(native.stx_mtime.tv_sec, native.stx_mtime.tv_nsec, "statx.modified_time");
    if ((native.stx_mask & STATX_CTIME) != 0) result.changed = timestamp(native.stx_ctime.tv_sec, native.stx_ctime.tv_nsec, "statx.changed_time");
    if ((native.stx_mask & STATX_BTIME) != 0) result.created = timestamp(native.stx_btime.tv_sec, native.stx_btime.tv_nsec, "statx.birth_time");
    if (result.kind.value() && *result.kind.value() == ObjectKind::RegularFile) {
        if ((native.stx_mask & STATX_SIZE) != 0) result.logical_size = Observation<std::uint64_t>::available(native.stx_size);
        if ((native.stx_mask & STATX_BLOCKS) != 0) {
            if (native.stx_blocks <= std::numeric_limits<std::uint64_t>::max() / 512U)
                result.allocated_size = Observation<std::uint64_t>::available(native.stx_blocks * 512U);
            else
                result.allocated_size = Observation<std::uint64_t>::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidNativeResult, "statx.blocks"));
        }
    } else if (result.kind.value()) {
        result.logical_size = not_applicable<std::uint64_t>("regular_file.size");
        result.allocated_size = not_applicable<std::uint64_t>("regular_file.allocation");
    }
    return Observation<BasicMetadata>::available(std::move(result));
}
#endif

#if defined(__linux__)
Observation<bool> compare_capture_bookend(const BasicMetadata& before,const BasicMetadata& after,const char* operation) {
    using R=Observation<bool>;
    if(!before.identity.value()||!after.identity.value()||
       compare_identity(*before.identity.value(),*after.identity.value())!=IdentityComparison::Same||
       !before.kind.value()||!after.kind.value()||*before.kind.value()!=*after.kind.value()||
       !before.mount_id.value()||!after.mount_id.value()||*before.mount_id.value()!=*after.mount_id.value()||
       !before.changed.value()||!after.changed.value()||*before.changed.value()!=*after.changed.value())
        return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,operation));
    if(*before.kind.value()==ObjectKind::RegularFile &&
       (!before.logical_size.value()||!after.logical_size.value()||*before.logical_size.value()!=*after.logical_size.value()))
        return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,operation));
    return R::available(true);
}
#endif

class OwnedDescriptor final {
public:
    explicit OwnedDescriptor(int descriptor) : descriptor_(descriptor) {}
    ~OwnedDescriptor() { if (descriptor_ >= 0 && close(descriptor_)!=0) {
        const int e=errno;detail::record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Posix,e,"metadata_capture.temporary_close"});errno=e;
    } }
    OwnedDescriptor(const OwnedDescriptor&) = delete;
    OwnedDescriptor& operator=(const OwnedDescriptor&) = delete;
    OwnedDescriptor(OwnedDescriptor&& other) noexcept : descriptor_(std::exchange(other.descriptor_, -1)) {}
    OwnedDescriptor& operator=(OwnedDescriptor&& other) noexcept {
        if (this != &other) {
            if (descriptor_ >= 0 && close(descriptor_)!=0) {const int e=errno;detail::record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Posix,e,"metadata_capture.temporary_close"});errno=e;}
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }
    int get() const noexcept { return descriptor_; }
    int release() noexcept { return std::exchange(descriptor_, -1); }
private:
    int descriptor_;
};

#if defined(__linux__)
// These identifiers are published in linux/nsfs.h; older userspace headers
// may predate the names. Unknown native namespace identities refuse Full.
constexpr ino_t linux_initial_user_namespace_inode=0xEFFFFFFDU;
Observation<bool> linux_full_close(OwnedDescriptor& owner,const char* operation) {
    const int fd=owner.release();if(fd<0||close(fd)==0)return Observation<bool>::available(true);
    const int code=errno;detail::record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Posix,code,operation});
    return Observation<bool>::unavailable(ObservationState::Failed,{ErrorDomain::Posix,code,operation});
}

Observation<bool> linux_full_environment() {
    using R=Observation<bool>;
    const auto unsupported=[](const char* op){return R::unavailable(ObservationState::Unsupported,
        adapter_error(AdapterError::ProviderReviewRequired,op));};
    __user_cap_header_struct h{};h.version=_LINUX_CAPABILITY_VERSION_3;
    __user_cap_data_struct caps[2]{};
    if(syscall(SYS_capget,&h,caps))return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_capget"});
    if(!(caps[CAP_SYS_ADMIN/32].effective&(1U<<(CAP_SYS_ADMIN%32))))
        return unsupported("metadata_replay.complete_requires_initial_sys_admin");
    // Anchor the actual current thread in one genuine proc mount. NO_XDEV
    // excludes bind-substituted task/ns entries, including same-filesystem
    // bind mounts. A held final symlink read cannot be redirected by rename.
    OwnedDescriptor proc(open("/proc",O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    struct stat st{};struct statfs fs{};
    if(proc.get()<0||fstatfs(proc.get(),&fs))return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_proc_open"});
    if(static_cast<unsigned long>(fs.f_type)!=static_cast<unsigned long>(PROC_SUPER_MAGIC))
        return unsupported("metadata_replay.full_proc_native_provider");
    open_how how{};how.flags=O_PATH|O_DIRECTORY|O_CLOEXEC;how.resolve=RESOLVE_NO_XDEV;
    OwnedDescriptor task(static_cast<int>(syscall(SYS_openat2,proc.get(),"thread-self",&how,sizeof(how))));
    if(task.get()<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_current_task"});
    how.flags=O_PATH|O_NOFOLLOW|O_CLOEXEC;how.resolve=RESOLVE_NO_XDEV|RESOLVE_NO_SYMLINKS;
    OwnedDescriptor link(static_cast<int>(syscall(SYS_openat2,task.get(),"ns/user",&how,sizeof(how))));
    if(link.get()<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_userns_link"});
    if(fstat(link.get(),&st)||fstatfs(link.get(),&fs))return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_userns_link_stat"});
    if(!S_ISLNK(st.st_mode)||static_cast<unsigned long>(fs.f_type)!=static_cast<unsigned long>(PROC_SUPER_MAGIC))
        return unsupported("metadata_replay.full_userns_link_provider");
    char identity[64];const auto n=readlinkat(link.get(),"",identity,sizeof(identity));
    if(n<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_userns_readlink"});
    if(std::string_view(identity,static_cast<std::size_t>(n))!="user:[4026531837]")
        return unsupported("metadata_replay.initial_user_namespace_unqualified");
    OwnedDescriptor ns(openat(task.get(),"ns/user",O_RDONLY|O_CLOEXEC));
    if(ns.get()<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_userns_open"});
    if(fstat(ns.get(),&st)||fstatfs(ns.get(),&fs))return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_userns_stat"});
    if(static_cast<unsigned long>(fs.f_type)!=static_cast<unsigned long>(NSFS_MAGIC)||
       st.st_ino!=linux_initial_user_namespace_inode||ioctl(ns.get(),NS_GET_NSTYPE)!=CLONE_NEWUSER)
        return unsupported("metadata_replay.initial_user_namespace_unqualified");
    for(auto* owner:{&ns,&link,&task,&proc}){const auto closed=linux_full_close(*owner,"metadata_replay.full_userns_close");if(!closed.value())return closed;}
    // lsm_list_modules is a direct kernel query, not a path-based assertion
    // about /sys/kernel/security/lsm. Both audited Linux syscall ABIs assign
    // number 461; use the toolchain constant when it is available.
#if defined(SYS_lsm_list_modules)
    constexpr long list_modules=SYS_lsm_list_modules;
#elif defined(__aarch64__) || defined(__x86_64__)
    constexpr long list_modules=461;
#else
    return unsupported("metadata_replay.full_lsm_syscall_abi_unqualified");
#endif
#if defined(SYS_lsm_list_modules) || defined(__aarch64__) || defined(__x86_64__)
    std::array<std::uint64_t,64> ids{};std::uint32_t bytes=sizeof(ids);
    const auto count=syscall(list_modules,ids.data(),&bytes,0U);
    if(count<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_lsm_list_modules"});
    if(bytes>sizeof(ids)||bytes%sizeof(std::uint64_t)||static_cast<std::uint64_t>(count)!=bytes/sizeof(std::uint64_t))
        return R::unavailable(ObservationState::Failed,adapter_error(AdapterError::InvalidNativeResult,"metadata_replay.full_lsm_reply_shape"));
    if(count!=1||bytes!=sizeof(std::uint64_t)||ids[0]!=100U)
        return unsupported("metadata_replay.full_active_lsm_unimplemented");
#endif
    return R::available(true);
}
template<class T>bool linux_full_equal(const Observation<T>&a,const Observation<T>&b) {
    return a.value()&&b.value()?*a.value()==*b.value():!a.value()&&!b.value()&&a.state()==b.state();
}
bool linux_full_equal(const Observation<LinuxFileAttributes>&a,const Observation<LinuxFileAttributes>&b) {
    return a.value()&&b.value()?a.value()->value==b.value()->value&&a.value()->known_mask==b.value()->known_mask:
        !a.value()&&!b.value()&&a.state()==b.state();
}
bool linux_full_owner(const Observation<ObjectIdentity>&a,const Observation<ObjectIdentity>&b) {
    return a.value()&&b.value()&&compare_identity(*a.value(),*b.value())==IdentityComparison::Same;
}
bool linux_full_basic(const BasicMetadata&a,const BasicMetadata&b,bool access_time) {
    return linux_full_owner(a.identity,b.identity)&&linux_full_equal(a.kind,b.kind)&&linux_full_equal(a.logical_size,b.logical_size)&&
        linux_full_equal(a.link_count,b.link_count)&&linux_full_equal(a.posix_uid,b.posix_uid)&&linux_full_equal(a.posix_gid,b.posix_gid)&&
        linux_full_equal(a.posix_permissions,b.posix_permissions)&&linux_full_equal(a.modified,b.modified)&&linux_full_equal(a.changed,b.changed)&&
        linux_full_equal(a.created,b.created)&&linux_full_equal(a.bsd_flags,b.bsd_flags)&&linux_full_equal(a.windows_attributes,b.windows_attributes)&&
        linux_full_equal(a.reparse_tag,b.reparse_tag)&&linux_full_equal(a.linux_attributes,b.linux_attributes)&&linux_full_equal(a.mount_id,b.mount_id)&&
        (!access_time||linux_full_equal(a.accessed,b.accessed));
}
bool linux_full_policy(const MetadataReplayPolicy&a,const MetadataReplayPolicy&b) {
    return a.version==b.version&&a.scope==b.scope&&a.ownership==b.ownership&&a.allow_privilege_metadata==b.allow_privilege_metadata&&
        a.limits.max_native_bytes==b.limits.max_native_bytes&&a.limits.max_records==b.limits.max_records;
}
bool linux_full_values(const MetadataReplaySnapshot&a,const MetadataReplaySnapshot&b,bool access_time) {
    if(!linux_full_policy(a.policy,b.policy)||!linux_full_basic(a.basic,b.basic,access_time)||
       a.attribute_coverage!=AttributeCoverage::CredentialsVisiblePosix||a.attribute_coverage!=b.attribute_coverage||
       a.channel_coverage!=DataChannelCoverage::Unknown||b.channel_coverage!=DataChannelCoverage::Unknown||
       !a.channels.empty()||!b.channels.empty()||a.channel_evidence||b.channel_evidence||
       a.attributes.size()!=b.attributes.size()||a.security.size()!=b.security.size())return false;
    std::set<std::string> names;
    for(const auto&x:a.attributes){const auto*n=x.identifier.posix_bytes();if(!n||!names.insert(*n).second)return false;
        auto y=std::find_if(b.attributes.begin(),b.attributes.end(),[&](const auto&v){return v.identifier==x.identifier;});
        if(y==b.attributes.end()||x.bytes!=y->bytes||!linux_full_equal(x.native_flags,y->native_flags)||
           !linux_full_owner(x.owner,a.basic.identity)||!linux_full_owner(y->owner,b.basic.identity))return false;}
    std::set<SecurityPart> parts;
    for(const auto&x:a.security){if(!parts.insert(x.part).second)return false;
        auto y=std::find_if(b.security.begin(),b.security.end(),[&](const auto&v){return v.part==x.part;});
        if(y==b.security.end()||x.encoding!=y->encoding||x.presence!=y->presence||x.bytes!=y->bytes||x.native_query_mask!=y->native_query_mask||
           !linux_full_owner(x.owner,a.basic.identity)||!linux_full_owner(y->owner,b.basic.identity))return false;}
    return true;
}
struct LinuxFullClassState {
    int inode_flags=0;fsxattr storage{};std::array<std::byte,sizeof(fsid_t)> filesystem{};
    bool same(const LinuxFullClassState&b)const noexcept {
        return inode_flags==b.inode_flags&&filesystem==b.filesystem&&storage.fsx_xflags==b.storage.fsx_xflags&&
            storage.fsx_projid==b.storage.fsx_projid&&storage.fsx_extsize==b.storage.fsx_extsize&&storage.fsx_cowextsize==b.storage.fsx_cowextsize;
    }
};
#endif

Observation<std::string> descriptor_path(int descriptor, const char* operation) {
#if defined(__linux__)
    constexpr std::size_t limit = 1024 * 1024;
    std::string link = "/proc/self/fd/" + std::to_string(descriptor);
    std::string result(limit, '\0');
    const auto length = readlink(link.c_str(), result.data(), result.size());
    if (length < 0)
        return Observation<std::string>::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, operation});
    if (static_cast<std::size_t>(length) >= result.size())
        return Observation<std::string>::unavailable(ObservationState::Unknown,
            adapter_error(AdapterError::InventoryLimit, operation));
    result.resize(static_cast<std::size_t>(length));
    if (result.size() >= 10 && result.compare(result.size() - 10, 10, " (deleted)") == 0)
        return Observation<std::string>::unavailable(ObservationState::Changed,
            adapter_error(AdapterError::MetadataChanged, operation));
    return Observation<std::string>::available(std::move(result));
#elif defined(__APPLE__)
    std::string result(PATH_MAX, '\0');
    if (fcntl(descriptor, F_GETPATH, result.data()) != 0)
        return Observation<std::string>::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, operation});
    result.resize(std::strlen(result.c_str()));
    return Observation<std::string>::available(std::move(result));
#else
    return Observation<std::string>::unavailable(ObservationState::Unsupported,
        adapter_error(AdapterError::UnsupportedQuery, operation));
#endif
}

Observation<std::string> mount_root_path(int source_descriptor, dev_t source_device, const char* operation) {
    using Result = Observation<std::string>;
    OwnedDescriptor current(fcntl(source_descriptor, F_DUPFD_CLOEXEC, 0));
    if (current.get() < 0)
        return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, operation});
    for (std::size_t depth = 0; depth < 4096; ++depth) {
        struct stat current_stat{};
        if (fstat(current.get(), &current_stat) != 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, operation});
        const auto parent_path = descriptor_path(current.get(), operation);
        if (!parent_path.value()) {
            const auto& e = *parent_path.unavailable_detail();
            return Result::unavailable(e.state, e.error);
        }
        OwnedDescriptor parent(openat(current.get(), "..", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (parent.get() < 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, operation});
        struct stat parent_stat{};
        if (fstat(parent.get(), &parent_stat) != 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, operation});
        if (current_stat.st_dev == source_device &&
            (parent_stat.st_dev != source_device ||
             (parent_stat.st_dev == current_stat.st_dev && parent_stat.st_ino == current_stat.st_ino)))
            return Result::available(*parent_path.value());
        current = std::move(parent);
    }
    return Result::unavailable(ObservationState::Unknown, adapter_error(AdapterError::InventoryLimit, operation));
}

struct TrashDirectories final {
    OwnedDescriptor files;
    OwnedDescriptor info;
};

Observation<OwnedDescriptor> open_directory_path(std::string_view path, bool create, const char* operation) {
    using Result = Observation<OwnedDescriptor>;
    if (path.empty() || path.front() != '/')
        return Result::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::UnsupportedQuery, operation));
#if defined(__APPLE__)
    // macOS volume Trash roots are commonly write/search-only (for example
    // .Trashes is mode 0333 with the sticky bit). O_RDONLY incorrectly turns
    // a usable native Trash into EACCES; O_SEARCH retains descriptor-relative
    // traversal and mkdirat/renameat authority without reading directory data.
    constexpr int directory_open_mode = O_SEARCH;
#else
    constexpr int directory_open_mode = O_RDONLY | O_DIRECTORY;
#endif
    OwnedDescriptor current(open("/", directory_open_mode | O_NOFOLLOW | O_CLOEXEC));
    if (current.get() < 0)
        return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, operation});
    std::size_t begin = 1;
    while (begin < path.size()) {
        const auto end = path.find('/', begin);
        const auto length = end == std::string_view::npos ? path.size() - begin : end - begin;
        const auto component = path.substr(begin, length);
        if (component.empty() || component == "." || component == ".." || component.find('\0') != std::string_view::npos)
            return Result::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::UnsupportedQuery, operation));

        OwnedDescriptor next(openat(current.get(), std::string(component).c_str(),
            directory_open_mode | O_NOFOLLOW | O_CLOEXEC));
        if (next.get() < 0 && create && errno == ENOENT) {
            if (mkdirat(current.get(), std::string(component).c_str(), 0700) != 0 && errno != EEXIST)
                return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, operation});
            if (fsync(current.get()) != 0)
                return Result::unavailable(ObservationState::Unknown, {ErrorDomain::Posix, errno, operation});
            next = OwnedDescriptor(openat(current.get(), std::string(component).c_str(),
                directory_open_mode | O_NOFOLLOW | O_CLOEXEC));
        }
        if (next.get() < 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, operation});
        current = std::move(next);
        if (end == std::string_view::npos) break;
        begin = end + 1;
    }
    return Result::available(std::move(current));
}

Observation<TrashDirectories> open_trash_root(std::string_view root_path, dev_t source_device, const char* operation) {
    using Result = Observation<TrashDirectories>;
    auto root = open_directory_path(root_path, true, operation);
    if (!root.value()) {
        const auto& e = *root.unavailable_detail();
        return Result::unavailable(e.state, e.error);
    }
    struct stat trash_stat{};
    if (fstat(root.value()->get(), &trash_stat) != 0)
        return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, operation});
    if (trash_stat.st_dev != source_device)
        return Result::unavailable(ObservationState::Unsupported,
            adapter_error(AdapterError::UnsupportedQuery, "trash_child.mount_specific_trash"));
    auto files = open_directory_path(std::string(root_path) + "/files", true, operation);
    if (!files.value()) {
        const auto& e = *files.unavailable_detail();
        return Result::unavailable(e.state, e.error);
    }
    auto info = open_directory_path(std::string(root_path) + "/info", true, operation);
    if (!info.value()) {
        const auto& e = *info.unavailable_detail();
        return Result::unavailable(e.state, e.error);
    }
    return Result::available({std::move(files).take_value(), std::move(info).take_value()});
}

Observation<TrashDirectories> open_trash_directories(int source_parent_descriptor,
                                                      const struct stat& source_parent,
                                                      const char* operation) {
    using Result = Observation<TrashDirectories>;
    const auto home = native_home_address();
    if (!home.value()) {
        const auto& e = *home.unavailable_detail();
        return Result::unavailable(e.state, e.error);
    }
    const auto home_path = home.value()->posix_bytes();
    if (!home_path || home_path->empty() || home_path->front() != '/')
        return Result::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::UnsupportedQuery, operation));

    auto home_directory = open_directory_path(*home_path, false, operation);
    if (!home_directory.value()) {
        const auto& e = *home_directory.unavailable_detail();
        return Result::unavailable(e.state, e.error);
    }
    struct stat home_stat{};
    if (fstat(home_directory.value()->get(), &home_stat) != 0)
        return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, operation});
    const auto source_device = source_parent.st_dev;
    const bool home_matches = home_stat.st_dev == source_device;
    std::optional<std::string> candidate;
#if defined(__APPLE__)
    if (home_matches) candidate = *home_path + "/.Trash";
#else
    const char* configured = std::getenv("XDG_DATA_HOME");
    if (configured && configured[0] == '/') {
        auto configured_directory = open_directory_path(configured, false, operation);
        if (configured_directory.value()) {
            struct stat configured_stat{};
            if (fstat(configured_directory.value()->get(), &configured_stat) != 0)
                return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, operation});
            if (configured_stat.st_dev == source_device) candidate = std::string(configured) + "/Trash";
            else if (!home_matches)
                candidate = std::nullopt;
        } else if (configured_directory.state() != ObservationState::Gone && !home_matches) {
            const auto& e = *configured_directory.unavailable_detail();
            return Result::unavailable(e.state, e.error);
        }
    }
    if (!candidate && home_matches) candidate = *home_path + "/.local/share/Trash";
#endif
    if (candidate) return open_trash_root(*candidate, source_device, operation);

    const auto mount_root = mount_root_path(source_parent_descriptor, source_device, operation);
    if (!mount_root.value()) {
        const auto& e = *mount_root.unavailable_detail();
        return Result::unavailable(e.state, e.error);
    }
#if defined(__APPLE__)
    const auto mount_trash = *mount_root.value() + "/.Trashes/" + std::to_string(static_cast<unsigned long long>(geteuid()));
#else
    const auto mount_trash = *mount_root.value() + "/.Trash-" + std::to_string(static_cast<unsigned long long>(geteuid()));
#endif
    return open_trash_root(mount_trash, source_device, operation);
}

std::string percent_encode_path(std::string_view path) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(path.size() + 7);
    constexpr auto unreserved = [](unsigned char byte) {
        return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
               (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == '.' || byte == '~' || byte == '/';
    };
    for (const auto byte : path) {
        const auto value = static_cast<unsigned char>(byte);
        if (unreserved(value)) result.push_back(static_cast<char>(value));
        else {
            result.push_back('%');
            result.push_back(hex[value >> 4]);
            result.push_back(hex[value & 0x0f]);
        }
    }
    return result;
}

std::string deletion_date() {
    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm local{};
#if defined(_WIN32)
    localtime_s(&local, &now);
#else
    localtime_r(&now, &local);
#endif
    std::ostringstream value;
    value << std::setfill('0') << std::setw(4) << local.tm_year + 1900 << '-'
          << std::setw(2) << local.tm_mon + 1 << '-' << std::setw(2) << local.tm_mday << 'T'
          << std::setw(2) << local.tm_hour << ':' << std::setw(2) << local.tm_min << ':' << std::setw(2) << local.tm_sec;
    return value.str();
}

int rename_noreplace(int source_parent, const char* source, int destination_parent, const char* destination) {
#if defined(__linux__) && defined(SYS_renameat2)
    return static_cast<int>(syscall(SYS_renameat2, source_parent, source, destination_parent, destination, 1U));
#elif defined(__APPLE__)
    return renameatx_np(source_parent, source, destination_parent, destination, RENAME_EXCL);
#else
    errno = ENOTSUP;
    return -1;
#endif
}

struct PosixPublicationContext final {
    PosixPublicationContext(OwnedDescriptor retained_parent, NativeName retained_name, bool anonymous_staging = false)
        : parent(std::move(retained_parent)), name(std::move(retained_name)), anonymous(anonymous_staging) {}
    OwnedDescriptor parent;
    NativeName name; // recovery hint only when anonymous; never resolved as a source
    bool anonymous = false;
};

class PosixOpenedEntry final : public OpenedEntry {
public:
    PosixOpenedEntry(OwnedDescriptor descriptor, AdapterScope scope, bool layout_access = false,
                     bool content_access = false, bool content_write_access = false,
                     std::unique_ptr<PosixPublicationContext> publication = {}, bool directory_metadata_target = false)
        : descriptor_(std::move(descriptor)), scope_(std::move(scope)), layout_access_(layout_access),
          content_access_(content_access), content_write_access_(content_write_access),
          publication_(std::move(publication)), directory_metadata_target_(directory_metadata_target) {}
#if defined(__linux__)
    Observation<LinuxFullClassState> full_security_class_state()const {
        using R=Observation<LinuxFullClassState>;
        const auto before=inspect_basic();if(!before.value()){const auto&e=*before.unavailable_detail();return R::unavailable(e.state,e.error);}
        const auto proxy=attribute_proxy();if(!proxy.value()){const auto&e=*proxy.unavailable_detail();return R::unavailable(e.state,e.error);}
        OwnedDescriptor readview(open(proxy.value()->c_str(),O_RDONLY|O_NONBLOCK|O_NOCTTY|O_CLOEXEC));
        if(readview.get()<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_class_readview"});
        const auto opened=statx_metadata(readview.get(),"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,scope_);
        if(!opened.value()||!linux_full_basic(*before.value(),*opened.value(),false))
            return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,"metadata_replay.full_class_identity"));
        struct statfs fs{};LinuxFullClassState state;
        if(fstatfs(readview.get(),&fs)||ioctl(readview.get(),FS_IOC_GETFLAGS,&state.inode_flags)||ioctl(readview.get(),FS_IOC_FSGETXATTR,&state.storage))
            return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_class_queries"});
        const auto provider=detail::linux_ordinary_metadata_provider(fs.f_type);
        const bool directory=before.value()->kind.value()&&*before.value()->kind.value()==ObjectKind::Directory;
        if(provider!=detail::LinuxOrdinaryMetadataProvider::Ext4||
           !detail::linux_ordinary_inode_flags(provider,static_cast<std::uint32_t>(state.inode_flags),directory)||
           !detail::linux_ordinary_storage_policy(provider,state.storage))
            return R::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::ProviderReviewRequired,"metadata_replay.full_native_policy_unimplemented"));
        std::memcpy(state.filesystem.data(),&fs.f_fsid,sizeof(fs.f_fsid));
        const auto after=inspect_basic();if(!after.value()||!linux_full_basic(*before.value(),*after.value(),false))
            return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,"metadata_replay.full_class_changed"));
        const auto closed=linux_full_close(readview,"metadata_replay.full_class_close");if(!closed.value()){const auto&e=*closed.unavailable_detail();return R::unavailable(e.state,e.error);}
        return R::available(state);
    }
    // Queries bounded metadata values only; never reads main content or calls
    // capture_metadata_replay recursively. Native environment/provider checks
    // precede the complete namespace/ACL query and are repeated at the bookend.
    Observation<MetadataReplaySnapshot> full_security_values(const MetadataReplayPolicy& policy)const {
        using R=Observation<MetadataReplaySnapshot>;
        const auto qualified=qualify_metadata_replay(policy);
        if(!qualified.value()){const auto&e=*qualified.unavailable_detail();return R::unavailable(e.state,e.error);}
        if(!*qualified.value()||policy.scope!=RegularMetadataScope::CompleteMetadataV1)
            return R::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::ProviderReviewRequired,"metadata_replay.full_scope_required"));
        MetadataReplaySnapshot result;result.policy=policy;
        const auto before=inspect_basic();if(!before.value()){const auto&e=*before.unavailable_detail();return R::unavailable(e.state,e.error);}result.basic=*before.value();
        if(!result.basic.identity.value()||!result.basic.kind.value()||!result.basic.posix_uid.value()||!result.basic.posix_gid.value()||
           !result.basic.posix_permissions.value()||!result.basic.link_count.value()||!result.basic.accessed.value()||!result.basic.modified.value()||!result.basic.changed.value()||
           (*result.basic.kind.value()==ObjectKind::RegularFile&&!result.basic.logical_size.value()))
            return R::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::ProviderReviewRequired,"metadata_replay.full_basic_coverage"));
        const auto catalog=inspect_attributes(policy.limits);
        if(!catalog.value()){const auto&e=*catalog.unavailable_detail();return R::unavailable(e.state,e.error);}
        if(catalog.value()->coverage!=AttributeCoverage::CredentialsVisiblePosix||!linux_full_owner(catalog.value()->owner,result.basic.identity)||catalog.value()->attributes.size()>policy.limits.max_records)
            return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,"metadata_replay.full_catalog_coverage"));
        result.attribute_coverage=catalog.value()->coverage;std::set<std::string> names;std::size_t total=0;
        for(const auto& item:catalog.value()->attributes){const auto*n=item.identifier.posix_bytes();
            if(!n||!names.insert(*n).second)return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,"metadata_replay.full_attribute_identifier"));
            const bool security=n->starts_with("security.");
            const bool known_security=*n=="security.capability"||*n=="security.selinux"||*n=="security.SMACK64"||*n=="security.SMACK64EXEC"||
                *n=="security.SMACK64MMAP"||*n=="security.SMACK64TRANSMUTE"||*n=="security.SMACK64IPIN"||*n=="security.SMACK64IPOUT";
            if((security&&!known_security)||(!security&&!n->starts_with("trusted.")&&!n->starts_with("user.")&&*n!="system.posix_acl_access"&&*n!="system.posix_acl_default"))
                return R::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::ProviderReviewRequired,"metadata_replay.full_attribute_class_unimplemented"));
            if((security||n->starts_with("trusted."))&&!policy.allow_privilege_metadata)
                return R::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::ProviderReviewRequired,"metadata_replay.full_privilege_optin_required"));
            const auto value=read_attribute(item.identifier,policy.limits);
            if(!value.value()){const auto&e=*value.unavailable_detail();return R::unavailable(e.state,e.error);}
            if(!linux_full_owner(value.value()->owner,result.basic.identity)||!item.value_size.value()||*item.value_size.value()!=value.value()->bytes.size())
                return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,"metadata_replay.full_attribute_changed"));
            if(value.value()->bytes.size()>policy.limits.max_native_bytes-total)
                return R::unavailable(ObservationState::Unknown,adapter_error(AdapterError::InventoryLimit,"metadata_replay.full_attribute_budget"));
            if(*n=="security.capability"){
                const auto& bytes=value.value()->bytes;std::uint32_t magic=0;
                if(bytes.size()>=4)for(unsigned i=0;i<4;++i)magic|=std::to_integer<std::uint32_t>(bytes[i])<<(8*i);
                const auto revision=magic&VFS_CAP_REVISION_MASK;
                const bool shape=(revision==VFS_CAP_REVISION_1&&bytes.size()==12)||(revision==VFS_CAP_REVISION_2&&bytes.size()==20)||(revision==VFS_CAP_REVISION_3&&bytes.size()==24);
                if(!shape||(magic&~(VFS_CAP_REVISION_MASK|VFS_CAP_FLAGS_EFFECTIVE)))return R::unavailable(ObservationState::Unsupported,
                    adapter_error(AdapterError::ProviderReviewRequired,"metadata_replay.full_capability_encoding_unimplemented"));
            }
            total+=value.value()->bytes.size();result.attributes.push_back(*value.value());
        }
        const bool directory=result.basic.kind.value()&&*result.basic.kind.value()==ObjectKind::Directory;
        const std::array parts{SecurityPart::LinuxAccessAcl,SecurityPart::LinuxDefaultAcl};
        for(unsigned i=0;i<(directory?2U:1U);++i){const auto value=read_security(parts[i],policy.limits);
            if(!value.value()){const auto&e=*value.unavailable_detail();return R::unavailable(e.state,e.error);}
            const auto& s=*value.value();if(s.encoding!=SecurityEncoding::LinuxPosixAclXattrV2||s.presence==SecurityPresence::Unknown||s.part!=parts[i]||s.native_query_mask||!linux_full_owner(s.owner,result.basic.identity))
                return R::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::ProviderReviewRequired,"metadata_replay.full_acl_coverage"));
            if(s.presence==SecurityPresence::Present){auto valid=detail::validate_linux_acl(s.bytes,policy.limits);if(!valid.value()){const auto&e=*valid.unavailable_detail();return R::unavailable(e.state,e.error);}}
            if(s.bytes.size()>policy.limits.max_native_bytes-total)return R::unavailable(ObservationState::Unknown,adapter_error(AdapterError::InventoryLimit,"metadata_replay.full_acl_budget"));
            total+=s.bytes.size();result.security.push_back(s);
        }
        const auto after=inspect_basic();if(!after.value()){const auto&e=*after.unavailable_detail();return R::unavailable(e.state,e.error);}
        if(!linux_full_basic(result.basic,*after.value(),false))return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,"metadata_replay.full_inventory_changed"));
        const auto environment=linux_full_environment();if(!environment.value()){const auto&e=*environment.unavailable_detail();return R::unavailable(e.state,e.error);}
        return R::available(std::move(result));
    }
    Observation<std::shared_ptr<const MetadataSecurityCoverageEvidence>> issue_linux_security_coverage(
        const MetadataReplaySnapshot&,std::shared_ptr<const void> lease={})const;
    Observation<std::shared_ptr<const MetadataSecurityCoverageEvidence>> issue_metadata_security_coverage(
        const MetadataReplaySnapshot& snapshot)const override {return issue_linux_security_coverage(snapshot);}
    Observation<bool> preflight_metadata_security_coverage(const MetadataReplaySnapshot&)override;
    Observation<bool> verify_metadata_security_coverage(const MetadataReplaySnapshot&)const override;
#endif

    Observation<bool> qualify_progressive_metadata_target(const NativeMetadataProof& proof)const {
        using R=Observation<bool>;
        if(auto e=proof.cleanup_error())return R::unavailable(e->state,{e->domain,e->code,e->operation});
        if(proof.io_finished()||!content_write_access_||finish_started_||(!publication_&&!directory_metadata_target_)||
           !proof.snapshot().channels.empty()||!proof.snapshot().policy.valid())
            return R::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::ProviderReviewRequired,"metadata_stream.private_open_target_required"));
        auto qualified=qualify_metadata_replay(proof.snapshot().policy);if(!qualified.value()||!*qualified.value())return qualified;
        auto target=inspect_basic();if(!target.value()){const auto&e=*target.unavailable_detail();return R::unavailable(e.state,e.error);}
        const auto& expected=proof.snapshot().basic;
        if(!expected.kind.value()||!target.value()->kind.value()||*expected.kind.value()!=*target.value()->kind.value()||
           (*expected.kind.value()==ObjectKind::RegularFile&&(!expected.logical_size.value()||!target.value()->logical_size.value()||
            *expected.logical_size.value()!=*target.value()->logical_size.value())))
            return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,"metadata_stream.target_shape"));
        return R::available(true);
    }
    void finish_capture_reads()noexcept {
        if(capture_close_started_){if(capture_close_error_)detail::record_metadata_capture_close(*capture_close_error_);return;}
        capture_close_started_=true;
        if(content_write_access_){capture_close_error_=MetadataCaptureCleanupError{ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"metadata_capture.writer_not_read_owner"};}
        else {finish_started_=true;content_access_=false;layout_access_=false;const int fd=descriptor_.release();
            // Consume once; POSIX EINTR/ambiguous failures are never retried.
            if(fd>=0&&close(fd)!=0)capture_close_error_=MetadataCaptureCleanupError{ObservationState::Failed,ErrorDomain::Posix,errno,"metadata_capture.source_close"};
        }
        if(capture_close_error_)detail::record_metadata_capture_close(*capture_close_error_);
#if defined(__linux__)
        target_read_clone_lease_.reset();
        target_read_clone_state_.reset();
        target_read_budget_.reset();
#endif
    }
    Observation<std::shared_ptr<const OpenedEntry>> open_progressive_metadata_source()const {
        using R=Observation<std::shared_ptr<const OpenedEntry>>;
        const auto basic=inspect_basic();if(!basic.value()){const auto&e=*basic.unavailable_detail();return R::unavailable(e.state,e.error);}
        const bool file=basic.value()->kind.value()&&*basic.value()->kind.value()==ObjectKind::RegularFile;
        const int flags=fcntl(descriptor_.get(),F_GETFL);
        if(flags<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_capture.source_flags"});
        if((flags&O_ACCMODE)!=O_RDONLY||content_write_access_||(file&&!content_access_))
            return R::unavailable(ObservationState::Denied,adapter_error(AdapterError::InvalidAccess,"metadata_capture.readonly_content_source_required"));
#if defined(__linux__)
        std::shared_ptr<detail::NativeTargetReadBudget> child_budget;
        if(target_read_budget_){
            auto lease=detail::NativeTargetReadBudget::acquire_child(target_read_budget_,1,sizeof(PosixOpenedEntry));
            if(!lease.value())return R::unavailable(lease.unavailable_detail()->state,lease.unavailable_detail()->error);
            child_budget=std::move(lease).take_value();
        }
        auto fresh=open_readonly_capture_description();
        if(!fresh.value()){const auto&e=*fresh.unavailable_detail();return R::unavailable(e.state,e.error);}
        OwnedDescriptor fd(std::move(fresh).take_value());
        auto clone=std::make_shared<PosixOpenedEntry>(std::move(fd),scope_,false,file);
        clone->target_read_budget_=std::move(child_budget);
        clone->target_read_clone_state_=target_read_clone_state_;
        if(clone->target_read_clone_state_)
            clone->target_read_clone_lease_=std::make_shared<NativeTargetReadCloneLease>(clone->target_read_clone_state_);
        return R::available(std::move(clone));
#else
        OwnedDescriptor fd(fcntl(descriptor_.get(),F_DUPFD_CLOEXEC,0));
        if(fd.get()<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_capture.source_dup"});
        return R::available(std::make_shared<PosixOpenedEntry>(std::move(fd),scope_,false,file));
#endif
    }
    Observation<ContentRead> read_content(ContentReadLimits limits = {}, std::uint64_t offset = 0,
                                          std::stop_token stop = {}) const override {
        using Result = Observation<ContentRead>;
        if (!limits.valid())
            return Result::unavailable(ObservationState::Failed,
                                       adapter_error(AdapterError::InvalidLimit, "content.limits"));
        if (stop.stop_requested())
            return Result::unavailable(ObservationState::Unknown,
                                       adapter_error(AdapterError::InterruptedRead, "content.cancelled"));
        if (!content_access_)
            return Result::unavailable(ObservationState::Denied,
                                       adapter_error(AdapterError::InvalidAccess, "content.access_not_requested"));
        const auto before = inspect_basic();
        if (!before.value()) {
            const auto &e = *before.unavailable_detail();
            return Result::unavailable(e.state, e.error);
        }
        if (!before.value()->kind.value() || *before.value()->kind.value() != ObjectKind::RegularFile)
            return Result::unavailable(ObservationState::Unsupported,
                                       adapter_error(AdapterError::NotApplicable, "content.object_kind"));
        if (!before.value()->logical_size.value()) {
            const auto &e = *before.value()->logical_size.unavailable_detail();
            return Result::unavailable(e.state, e.error);
        }
        const auto size = *before.value()->logical_size.value();
        if (offset > size)
            return Result::unavailable(ObservationState::Changed,
                                       adapter_error(AdapterError::MetadataChanged, "content.offset"));
        if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()))
            return Result::unavailable(ObservationState::Unsupported,
                                       adapter_error(AdapterError::UnsupportedQuery, "content.offset_range"));
        const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(limits.max_bytes, size - offset));
        std::vector<std::byte> bytes(count);
        const auto read = pread(descriptor_.get(), bytes.data(), bytes.size(), static_cast<off_t>(offset));
        if (read < 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "content.pread"});
        bytes.resize(static_cast<std::size_t>(read));
        if (stop.stop_requested())
            return Result::unavailable(ObservationState::Unknown,
                                       adapter_error(AdapterError::InterruptedRead, "content.cancelled"));
        const auto after = inspect_basic();
        if (!after.value()) {
            const auto &e = *after.unavailable_detail();
            return Result::unavailable(e.state, e.error);
        }
        if (!after.value()->identity.value() || !before.value()->identity.value() ||
            compare_identity(*before.value()->identity.value(), *after.value()->identity.value()) != IdentityComparison::Same ||
            !after.value()->logical_size.value() || *after.value()->logical_size.value() != size)
            return Result::unavailable(ObservationState::Changed,
                                       adapter_error(AdapterError::MetadataChanged, "content.identity"));
        return Result::available({std::move(bytes), offset + static_cast<std::uint64_t>(read) >= size});
    }
    Observation<std::size_t> write_content(std::uint64_t offset, std::span<const std::byte> bytes,
                                            ContentWriteLimits limits = {}, std::stop_token stop = {}) override {
        using Result = Observation<std::size_t>;
        if (!limits.valid() || bytes.size() > limits.max_bytes)
            return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidLimit, "content.write_limits"));
        if (stop.stop_requested())
            return Result::unavailable(ObservationState::Unknown, adapter_error(AdapterError::InterruptedRead, "content.write_cancelled"));
        if (!content_write_access_)
            return Result::unavailable(ObservationState::Denied, adapter_error(AdapterError::InvalidAccess, "content.write_access_not_requested"));
        const auto before = inspect_basic();
        if (!before.value()) { const auto& e = *before.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (!before.value()->kind.value() || *before.value()->kind.value() != ObjectKind::RegularFile)
            return Result::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::NotApplicable, "content.write_object_kind"));
        const auto maximum = static_cast<std::uint64_t>(std::numeric_limits<off_t>::max());
        if (offset > maximum || bytes.size() > maximum - offset)
            return Result::unavailable(ObservationState::Unknown, adapter_error(AdapterError::InvalidLimit, "content.write_offset"));
        const auto written = pwrite(descriptor_.get(), bytes.data(), bytes.size(), static_cast<off_t>(offset));
        if (written < 0) return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "content.pwrite"});
        if (stop.stop_requested())
            return Result::unavailable(ObservationState::Unknown, adapter_error(AdapterError::InterruptedRead, "content.write_cancelled"));
        const auto after = inspect_basic();
        if (!after.value()) { const auto& e = *after.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (!after.value()->identity.value() || !before.value()->identity.value() ||
            compare_identity(*before.value()->identity.value(), *after.value()->identity.value()) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed, adapter_error(AdapterError::MetadataChanged, "content.write_identity"));
        return Result::available(static_cast<std::size_t>(written));
    }
    Observation<bool> flush_content() override {
        if (!content_write_access_)
            return Observation<bool>::unavailable(ObservationState::Denied, adapter_error(AdapterError::InvalidAccess, "content.flush_access"));
        if (fsync(descriptor_.get()) != 0)
            return Observation<bool>::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "content.fsync"});
#if defined(__APPLE__)
        if (fcntl(descriptor_.get(),F_FULLFSYNC) != 0)
            return Observation<bool>::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "content.F_FULLFSYNC"});
#endif
        return Observation<bool>::available(true);
    }
    Observation<bool> finish_content_writes() override {
        using Result=Observation<bool>;
        if (finish_result_) return *finish_result_;
        if (finish_started_) return Result::unavailable(ObservationState::Failed,
            adapter_error(AdapterError::InvalidAccess,"content.finish_result_unrecorded"));
        if (!content_write_access_) return Result::available(true);
        finish_started_=true;
        content_write_access_=false;
        content_access_=false;
        layout_access_=false;
        const int writer=descriptor_.release();
        // No duplicate of this open-file description survives here. Always
        // attempt its one close, even if fsync fails. Capture errno before any
        // further call, and never retry close on EINTR or an ambiguous error.
        const int flush_error=fsync(writer)==0 ? 0 : errno;
#if defined(__APPLE__)
        const int fullsync_error=flush_error==0 && fcntl(writer,F_FULLFSYNC)!=0 ? errno : 0;
#endif
        const int close_error=close(writer)==0 ? 0 : errno;
        if (flush_error) finish_result_=Result::unavailable(errno_state(flush_error),
            {ErrorDomain::Posix,flush_error,"content.finish_fsync"});
#if defined(__APPLE__)
        else if (fullsync_error) finish_result_=Result::unavailable(errno_state(fullsync_error),
            {ErrorDomain::Posix,fullsync_error,"content.finish_F_FULLFSYNC"});
#endif
        else if (close_error) finish_result_=Result::unavailable(
            close_error==EINTR ? ObservationState::Unknown : errno_state(close_error),
            {ErrorDomain::Posix,close_error,"content.finish_close"});
        else finish_result_=Result::available(true);
        return *finish_result_;
    }
    Observation<bool> apply_current_caller_ownership() override {
        using Result = Observation<bool>;
        if (!content_write_access_ || (!publication_&&!directory_metadata_target_))
            return Result::unavailable(ObservationState::Denied,
                adapter_error(AdapterError::InvalidAccess, "regular_metadata.ownership_staging_only"));
        const auto ownership=qualify_ownership_semantics();
        if (!ownership.value()) {const auto& e=*ownership.unavailable_detail();return Result::unavailable(e.state,e.error);}
        struct stat native{};
        if (fstat(descriptor_.get(), &native) != 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "regular_metadata.ownership_before"});
        if ((!S_ISREG(native.st_mode)&&!(directory_metadata_target_&&S_ISDIR(native.st_mode))) ||
            (directory_metadata_target_?native.st_nlink<1:!metadata_link_count_qualified(native.st_nlink)))
            return Result::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::ProviderReviewRequired, "regular_metadata.ownership_kind_links"));
        const auto uid = geteuid();
        const auto gid = getegid();
        // Account explicitly for setgid-parent inheritance. Only staging is
        // writable here, and the source's uid/gid are never replayed.
        if ((native.st_uid != uid || native.st_gid != gid) && fchown(descriptor_.get(), uid, gid) != 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "regular_metadata.fchown_caller"});
        if (fstat(descriptor_.get(), &native) != 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "regular_metadata.ownership_after"});
        if (native.st_uid != uid || native.st_gid != gid)
            return Result::unavailable(ObservationState::Changed,
                adapter_error(AdapterError::MetadataChanged, "regular_metadata.ownership_verification"));
        return Result::available(true);
    }
    Observation<bool> qualify_ordinary_regular_metadata() const override {
        using Result = Observation<bool>;
        const auto refuse = [](const char* operation) {
            return Result::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::ProviderReviewRequired, operation));
        };
        const auto ownership=qualify_ownership_semantics();
        if (!ownership.value()) {const auto& e=*ownership.unavailable_detail();return Result::unavailable(e.state,e.error);}
        auto before = inspect_basic();
        if (!before.value()) return refuse("regular_metadata.basic_coverage");
        const auto& basic = *before.value();
        if (!basic.kind.value() || *basic.kind.value() != ObjectKind::RegularFile ||
            !basic.posix_permissions.value() || (*basic.posix_permissions.value() & ~0777U) != 0 ||
            !basic.link_count.value() || !metadata_link_count_qualified(*basic.link_count.value()))
            return refuse("regular_metadata.kind_mode_links");
        const auto storage = inspect_storage();
        if (!storage.value() || !storage.value()->flags.value() || storage.value()->flags.value()->value != 0)
            return refuse("regular_metadata.storage_flags");
        OwnedDescriptor readable(-1);
#if defined(__linux__)
        struct statfs filesystem{};
        if (fstatfs(descriptor_.get(), &filesystem) != 0)
            return refuse("regular_metadata.unaudited_linux_filesystem");
        const auto provider=detail::linux_ordinary_metadata_provider(filesystem.f_type);
        if (provider==detail::LinuxOrdinaryMetadataProvider::Unknown)
            return refuse("regular_metadata.unaudited_linux_filesystem");
        // Acquire metadata-query read rights from the verified held-fd proxy,
        // never the original basename, and without privilege/elevation.
        const auto proxy = attribute_proxy();
        if (!proxy.value()) return refuse("regular_metadata.held_descriptor_proxy");
        readable = OwnedDescriptor(open(proxy.value()->c_str(), O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC));
        if (readable.get() < 0) return refuse("regular_metadata.held_descriptor_read_access");
        struct stat original{}, reopened{};
        if (fstat(descriptor_.get(), &original) != 0 || fstat(readable.get(), &reopened) != 0 ||
            original.st_dev != reopened.st_dev || original.st_ino != reopened.st_ino || !S_ISREG(reopened.st_mode))
            return refuse("regular_metadata.held_handle_identity");
        int flags = 0;
        // Provider-specific representation bits are distinct from policy.
        if (ioctl(readable.get(), FS_IOC_GETFLAGS, &flags) != 0 ||
            !detail::linux_ordinary_inode_flags(provider,static_cast<std::uint32_t>(flags)))
            return refuse("regular_metadata.inode_flags");
        struct fsxattr extended{};
        if (ioctl(readable.get(), FS_IOC_FSGETXATTR, &extended) != 0 ||
            !detail::linux_ordinary_storage_policy(provider,extended))
            return refuse("regular_metadata.project_storage_policy");
        const auto names = flistxattr(readable.get(), nullptr, 0);
#else
        struct statfs filesystem{};
        if (fstatfs(descriptor_.get(), &filesystem) != 0 ||
            (std::strcmp(filesystem.f_fstypename, "apfs") != 0 && std::strcmp(filesystem.f_fstypename, "hfs") != 0))
            return refuse("regular_metadata.unaudited_darwin_filesystem");
        readable = OwnedDescriptor(fcntl(descriptor_.get(), F_DUPFD_CLOEXEC, 0));
        if (readable.get() < 0) return refuse("regular_metadata.held_descriptor");
        const auto names = flistxattr(readable.get(), nullptr, 0, XATTR_SHOWCOMPRESSION);
#endif
        if (names != 0) return refuse("regular_metadata.xattrs_labels_capabilities");
#if defined(__linux__)
        // Required known security names are probed even if omitted from the
        // caller-visible list. Denied/unsupported replies are not absence.
        // Arbitrary trusted.* remains unknown under the versioned subset.
        for (const auto* name : {"system.posix_acl_access", "system.posix_acl_default",
            "security.capability", "security.selinux", "security.SMACK64", "security.SMACK64EXEC",
            "security.SMACK64MMAP", "security.SMACK64TRANSMUTE", "security.SMACK64IPIN",
            "security.SMACK64IPOUT", "security.ima", "security.evm"}) {
            errno = 0;
            if (fgetxattr(readable.get(), name, nullptr, 0) >= 0 || errno != ENODATA)
                return refuse("regular_metadata.required_security_name");
        }
#else
        const auto acl = read_security(SecurityPart::DarwinExtendedAcl);
        if (!acl.value() || acl.value()->presence != SecurityPresence::Absent)
            return refuse("regular_metadata.required_security_name");
#endif
        PosixOpenedEntry query(std::move(readable), scope_, true);
        const auto layout = query.inspect_data_layout();
        if (!layout.value() || !basic.logical_size.value() ||
            layout.value()->logical_size != *basic.logical_size.value())
            return refuse("regular_metadata.layout_coverage");
        const auto& ranges = layout.value()->ranges;
        const auto size = *basic.logical_size.value();
        if ((size == 0 && !ranges.empty()) || (size != 0 &&
            (ranges.size() != 1 || ranges.front().offset != 0 || ranges.front().length != size)))
            return refuse("regular_metadata.sparse_layout");
        const auto after = inspect_basic();
        if (!after.value()) return refuse("regular_metadata.final_basic_coverage");
        auto unchanged = detail::data_layout_metadata_unchanged(basic, *after.value());
        if (!unchanged.value() || !*unchanged.value()) return refuse("regular_metadata.changed_during_qualification");
        return Result::available(true);
    }
    Observation<std::unique_ptr<OpenedEntry>> open_directory_metadata_target(const MetadataReplayPolicy& policy) const override {
        using Result=Observation<std::unique_ptr<OpenedEntry>>;
        if(!policy.valid())return Result::unavailable(ObservationState::Failed,adapter_error(AdapterError::InvalidIdentifier,"metadata_replay.directory_policy"));
        const auto ownership=qualify_ownership_semantics();
        if(!ownership.value()){const auto& e=*ownership.unavailable_detail();return Result::unavailable(e.state,e.error);}
        const auto before=inspect_basic();
        if(!before.value()){const auto& e=*before.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if(!before.value()->kind.value()||*before.value()->kind.value()!=ObjectKind::Directory||!before.value()->identity.value())
            return Result::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::NotApplicable,"metadata_replay.directory_kind"));
        // A fresh open description, not dup(): finalization fully closes this
        // operation's writer while the caller's held directory stays alive.
        OwnedDescriptor opened(openat(descriptor_.get(),".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        if(opened.get()<0)return Result::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.directory_openat"});
        auto writer=std::make_unique<PosixOpenedEntry>(std::move(opened),scope_,false,false,true,nullptr,true);
        const auto after=writer->inspect_basic();
        if(!after.value()||!after.value()->identity.value()||
           compare_identity(*before.value()->identity.value(),*after.value()->identity.value())!=IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,"metadata_replay.directory_writer_identity"));
        return Result::available(std::move(writer));
    }
    Observation<bool> qualify_metadata_replay(const MetadataReplayPolicy& policy) const override {
        using Result = Observation<bool>;
        const auto refuse = [](const char* operation) {
            return Result::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::ProviderReviewRequired, operation));
        };
        if (!policy.valid()) return refuse("metadata_replay.policy");
        const auto ownership=qualify_ownership_semantics();
        if (!ownership.value()) {const auto& e=*ownership.unavailable_detail();return Result::unavailable(e.state,e.error);}
#if defined(__linux__)
        if (policy.scope == RegularMetadataScope::CompleteMetadataV1) {
            // trusted.* enumeration needs effective CAP_SYS_ADMIN in the
            // initial user namespace, not merely uid 0 in a container.
            __user_cap_header_struct header{};header.version=_LINUX_CAPABILITY_VERSION_3;
            __user_cap_data_struct capabilities[2]{};
            if (syscall(SYS_capget,&header,capabilities)!=0)
                return Result::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.capget"});
            if ((capabilities[CAP_SYS_ADMIN/32].effective & (1U<<(CAP_SYS_ADMIN%32)))==0)
                return refuse("metadata_replay.complete_requires_initial_sys_admin");
            OwnedDescriptor mapping(open("/proc/self/uid_map",O_RDONLY|O_CLOEXEC));
            if (mapping.get()<0) return Result::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.uid_map"});
            struct statfs mapfs{};
            if (fstatfs(mapping.get(),&mapfs)!=0 || static_cast<unsigned long>(mapfs.f_type)!=static_cast<unsigned long>(PROC_SUPER_MAGIC))
                return refuse("metadata_replay.initial_user_namespace_unqualified");
            char bytes[128]{};const auto count=read(mapping.get(),bytes,sizeof(bytes)-1);
            if (count<0) return Result::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.uid_map_read"});
            std::istringstream parsed(std::string(bytes,static_cast<std::size_t>(count)));
            std::uint64_t inside=1,outside=1,length=0;std::string trailing;
            if (!(parsed>>inside>>outside>>length) || inside!=0 || outside!=0 || length!=4294967295ULL || (parsed>>trailing))
                return refuse("metadata_replay.initial_user_namespace_unqualified");
            const auto closed=linux_full_close(mapping,"metadata_replay.full_uid_map_close");if(!closed.value())return closed;
            const auto environment=linux_full_environment();if(!environment.value()){const auto&e=*environment.unavailable_detail();return Result::unavailable(e.state,e.error);}
        }
#endif
        auto before = inspect_basic();
        if (!before.value()) return refuse("regular_metadata.basic_coverage");
        const auto& basic = *before.value();
        const bool directory=basic.kind.value()&&*basic.kind.value()==ObjectKind::Directory;
        if (!basic.kind.value() || (!directory&&*basic.kind.value() != ObjectKind::RegularFile) ||
            !basic.posix_permissions.value() ||
            !basic.link_count.value() || (directory?*basic.link_count.value()<1:!metadata_link_count_qualified(*basic.link_count.value())))
            return refuse("regular_metadata.kind_mode_links");
#if defined(__linux__)
        if (policy.scope==RegularMetadataScope::CompleteMetadataV1 && basic.created.value())
            return refuse("metadata_replay.ext4_birthtime_setter_unavailable");
#endif
        const auto storage = inspect_storage();
        if (!storage.value() || !storage.value()->flags.value() || storage.value()->flags.value()->value != 0)
            return refuse("regular_metadata.storage_flags");
        OwnedDescriptor readable(-1);
#if defined(__linux__)
        struct statfs filesystem{};
        if (fstatfs(descriptor_.get(), &filesystem) != 0)
            return refuse("regular_metadata.unaudited_linux_filesystem");
        const auto provider=detail::linux_ordinary_metadata_provider(filesystem.f_type);
        if (provider==detail::LinuxOrdinaryMetadataProvider::Unknown ||
            (policy.scope!=RegularMetadataScope::OrdinaryCallerVisibleV1 &&
             provider!=detail::LinuxOrdinaryMetadataProvider::Ext4))
            return refuse("regular_metadata.unaudited_linux_filesystem");
        // Acquire metadata-query read rights from the verified held-fd proxy,
        // never the original basename, and without privilege/elevation.
        const auto proxy = attribute_proxy();
        if (!proxy.value()) return refuse("regular_metadata.held_descriptor_proxy");
        readable = OwnedDescriptor(open(proxy.value()->c_str(), O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC));
        if (readable.get() < 0) return refuse("regular_metadata.held_descriptor_read_access");
        struct stat original{}, reopened{};
        if (fstat(descriptor_.get(), &original) != 0 || fstat(readable.get(), &reopened) != 0 ||
            original.st_dev != reopened.st_dev || original.st_ino != reopened.st_ino || (directory?!S_ISDIR(reopened.st_mode):!S_ISREG(reopened.st_mode)))
            return refuse("regular_metadata.held_handle_identity");
        int flags = 0;
        // Provider-specific representation bits are distinct from policy.
        if (ioctl(readable.get(), FS_IOC_GETFLAGS, &flags) != 0 ||
            !detail::linux_ordinary_inode_flags(provider,static_cast<std::uint32_t>(flags),directory))
            return refuse("regular_metadata.inode_flags");
        struct fsxattr extended{};
        if (ioctl(readable.get(), FS_IOC_FSGETXATTR, &extended) != 0 ||
            !detail::linux_ordinary_storage_policy(provider,extended))
            return refuse("regular_metadata.project_storage_policy");

#else
        struct statfs filesystem{};
        if (fstatfs(descriptor_.get(), &filesystem) != 0 ||
            (std::strcmp(filesystem.f_fstypename, "apfs") != 0 && std::strcmp(filesystem.f_fstypename, "hfs") != 0))
            return refuse("regular_metadata.unaudited_darwin_filesystem");
        readable = OwnedDescriptor(fcntl(descriptor_.get(), F_DUPFD_CLOEXEC, 0));
        if (readable.get() < 0) return refuse("regular_metadata.held_descriptor");

#endif
#if defined(__linux__)
        const auto catalog=inspect_attributes(policy.limits);
        if (!catalog.value()) {const auto& e=*catalog.unavailable_detail();return Result::unavailable(e.state,e.error);}
        for (const auto* security_name:{"security.capability","security.selinux","security.SMACK64","security.SMACK64EXEC",
            "security.SMACK64MMAP","security.SMACK64TRANSMUTE","security.SMACK64IPIN","security.SMACK64IPOUT","security.ima","security.evm"}) {
            const auto id=*NativeFeatureIdentifier::from_posix(security_name);
            const auto probe=read_attribute(id,policy.limits);
            if (!probe.value()) {
                const auto& e=*probe.unavailable_detail();
                if (e.error.domain==ErrorDomain::Posix && e.error.code==ENODATA) continue;
                return Result::unavailable(e.state,e.error);
            }
            if (std::none_of(catalog.value()->attributes.begin(),catalog.value()->attributes.end(),
                [&](const auto& attribute){return attribute.identifier==id;}))
                return refuse("metadata_replay.linux_unlisted_security_attribute");
        }
#endif
        if (!directory) {
        PosixOpenedEntry query(std::move(readable), scope_, true);
        const auto layout = query.inspect_data_layout();
        if (!layout.value() || !basic.logical_size.value() ||
            layout.value()->logical_size != *basic.logical_size.value())
            return refuse("regular_metadata.layout_coverage");
        const auto& ranges = layout.value()->ranges;
        const auto size = *basic.logical_size.value();
        if ((size == 0 && !ranges.empty()) || (size != 0 &&
            (ranges.size() != 1 || ranges.front().offset != 0 || ranges.front().length != size)))
            return refuse("regular_metadata.sparse_layout");
        }
        const auto after = inspect_basic();
        if (!after.value()) return refuse("regular_metadata.final_basic_coverage");
        if(directory) {
            const auto& current=*after.value();
            const auto same=[](const auto& a,const auto& b){return a.value()&&b.value()?*a.value()==*b.value():!a.value()&&!b.value()&&a.state()==b.state();};
            if(!current.identity.value()||!basic.identity.value()||
               compare_identity(*basic.identity.value(),*current.identity.value())!=IdentityComparison::Same||
               !current.kind.value()||*current.kind.value()!=ObjectKind::Directory||
               !same(basic.link_count,current.link_count)||!same(basic.modified,current.modified)||!same(basic.changed,current.changed)||
               !same(basic.posix_permissions,current.posix_permissions)||!same(basic.posix_uid,current.posix_uid)||
               !same(basic.posix_gid,current.posix_gid)||!same(basic.bsd_flags,current.bsd_flags))
                return Result::unavailable(ObservationState::Changed,
                    adapter_error(AdapterError::MetadataChanged,"metadata_replay.directory_changed_during_qualification"));
            return Result::available(true);
        }
        auto unchanged = detail::data_layout_metadata_unchanged(basic, *after.value());
        if (!unchanged.value() || !*unchanged.value()) return refuse("regular_metadata.changed_during_qualification");
        return Result::available(true);
    }
    Observation<bool> apply_portable_basic_metadata(const BasicMetadata& source) override {
        using Result = Observation<bool>;
        if (!content_write_access_)
            return Result::unavailable(ObservationState::Denied,
                adapter_error(AdapterError::InvalidAccess, "metadata.portable_basic.write_access"));
        const auto target = inspect_basic();
        if (!target.value()) {
            const auto& error = *target.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        if (!target.value()->kind.value() || *target.value()->kind.value() != ObjectKind::RegularFile)
            return Result::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::NotApplicable, "metadata.portable_basic.target_kind"));
        if (!source.kind.value() || *source.kind.value() != ObjectKind::RegularFile)
            return Result::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::NotApplicable, "metadata.portable_basic.source_kind"));
        if (!source.posix_permissions.value()) {
            const auto& error = *source.posix_permissions.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        if (!source.accessed.value()) {
            const auto& error = *source.accessed.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        if (!source.modified.value()) {
            const auto& error = *source.modified.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        if (fchmod(descriptor_.get(), static_cast<mode_t>(*source.posix_permissions.value() & 0777U)) != 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "metadata.portable_basic.fchmod"});
        const auto to_timespec = [](const FileTimestamp& value, timespec& result, const char* operation)
            -> std::optional<UnavailableObservation> {
            const auto seconds = value.seconds();
            if constexpr (std::numeric_limits<time_t>::is_signed) {
                if (seconds < static_cast<std::int64_t>(std::numeric_limits<time_t>::lowest()) ||
                    seconds > static_cast<std::int64_t>(std::numeric_limits<time_t>::max()))
                    return UnavailableObservation{ObservationState::Unsupported, adapter_error(AdapterError::UnsupportedQuery, operation)};
            } else if (seconds < 0 || static_cast<std::uint64_t>(seconds) > std::numeric_limits<time_t>::max()) {
                return UnavailableObservation{ObservationState::Unsupported, adapter_error(AdapterError::UnsupportedQuery, operation)};
            }
            result.tv_sec = static_cast<time_t>(seconds);
            result.tv_nsec = static_cast<long>(value.nanoseconds());
            return std::nullopt;
        };
        timespec times[2]{};
        if (const auto error = to_timespec(*source.accessed.value(), times[0], "metadata.portable_basic.accessed_range"))
            return Result::unavailable(error->state, error->error);
        if (const auto error = to_timespec(*source.modified.value(), times[1], "metadata.portable_basic.modified_range"))
            return Result::unavailable(error->state, error->error);
        if (futimens(descriptor_.get(), times) != 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "metadata.portable_basic.futimens"});
        return Result::available(true);
    }
    Observation<bool> apply_nonsecurity_attribute(const AttributeValue& source) override {
        using Result = Observation<bool>;
        if (!content_write_access_)
            return Result::unavailable(ObservationState::Denied,
                adapter_error(AdapterError::InvalidAccess, "attributes.nonsecurity.write_access"));
        const auto* name = source.identifier.posix_bytes();
        if (!name || !NativeFeatureIdentifier::from_posix(*name))
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InvalidIdentifier, "attributes.nonsecurity.identifier"));
        if (attribute_role(source.identifier) == AttributeRole::Security)
            return Result::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::NotApplicable, "attributes.nonsecurity.security_attribute"));
        if (source.bytes.size() > InventoryLimits::hard_native_bytes)
            return Result::unavailable(ObservationState::Unknown,
                adapter_error(AdapterError::InventoryLimit, "attributes.nonsecurity.value_limit"));
        if (!source.owner.value() || !source.owner.value()->scope.is_valid()) {
            if (!source.owner.value()) {
                const auto& error = *source.owner.unavailable_detail();
                return Result::unavailable(error.state, error.error);
            }
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::UnqualifiedIdentity, "attributes.nonsecurity.owner"));
        }
        const auto before = inspect_basic();
        if (!before.value()) {
            const auto& error = *before.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        if (!before.value()->identity.value() || !before.value()->kind.value() ||
            *before.value()->kind.value() != ObjectKind::RegularFile)
            return Result::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::NotApplicable, "attributes.nonsecurity.target_kind"));
#if defined(__APPLE__)
        if (const auto guarded = provider_guard(*before.value()))
            return Result::unavailable(guarded->state, guarded->error);
#endif
        const auto proxy = attribute_proxy();
        if (!proxy.value()) {
            const auto& error = *proxy.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
#if defined(__linux__)
        if (setxattr(proxy.value()->c_str(), name->c_str(), source.bytes.data(), source.bytes.size(), 0) != 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "attributes.nonsecurity.setxattr"});
#else
        if (fsetxattr(descriptor_.get(), name->c_str(), source.bytes.data(), source.bytes.size(), 0, XATTR_SHOWCOMPRESSION) != 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "attributes.nonsecurity.fsetxattr"});
#endif
        const auto after = inspect_basic();
        if (!after.value()) {
            const auto& error = *after.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        if (!after.value()->identity.value() ||
            compare_identity(*before.value()->identity.value(), *after.value()->identity.value()) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                adapter_error(AdapterError::MetadataChanged, "attributes.nonsecurity.identity"));
        return Result::available(true);
    }
    Observation<bool> apply_replay_ownership(const BasicMetadata& source, const MetadataReplayPolicy& policy) override {
        using Result = Observation<bool>;
        if (!policy.valid() || !content_write_access_ || (!publication_&&!directory_metadata_target_))
            return Result::unavailable(ObservationState::Denied, adapter_error(AdapterError::InvalidAccess, "metadata_replay.staging_ownership"));
        const auto ownership=qualify_ownership_semantics();
        if (!ownership.value()) {const auto& e=*ownership.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if (policy.ownership == MetadataOwnership::CurrentCaller) return apply_current_caller_ownership();
        if (!source.posix_uid.value() || !source.posix_gid.value() ||
            *source.posix_uid.value() >= std::numeric_limits<uid_t>::max() ||
            *source.posix_gid.value() >= std::numeric_limits<gid_t>::max())
            return Result::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::UnsupportedQuery, "metadata_replay.original_owner_range"));
        if (fchown(descriptor_.get(), static_cast<uid_t>(*source.posix_uid.value()), static_cast<gid_t>(*source.posix_gid.value())) != 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "metadata_replay.fchown_original"});
        return Result::available(true);
    }
    Observation<bool> apply_replay_attribute(const AttributeValue& value, const MetadataReplayPolicy& policy) override {
        using Result = Observation<bool>;
        const auto* name = value.identifier.posix_bytes();
        if (!policy.valid() || !content_write_access_ || (!publication_&&!directory_metadata_target_) || !name || !NativeFeatureIdentifier::from_posix(*name))
            return Result::unavailable(ObservationState::Denied, adapter_error(AdapterError::InvalidAccess, "metadata_replay.staging_attribute"));
        if (value.bytes.size() > policy.limits.max_native_bytes || !value.owner.value() ||
            compare_identity(*value.owner.value(), *value.owner.value()) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidIdentifier, "metadata_replay.attribute_value"));
        if ((name->starts_with("security.") || *name == "com.apple.macl" || *name == "com.apple.rootless" || name->starts_with("trusted.")) && !policy.allow_privilege_metadata)
            return Result::unavailable(ObservationState::Denied, adapter_error(AdapterError::InvalidAccess, "metadata_replay.attribute_optin"));
        if (attribute_role(value.identifier) == AttributeRole::StorageRepresentation)
            return Result::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::ProviderReviewRequired, "metadata_replay.storage_attribute"));
#if defined(__linux__)
        if (fsetxattr(descriptor_.get(), name->c_str(), value.bytes.data(), value.bytes.size(), 0) != 0)
#else
        // Opaque com.apple.provenance is replayed byte-for-byte, like every
        // inventoried native xattr. Never filtered by copyfile export policy.
        if (fsetxattr(descriptor_.get(), name->c_str(), value.bytes.data(), value.bytes.size(), 0, 0) != 0)
#endif
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "metadata_replay.fsetxattr"});
        return Result::available(true);
    }
    Observation<bool> remove_replay_attribute(const NativeFeatureIdentifier& id, const MetadataReplayPolicy& policy) override {
        using Result = Observation<bool>;
        const auto* name=id.posix_bytes();
        if (!policy.valid() || !content_write_access_ || (!publication_&&!directory_metadata_target_) || !name || !NativeFeatureIdentifier::from_posix(*name))
            return Result::unavailable(ObservationState::Denied, adapter_error(AdapterError::InvalidAccess,"metadata_replay.staging_remove_attribute"));
        if ((name->starts_with("security.") || *name == "com.apple.macl" || *name == "com.apple.rootless" || name->starts_with("trusted.")) && !policy.allow_privilege_metadata)
            return Result::unavailable(ObservationState::Denied, adapter_error(AdapterError::InvalidAccess,"metadata_replay.remove_attribute_optin"));
#if defined(__linux__)
        if (fremovexattr(descriptor_.get(),name->c_str()) != 0 && errno != ENODATA)
#else
        if (fremovexattr(descriptor_.get(),name->c_str(),0) != 0 && errno != ENOATTR)
#endif
            return Result::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.fremovexattr"});
        return Result::available(true);
    }
    Observation<bool> apply_replay_security(const NativeSecurityValue& value, const MetadataReplayPolicy& policy) override {
        using Result = Observation<bool>;
        if (!policy.valid() || !content_write_access_ || (!publication_&&!directory_metadata_target_) || !value.owner.value() ||
            value.bytes.size() > policy.limits.max_native_bytes ||
            (value.presence != SecurityPresence::Present && value.presence != SecurityPresence::Absent) ||
            (value.presence == SecurityPresence::Absent && !value.bytes.empty()))
            return Result::unavailable(ObservationState::Denied, adapter_error(AdapterError::InvalidAccess,"metadata_replay.staging_security"));
        const auto ownership=qualify_ownership_semantics();
        if (!ownership.value()) {const auto& e=*ownership.unavailable_detail();return Result::unavailable(e.state,e.error);}
#if defined(__linux__)
        if ((value.part != SecurityPart::LinuxAccessAcl&&value.part!=SecurityPart::LinuxDefaultAcl) || value.encoding != SecurityEncoding::LinuxPosixAclXattrV2)
            return Result::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::NotApplicable,"metadata_replay.acl_model"));
        if(value.part==SecurityPart::LinuxDefaultAcl) {
            const auto basic=inspect_basic();
            if(!basic.value()||!basic.value()->kind.value()||*basic.value()->kind.value()!=ObjectKind::Directory)
                return Result::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::NotApplicable,"metadata_replay.default_acl_directory"));
        }
        const auto id=*NativeFeatureIdentifier::from_posix(value.part==SecurityPart::LinuxDefaultAcl?"system.posix_acl_default":"system.posix_acl_access");
        if (value.presence == SecurityPresence::Absent) return remove_replay_attribute(id,policy);
        const auto valid=detail::validate_linux_acl(value.bytes,policy.limits);
        if (!valid.value()) {const auto& e=*valid.unavailable_detail();return Result::unavailable(e.state,e.error);}
        return apply_replay_attribute({id,value.bytes,value.owner,{}},policy);
#else
        if (value.part != SecurityPart::DarwinExtendedAcl || value.encoding != SecurityEncoding::DarwinExternalAcl)
            return Result::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::NotApplicable,"metadata_replay.acl_model"));
        int result=0;
        if (value.presence == SecurityPresence::Absent) {
            const auto current=read_security(value.part,policy.limits);
            if (!current.value()) {const auto& e=*current.unavailable_detail();return Result::unavailable(e.state,e.error);}
            if (current.value()->presence == SecurityPresence::Absent) return Result::available(true);
            result=acl_set_fd_np(descriptor_.get(),static_cast<acl_t>(_FILESEC_REMOVE_ACL),ACL_TYPE_EXTENDED);
        } else {
            // acl_copy_int has no length parameter: first bound and validate
            // Darwin's external representation header and exact record count.
            constexpr auto header=offsetof(kauth_filesec,fsec_ace);
            if (value.bytes.size()<header)
                return Result::unavailable(ObservationState::Failed,adapter_error(AdapterError::InvalidNativeResult,"metadata_replay.acl_header"));
            std::uint32_t magic=0,count=0;
            std::memcpy(&magic,value.bytes.data()+offsetof(kauth_filesec,fsec_magic),sizeof(magic));
            std::memcpy(&count,value.bytes.data()+offsetof(kauth_filesec,fsec_acl)+offsetof(kauth_acl,acl_entrycount),sizeof(count));
            count=OSSwapBigToHostInt32(count);
            if (OSSwapBigToHostInt32(magic)!=KAUTH_FILESEC_MAGIC || count>ACL_MAX_ENTRIES ||
                count>policy.limits.max_records || value.bytes.size()!=header+count*sizeof(kauth_ace))
                return Result::unavailable(ObservationState::Failed,adapter_error(AdapterError::InvalidNativeResult,"metadata_replay.acl_record_count"));
            acl_t acl=acl_copy_int(value.bytes.data());
            if (!acl) return Result::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.acl_copy_int"});
            if (acl_valid(acl)!=0 || acl_size(acl)!=static_cast<ssize_t>(value.bytes.size())) {
                acl_free(acl);return Result::unavailable(ObservationState::Failed,adapter_error(AdapterError::InvalidNativeResult,"metadata_replay.acl_size"));
            }
            result=acl_set_fd_np(descriptor_.get(),acl,ACL_TYPE_EXTENDED);
            const int code=errno;acl_free(acl);errno=code;
        }
        if (result!=0) return Result::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.set_acl"});
        return Result::available(true);
#endif
    }
    Observation<bool> verify_replay_security(const NativeSecurityValue& value, const MetadataReplayPolicy& policy) const override {
        const auto ownership=qualify_ownership_semantics();
        if (!ownership.value()) return ownership;
        return OpenedEntry::verify_replay_security(value,policy);
    }
    Observation<bool> apply_replay_basic(const BasicMetadata& source, const MetadataReplayPolicy& policy) override {
        using Result=Observation<bool>;
        if (!policy.valid() || !content_write_access_ || (!publication_&&!directory_metadata_target_) || !source.posix_permissions.value())
            return Result::unavailable(ObservationState::Denied,adapter_error(AdapterError::InvalidAccess,"metadata_replay.staging_basic"));
        if ((*source.posix_permissions.value() & 07000U) && !policy.allow_privilege_metadata)
            return Result::unavailable(ObservationState::Denied,adapter_error(AdapterError::InvalidAccess,"metadata_replay.mode_optin"));
        const auto target=inspect_basic();
        if (!target.value()) {const auto& e=*target.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if (!source.accessed.value() || !source.modified.value() || !target.value()->posix_permissions.value() ||
            !target.value()->kind.value() || (*target.value()->kind.value()!=ObjectKind::RegularFile&&!(directory_metadata_target_&&*target.value()->kind.value()==ObjectKind::Directory)))
            return Result::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::UnsupportedQuery,"metadata_replay.basic_fields"));
        const auto mode=*source.posix_permissions.value() & 07777U;
        // The initial mode is established before ACL/capability replay. Final
        // timestamp phases must not chmod an already exact mode: chmod can
        // rewrite the POSIX ACL mask and must not disturb security metadata.
        if (*target.value()->posix_permissions.value()!=mode && fchmod(descriptor_.get(),static_cast<mode_t>(mode))!=0)
            return Result::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.fchmod"});
        timespec times[2]{};
        const FileTimestamp* values[]{source.accessed.value(),source.modified.value()};
        for (int i=0;i<2;++i) {
            const auto seconds=values[i]->seconds();
            if constexpr (std::numeric_limits<time_t>::is_signed) {
                if (seconds<static_cast<std::int64_t>(std::numeric_limits<time_t>::min()) || seconds>static_cast<std::int64_t>(std::numeric_limits<time_t>::max()))
                    return Result::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::UnsupportedQuery,"metadata_replay.time_range"));
            } else if (seconds<0 || static_cast<std::uint64_t>(seconds)>std::numeric_limits<time_t>::max())
                return Result::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::UnsupportedQuery,"metadata_replay.time_range"));
            times[i]={static_cast<time_t>(seconds),static_cast<long>(values[i]->nanoseconds())};
        }
        if ((!target.value()->accessed.value() || *target.value()->accessed.value()!=*source.accessed.value() ||
             !target.value()->modified.value() || *target.value()->modified.value()!=*source.modified.value()) &&
            futimens(descriptor_.get(),times)!=0)
            return Result::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.futimens"});
#if defined(__APPLE__)
        if (policy.scope==RegularMetadataScope::CompleteMetadataV1) {
            if (!source.created.value()) return Result::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::UnsupportedQuery,"metadata_replay.birthtime_missing"));
            struct attrlist attributes{};attributes.bitmapcount=ATTR_BIT_MAP_COUNT;attributes.commonattr=ATTR_CMN_CRTIME;
            timespec birth{static_cast<time_t>(source.created.value()->seconds()),static_cast<long>(source.created.value()->nanoseconds())};
            if ((!target.value()->created.value() || *target.value()->created.value()!=*source.created.value()) &&
                fsetattrlist(descriptor_.get(),&attributes,&birth,sizeof(birth),0)!=0)
                return Result::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.fsetattrlist_birth"});
        }
#endif
        return Result::available(true);
    }
    Observation<bool> publish_noreplace(const DirectoryCursor& destination, const NativeName& name) override;
#if defined(__linux__)
    Observation<FileInodeFlags> inspect_inode_flags(InventoryLimits limits = {}) const override {
        using Result = Observation<FileInodeFlags>;
        if (!limits.valid()) return Result::unavailable(ObservationState::Failed,adapter_error(AdapterError::InvalidLimit,"inode_flags.limits"));
        if (limits.max_native_bytes < sizeof(std::uint32_t)) return Result::unavailable(ObservationState::Unknown,adapter_error(AdapterError::InventoryLimit,"inode_flags.buffer_limit"));
        if (!inode_flags_access_) return Result::unavailable(ObservationState::Denied,adapter_error(AdapterError::InvalidAccess,"inode_flags.access_not_requested"));
        const auto before = inspect_basic(); const auto valid = detail::qualify_inode_flags_subject(before,before);
        if (!valid.value()) { const auto& e = *valid.unavailable_detail(); return Result::unavailable(e.state,e.error); }
        static_assert(sizeof(int) == sizeof(std::uint32_t));
        static_assert(FS_NODUMP_FL == 0x40U && FS_NOATIME_FL == 0x80U && FS_NOCOW_FL == 0x800000U);
        int flags = 0;
        if (ioctl(descriptor_.get(),FS_IOC_GETFLAGS,&flags) != 0) {
            const int code = errno;
            return Result::unavailable(code == ENOTTY ? ObservationState::Unsupported : code == EINVAL ? ObservationState::Unknown : errno_state(code),
                {ErrorDomain::Posix,code,"FS_IOC_GETFLAGS.file"});
        }
        const auto after = inspect_basic(); const auto owner = detail::qualify_inode_flags_subject(before,after);
        if (!owner.value()) { const auto& e = *owner.unavailable_detail(); return Result::unavailable(e.state,e.error); }
        return Result::available({InodeFlagQueryFamily::LinuxIoctlGetFlags,owner,ObjectKind::RegularFile,static_cast<std::uint32_t>(flags)});
    }
#endif
    Observation<FileLinkLimits> inspect_link_limits() const override {
        using Result = Observation<FileLinkLimits>;
        const auto before = inspect_basic();
        const auto valid = detail::qualify_file_link_subject(before, before);
        if (!valid.value()) { const auto& e = *valid.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        auto maximum = descriptor_limit(descriptor_.get(), _PC_LINK_MAX, "fpathconf.link_max");
        const auto after = inspect_basic();
        const auto owner = detail::qualify_file_link_subject(before, after);
        if (!owner.value()) { const auto& e = *owner.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto& before_metadata = *before.value();
        const auto& after_metadata = *after.value();
        const auto* before_kind = before_metadata.kind.value();
        if (!before_kind) {
            const auto& e = *before_metadata.kind.unavailable_detail();
            return Result::unavailable(e.state, e.error);
        }
        return Result::available({FileLinkLimitFamily::PosixFpathconf, *owner.value(), *before_kind,
            before_metadata.link_count, after_metadata.link_count, std::move(maximum)});
    }
    Observation<FileDataLayout> inspect_data_layout(InventoryLimits limits = {}, std::stop_token stop = {}) const override {
        using Result = Observation<FileDataLayout>;
        if (!limits.valid()) return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidLimit, "layout.limits"));
        if (stop.stop_requested()) return Result::unavailable(ObservationState::Unknown, adapter_error(AdapterError::InterruptedRead, "layout.cancelled"));
        if (!layout_access_) return Result::unavailable(ObservationState::Denied, adapter_error(AdapterError::InvalidAccess, "layout.access_not_requested"));
        const auto before = inspect_basic();
        if (!before.value()) { const auto& e = *before.unavailable_detail(); return Result::unavailable(e.state, e.error); }
#if defined(__linux__)
        constexpr auto model = StorageModel::LinuxStatx;
#else
        constexpr auto model = StorageModel::DarwinStatFlags;
#endif
        const auto guard = detail::data_layout_access_guard(*before.value(), model);
        if (!guard.value()) { const auto& e = *guard.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (!before.value()->logical_size.value()) { const auto& e = *before.value()->logical_size.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto size = *before.value()->logical_size.value();
        if (size > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max()))
            return Result::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::UnsupportedQuery, "layout.offset_range"));
        const auto query = [&](std::uint64_t at, std::uint64_t) -> Observation<std::optional<FileDataRange>> {
            using Reply = Observation<std::optional<FileDataRange>>;
            const auto data = lseek(descriptor_.get(), static_cast<off_t>(at), SEEK_DATA);
            if (data < 0) {
                const int code = errno;
                if (code == ENXIO) return Reply::available(std::nullopt);
                return Reply::unavailable(code == EINVAL ? ObservationState::Unsupported : errno_state(code), {ErrorDomain::Posix, code, "lseek.data"});
            }
            if (stop.stop_requested()) return Reply::unavailable(ObservationState::Unknown, adapter_error(AdapterError::InterruptedRead, "layout.cancelled"));
            const auto hole = lseek(descriptor_.get(), data, SEEK_HOLE);
            if (hole < 0) {
                const int code = errno;
                return Reply::unavailable(code == EINVAL ? ObservationState::Unsupported : code == ENXIO ? ObservationState::Changed : errno_state(code),
                    {ErrorDomain::Posix, code, "lseek.hole"});
            }
            if (hole <= data) return Reply::unavailable(ObservationState::Changed, adapter_error(AdapterError::MetadataChanged, "lseek.progress"));
            return Reply::available(FileDataRange{static_cast<std::uint64_t>(data), static_cast<std::uint64_t>(hole - data)});
        };
        auto result = detail::collect_data_layout(query, DataLayoutFamily::PosixSeekDataHole, before.value()->identity, size, limits, stop);
        if (!result.value()) return result;
        if (stop.stop_requested()) return Result::unavailable(ObservationState::Unknown, adapter_error(AdapterError::InterruptedRead, "layout.cancelled"));
        const auto after = inspect_basic();
        if (stop.stop_requested()) return Result::unavailable(ObservationState::Unknown, adapter_error(AdapterError::InterruptedRead, "layout.cancelled"));
        if (!after.value()) { const auto& e = *after.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto unchanged = detail::data_layout_metadata_unchanged(*before.value(), *after.value());
        if (!unchanged.value()) { const auto& e = *unchanged.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        return result;
    }
    Observation<std::unique_ptr<OpenedEntry>> open_parent_directory() const override;
    Observation<LinkMetadata> read_link_metadata(InventoryLimits limits = {}) const override {
        using Result = Observation<LinkMetadata>;
        if (!limits.valid()) return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidLimit, "link.limits"));
        const auto metadata = inspect_basic();
        if (!metadata.value()) { const auto& e = *metadata.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (!metadata.value()->kind.value()) { const auto& e = *metadata.value()->kind.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (*metadata.value()->kind.value() != ObjectKind::SymbolicLink)
            return Result::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::NotApplicable, "link.object_kind"));
        const auto query = [&](std::span<std::byte> buffer) -> detail::LinkReadReply {
#if defined(__linux__)
            const auto count = readlinkat(descriptor_.get(), "", reinterpret_cast<char*>(buffer.data()), buffer.size());
            constexpr const char* operation = "readlinkat.descriptor";
#else
            ssize_t count = -1;
            if (__builtin_available(macos 13.0, *))
                count = freadlink(descriptor_.get(), reinterpret_cast<char*>(buffer.data()), buffer.size());
            else return UnavailableObservation{ObservationState::Unsupported, adapter_error(AdapterError::UnsupportedQuery, "freadlink.availability")};
            constexpr const char* operation = "freadlink";
#endif
            if (count >= 0) return static_cast<std::size_t>(count);
            const int code = errno;
            return UnavailableObservation{errno_state(code), {ErrorDomain::Posix, code, operation}};
        };
        auto target = detail::read_posix_link(query, limits);
        if (!target.value()) { const auto& e = *target.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        return Result::available({metadata.value()->identity, std::move(target).take_value()});
    }
    Observation<StorageInfo> inspect_storage() const override {
        const auto metadata = inspect_basic();
        if (!metadata.value()) { const auto& e = *metadata.unavailable_detail(); return Observation<StorageInfo>::unavailable(e.state, e.error); }
#if defined(__linux__)
        return storage_from_basic(*metadata.value(), StorageModel::LinuxStatx);
#else
        return storage_from_basic(*metadata.value(), StorageModel::DarwinStatFlags);
#endif
    }
    Observation<BasicMetadata> inspect_basic() const override {
        if (finish_started_) return Observation<BasicMetadata>::unavailable(ObservationState::Failed,
            adapter_error(AdapterError::InvalidAccess,"content.finished_inspection"));
#if defined(__linux__)
        return statx_metadata(descriptor_.get(), "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, scope_);
#else
        return stat_metadata(descriptor_.get(), nullptr, true, scope_);
#endif
    }
#if defined(__APPLE__)
    Observation<DataChannelCatalog> inspect_data_channels(InventoryLimits limits = {}) const override {
        using Result = Observation<DataChannelCatalog>;
        if (!limits.valid())
            return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidLimit, "channels.limits"));
        const auto metadata = inspect_basic();
        if (!metadata.value()) {
            const auto& detail = *metadata.unavailable_detail();
            return Result::unavailable(detail.state, detail.error);
        }
        DataChannelCatalog result;
        if (const auto guarded = provider_guard(*metadata.value())) return Result::unavailable(guarded->state, guarded->error);
        result.coverage = DataChannelCoverage::MacResourceFork;
        result.owner = metadata.value()->identity;
        constexpr const char* resource_fork = "com.apple.ResourceFork";
        const auto size = fgetxattr(descriptor_.get(), resource_fork, nullptr, 0, 0, 0);
        if (size < 0) {
            const int code = errno;
            if (code != ENOATTR)
                return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "fgetxattr.resource_fork_size"});
        } else {
            result.channels.push_back({*NativeFeatureIdentifier::from_posix(resource_fork), DataChannelKind::ResourceFork,
                Observation<std::uint64_t>::available(static_cast<std::uint64_t>(size)), {}});
        }
        return Result::available(std::move(result));
    }
#endif
    Observation<AttributeCatalog> inspect_attributes(InventoryLimits limits = {}) const override {
        using Result = Observation<AttributeCatalog>;
        if (!limits.valid()) return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidLimit, "attributes.limits"));
        const auto metadata = inspect_basic();
        if (!metadata.value()) { const auto& e = *metadata.unavailable_detail(); return Result::unavailable(e.state, e.error); }
#if defined(__APPLE__)
        if (const auto guarded = provider_guard(*metadata.value())) return Result::unavailable(guarded->state, guarded->error);
#endif
        const auto proxy = attribute_proxy();
        if (!proxy.value()) { const auto& e = *proxy.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto bytes = detail::read_attribute_bytes([&](std::span<std::byte> buffer) {
#if defined(__linux__)
            const auto count = listxattr(proxy.value()->c_str(), reinterpret_cast<char*>(buffer.data()), buffer.size());
#else
            const auto count = flistxattr(descriptor_.get(), reinterpret_cast<char*>(buffer.data()), buffer.size(), XATTR_SHOWCOMPRESSION);
#endif
            return attribute_reply(count, "listxattr.names");
        }, limits);
        if (!bytes.value()) { const auto& e = *bytes.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        auto decoded = detail::decode_posix_attribute_names(*bytes.value(), limits);
        if (!decoded.value()) { const auto& e = *decoded.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        AttributeCatalog result;
        result.owner = metadata.value()->identity;
        result.coverage = AttributeCoverage::CredentialsVisiblePosix;
        auto names = std::move(decoded).take_value();
        for (auto& id : names) {
            const auto size = attribute_size(*id.posix_bytes(), *proxy.value());
            result.attributes.push_back({std::move(id), AttributeRole::Opaque, size,
                Observation<std::uint32_t>::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::NotApplicable, "attributes.flags"))});
            result.attributes.back().role = attribute_role(result.attributes.back().identifier);
        }
        const auto checked = attribute_proxy();
        if (!checked.value()) { const auto& e = *checked.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        return Result::available(std::move(result));
    }
    Observation<AttributeValue> read_attribute(const NativeFeatureIdentifier& id, InventoryLimits limits = {}) const override {
        using Result = Observation<AttributeValue>;
        if (!limits.valid()) return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidLimit, "attributes.limits"));
        const auto* name = id.posix_bytes();
        if (!name || !NativeFeatureIdentifier::from_posix(*name))
            return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidIdentifier, "attributes.identifier"));
        const auto metadata = inspect_basic();
        if (!metadata.value()) { const auto& e = *metadata.unavailable_detail(); return Result::unavailable(e.state, e.error); }
#if defined(__APPLE__)
        if (const auto guarded = provider_guard(*metadata.value())) return Result::unavailable(guarded->state, guarded->error);
#endif
        const auto proxy = attribute_proxy();
        if (!proxy.value()) { const auto& e = *proxy.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        auto bytes = detail::read_attribute_bytes([&](std::span<std::byte> buffer) {
#if defined(__linux__)
            const auto count = getxattr(proxy.value()->c_str(), name->c_str(), buffer.data(), buffer.size());
#else
            const auto count = fgetxattr(descriptor_.get(), name->c_str(), buffer.data(), buffer.size(), 0, XATTR_SHOWCOMPRESSION);
#endif
            return attribute_reply(count, "getxattr.value");
        }, limits);
        if (!bytes.value()) { const auto& e = *bytes.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto checked = attribute_proxy();
        if (!checked.value()) { const auto& e = *checked.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        return Result::available({id, std::move(bytes).take_value(), metadata.value()->identity,
            Observation<std::uint32_t>::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::NotApplicable, "attributes.flags"))});
    }
    Observation<NativeSecurityValue> read_security(SecurityPart part, InventoryLimits limits = {}) const override {
        using Result = Observation<NativeSecurityValue>;
        if (!valid_security_part(part) || !limits.valid())
            return Result::unavailable(ObservationState::Failed, adapter_error(!valid_security_part(part) ? AdapterError::InvalidIdentifier : AdapterError::InvalidLimit, "security.query"));
#if defined(__linux__)
        if (part != SecurityPart::LinuxAccessAcl && part != SecurityPart::LinuxDefaultAcl)
            return Result::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::NotApplicable, "security.model"));
        const auto id = *NativeFeatureIdentifier::from_posix(part == SecurityPart::LinuxAccessAcl ? "system.posix_acl_access" : "system.posix_acl_default");
        auto queried = read_attribute(id, limits);
        if (!queried.value()) {
            const auto& e = *queried.unavailable_detail();
            if (e.error.domain == ErrorDomain::Posix && e.error.code == ENODATA) {
                const auto metadata = inspect_basic();
                if (!metadata.value()) { const auto& error = *metadata.unavailable_detail(); return Result::unavailable(error.state, error.error); }
                return Result::available({part, SecurityEncoding::LinuxPosixAclXattrV2, SecurityPresence::Absent, {}, metadata.value()->identity, 0});
            }
            return Result::unavailable(e.state, e.error);
        }
        auto value = std::move(queried).take_value();
        const auto checked = detail::validate_linux_acl(value.bytes, limits);
        if (!checked.value()) { const auto& e = *checked.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        return Result::available({part, SecurityEncoding::LinuxPosixAclXattrV2, SecurityPresence::Present, std::move(value.bytes), std::move(value.owner), 0});
#else
        if (part != SecurityPart::DarwinExtendedAcl)
            return Result::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::NotApplicable, "security.model"));
        const auto metadata = inspect_basic();
        if (!metadata.value()) { const auto& e = *metadata.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto native_error = [](int code, const char* operation) {
            return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, operation});
        };
        struct FileSecurityOwner {
            filesec_t value;
            ~FileSecurityOwner() { if (value) filesec_free(value); }
        } security{filesec_init()};
        if (!security.value) return native_error(errno, "filesec_init");
        struct stat native{};
        if (fstatx_np(descriptor_.get(), &native, security.value) != 0) return native_error(errno, "fstatx_np.security");
        int present = 0;
        if (filesec_query_property(security.value, FILESEC_ACL, &present) != 0) return native_error(errno, "filesec_query_property.acl");
        if (!present) {
            // Unlike acl_get_fd_np's overloaded ENOENT, this is a successful
            // object query with an explicitly missing ACL property. Qualify
            // native extended-security support before calling it absent.
            errno = 0;
            const auto supported = fpathconf(descriptor_.get(), _PC_EXTENDED_SECURITY_NP);
            if (supported < 0) {
                const int code = errno;
                if (code != 0) return native_error(code, "fpathconf.extended_security");
                return Result::unavailable(ObservationState::Unknown, adapter_error(AdapterError::UnsupportedQuery, "fpathconf.extended_security"));
            }
            if (supported == 0) return Result::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::UnsupportedQuery, "security.extended_acl"));
            return Result::available({part, SecurityEncoding::DarwinExternalAcl, SecurityPresence::Absent, {}, metadata.value()->identity, 0});
        }
        struct AclOwner {
            acl_t value = nullptr;
            ~AclOwner() { if (value) acl_free(value); }
        } acl;
        if (filesec_get_property(security.value, FILESEC_ACL, &acl.value) != 0) return native_error(errno, "filesec_get_property.acl");
        if (!acl.value) return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidNativeResult, "filesec_get_property.null_acl"));
        if (acl_valid(acl.value) != 0) return native_error(errno, "acl_valid");
        std::size_t entries = 0;
        acl_entry_t entry{};
        int selector = ACL_FIRST_ENTRY;
        for (;;) {
            if (acl_get_entry(acl.value, selector, &entry) != 0) {
                const int code = errno;
                if (code != EINVAL) return native_error(code, "acl_get_entry");
                break; // Darwin's documented end-of-working-ACL result.
            }
            if (entries == limits.max_records)
                return Result::unavailable(ObservationState::Unknown, adapter_error(AdapterError::InventoryLimit, "security.records"));
            ++entries;
            selector = ACL_NEXT_ENTRY;
        }
        const auto size = acl_size(acl.value);
        if (size < 0) return native_error(errno, "acl_size");
        if (static_cast<std::uint64_t>(size) > limits.max_native_bytes)
            return Result::unavailable(ObservationState::Unknown, adapter_error(AdapterError::InventoryLimit, "security.bytes"));
        NativeBytes bytes(static_cast<std::size_t>(size));
        const auto copied = acl_copy_ext(bytes.data(), acl.value, size);
        if (copied < 0) return native_error(errno, "acl_copy_ext");
        if (copied != size) return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidNativeResult, "acl_copy_ext.size"));
        return Result::available({part, SecurityEncoding::DarwinExternalAcl, SecurityPresence::Present, std::move(bytes), metadata.value()->identity, 0});
#endif
    }
private:
    bool metadata_link_count_qualified(std::uint64_t count) const noexcept {
        // Read-only native observations can retain an ordinary multiply-linked
        // inode. Writable targets retain their single-name/owned-anonymous rule.
        if (!content_write_access_) return count>=1;
        if (count==1) return true;
#if defined(__linux__)
        return count==0 && publication_ && publication_->anonymous;
#else
        return false;
#endif
    }
    Observation<bool> qualify_ownership_semantics() const {
#if defined(__APPLE__)
        struct statfs filesystem{};
        if (fstatfs(descriptor_.get(),&filesystem)!=0)
            return Observation<bool>::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.fstatfs_ownership"});
        // noowners virtualizes uid/gid and bypasses ownership enforcement.
        // Matching fstat values or ACL bytes cannot qualify these semantics.
        if ((filesystem.f_flags & MNT_IGNORE_OWNERSHIP)!=0)
            return Observation<bool>::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::ProviderReviewRequired,"metadata_replay.ignored_ownership_mount"));
#endif
        return Observation<bool>::available(true);
    }
    friend class PosixDirectoryCursor;
    friend class PosixTargetReadSeed;
#if defined(__APPLE__)
    static std::optional<UnavailableObservation> provider_guard(const BasicMetadata& metadata) {
        const auto review = provider_review_required(metadata, StorageModel::DarwinStatFlags);
        if (!review.value()) return *review.unavailable_detail();
        if (*review.value()) return UnavailableObservation{ObservationState::Unknown,
            adapter_error(AdapterError::ProviderReviewRequired, "attributes.provider_review")};
        return std::nullopt;
    }
#endif
    static detail::BufferReply attribute_reply(ssize_t count, const char* operation) {
        if (count >= 0) return static_cast<std::size_t>(count);
        const int code = errno;
        const NativeError error{ErrorDomain::Posix, code, operation};
        if (code == ERANGE) return detail::BufferTooSmall{error};
#if defined(__linux__)
        const auto state = code == ENODATA ? ObservationState::Gone : errno_state(code);
#else
        const auto state = code == ENOATTR ? ObservationState::Gone : errno_state(code);
#endif
        return UnavailableObservation{state, error};
    }
    Observation<std::uint64_t> attribute_size(const std::string& name, const std::string& proxy) const {
#if defined(__linux__)
        const auto count = getxattr(proxy.c_str(), name.c_str(), nullptr, 0);
#else
        (void)proxy;
        const auto count = fgetxattr(descriptor_.get(), name.c_str(), nullptr, 0, 0, XATTR_SHOWCOMPRESSION);
#endif
        auto reply = attribute_reply(count, "getxattr.size");
        if (const auto* size = std::get_if<std::size_t>(&reply)) return Observation<std::uint64_t>::available(*size);
        if (const auto* error = std::get_if<UnavailableObservation>(&reply))
            return Observation<std::uint64_t>::unavailable(error->state, error->error);
        return Observation<std::uint64_t>::unavailable(ObservationState::Changed, std::get<detail::BufferTooSmall>(reply).error);
    }
    Observation<std::string> attribute_proxy() const {
        using Result = Observation<std::string>;
#if defined(__linux__)
        // The kernel's descriptor namespace refers to the held object, including
        // after rename/unlink. No source pathname or data-read fd is opened.
        struct statfs native{};
        if (statfs("/proc/self/fd", &native) != 0) {
            const int code = errno;
            return Result::unavailable(code == ENOENT || code == ENOTDIR ? ObservationState::Unknown : errno_state(code),
                {ErrorDomain::Posix, code, "attributes.proc_namespace"});
        }
        if (static_cast<unsigned long>(native.f_type) != static_cast<unsigned long>(PROC_SUPER_MAGIC))
            return Result::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::UnsupportedQuery, "attributes.proc_namespace"));
        const auto path = std::string("/proc/self/fd/") + std::to_string(descriptor_.get());
        const auto original = inspect_basic();
        const auto via_proxy = statx_metadata(AT_FDCWD, path.c_str(), 0, scope_);
        if (!original.value()) { const auto& e = *original.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (!via_proxy.value()) {
            const auto& e = *via_proxy.unavailable_detail();
            return Result::unavailable(e.state == ObservationState::Gone ? ObservationState::Unknown : e.state, e.error);
        }
        const auto* expected = original.value()->identity.value();
        const auto* actual = via_proxy.value()->identity.value();
        const auto comparison = expected && actual ? compare_identity(*expected, *actual) : IdentityComparison::Unknown;
        if (comparison != IdentityComparison::Same)
            return Result::unavailable(comparison == IdentityComparison::Different ? ObservationState::Changed : ObservationState::Unknown,
                adapter_error(AdapterError::UnqualifiedIdentity, "attributes.descriptor_identity"));
        return Result::available(path);
#else
        return Result::available({}); // Darwin uses only the owned fd.
#endif
    }
    Observation<OwnedDescriptor> open_readonly_capture_description() const {
        using R=Observation<OwnedDescriptor>;
#if defined(__linux__)
        OwnedDescriptor proc(open("/proc/self/fd", O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        if(proc.get()<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"target_read.proc_open"});
        struct statfs proc_filesystem{};
        if(fstatfs(proc.get(),&proc_filesystem)!=0)
            return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"target_read.proc_statfs"});
        if(static_cast<unsigned long>(proc_filesystem.f_type)!=static_cast<unsigned long>(PROC_SUPER_MAGIC))
            return R::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::ProviderReviewRequired,"target_read.proc_namespace"));
        const auto descriptor_name=std::to_string(descriptor_.get());
        OwnedDescriptor fresh(openat(proc.get(),descriptor_name.c_str(),O_RDONLY|O_NOATIME|O_CLOEXEC));
        if(fresh.get()<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"target_read.proc_reopen"});
        const int flags=fcntl(fresh.get(),F_GETFL);
        if(flags<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"target_read.read_flags"});
        if((flags&O_ACCMODE)!=O_RDONLY||(flags&O_NOATIME)==0)
            return R::unavailable(ObservationState::Denied,adapter_error(AdapterError::InvalidAccess,"target_read.readonly_noatime"));
        const int descriptor_flags=fcntl(fresh.get(),F_GETFD);
        if(descriptor_flags<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"target_read.fd_flags"});
        if((descriptor_flags&FD_CLOEXEC)==0)
            return R::unavailable(ObservationState::Failed,adapter_error(AdapterError::InvalidNativeResult,"target_read.fd_cloexec"));
        const auto before=inspect_basic();
        const auto after=statx_metadata(fresh.get(),"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,scope_);
        if(!before.value()){const auto&e=*before.unavailable_detail();return R::unavailable(e.state,e.error);}
        if(!after.value()) { const auto&e=*after.unavailable_detail(); return R::unavailable(e.state,e.error); }
        const auto same=compare_capture_bookend(*before.value(),*after.value(),"target_read.reopen_identity");
        if(!same.value()) { const auto&e=*same.unavailable_detail(); return R::unavailable(e.state,e.error); }
        return R::available(std::move(fresh));
#else
        return R::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::NotApplicable,"target_read.linux_only"));
#endif
    }
#if defined(__linux__)
    // Declare reservations before the native owner.  C++ destroys members in
    // reverse declaration order, so descriptor_ closes before these leases
    // release their budget/clone reservations.
    std::shared_ptr<detail::NativeTargetReadBudget> target_read_budget_;
    std::shared_ptr<NativeTargetReadCloneState> target_read_clone_state_;
    std::shared_ptr<NativeTargetReadCloneLease> target_read_clone_lease_;
#endif
    bool capture_close_started_=false;
    std::optional<MetadataCaptureCleanupError> capture_close_error_;
    OwnedDescriptor descriptor_;
    bool finish_started_ = false;
    std::optional<Observation<bool>> finish_result_;
    AdapterScope scope_;
    bool layout_access_;
    bool content_access_ = false;
    bool content_write_access_ = false;
    std::unique_ptr<PosixPublicationContext> publication_;
    bool directory_metadata_target_=false;
#if defined(__linux__)
    bool inode_flags_access_ = false;
#endif
};

Observation<std::unique_ptr<OpenedEntry>> open_posix_parent(int descriptor, const AdapterScope& scope) {
    using Result = Observation<std::unique_ptr<OpenedEntry>>;
    const auto check = [](const Observation<BasicMetadata>& metadata) -> std::optional<UnavailableObservation> {
        if (!metadata.value()) return *metadata.unavailable_detail();
        if (!metadata.value()->kind.value()) return *metadata.value()->kind.unavailable_detail();
        if (*metadata.value()->kind.value() != ObjectKind::Directory) return UnavailableObservation{ObservationState::Unsupported,
            adapter_error(AdapterError::NotApplicable, "parent.object_kind")};
#if defined(__APPLE__)
        const auto review = provider_review_required(*metadata.value(), StorageModel::DarwinStatFlags);
        if (!review.value()) return *review.unavailable_detail();
        if (*review.value()) return UnavailableObservation{ObservationState::Unknown, adapter_error(AdapterError::ProviderReviewRequired, "parent.provider_review")};
#endif
        return {};
    };
    if (const auto failure = check(stat_metadata(descriptor, nullptr, true, scope))) return Result::unavailable(failure->state, failure->error);
#if defined(__linux__)
    constexpr auto flags = O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
#else
    constexpr auto flags = O_EVTONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
#endif
    OwnedDescriptor parent(openat(descriptor, "..", flags));
    if (parent.get() < 0) { const int code = errno; return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "openat.parent"}); }
    if (const auto failure = check(stat_metadata(parent.get(), nullptr, true, scope))) return Result::unavailable(failure->state, failure->error);
    return Result::available(std::make_unique<PosixOpenedEntry>(std::move(parent), scope));
}
Observation<std::unique_ptr<OpenedEntry>> PosixOpenedEntry::open_parent_directory() const { return open_posix_parent(descriptor_.get(), scope_); }

#if defined(__linux__)
class LinuxPersistentSecurityProof final:public MetadataSecurityCoverageEvidence {
public:
    LinuxPersistentSecurityProof(std::shared_ptr<const PosixOpenedEntry> source,MetadataReplaySnapshot observed,
        LinuxFullClassState classes,std::shared_ptr<const void> lease)
        :source_(std::move(source)),observed_(std::move(observed)),classes_(classes),lease_(std::move(lease)){observed_.security_coverage.reset();}
    MetadataSecurityCoverage family()const noexcept override{return MetadataSecurityCoverage::LinuxPersistentSecurityV1;}
    Observation<bool> recheck(const MetadataReplaySnapshot& requested)const override {
        using R=Observation<bool>;
        const auto live=source_->inspect_basic();if(!live.value()){const auto&e=*live.unavailable_detail();return R::unavailable(e.state,e.error);}
        if(!linux_full_values(requested,observed_,true))return R::unavailable(ObservationState::Changed,
            adapter_error(AdapterError::MetadataChanged,"metadata_replay.linux_coverage_manifest"));
        const auto actual=source_->full_security_values(observed_.policy);
        if(!actual.value()){const auto&e=*actual.unavailable_detail();return R::unavailable(e.state,e.error);}
        if(!linux_full_values(observed_,*actual.value(),false))return R::unavailable(ObservationState::Changed,
            adapter_error(AdapterError::MetadataChanged,"metadata_replay.linux_coverage_source_changed"));
        const auto classes=source_->full_security_class_state();
        if(!classes.value()){const auto&e=*classes.unavailable_detail();return R::unavailable(e.state,e.error);}
        if(!classes_.same(*classes.value()))return R::unavailable(ObservationState::Changed,
            adapter_error(AdapterError::MetadataChanged,"metadata_replay.linux_coverage_native_classes_changed"));
        return R::available(true);
    }
    void finish_capture_reads()const noexcept {const_cast<PosixOpenedEntry*>(source_.get())->finish_capture_reads();}
private:
    std::shared_ptr<const PosixOpenedEntry> source_;
    MetadataReplaySnapshot observed_;
    LinuxFullClassState classes_;
    std::shared_ptr<const void> lease_;
};
Observation<std::shared_ptr<const MetadataSecurityCoverageEvidence>> PosixOpenedEntry::issue_linux_security_coverage(
    const MetadataReplaySnapshot& snapshot,std::shared_ptr<const void> lease)const {
    using R=Observation<std::shared_ptr<const MetadataSecurityCoverageEvidence>>;
    const auto qualified=qualify_metadata_replay(snapshot.policy);
    if(!qualified.value()){const auto&e=*qualified.unavailable_detail();return R::unavailable(e.state,e.error);}
    const auto proxy=attribute_proxy();if(!proxy.value()){const auto&e=*proxy.unavailable_detail();return R::unavailable(e.state,e.error);}
    OwnedDescriptor readview(open(proxy.value()->c_str(),O_RDONLY|O_NONBLOCK|O_NOCTTY|O_CLOEXEC));
    if(readview.get()<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_source_readview"});
    const bool file=snapshot.basic.kind.value()&&*snapshot.basic.kind.value()==ObjectKind::RegularFile;
    auto source=std::make_shared<PosixOpenedEntry>(std::move(readview),scope_,false,file);
    const auto actual=source->full_security_values(snapshot.policy);
    if(!actual.value()){const auto&e=*actual.unavailable_detail();return R::unavailable(e.state,e.error);}
    // Only the private progressive seal supplies a lease: its first native
    // access-time sample predates its own data reads. The public legacy
    // issuer must authenticate the supplied access time against live native
    // values, rather than endorse a caller-chosen timestamp.
    if(!linux_full_values(snapshot,*actual.value(),!lease))return R::unavailable(ObservationState::Changed,
        adapter_error(AdapterError::MetadataChanged,"metadata_replay.full_source_snapshot_binding"));
    const auto classes=source->full_security_class_state();
    if(!classes.value()){const auto&e=*classes.unavailable_detail();return R::unavailable(e.state,e.error);}
    auto proof=std::make_shared<LinuxPersistentSecurityProof>(std::move(source),snapshot,*classes.value(),std::move(lease));
    const auto checked=proof->recheck(snapshot);if(!checked.value()){const auto&e=*checked.unavailable_detail();return R::unavailable(e.state,e.error);}
    if(!*checked.value())return R::unavailable(ObservationState::Failed,adapter_error(AdapterError::InvalidNativeResult,"metadata_replay.full_native_evidence_false"));
    return R::available(std::move(proof));
}
Observation<bool> PosixOpenedEntry::verify_metadata_security_coverage(const MetadataReplaySnapshot& snapshot)const {
    using R=Observation<bool>;
    const auto* proof=dynamic_cast<const LinuxPersistentSecurityProof*>(snapshot.security_coverage.get());
    if(!proof)return R::unavailable(ObservationState::Unsupported,
        adapter_error(AdapterError::ProviderReviewRequired,"metadata_replay.linux_native_security_evidence_required"));
    const auto checked=proof->recheck(snapshot);if(!checked.value()||!*checked.value())return checked;
    // Coverage is actual target query capability; generic replay verification
    // separately compares every target byte, mode, owner, ACL and timestamp.
    const auto values=full_security_values(snapshot.policy);
    if(!values.value()){const auto&e=*values.unavailable_detail();return R::unavailable(e.state,e.error);}
    const auto classes=full_security_class_state();
    if(!classes.value()){const auto&e=*classes.unavailable_detail();return R::unavailable(e.state,e.error);}
    return R::available(true);
}
Observation<bool> PosixOpenedEntry::preflight_metadata_security_coverage(const MetadataReplaySnapshot& snapshot) {
    using R=Observation<bool>;
    if(!content_write_access_||(!publication_&&!directory_metadata_target_))return R::unavailable(ObservationState::Denied,
        adapter_error(AdapterError::InvalidAccess,"metadata_replay.full_target_write_authority"));
    const auto checked=verify_metadata_security_coverage(snapshot);if(!checked.value()||!*checked.value())return checked;
    const auto actual=full_security_values(snapshot.policy);
    if(!actual.value()){const auto&e=*actual.unavailable_detail();return R::unavailable(e.state,e.error);}
    const auto& a=actual.value()->basic;const auto& b=snapshot.basic;
    if(!a.posix_uid.value()||!a.posix_gid.value()||!b.posix_uid.value()||!b.posix_gid.value())return R::unavailable(ObservationState::Unsupported,
        adapter_error(AdapterError::ProviderReviewRequired,"metadata_replay.full_owner_fields"));
    const auto uid=snapshot.policy.ownership==MetadataOwnership::Original?*b.posix_uid.value():static_cast<std::uint64_t>(geteuid());
    const auto gid=snapshot.policy.ownership==MetadataOwnership::Original?*b.posix_gid.value():static_cast<std::uint64_t>(getegid());
    __user_cap_header_struct h{};h.version=_LINUX_CAPABILITY_VERSION_3;__user_cap_data_struct caps[2]{};
    if(syscall(SYS_capget,&h,caps))return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_target_capget"});
    const auto has=[&](unsigned cap){return (caps[cap/32].effective&(1U<<(cap%32)))!=0;};
    if((uid!=*a.posix_uid.value()||gid!=*a.posix_gid.value())&&!has(CAP_CHOWN))return R::unavailable(ObservationState::Denied,
        adapter_error(AdapterError::InvalidAccess,"metadata_replay.full_target_chown_required"));
    if(uid!=static_cast<std::uint64_t>(geteuid())&&!has(CAP_FOWNER))return R::unavailable(ObservationState::Denied,
        adapter_error(AdapterError::InvalidAccess,"metadata_replay.full_target_fowner_required"));
    if(b.posix_permissions.value()&&(*b.posix_permissions.value()&S_ISGID)&&!has(CAP_FSETID)){
        // Invalid gid -1 is a query: the verified initial namespace never
        // maps it, so setfsgid cannot change this thread's filesystem gid.
        const auto fs_gid=static_cast<gid_t>(setfsgid(static_cast<gid_t>(-1)));
        const int count=getgroups(0,nullptr);if(count<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_target_getgroups"});
        if(static_cast<unsigned>(count)>InventoryLimits::hard_records)return R::unavailable(ObservationState::Unsupported,
            adapter_error(AdapterError::InventoryLimit,"metadata_replay.full_target_group_inventory"));
        std::vector<gid_t> groups(static_cast<std::size_t>(count));
        const int observed=getgroups(count,groups.data());
        if(observed<0&&errno!=EINVAL)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_replay.full_target_getgroups"});
        if(observed!=count)return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,"metadata_replay.full_target_groups_changed"));
        if(gid!=static_cast<std::uint64_t>(fs_gid)&&std::none_of(groups.begin(),groups.end(),[&](gid_t g){return static_cast<std::uint64_t>(g)==gid;}))
            return R::unavailable(ObservationState::Denied,adapter_error(AdapterError::InvalidAccess,"metadata_replay.full_target_fsetid_required"));
    }
    const auto filecaps=[](const auto& values){return std::any_of(values.attributes.begin(),values.attributes.end(),[](const auto& v){const auto*n=v.identifier.posix_bytes();return n&&*n=="security.capability";});};
    if((filecaps(snapshot)||filecaps(*actual.value()))&&!has(CAP_SETFCAP))return R::unavailable(ObservationState::Denied,
        adapter_error(AdapterError::InvalidAccess,"metadata_replay.full_target_setfcap_required"));
    return R::available(true);
}
#endif

struct DirectoryCloser {
    void operator()(DIR* directory) const noexcept { if(closedir(directory)!=0){const int e=errno;detail::record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Posix,e,"metadata_capture.temporary_closedir"});errno=e;} }
};
using OwnedDirectory = std::unique_ptr<DIR, DirectoryCloser>;

class PosixDirectoryCursor final : public DirectoryCursor {
public:
    Observation<std::unique_ptr<DirectoryCursor>> open_current_directory_reader()const {
        using R=Observation<std::unique_ptr<DirectoryCursor>>;
        const auto before=inspect_basic();
        if(!before.value()){const auto&e=*before.unavailable_detail();return R::unavailable(e.state,e.error);}
        if(!identity().value()||!before.value()->identity.value()||
           compare_identity(*identity().value(),*before.value()->identity.value())!=IdentityComparison::Same)
            return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,"directory_reader.held_identity"));
        OwnedDescriptor fd(openat(dirfd(directory_.get()),".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        if(fd.get()<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"directory_reader.open_self"});
        struct stat st{};if(fstat(fd.get(),&st))return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"directory_reader.fstat"});
        if(!S_ISDIR(st.st_mode))return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,"directory_reader.kind"));
        std::optional<std::uint64_t> generation;
#if defined(__APPLE__)
        generation=st.st_gen;
#endif
        auto id=Observation<ObjectIdentity>::available({scope_,IdentityScheme::PosixDeviceInode,
            NativeIdentifier::from_u64(static_cast<std::uint64_t>(st.st_dev)),
            NativeIdentifier::from_u64(static_cast<std::uint64_t>(st.st_ino)),generation});
        if(compare_identity(*before.value()->identity.value(),*id.value())!=IdentityComparison::Same)
            return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,"directory_reader.open_identity"));
        OwnedDirectory directory(fdopendir(fd.get()));
        if(!directory)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"directory_reader.fdopendir"});
        fd.release();
        auto reader=std::make_unique<PosixDirectoryCursor>(std::move(directory),std::move(id),scope_);
        const auto after=inspect_basic();const auto opened=reader->inspect_basic();
        const auto same=[&](const Observation<BasicMetadata>& b){return b.value()&&b.value()->identity.value()&&
            compare_identity(*before.value()->identity.value(),*b.value()->identity.value())==IdentityComparison::Same&&
            before.value()->modified.value()&&b.value()->modified.value()&&*before.value()->modified.value()==*b.value()->modified.value()&&
            before.value()->changed.value()&&b.value()->changed.value()&&*before.value()->changed.value()==*b.value()->changed.value();};
        if(!same(after)||!same(opened))return R::unavailable(ObservationState::Changed,
            adapter_error(AdapterError::MetadataChanged,"directory_reader.open_bookend"));
        return R::available(std::move(reader));
    }
    Observation<std::shared_ptr<const OpenedEntry>> open_progressive_directory_source()const {
        using R=Observation<std::shared_ptr<const OpenedEntry>>;
#if defined(__linux__)
        std::shared_ptr<detail::NativeTargetReadBudget> child_budget;
        if(target_read_budget_){
            auto lease=detail::NativeTargetReadBudget::acquire_child(target_read_budget_,1,sizeof(PosixOpenedEntry));
            if(!lease.value())return R::unavailable(lease.unavailable_detail()->state,lease.unavailable_detail()->error);
            child_budget=std::move(lease).take_value();
        }
#endif
        OwnedDescriptor fd(fcntl(dirfd(directory_.get()),F_DUPFD_CLOEXEC,0));
        if(fd.get()<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"metadata_capture.directory_query_dup"});
        auto clone=std::make_shared<PosixOpenedEntry>(std::move(fd),scope_);
#if defined(__linux__)
        clone->target_read_budget_=std::move(child_budget);
        clone->target_read_clone_state_=target_read_clone_state_;
        if(clone->target_read_clone_state_)
            clone->target_read_clone_lease_=std::make_shared<NativeTargetReadCloneLease>(clone->target_read_clone_state_);
#endif
        return R::available(std::move(clone));
    }

    PosixDirectoryCursor(OwnedDirectory directory, Observation<ObjectIdentity> identity, AdapterScope scope)
        : DirectoryCursor(std::move(identity)), directory_(std::move(directory)), scope_(std::move(scope)) {}
    Observation<AdapterScope> source_scope() const override { return Observation<AdapterScope>::available(scope_); }
    Observation<int> duplicate_journal_directory() const {
        auto current=inspect_basic();
        if(!current.value())return Observation<int>::unavailable(current.state(),current.unavailable_detail()->error);
        if(!identity().value()||!current.value()->identity.value()||
            compare_identity(*identity().value(),*current.value()->identity.value())!=IdentityComparison::Same)
            return Observation<int>::unavailable(ObservationState::Changed,
                adapter_error(AdapterError::MetadataChanged,"journal_root.cursor_changed"));
        const int duplicate=fcntl(dirfd(directory_.get()),F_DUPFD_CLOEXEC,0);
        if(duplicate<0)return Observation<int>::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"journal_root.duplicate_cursor"});
        return Observation<int>::available(duplicate);
    }
    Observation<BasicMetadata> inspect_basic() const override {
#if defined(__linux__)
        return statx_metadata(dirfd(directory_.get()), "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW, scope_);
#else
        return stat_metadata(dirfd(directory_.get()), nullptr, true, scope_);
#endif
    }
    Observation<std::unique_ptr<OpenedEntry>> open_parent_directory() const override { return open_posix_parent(dirfd(directory_.get()), scope_); }
    Observation<CreatedStagingFile> create_staging_file(const NativeName& recovery_hint) const override {
        using Result = Observation<CreatedStagingFile>;
        if (!recovery_hint.is_valid() || !recovery_hint.posix_bytes())
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InvalidIdentifier, "create_staging_file.hint"));
#if defined(__linux__)
        OwnedDescriptor parent(fcntl(dirfd(directory_.get()), F_DUPFD_CLOEXEC, 0));
        if (parent.get() < 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "create_staging_file.parent"});
        auto created = detail::create_linux_anonymous_staging(parent.get());
        if (!created.value()) return Result::unavailable(created.state(), created.unavailable_detail()->error);
        OwnedDescriptor file(std::move(created).take_value());
        auto entry = std::make_unique<PosixOpenedEntry>(std::move(file), scope_, false, true, true,
            std::make_unique<PosixPublicationContext>(std::move(parent), recovery_hint, true));
        return Result::available({std::move(entry), StagingNamespace::Anonymous, std::nullopt});
#else
        return Result::unavailable(ObservationState::Unsupported,
            adapter_error(AdapterError::UnsupportedQuery, "create_staging_file.fd_publication_unqualified"));
#endif
    }
    Observation<std::unique_ptr<OpenedEntry>> create_child_file(const NativeName& name) const override {
        using Result = Observation<std::unique_ptr<OpenedEntry>>;
        const auto* spelling = name.posix_bytes();
        if (!name.is_valid() || !spelling)
            return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidIdentifier, "create_child_file.name"));
        const int parent = fcntl(dirfd(directory_.get()), F_DUPFD_CLOEXEC, 0);
        if (parent < 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "fcntl.create_child_file_parent"});
        OwnedDescriptor retained_parent(parent);
        OwnedDescriptor descriptor(openat(dirfd(directory_.get()), spelling->c_str(),
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        if (descriptor.get() < 0) {
            const int code = errno;
            return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "openat.create_child_file"});
        }
        struct stat native{};
        if (fstat(descriptor.get(), &native) != 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "fstat.create_child_file"});
        if (!S_ISREG(native.st_mode) || native.st_nlink != 1)
            return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidNativeResult, "create_child_file.kind"));
        return Result::available(std::make_unique<PosixOpenedEntry>(std::move(descriptor), scope_, false, true, true,
            std::make_unique<PosixPublicationContext>(std::move(retained_parent), name)));
    }
    Observation<bool> create_hard_link(const NativeName& source_name, const ObjectIdentity& expected_source,
                                        const DirectoryCursor& destination,
                                        const NativeName& destination_name) const override {
        using Result = Observation<bool>;
        const auto *source_spelling = source_name.posix_bytes();
        const auto *destination_spelling = destination_name.posix_bytes();
        const auto *target = dynamic_cast<const PosixDirectoryCursor *>(&destination);
        if (!source_name.is_valid() || !destination_name.is_valid() || !source_spelling || !destination_spelling)
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InvalidIdentifier, "create_hard_link.name"));
        if (!target || !identity().value() || !target->identity().value() ||
            scope_ != target->scope_ ||
            identity().value()->scheme != target->identity().value()->scheme ||
            identity().value()->volume != target->identity().value()->volume)
            return Result::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::UnsupportedQuery, "create_hard_link.destination"));
        const auto source_metadata = stat_metadata(dirfd(directory_.get()), source_spelling->c_str(), false, scope_,
                                                   AT_SYMLINK_NOFOLLOW);
        if (!source_metadata.value())
            return Result::unavailable(source_metadata.unavailable_detail()->state,
                                       source_metadata.unavailable_detail()->error);
        if (!source_metadata.value()->identity.value() ||
            compare_identity(*source_metadata.value()->identity.value(), expected_source) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                adapter_error(AdapterError::MetadataChanged, "create_hard_link.source_identity"));
        if (!source_metadata.value()->kind.value() ||
            *source_metadata.value()->kind.value() != ObjectKind::RegularFile)
            return Result::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::NotApplicable, "create_hard_link.source_kind"));
        if (linkat(dirfd(directory_.get()), source_spelling->c_str(), dirfd(target->directory_.get()),
                   destination_spelling->c_str(), 0) != 0) {
            const int code = errno;
            return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "linkat.create_hard_link"});
        }
        const auto published = stat_metadata(dirfd(target->directory_.get()), destination_spelling->c_str(), false,
                                             target->scope_,
                                             AT_SYMLINK_NOFOLLOW);
        if (!published.value() || !published.value()->identity.value() ||
            compare_identity(*published.value()->identity.value(), *source_metadata.value()->identity.value()) !=
                IdentityComparison::Same)
            return Result::unavailable(ObservationState::Unknown,
                adapter_error(AdapterError::MetadataChanged, "create_hard_link.published_identity"));
        if (fsync(dirfd(target->directory_.get())) != 0)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Posix, errno, "fsync.create_hard_link_parent"});
        return Result::available(true);
    }
    Observation<bool> create_symbolic_link(const SymbolicLinkTarget& target,
                                           const NativeName& destination_name) const override {
        using Result = Observation<bool>;
        const auto* target_bytes = std::get_if<std::string>(&target);
        const auto* spelling = destination_name.posix_bytes();
        if (!destination_name.is_valid() || !spelling || !target_bytes || target_bytes->empty() ||
            target_bytes->find('\0') != std::string::npos)
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InvalidIdentifier, "create_symbolic_link.input"));
        errno = 0;
        const auto maximum = fpathconf(dirfd(directory_.get()), _PC_SYMLINK_MAX);
        if (maximum == 0 || (maximum < 0 && errno != 0))
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "fpathconf.create_symbolic_link"});
        if (maximum > 0 && target_bytes->size() > static_cast<std::size_t>(maximum))
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InventoryLimit, "create_symbolic_link.target_limit"));
        if (symlinkat(target_bytes->c_str(), dirfd(directory_.get()), spelling->c_str()) != 0) {
            const int code = errno;
            if (code == EEXIST) return Result::unavailable(ObservationState::Changed,
                {ErrorDomain::Posix, code, "symlinkat.destination_occupied"});
            return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "symlinkat.create_symbolic_link"});
        }
        const auto published = stat_metadata(dirfd(directory_.get()), spelling->c_str(), false, scope_, AT_SYMLINK_NOFOLLOW);
        if (!published.value() || !published.value()->identity.value() || !published.value()->kind.value() ||
            *published.value()->kind.value() != ObjectKind::SymbolicLink)
            return Result::unavailable(ObservationState::Unknown,
                adapter_error(AdapterError::InvalidNativeResult, "create_symbolic_link.published_metadata"));
        auto opened = open_child(destination_name, EntryAccess::MetadataOnly);
        if (!opened.value()) {
            const auto& error = *opened.unavailable_detail();
            return Result::unavailable(ObservationState::Unknown, error.error);
        }
        auto link = (*opened.value())->read_link_metadata();
        if (!link.value() || link.value()->owner.value() == nullptr ||
            compare_identity(*link.value()->owner.value(), *published.value()->identity.value()) != IdentityComparison::Same ||
            !std::holds_alternative<PosixSymlinkData>(link.value()->payload) ||
            std::get<PosixSymlinkData>(link.value()->payload).target != *target_bytes)
            return Result::unavailable(ObservationState::Unknown,
                adapter_error(AdapterError::MetadataChanged, "create_symbolic_link.published_target"));
        if (fsync(dirfd(directory_.get())) != 0)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Posix, errno, "fsync.create_symbolic_link_parent"});
        return Result::available(true);
    }
    Observation<std::unique_ptr<DirectoryCursor>> create_child_directory(const NativeName& name) const override {
        using Result = Observation<std::unique_ptr<DirectoryCursor>>;
        const auto* spelling = name.posix_bytes();
        if (!name.is_valid() || !spelling)
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InvalidIdentifier, "create_child_directory.name"));
        if (mkdirat(dirfd(directory_.get()), spelling->c_str(), 0700) != 0) {
            const int code = errno;
            if (code == EEXIST)
                return Result::unavailable(ObservationState::Changed,
                    adapter_error(AdapterError::PlanDecisionStale, "create_child_directory.existing"));
            return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "mkdirat.create_child_directory"});
        }

        struct stat expected{};
        if (fstatat(dirfd(directory_.get()), spelling->c_str(), &expected, AT_SYMLINK_NOFOLLOW) != 0)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Posix, errno, "create_child_directory.created_identity"});
        if (!S_ISDIR(expected.st_mode))
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InvalidNativeResult, "create_child_directory.created_kind"));
        const int raw = openat(dirfd(directory_.get()), spelling->c_str(),
#if defined(__linux__)
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
#else
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
#endif
        );
        if (raw < 0) {
            const int code = errno;
            return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "openat.create_child_directory"});
        }
        OwnedDirectory opened(fdopendir(raw));
        if (!opened) {
            const int code = errno;
            close(raw);
            return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "openat.create_child_directory"});
        }
        struct stat actual{};
        if (fstat(dirfd(opened.get()), &actual) != 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "fstat.create_child_directory"});
        if (!S_ISDIR(actual.st_mode) || actual.st_dev != expected.st_dev || actual.st_ino != expected.st_ino)
            return Result::unavailable(ObservationState::Changed,
                adapter_error(AdapterError::MetadataChanged, "create_child_directory.identity"));
        if (fsync(dirfd(directory_.get())) != 0) {
            const int code = errno;
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Posix, code, "fsync.create_child_directory_parent"});
        }
        std::optional<std::uint64_t> generation;
#if defined(__APPLE__)
        generation = actual.st_gen;
#endif
        auto observed = Observation<ObjectIdentity>::available({scope_, IdentityScheme::PosixDeviceInode,
            NativeIdentifier::from_u64(static_cast<std::uint64_t>(actual.st_dev)),
            NativeIdentifier::from_u64(static_cast<std::uint64_t>(actual.st_ino)), generation});
        return Result::available(std::make_unique<PosixDirectoryCursor>(std::move(opened), std::move(observed), scope_));
    }
    Observation<bool> trash_child(const NativeName& name, const ObjectIdentity& expected_identity) const override {
        using Result = Observation<bool>;
        const auto* spelling = name.posix_bytes();
        if (!name.is_valid() || !spelling)
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InvalidIdentifier, "trash_child.name"));
        if (compare_identity(expected_identity, expected_identity) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::UnqualifiedIdentity, "trash_child.identity"));

        const int source_parent = dirfd(directory_.get());
        struct stat source_parent_stat{};
        if (fstat(source_parent, &source_parent_stat) != 0)
            return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "trash_child.parent"});
        const auto source_path = descriptor_path(source_parent, "trash_child.original_parent");
        if (!source_path.value()) {
            const auto& e = *source_path.unavailable_detail();
            return Result::unavailable(e.state, e.error);
        }
        const auto metadata = stat_metadata(source_parent, spelling->c_str(), false, scope_);
        if (!metadata.value() || !metadata.value()->identity.value() || !metadata.value()->kind.value()) {
            if (!metadata.value()) {
                const auto& e = *metadata.unavailable_detail();
                return Result::unavailable(e.state, e.error);
            }
            return Result::unavailable(ObservationState::Unknown,
                adapter_error(AdapterError::UnqualifiedIdentity, "trash_child.source_metadata"));
        }
        if (compare_identity(*metadata.value()->identity.value(), expected_identity) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                adapter_error(AdapterError::MetadataChanged, "trash_child.source_identity"));
        if (*metadata.value()->kind.value() == ObjectKind::Fifo || *metadata.value()->kind.value() == ObjectKind::Socket ||
            *metadata.value()->kind.value() == ObjectKind::CharacterDevice || *metadata.value()->kind.value() == ObjectKind::BlockDevice ||
            *metadata.value()->kind.value() == ObjectKind::Other)
            return Result::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::NotApplicable, "trash_child.kind"));
        if (*metadata.value()->kind.value() == ObjectKind::RegularFile &&
            metadata.value()->link_count.value() && *metadata.value()->link_count.value() > 1)
            return Result::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::UnsupportedQuery, "trash_child.hard_link"));

        const std::string original_path = *source_path.value() == "/"
            ? "/" + *spelling : *source_path.value() + "/" + *spelling;
        auto directories = open_trash_directories(source_parent, source_parent_stat, "trash_child.directories");
        if (!directories.value()) {
            const auto& e = *directories.unavailable_detail();
            return Result::unavailable(e.state, e.error);
        }
        auto trash = std::move(directories).take_value();
        const auto name_limit = fpathconf(trash.files.get(), _PC_NAME_MAX);
        const std::size_t max_component = name_limit > 0 ? static_cast<std::size_t>(name_limit) : 255U;
        const auto suffix = std::string(".ck-") + std::to_string(static_cast<unsigned long long>(getpid()));
        const auto info_suffix = std::string(".trashinfo");
        const auto can_use_original = spelling->size() <= max_component &&
                                      spelling->size() + info_suffix.size() <= max_component;
        const auto original_candidate = can_use_original ? *spelling : std::string{};
        const auto body = std::string("[Trash Info]\nPath=file://") + percent_encode_path(original_path) +
                          "\nDeletionDate=" + deletion_date() + "\n";

        for (std::uint32_t attempt = 0; attempt < 10000; ++attempt) {
            std::string candidate = original_candidate;
            if (candidate.empty() || attempt != 0)
                candidate = std::string("ckutilities") + suffix + "-" + std::to_string(attempt);
            if (candidate.size() > max_component || candidate.size() + info_suffix.size() > max_component)
                continue;
            const auto info_name = candidate + info_suffix;
            errno = 0;
            OwnedDescriptor info(openat(trash.info.get(), info_name.c_str(),
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
            if (info.get() < 0) {
                if (errno == EEXIST) continue;
                if (errno == ENAMETOOLONG) continue;
                return Result::unavailable(errno_state(errno), {ErrorDomain::Posix, errno, "trash_child.metadata_create"});
            }
            bool metadata_written = true;
            std::size_t offset = 0;
            while (offset < body.size()) {
                const auto written = write(info.get(), body.data() + offset, body.size() - offset);
                if (written < 0) {
                    if (errno == EINTR) continue;
                    metadata_written = false;
                    break;
                }
                if (written == 0) {
                    metadata_written = false;
                    break;
                }
                offset += static_cast<std::size_t>(written);
            }
            if (!metadata_written || fsync(info.get()) != 0) {
                const int code = errno;
                unlinkat(trash.info.get(), info_name.c_str(), 0);
                return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "trash_child.metadata_write"});
            }

            if (rename_noreplace(source_parent, spelling->c_str(), trash.files.get(), candidate.c_str()) != 0) {
                const int code = errno;
                unlinkat(trash.info.get(), info_name.c_str(), 0);
                if (code == EEXIST) continue;
                if (code == EXDEV || code == ENOSYS || code == ENOTSUP || code == EOPNOTSUPP)
                    return Result::unavailable(ObservationState::Unsupported,
                        {ErrorDomain::Posix, code, "trash_child.mount_or_atomic_primitive"});
                return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "trash_child.native_rename"});
            }

            const auto published = stat_metadata(trash.files.get(), candidate.c_str(), false, scope_);
            if (!published.value() || !published.value()->identity.value() ||
                compare_identity(*published.value()->identity.value(), expected_identity) != IdentityComparison::Same)
                return Result::unavailable(ObservationState::Unknown,
                    adapter_error(AdapterError::UnqualifiedIdentity, "trash_child.destination_identity"));
            if (fsync(trash.files.get()) != 0 || fsync(source_parent) != 0 || fsync(trash.info.get()) != 0) {
                const int code = errno;
                return Result::unavailable(ObservationState::Unknown,
                    {ErrorDomain::Posix, code, "trash_child.directory_fsync"});
            }
            return Result::available(true);
        }
        return Result::unavailable(ObservationState::Unknown,
            adapter_error(AdapterError::InventoryLimit, "trash_child.name_exhausted"));
    }
    Observation<bool> publish_anonymous_noreplace(int source, const NativeName& name) const {
#if defined(__linux__)
        const auto now = inspect_basic();
        if (!now.value()) return Observation<bool>::unavailable(now.state(), now.unavailable_detail()->error);
        if (!identity().value() || !now.value()->identity.value() ||
            compare_identity(*identity().value(), *now.value()->identity.value()) != IdentityComparison::Same)
            return Observation<bool>::unavailable(ObservationState::Changed,
                adapter_error(AdapterError::MetadataChanged, "publish_anonymous.parent_changed"));
        return detail::publish_linux_anonymous_staging(source, dirfd(directory_.get()), name);
#else
        (void)source; (void)name;
        return Observation<bool>::unavailable(ObservationState::Unsupported,
            adapter_error(AdapterError::UnsupportedQuery, "publish_anonymous.native_unavailable"));
#endif
    }

    Observation<bool> rename_child_noreplace(const NativeName& name, const ObjectIdentity& expected_identity,
                                              const DirectoryCursor& destination,
                                              const NativeName& destination_name) const override {
        using Result = Observation<bool>;
        const auto* target = dynamic_cast<const PosixDirectoryCursor*>(&destination);
        const auto* source_spelling = name.posix_bytes();
        const auto* destination_spelling = destination_name.posix_bytes();
        if (!target || !name.is_valid() || !destination_name.is_valid() || !source_spelling || !destination_spelling)
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InvalidIdentifier, "rename_child_noreplace.name"));
        if (compare_identity(expected_identity, expected_identity) != IdentityComparison::Same ||
            !identity().value() || !destination.identity().value())
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::UnqualifiedIdentity, "rename_child_noreplace.identity"));

        const auto source = stat_metadata(dirfd(directory_.get()), source_spelling->c_str(), false, scope_);
        if (!source.value() || !source.value()->identity.value() ||
            compare_identity(*source.value()->identity.value(), expected_identity) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                adapter_error(AdapterError::MetadataChanged, "rename_child_noreplace.source_identity"));

        const auto occupied = stat_metadata(dirfd(target->directory_.get()), destination_spelling->c_str(), false, target->scope_);
        if (occupied.value())
            return Result::unavailable(ObservationState::Changed,
                adapter_error(AdapterError::PlanDecisionStale, "rename_child_noreplace.destination_occupied"));
        if (occupied.state() != ObservationState::Gone) {
            const auto& error = *occupied.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }

        int status = -1;
#if defined(__linux__) && defined(SYS_renameat2)
        constexpr unsigned int no_replace = 1U;
        status = static_cast<int>(syscall(SYS_renameat2, dirfd(directory_.get()), source_spelling->c_str(),
                                           dirfd(target->directory_.get()), destination_spelling->c_str(), no_replace));
#elif defined(__APPLE__)
        status = renameatx_np(dirfd(directory_.get()), source_spelling->c_str(), dirfd(target->directory_.get()),
                              destination_spelling->c_str(), RENAME_EXCL);
#else
        errno = ENOTSUP;
#endif
        if (status != 0) {
            const int code = errno;
            if (code == EEXIST)
                return Result::unavailable(ObservationState::Changed,
                    adapter_error(AdapterError::PlanDecisionStale, "rename_child_noreplace.destination_occupied"));
            if (code == ENOSYS || code == ENOTSUP || code == EOPNOTSUPP)
                return Result::unavailable(ObservationState::Unsupported,
                    {ErrorDomain::Posix, code, "rename_child_noreplace.atomic_primitive"});
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Posix, code, "rename_child_noreplace.atomic_primitive"});
        }

        const auto published = stat_metadata(dirfd(target->directory_.get()), destination_spelling->c_str(), false, target->scope_);
        if (!published.value() || !published.value()->identity.value() ||
            compare_identity(*published.value()->identity.value(), *source.value()->identity.value()) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Posix, static_cast<std::int64_t>(errno), "rename_child_noreplace.destination_identity"});
        if (fsync(dirfd(target->directory_.get())) != 0) {
            const int code = errno;
            return Result::unavailable(ObservationState::Unknown, {ErrorDomain::Posix, code, "rename_child_noreplace.destination_fsync"});
        }
        if (fsync(dirfd(directory_.get())) != 0) {
            const int code = errno;
            return Result::unavailable(ObservationState::Unknown, {ErrorDomain::Posix, code, "rename_child_noreplace.source_fsync"});
        }
        return Result::available(true);
    }

    Observation<bool> rename_child_case_only(const NativeName& name, const ObjectIdentity& expected_identity,
                                              const NativeName& destination_name) const override {
        using Result = Observation<bool>;
        const auto* source_spelling = name.posix_bytes();
        const auto* destination_spelling = destination_name.posix_bytes();
        if (!name.is_valid() || !destination_name.is_valid() || !source_spelling || !destination_spelling || name == destination_name)
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InvalidIdentifier, "rename_child_case_only.name"));
        if (compare_identity(expected_identity, expected_identity) != IdentityComparison::Same || !identity().value())
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::UnqualifiedIdentity, "rename_child_case_only.identity"));

        const auto source = stat_metadata(dirfd(directory_.get()), source_spelling->c_str(), false, scope_);
        if (!source.value() || !source.value()->identity.value() ||
            compare_identity(*source.value()->identity.value(), expected_identity) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                adapter_error(AdapterError::MetadataChanged, "rename_child_case_only.source_identity"));
        const auto destination = stat_metadata(dirfd(directory_.get()), destination_spelling->c_str(), false, scope_);
        if (!destination.value() || !destination.value()->identity.value())
            return Result::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::UnsupportedQuery, "rename_child_case_only.native_case_proof"));
        if (compare_identity(*destination.value()->identity.value(), *source.value()->identity.value()) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                adapter_error(AdapterError::PlanDecisionStale, "rename_child_case_only.destination_identity"));

        if (renameat(dirfd(directory_.get()), source_spelling->c_str(), dirfd(directory_.get()), destination_spelling->c_str()) != 0) {
            const int code = errno;
            return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "rename_child_case_only.native_primitive"});
        }
        const auto published = stat_metadata(dirfd(directory_.get()), destination_spelling->c_str(), false, scope_);
        if (!published.value() || !published.value()->identity.value() ||
            compare_identity(*published.value()->identity.value(), *source.value()->identity.value()) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Posix, static_cast<std::int64_t>(errno), "rename_child_case_only.destination_identity"});
        if (fsync(dirfd(directory_.get())) != 0) {
            const int code = errno;
            return Result::unavailable(ObservationState::Unknown, {ErrorDomain::Posix, code, "rename_child_case_only.parent_fsync"});
        }
        return Result::available(true);
    }

    Observation<DirectoryAccessCheck> check_access(DirectoryAccess access) const override {
        using Result = Observation<DirectoryAccessCheck>;
        if (!valid_directory_access(access)) return Result::unavailable(ObservationState::Failed,
            adapter_error(AdapterError::InvalidAccess, "directory.check_access"));
#if defined(__linux__)
        constexpr auto model = StorageModel::LinuxStatx;
#else
        constexpr auto model = StorageModel::DarwinStatFlags;
#endif
        const auto before = inspect_basic();
        const auto qualified = detail::qualify_access_directory(before, before, model);
        if (!qualified.value()) { const auto& e = *qualified.unavailable_detail(); return Result::unavailable(e.state, e.error); }
#if defined(__linux__) && !defined(SYS_faccessat2)
        return Result::unavailable(ObservationState::Unsupported, adapter_error(AdapterError::UnsupportedQuery, "faccessat2.unavailable"));
#else
        const int mode = access == DirectoryAccess::List ? R_OK : access == DirectoryAccess::Search ? X_OK : W_OK | X_OK;
        const int fd = dirfd(directory_.get());
#if defined(__linux__)
        const auto status = syscall(SYS_faccessat2, fd, "", mode, AT_EMPTY_PATH | AT_EACCESS);
        constexpr auto operation = "faccessat2.directory_effective_access";
        constexpr auto family = DirectoryAccessFamily::LinuxFaccessat2;
#else
        const auto status = faccessat(fd, ".", mode, AT_EACCESS);
        constexpr auto operation = "faccessat.directory_effective_access";
        constexpr auto family = DirectoryAccessFamily::DarwinFaccessat;
#endif
        if (status != 0) { const int code = errno; return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, operation}); }
        auto identity = detail::qualify_access_directory(before, inspect_basic(), model);
        if (!identity.value()) { const auto& e = *identity.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        return Result::available({access, family, std::move(identity).take_value(), static_cast<std::uint32_t>(mode)});
#endif
    }

    Observation<DirectoryFscryptKeyStatus> inspect_fscrypt_key_status() const override {
#if defined(__linux__) && defined(FS_IOC_GET_ENCRYPTION_KEY_STATUS)
        using Result = Observation<DirectoryFscryptKeyStatus>;
        static_assert(sizeof(fscrypt_get_key_status_arg) == 128 && sizeof(fscrypt_key_specifier) == 40);
        static_assert(offsetof(fscrypt_get_key_status_arg, status) == 64 && offsetof(fscrypt_get_key_status_arg, status_flags) == 68);
        static_assert(offsetof(fscrypt_get_key_status_arg, user_count) == 72 && offsetof(fscrypt_get_key_status_arg, __out_reserved) == 76);
        static_assert(FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR == 1 && FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER == 2);
        static_assert(FSCRYPT_KEY_STATUS_ABSENT == 1 && FSCRYPT_KEY_STATUS_PRESENT == 2 && FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED == 3);
        static_assert(FSCRYPT_KEY_STATUS_FLAG_ADDED_BY_SELF == 1);
        const auto before = inspect_fscrypt_policy();
        const auto qualified = detail::qualify_fscrypt_key_policy(before, before);
        if (!qualified.value()) { const auto& e = *qualified.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto& policy = std::get<FscryptPolicyData>(before.value()->policy);
        fscrypt_get_key_status_arg native{};
        native.key_spec.type = policy.version() == 0 ? FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR : FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
        const auto reference = policy.key_reference();
        auto* destination = policy.version() == 0 ? native.key_spec.u.descriptor : native.key_spec.u.identifier;
        for (std::size_t i = 0; i < reference.size(); ++i) destination[i] = std::to_integer<unsigned char>(reference[i]);
        const auto requested = native.key_spec;
        constexpr const char* operation = "FS_IOC_GET_ENCRYPTION_KEY_STATUS.directory";
        const int status = ioctl(dirfd(directory_.get()), FS_IOC_GET_ENCRYPTION_KEY_STATUS, &native);
        if (status < 0) { const int code = errno; return Result::unavailable(code == ENOTTY ? ObservationState::Unsupported :
            code == EINVAL ? ObservationState::Unknown : errno_state(code), {ErrorDomain::Posix, code, operation}); }
        if (status != 0 || std::memcmp(&requested, &native.key_spec, sizeof(requested)) != 0 ||
            std::any_of(std::begin(native.__reserved), std::end(native.__reserved), [](auto value) { return value != 0; }))
            return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidNativeResult, "fscrypt.key_status_reply"));
        const auto identity = detail::qualify_fscrypt_key_policy(before, inspect_fscrypt_policy());
        if (!identity.value()) { const auto& e = *identity.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        FscryptKeyStatusData key{native.status, native.status_flags, native.user_count, {}};
        std::copy(std::begin(native.__out_reserved), std::end(native.__out_reserved), key.reserved.begin());
        return Result::available({*identity.value(), policy, key});
#else
        return DirectoryCursor::inspect_fscrypt_key_status();
#endif
    }

    Observation<DirectoryFscryptPolicy> inspect_fscrypt_policy() const override {
#if defined(__linux__) && defined(FS_IOC_GET_ENCRYPTION_POLICY_EX)
        using Result = Observation<DirectoryFscryptPolicy>;
        static_assert(sizeof(fscrypt_policy_v1) == 12 && sizeof(fscrypt_policy_v2) == 24);
        static_assert(offsetof(fscrypt_get_policy_ex_arg, policy) == 8 && sizeof(fscrypt_get_policy_ex_arg) == 32);
        static_assert(FSCRYPT_POLICY_V1 == 0 && FSCRYPT_POLICY_V2 == 2 && STATX_ATTR_ENCRYPTED == 0x800);
        static_assert(offsetof(fscrypt_policy_v1, master_key_descriptor) == 4 && offsetof(fscrypt_policy_v2, master_key_identifier) == 8);
        static_assert(offsetof(fscrypt_policy_v1, flags) == 3 && offsetof(fscrypt_policy_v2, flags) == 3);
        const auto before = inspect_basic();
        const auto qualified = detail::qualify_fscrypt_directory(before, before);
        if (!qualified.value()) { const auto& e = *qualified.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        fscrypt_get_policy_ex_arg native{}; native.policy_size = sizeof(native.policy);
        constexpr const char* operation = "FS_IOC_GET_ENCRYPTION_POLICY_EX.directory";
        const int status = ioctl(dirfd(directory_.get()), FS_IOC_GET_ENCRYPTION_POLICY_EX, &native);
        const int code = status < 0 ? errno : 0;
        if (status > 0) return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidNativeResult, "fscrypt.ioctl_status"));
        if (status != 0 && code != ENODATA)
            return Result::unavailable(code == ENOTTY ? ObservationState::Unsupported :
                code == EOVERFLOW || code == EINVAL ? ObservationState::Unknown : errno_state(code), {ErrorDomain::Posix, code, operation});
        const bool present = status == 0;
        std::variant<FscryptPolicyAbsent, FscryptPolicyData> policy{FscryptPolicyAbsent{{ErrorDomain::Posix, code, operation}}};
        if (present) {
            if (native.policy_size > sizeof(native.policy)) return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InvalidNativeResult, "fscrypt.returned_policy_size"));
            auto decoded = FscryptPolicyData::decode(std::as_bytes(std::span(&native.policy, 1)).first(static_cast<std::size_t>(native.policy_size)));
            if (!decoded.value()) { const auto& e = *decoded.unavailable_detail(); return Result::unavailable(e.state, e.error); }
            policy = std::move(decoded).take_value();
        }
        auto identity = detail::qualify_fscrypt_directory(before, inspect_basic(), present);
        if (!identity.value()) { const auto& e = *identity.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        return Result::available({std::move(identity).take_value(), std::move(policy)});
#else
        return DirectoryCursor::inspect_fscrypt_policy();
#endif
    }

    Observation<LocationInfo> inspect_location() const override {
        LocationInfo result;
        const auto fd = dirfd(directory_.get());
        const auto metadata = stat_metadata(fd, nullptr, true, scope_);
        if (!metadata.value()) {
            const auto& e = *metadata.unavailable_detail();
            return Observation<LocationInfo>::unavailable(e.state, e.error);
        }
        result.directory = metadata.value()->identity;
        result.volume_query_serial = not_applicable<std::uint64_t>("volume.query_serial");
        result.windows_component_utf16_max = not_applicable<std::uint64_t>("volume.windows_component_limit");
        result.windows_directory_case_flags = not_applicable<std::uint32_t>("volume.windows_directory_case_flags");
        const auto limit = [&](int name, const char* operation) { return descriptor_limit(fd, name, operation); };
        result.posix_name_max = limit(_PC_NAME_MAX, "fpathconf.name_max");
        result.posix_path_max = limit(_PC_PATH_MAX, "fpathconf.path_max");
        result.posix_file_size_bits = limit(_PC_FILESIZEBITS, "fpathconf.file_size_bits");
        result.posix_symlink_max = limit(_PC_SYMLINK_MAX, "fpathconf.symlink_max");
#if defined(__linux__)
        result.family = LocationQueryFamily::LinuxDescriptor;
        // The ioctl ABI takes int*, despite its historical long-sized request
        // encoding. No SETFLAGS, path reopen, synchronization or retry occurs.
        static_assert(sizeof(int) == sizeof(std::uint32_t));
        static_assert(FS_CASEFOLD_FL == 0x40000000U && FS_ENCRYPT_FL == 0x800U && EXT4_SUPER_MAGIC == 0xef53U);
        static_assert(FS_NOCOW_FL == 0x00800000U && FS_PROJINHERIT_FL == 0x20000000U);
        int inode_flags = 0;
        if (ioctl(fd, FS_IOC_GETFLAGS, &inode_flags) == 0)
            result.linux_directory_inode_flags = Observation<std::uint32_t>::available(static_cast<std::uint32_t>(inode_flags));
        else {
            const int code = errno;
            result.linux_directory_inode_flags = Observation<std::uint32_t>::unavailable(
                code == ENOTTY ? ObservationState::Unsupported : errno_state(code),
                {ErrorDomain::Posix, code, "FS_IOC_GETFLAGS.directory"});
        }

        result.posix_name_chars_max = not_applicable<std::uint64_t>("volume.name_chars_max");
        result.features = Observation<NativeVolumeFeatures>::unavailable(ObservationState::Unsupported,
            adapter_error(AdapterError::UnsupportedQuery, "volume.feature_advertisements"));
        result.case_sensitive_directory = Observation<bool>::unavailable(ObservationState::Unsupported,
            adapter_error(AdapterError::UnsupportedQuery, "volume.directory_case"));
        result.case_preserving_names = Observation<bool>::unavailable(ObservationState::Unsupported,
            adapter_error(AdapterError::UnsupportedQuery, "volume.case_preservation"));
        result.filesystem_name = Observation<NativeFeatureIdentifier>::unavailable(ObservationState::Unsupported,
            adapter_error(AdapterError::UnsupportedQuery, "volume.filesystem_name"));
        struct statvfs space{};
        if (fstatvfs(fd, &space) == 0) {
            result.native_mount_flags = Observation<std::uint64_t>::available(space.f_flag);
            result.read_only_mount = Observation<bool>::available((space.f_flag & ST_RDONLY) != 0);
            result.space_accounting_unit = detail::space_bytes(1, space.f_frsize);
            result.total_bytes = detail::space_bytes(space.f_blocks, space.f_frsize);
            result.free_bytes = detail::space_bytes(space.f_bfree, space.f_frsize);
            result.available_bytes = detail::space_bytes(space.f_bavail, space.f_frsize);
        } else {
            const int code = errno;
            const NativeError error{ErrorDomain::Posix, code, "fstatvfs"};
            result.native_mount_flags = Observation<std::uint64_t>::unavailable(errno_state(code), error);
            result.read_only_mount = Observation<bool>::unavailable(errno_state(code), error);
            result.space_accounting_unit = result.total_bytes = result.free_bytes = result.available_bytes =
                Observation<std::uint64_t>::unavailable(errno_state(code), error);
        }
        struct statfs native{};
#else
        result.family = LocationQueryFamily::DarwinDescriptor;
        result.linux_directory_inode_flags = not_applicable<std::uint32_t>("volume.linux_directory_inode_flags");
        result.posix_name_chars_max = limit(_PC_NAME_CHARS_MAX, "fpathconf.name_chars_max");
        const auto boolean = [&](int name, const char* operation) {
            errno = 0;
            const auto value = fpathconf(fd, name);
            const int code = errno;
            if (value < 0) return Observation<bool>::unavailable(code == 0 ? ObservationState::Unknown : errno_state(code),
                {ErrorDomain::Posix, code, operation});
            if (value > 1) return Observation<bool>::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidNativeResult, operation));
            return Observation<bool>::available(value != 0);
        };
        result.case_sensitive_directory = boolean(_PC_CASE_SENSITIVE, "fpathconf.case_sensitive");
        result.case_preserving_names = boolean(_PC_CASE_PRESERVING, "fpathconf.case_preserving");
        struct CapabilityRecord { std::uint32_t length; vol_capabilities_attr_t caps; } capabilities{};
        static_assert(offsetof(CapabilityRecord, caps) == 4 && sizeof(CapabilityRecord) == 36);
        struct attrlist attributes{};
        attributes.bitmapcount = ATTR_BIT_MAP_COUNT;
        attributes.volattr = ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES;
        if (fgetattrlist(fd, &attributes, &capabilities, sizeof(capabilities), 0) == 0) {
            if (capabilities.length == sizeof(capabilities)) {
                NativeVolumeFeatures features;
                features.domain = VolumeFeatureDomain::DarwinVolumeCapabilities;
                for (std::size_t group = 0; group < 4; ++group) {
                    features.value[group] = capabilities.caps.capabilities[group];
                    features.valid[group] = capabilities.caps.valid[group];
                }
                result.features = Observation<NativeVolumeFeatures>::available(features);
            } else result.features = Observation<NativeVolumeFeatures>::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InvalidNativeResult, "fgetattrlist.volume_capabilities_size"));
        } else {
            const int code = errno;
            result.features = Observation<NativeVolumeFeatures>::unavailable(code == EINVAL ? ObservationState::Unsupported : errno_state(code),
                {ErrorDomain::Posix, code, "fgetattrlist.volume_capabilities"});
        }
        struct statfs native{};
#endif
        if (fstatfs(fd, &native) == 0) {
            result.filesystem_type_code = Observation<std::uint64_t>::available(static_cast<std::uint64_t>(native.f_type));
            NativeIdentifier id;
            static_assert(sizeof(native.f_fsid) <= sizeof(id.bytes));
            std::memcpy(id.bytes.data(), &native.f_fsid, sizeof(native.f_fsid));
            result.filesystem_query_id = Observation<NativeIdentifier>::available(id);
#if defined(__APPLE__)
            result.native_mount_flags = Observation<std::uint64_t>::available(native.f_flags);
            result.read_only_mount = Observation<bool>::available((native.f_flags & MNT_RDONLY) != 0);
            result.space_accounting_unit = detail::space_bytes(1, native.f_bsize);
            result.total_bytes = detail::space_bytes(native.f_blocks, native.f_bsize);
            result.free_bytes = detail::space_bytes(native.f_bfree, native.f_bsize);
            result.available_bytes = detail::space_bytes(native.f_bavail, native.f_bsize);
            const auto length = strnlen(native.f_fstypename, sizeof(native.f_fstypename));
            auto name = length < sizeof(native.f_fstypename) ? NativeFeatureIdentifier::from_posix(std::string(native.f_fstypename, length)) : std::nullopt;
            result.filesystem_name = name ? Observation<NativeFeatureIdentifier>::available(std::move(*name)) :
                Observation<NativeFeatureIdentifier>::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidNativeResult, "fstatfs.filesystem_name"));
#endif
        } else {
            const int code = errno;
            const NativeError error{ErrorDomain::Posix, code, "fstatfs"};
            result.filesystem_type_code = Observation<std::uint64_t>::unavailable(errno_state(code), error);
            result.filesystem_query_id = Observation<NativeIdentifier>::unavailable(errno_state(code), error);
#if defined(__APPLE__)
            result.filesystem_name = Observation<NativeFeatureIdentifier>::unavailable(errno_state(code), error);
            result.native_mount_flags = Observation<std::uint64_t>::unavailable(errno_state(code), error);
            result.read_only_mount = Observation<bool>::unavailable(errno_state(code), error);
            result.space_accounting_unit = result.total_bytes = result.free_bytes = result.available_bytes =
                Observation<std::uint64_t>::unavailable(errno_state(code), error);
#endif
        }
        return Observation<LocationInfo>::available(std::move(result));
    }
    Observation<std::unique_ptr<DirectoryCursor>> open_directory_child(const NativeName& name) const override {
        using Result = Observation<std::unique_ptr<DirectoryCursor>>;
        const auto* spelling = name.posix_bytes();
        if (!name.is_valid() || !spelling) return Result::unavailable(ObservationState::Failed,
            adapter_error(AdapterError::InvalidIdentifier, "open_directory_child.name"));
        OwnedDescriptor fd(openat(dirfd(directory_.get()), spelling->c_str(),
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC));
        if (fd.get() < 0) {
            const int code = errno;
            return Result::unavailable(code == ENOTDIR ? ObservationState::Failed : errno_state(code),
                {ErrorDomain::Posix, code, "openat.directory_child"});
        }
        struct stat native{};
        if (fstat(fd.get(), &native) != 0) {
            const int code = errno;
            return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "fstat.directory_child"});
        }
        std::optional<std::uint64_t> generation;
#if defined(__APPLE__)
        generation = native.st_gen;
#endif
        auto observed = Observation<ObjectIdentity>::available({scope_, IdentityScheme::PosixDeviceInode,
            NativeIdentifier::from_u64(static_cast<std::uint64_t>(native.st_dev)),
            NativeIdentifier::from_u64(static_cast<std::uint64_t>(native.st_ino)), generation});
        OwnedDirectory child(fdopendir(fd.get()));
        if (!child) {
            const int code = errno;
            return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "fdopendir.child"});
        }
        fd.release();
        return Result::available(std::make_unique<PosixDirectoryCursor>(std::move(child), std::move(observed), scope_));
    }
    Observation<ChildLookup> lookup_child(const NativeName& name, ChildLookupMode mode) const override {
        using Result=Observation<ChildLookup>;
        if(!name.is_valid()||!name.posix_bytes()||!valid_child_lookup_mode(mode))
            return Result::unavailable(ObservationState::Failed,adapter_error(AdapterError::InvalidIdentifier,"lookup_child.input"));
        if(mode!=ChildLookupMode::NativeDefault)
            return Result::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::UnsupportedQuery,"lookup_child.mode"));
        auto opened=open_child(name,EntryAccess::MetadataOnly);
        if(opened.value()) {
            auto owned=std::move(opened).take_value();
            if(!owned)return Result::unavailable(ObservationState::Failed,adapter_error(AdapterError::InvalidNativeResult,"lookup_child.null_entry"));
            return Result::available(ChildLookup::found({name,mode,identity()},std::move(owned)));
        }
        const auto& e=*opened.unavailable_detail();
        if(detail::definite_child_absence(e,detail::ChildLookupFamily::PosixAt))
            return Result::available(ChildLookup::missing({name,mode,identity()},e.error));
        return Result::unavailable(e.state,e.error);
    }
    Observation<std::unique_ptr<OpenedEntry>> open_child(const NativeName& name, EntryAccess access = EntryAccess::MetadataOnly) const override {
        if (!valid_entry_access(access)) return Observation<std::unique_ptr<OpenedEntry>>::unavailable(ObservationState::Failed,
            adapter_error(AdapterError::InvalidAccess, "open_child.access"));
        if (requests_move_source(access) || requests_rename_source(access))
            return Observation<std::unique_ptr<OpenedEntry>>::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::UnsupportedQuery, "open_child.move_source_exclusion"));
        using Result = Observation<std::unique_ptr<OpenedEntry>>;
        const auto* spelling = name.posix_bytes();
        if (!spelling || !name.is_valid())
            return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidPath, "open_child.name"));
#if defined(__linux__)
        const int flags = requests_content_read(access) ? O_RDONLY | O_NOFOLLOW | O_CLOEXEC
                                                         : O_PATH | O_NOFOLLOW | O_CLOEXEC;
#else
        // A public event-only descriptor observes identity/metadata; it is not a
        // data-read API and does not prevent volume unmount. The open can still
        // require read permission: preserve Denied rather than bypassing it. O_SYMLINK
        // opens the final symlink itself, including a dangling link.
        const int flags = requests_content_read(access) ? O_RDONLY | O_NOFOLLOW | O_CLOEXEC
                                                         : O_EVTONLY | O_SYMLINK | O_NONBLOCK | O_NOCTTY | O_CLOEXEC;
#endif
        OwnedDescriptor descriptor(openat(dirfd(directory_.get()), spelling->c_str(), flags));
        if (descriptor.get() < 0) {
            const int code = errno;
            return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "openat.child"});
        }
        auto original = std::make_unique<PosixOpenedEntry>(std::move(descriptor), scope_);
#if defined(__linux__)
        const bool readable_requested = requests_layout(access) || requests_inode_flags(access) || requests_content_read(access);
#else
        const bool readable_requested = requests_layout(access) || requests_content_read(access);
#endif
        if (!readable_requested) return Result::available(std::move(original));
        const auto before = original->inspect_basic();
        if (!before.value()) { const auto& e = *before.unavailable_detail(); return Result::unavailable(e.state, e.error); }
#if defined(__linux__)
        constexpr auto model = StorageModel::LinuxStatx;
#else
        constexpr auto model = StorageModel::DarwinStatFlags;
#endif
        if (requests_layout(access)) {
            const auto guard = detail::data_layout_access_guard(*before.value(), model);
            if (!guard.value()) { const auto& e = *guard.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        }
        if (requests_content_read(access)) {
            original->content_access_ = true;
#if defined(__linux__)
            original->inode_flags_access_ = requests_inode_flags(access);
#endif
            original->layout_access_ = requests_layout(access);
            return Result::available(std::move(original));
        }
#if defined(__APPLE__)
        // SEEK_DATA/SEEK_HOLE operate on the existing event-only descriptor.
        // No basename reopen or additional data-read handle is necessary.
        original->layout_access_ = true;
        return Result::available(std::move(original));
#else
        // O_PATH cannot seek or use FS_IOC_GETFLAGS. Obtain the explicitly
        // requested read access through a verified procfs fd
        // directory and its kernel fd link, never the original basename. The
        // original held regular object cannot be swapped for a device/link.
        OwnedDescriptor proc(open("/proc/self/fd", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (proc.get() < 0) {
            const int code = errno;
            return Result::unavailable(code == ENOENT || code == ENOTDIR ? ObservationState::Unsupported : errno_state(code),
                {ErrorDomain::Posix, code, "read_access.proc_directory"});
        }
        struct statfs filesystem{};
        if (fstatfs(proc.get(), &filesystem) != 0) { const int code = errno; return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "read_access.proc_statfs"}); }
        if (filesystem.f_type != PROC_SUPER_MAGIC) return Result::unavailable(ObservationState::Unsupported,
            adapter_error(AdapterError::UnsupportedQuery, "read_access.proc_filesystem"));
        const auto descriptor_name = std::to_string(original->descriptor_.get());
        OwnedDescriptor readable(openat(proc.get(), descriptor_name.c_str(), O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC));
        if (readable.get() < 0) { const int code = errno; return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "openat.read_access_fd"}); }
        auto opened = std::make_unique<PosixOpenedEntry>(std::move(readable), scope_, requests_layout(access));
        opened->inode_flags_access_ = requests_inode_flags(access);
        const auto after = opened->inspect_basic();
        if (!after.value()) { const auto& e = *after.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (requests_layout(access)) {
            const auto checked = detail::data_layout_metadata_unchanged(*before.value(), *after.value());
            if (!checked.value()) { const auto& e = *checked.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        } else {
            const auto checked = detail::qualify_inode_flags_subject(before,after);
            if (!checked.value()) { const auto& e = *checked.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        }
        const auto final_guard = detail::data_layout_access_guard(*after.value(), model);
        if (!final_guard.value()) { const auto& e = *final_guard.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        return Result::available(std::move(opened));
#endif
    }
private:
    friend class PosixTargetReadSeed;
    Observation<DirectoryStep> next_step() override {
        using Result = Observation<DirectoryStep>;
        errno = 0;
        const auto* entry = readdir(directory_.get());
        if (!entry) {
            const int code = errno;
            if (code == 0) {
                // EOF releases only the single-consumer position lease. The
                // DIR owner and its native-read budget remain held until the
                // cursor itself is destroyed.
#if defined(__linux__)
                target_read_position_lease_.reset();
#endif
                return Result::available(DirectoryEnd{});
            }
            return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "readdir"});
        }
        constexpr auto name_offset = offsetof(struct dirent, d_name);
        if (entry->d_reclen <= name_offset)
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InvalidNativeResult, "readdir.record"));
        const auto capacity = static_cast<std::size_t>(entry->d_reclen) - name_offset;
        const auto length = strnlen(entry->d_name, capacity);
        if (length == capacity)
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InvalidNativeResult, "readdir.name_length"));
        const std::string_view spelling(entry->d_name, length);
        if (spelling == "." || spelling == "..") return Result::available(DirectorySkip{});
        auto name = NativeName::from_posix(std::string(spelling));
        if (!name)
            return Result::unavailable(ObservationState::Failed,
                adapter_error(AdapterError::InvalidNativeResult, "readdir.name"));
        return Result::available(std::move(*name));
    }
#if defined(__linux__)
    // The directory stream must close while its reservation is still held;
    // leases therefore precede the native owner in declaration order.
    std::shared_ptr<detail::NativeTargetReadBudget> target_read_budget_;
    std::shared_ptr<NativeTargetReadCloneState> target_read_clone_state_;
    std::shared_ptr<NativeTargetReadCloneLease> target_read_clone_lease_;
    std::shared_ptr<const void> target_read_position_lease_;
#endif
    OwnedDirectory directory_;
    AdapterScope scope_;
};

#if defined(__linux__)
// Linux target observation is deliberately an adapter-private capability.  It
// never accepts a descriptor/path from the caller: factories below first brand
// check the genuine POSIX classes, then this worker opens independent
// descriptions while the creator/held directory is still available.
class PosixTargetReadSeed final : public detail::NativeTargetReadSeed,
                                  public MetadataCaptureFailureLatch {
public:
    PosixTargetReadSeed(PosixOpenedEntry* target,std::shared_ptr<const PosixDirectoryCursor> directory,
        std::shared_ptr<const NativeMetadataProof> proof,MetadataCaptureLimits limits,
        std::shared_ptr<MetadataCaptureBudget> budget,std::shared_ptr<const MetadataCaptureFailureLatch> latch)
        :target_(target),directory_(std::move(directory)),proof_(std::move(proof)),limits_(limits),
         budget_(std::move(budget)),latch_(std::move(latch)),
         clone_state_(std::make_shared<NativeTargetReadCloneState>()) {}
    ~PosixTargetReadSeed() override { try { (void)finish_io(); } catch (...) {} }

    void record_first(MetadataCaptureCleanupError error) const noexcept override {
        if(!close_error_) close_error_=error;
        if(latch_) latch_->record_first(error);
    }

    Observation<bool> advance(std::stop_token stop = {}) override {
        if(failed_) return failure_result();
        if(finished_) return closed<bool>();
        if(ready_) return Observation<bool>::available(true);
        detail::MetadataCaptureCleanupScope cleanup(this);
        try {
            if(stop.stop_requested()) return fail(ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InterruptedRead),"seed.cancelled");
            if(!proof_ || proof_->io_finished()) return fail(ObservationState::Changed,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidAccess),"seed.closed_proof");
            if(auto error=proof_->cleanup_error()) return fail(error->state,error->domain,error->code,"seed.proof_close");
            if(!limits_.valid() || !budget_ || !latch_ || !proof_->snapshot().policy.valid())
                return fail(ObservationState::Failed,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidLimit),"seed.inputs");
            const auto& expected=proof_->snapshot().basic;
            if(!expected.kind.value() || !expected.identity.value())
                return fail(ObservationState::Unsupported,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"seed.proof_shape");
            const bool is_directory=*expected.kind.value()==ObjectKind::Directory;
            if(!is_directory && *expected.kind.value()!=ObjectKind::RegularFile)
                return fail(ObservationState::Unsupported,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::NotApplicable),"seed.kind");
            if(directory_ != nullptr && !is_directory)
                return fail(ObservationState::Changed,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::MetadataChanged),"seed.directory_kind");

            const auto current=directory_ ? directory_->inspect_basic() : target_->inspect_basic();
            if(!current.value()) return fail(current.unavailable_detail()->state,current.unavailable_detail()->error.domain,
                current.unavailable_detail()->error.code,"seed.current_basic");
            if(target_){
                if(!target_bookend_){
                    auto bookend=make_target_bookend(*current.value());
                    if(!bookend.value()) return fail(bookend.unavailable_detail()->state,bookend.unavailable_detail()->error.domain,
                        bookend.unavailable_detail()->error.code,"seed.target_bookend");
                    target_bookend_=std::move(bookend).take_value();
                } else {
                    // Metadata replay may intentionally change ctime/size on
                    // the still-held target. This capability proves only
                    // native continuity; the owning tree layer validates the
                    // fresh post-replay metadata before effects.
                    const auto stable=compare_target_identity(*target_bookend_,*current.value(),"seed.target_identity_changed");
                    if(!stable.value()) return fail(stable.unavailable_detail()->state,stable.unavailable_detail()->error.domain,
                        stable.unavailable_detail()->error.code,"seed.target_changed");
                }
                if(!expected.identity.value()||expected.identity.value()->scope!=current.value()->identity.value()->scope)
                    return fail(ObservationState::Unsupported,ErrorDomain::Adapter,
                        static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity),"seed.source_target_scope");
                auto qualified=target_->qualify_progressive_metadata_target(*proof_);
                if(!qualified.value())
                    return fail(qualified.unavailable_detail()->state,qualified.unavailable_detail()->error.domain,
                        qualified.unavailable_detail()->error.code,"seed.target_qualification");
                if(!*qualified.value())
                    return fail(ObservationState::Unsupported,ErrorDomain::Adapter,
                        static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"seed.target_qualification");
            } else {
                const auto proof_match=compare_capture_bookend(expected,*current.value(),"seed.proof_identity");
                if(!proof_match.value()) return fail(proof_match.unavailable_detail()->state,proof_match.unavailable_detail()->error.domain,
                    proof_match.unavailable_detail()->error.code,"seed.proof_identity");
            }
            if(!target_ && (!directory_ || !directory_->identity().value() ||
                compare_identity(*directory_->identity().value(),*expected.identity.value())!=IdentityComparison::Same)) {
                return fail(ObservationState::Unsupported,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity),"seed.directory_brand");
            }

            if(is_directory && source_ && enum_parent_.get()<0){
                auto fresh_directory=target_?open_fresh_directory_target(target_->descriptor_.get(),*target_bookend_,"seed.enumerator_open"):
                    open_fresh_directory(dirfd(directory_->directory_.get()),expected,"seed.enumerator_open");
                if(!fresh_directory.value()) return fail(fresh_directory.unavailable_detail()->state,fresh_directory.unavailable_detail()->error.domain,
                    fresh_directory.unavailable_detail()->error.code,"seed.enumerator_open");
                enum_parent_=std::move(fresh_directory).take_value();
                ready_=true;
                return Observation<bool>::available(true);
            }

            if(!base_budget_){
                const std::size_t handles=is_directory?2U:1U;
                const std::size_t bytes=sizeof(PosixTargetReadSeed)+sizeof(PosixOpenedEntry)+(is_directory?sizeof(PosixDirectoryCursor):0U);
                auto lease=detail::NativeTargetReadBudget::acquire(budget_,handles,bytes);
                if(!lease.value()) return fail(lease.unavailable_detail()->state,lease.unavailable_detail()->error.domain,
                    lease.unavailable_detail()->error.code,"seed.budget");
                base_budget_=std::move(lease).take_value();
            }

            if(!source_ && target_){
                auto fresh=target_->open_readonly_capture_description();
                if(!fresh.value()) return fail(fresh.unavailable_detail()->state,fresh.unavailable_detail()->error.domain,
                    fresh.unavailable_detail()->error.code,"seed.reader_open");
                auto source=std::make_shared<PosixOpenedEntry>(std::move(fresh).take_value(),target_->scope_,false,!is_directory);
                source->target_read_budget_=base_budget_;
                source->target_read_clone_state_=clone_state_;
                const auto source_basic=source->inspect_basic();
                if(!source_basic.value()) return fail(source_basic.unavailable_detail()->state,source_basic.unavailable_detail()->error.domain,
                    source_basic.unavailable_detail()->error.code,"seed.reader_basic");
                const auto source_match=compare_target_bookend(*target_bookend_,*source_basic.value(),"seed.reader_identity");
                if(!source_match.value()) return fail(source_match.unavailable_detail()->state,source_match.unavailable_detail()->error.domain,
                    source_match.unavailable_detail()->error.code,"seed.reader_identity");
                source_=std::move(source);
            } else if(!source_) {
                auto fresh=open_fresh_directory(dirfd(directory_->directory_.get()),expected,"seed.reader_open");
                if(!fresh.value()) return fail(fresh.unavailable_detail()->state,fresh.unavailable_detail()->error.domain,
                    fresh.unavailable_detail()->error.code,"seed.reader_open");
                auto source=std::make_shared<PosixOpenedEntry>(std::move(fresh).take_value(),directory_->scope_,false,false);
                source->target_read_budget_=base_budget_;
                source->target_read_clone_state_=clone_state_;
                source_=std::move(source);
            }
            if(is_directory) return Observation<bool>::available(false);
            ready_=true;
            return Observation<bool>::available(true);
        } catch (...) {
            return fail(ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"seed.exception");
        }
    }

    Observation<std::shared_ptr<const OpenedEntry>> source() const override {
        using R=Observation<std::shared_ptr<const OpenedEntry>>;
        if(!ready_||finished_||failed_||!source_) return closed<std::shared_ptr<const OpenedEntry>>();
        return R::available(source_);
    }

    Observation<std::shared_ptr<const DirectoryCursor>> directory_cursor() override {
        using R=Observation<std::shared_ptr<const DirectoryCursor>>;
        if(!ready_||finished_||failed_||enum_parent_.get()<0) return closed<std::shared_ptr<const DirectoryCursor>>();
        if(!active_.expired()) return R::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"seed.enumerator_owned"});
        detail::MetadataCaptureCleanupScope cleanup(this);
        try {
            auto lease=detail::NativeTargetReadBudget::acquire(budget_,1,sizeof(PosixDirectoryCursor));
            if(!lease.value()) return R::unavailable(lease.unavailable_detail()->state,lease.unavailable_detail()->error);
            const auto& expected=proof_->snapshot().basic;
            auto fresh=target_?duplicate_prepared_directory(enum_parent_.get(),*target_bookend_,"seed.enumerator_open"):
                open_fresh_directory(enum_parent_.get(),expected,"seed.enumerator_open");
            if(!fresh.value()) return R::unavailable(fresh.unavailable_detail()->state,fresh.unavailable_detail()->error);
            auto descriptor=std::move(fresh).take_value();
            DIR* stream=fdopendir(descriptor.get());
            if(!stream){const int code=errno;return R::unavailable(errno_state(code),{ErrorDomain::Posix,code,"seed.enumerator_fdopendir"});}
            descriptor.release();
            if(target_) rewinddir(stream);
            OwnedDirectory directory(stream);
            const auto observed=statx_metadata(dirfd(directory.get()),"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,source_->scope_);
            if(!observed.value()) return R::unavailable(observed.unavailable_detail()->state,observed.unavailable_detail()->error);
            const auto same=target_?compare_target_identity(*target_bookend_,*observed.value(),"seed.target_enumerator_identity"):
                compare_capture_bookend(expected,*observed.value(),"seed.enumerator_identity");
            if(!same.value()) return R::unavailable(same.unavailable_detail()->state,same.unavailable_detail()->error);
            auto cursor=std::make_shared<PosixDirectoryCursor>(std::move(directory),observed.value()->identity,source_->scope_);
            cursor->target_read_budget_=std::move(lease).take_value();
            cursor->target_read_clone_state_=clone_state_;
            cursor->target_read_position_lease_=std::make_shared<const std::byte>();
            active_=cursor->target_read_position_lease_;
            return R::available(std::shared_ptr<const DirectoryCursor>(std::move(cursor)));
        } catch (...) {
            return R::unavailable(ObservationState::Unknown,{ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"seed.enumerator_exception"});
        }
    }

    Observation<bool> finish_io() override {
        // A returned source/cursor is an active consumer. Do not close the
        // seed's native owners underneath it: callers must drain and release
        // every view before the seed can consume its own descriptions.
        if(!finished_ && (source_.use_count()>1 || !active_.expired() ||
            (clone_state_ && clone_state_->active_clones.load(std::memory_order_acquire)!=0)))
            return Observation<bool>::unavailable(ObservationState::Changed,
                {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"seed.consumers_active"});
        if(!finished_){
            detail::MetadataCaptureCleanupScope cleanup(this);
            finished_=true;
            if(source_) source_->finish_capture_reads();
            source_.reset();
            enum_parent_=OwnedDescriptor(-1);
            base_budget_.reset();
            proof_.reset();
            directory_.reset();
            target_=nullptr;
            budget_.reset();
        }
        if(close_error_) return Observation<bool>::unavailable(close_error_->state,
            {close_error_->domain,close_error_->code,close_error_->operation});
        return Observation<bool>::available(true);
    }

private:
    struct TargetBookend final {
        ObjectIdentity identity;
        std::uint64_t mount_id=0;
        ObjectKind kind=ObjectKind::Other;
        std::optional<std::uint64_t> logical_size;
        std::optional<FileTimestamp> changed;
    };
    static Observation<TargetBookend> make_target_bookend(const BasicMetadata& metadata) {
        using R=Observation<TargetBookend>;
        if(!metadata.identity.value()||!metadata.mount_id.value()||!metadata.kind.value()||!metadata.changed.value())
            return R::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::ProviderReviewRequired,"seed.target_bookend_fields"));
        TargetBookend result{*metadata.identity.value(),*metadata.mount_id.value(),*metadata.kind.value(),{},*metadata.changed.value()};
        if(result.kind==ObjectKind::RegularFile){
            if(!metadata.logical_size.value()) return R::unavailable(ObservationState::Unsupported,
                adapter_error(AdapterError::ProviderReviewRequired,"seed.target_bookend_size"));
            result.logical_size=*metadata.logical_size.value();
        }
        return R::available(std::move(result));
    }
    static Observation<bool> compare_target_bookend(const TargetBookend& expected,const BasicMetadata& actual,const char* operation) {
        using R=Observation<bool>;
        if(!actual.identity.value()||compare_identity(expected.identity,*actual.identity.value())!=IdentityComparison::Same||
           !actual.mount_id.value()||*actual.mount_id.value()!=expected.mount_id||
           !actual.kind.value()||*actual.kind.value()!=expected.kind||
           !actual.changed.value()||!expected.changed||*actual.changed.value()!=*expected.changed)
            return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,operation));
        if(expected.kind==ObjectKind::RegularFile&&(!actual.logical_size.value()||!expected.logical_size||*actual.logical_size.value()!=*expected.logical_size))
            return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,operation));
        return R::available(true);
    }
    static Observation<bool> compare_target_identity(const TargetBookend& expected,const BasicMetadata& actual,const char* operation) {
        using R=Observation<bool>;
        if(!actual.identity.value()||compare_identity(expected.identity,*actual.identity.value())!=IdentityComparison::Same||
           !actual.mount_id.value()||*actual.mount_id.value()!=expected.mount_id||
           !actual.kind.value()||*actual.kind.value()!=expected.kind)
            return R::unavailable(ObservationState::Changed,adapter_error(AdapterError::MetadataChanged,operation));
        return R::available(true);
    }
    template<class T> static Observation<T> closed(){return Observation<T>::unavailable(ObservationState::Changed,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"seed.closed"});}
    Observation<bool> failure_result() const { return Observation<bool>::unavailable(failure_state_,
        {failure_domain_,failure_code_,failure_operation_}); }
    Observation<bool> fail(ObservationState state,ErrorDomain domain,std::int64_t code,const char* operation){
        if(!failed_){failed_=true;failure_state_=state;failure_domain_=domain;failure_code_=code;failure_operation_=operation;}
        (void)finish_io();
        return close_error_?Observation<bool>::unavailable(close_error_->state,
            {close_error_->domain,close_error_->code,close_error_->operation}):failure_result();
    }
    static Observation<OwnedDescriptor> open_fresh_directory(int base,const BasicMetadata& expected,const char* operation){
        using R=Observation<OwnedDescriptor>;
        OwnedDescriptor fresh(openat(base,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_NOATIME));
        if(fresh.get()<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,operation});
        const int flags=fcntl(fresh.get(),F_GETFL);
        if(flags<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"seed.directory_flags"});
        if((flags&O_ACCMODE)!=O_RDONLY||(flags&O_NOATIME)==0)
            return R::unavailable(ObservationState::Denied,adapter_error(AdapterError::InvalidAccess,"seed.directory_noatime"));
        const int descriptor_flags=fcntl(fresh.get(),F_GETFD);
        if(descriptor_flags<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"seed.directory_fd_flags"});
        if((descriptor_flags&FD_CLOEXEC)==0)return R::unavailable(ObservationState::Failed,
            adapter_error(AdapterError::InvalidNativeResult,"seed.directory_cloexec"));
        const auto after=statx_metadata(fresh.get(),"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,expected.identity.value()->scope);
        if(!after.value())return R::unavailable(after.unavailable_detail()->state,after.unavailable_detail()->error);
        const auto same=compare_capture_bookend(expected,*after.value(),"seed.directory_identity");
        if(!same.value())return R::unavailable(same.unavailable_detail()->state,same.unavailable_detail()->error);
        return R::available(std::move(fresh));
    }
    static Observation<OwnedDescriptor> open_fresh_directory_target(int base,const TargetBookend& expected,const char* operation){
        using R=Observation<OwnedDescriptor>;
        OwnedDescriptor fresh(openat(base,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_NOATIME));
        if(fresh.get()<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,operation});
        const int flags=fcntl(fresh.get(),F_GETFL);
        if(flags<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"seed.directory_flags"});
        if((flags&O_ACCMODE)!=O_RDONLY||(flags&O_NOATIME)==0)
            return R::unavailable(ObservationState::Denied,adapter_error(AdapterError::InvalidAccess,"seed.directory_noatime"));
        const int descriptor_flags=fcntl(fresh.get(),F_GETFD);
        if(descriptor_flags<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"seed.directory_fd_flags"});
        if((descriptor_flags&FD_CLOEXEC)==0)return R::unavailable(ObservationState::Failed,
            adapter_error(AdapterError::InvalidNativeResult,"seed.directory_cloexec"));
        const auto after=statx_metadata(fresh.get(),"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,expected.identity.scope);
        if(!after.value())return R::unavailable(after.unavailable_detail()->state,after.unavailable_detail()->error);
        const auto same=compare_target_bookend(expected,*after.value(),"seed.target_directory_identity");
        if(!same.value())return R::unavailable(same.unavailable_detail()->state,same.unavailable_detail()->error);
        return R::available(std::move(fresh));
    }
    static Observation<OwnedDescriptor> duplicate_prepared_directory(int base,const TargetBookend& expected,const char* operation){
        using R=Observation<OwnedDescriptor>;
        OwnedDescriptor fresh(fcntl(base,F_DUPFD_CLOEXEC,0));
        if(fresh.get()<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,operation});
        const int flags=fcntl(fresh.get(),F_GETFL);
        if(flags<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"seed.directory_flags"});
        if((flags&O_ACCMODE)!=O_RDONLY||(flags&O_NOATIME)==0)
            return R::unavailable(ObservationState::Denied,adapter_error(AdapterError::InvalidAccess,"seed.directory_noatime"));
        const int descriptor_flags=fcntl(fresh.get(),F_GETFD);
        if(descriptor_flags<0)return R::unavailable(errno_state(errno),{ErrorDomain::Posix,errno,"seed.directory_fd_flags"});
        if((descriptor_flags&FD_CLOEXEC)==0)return R::unavailable(ObservationState::Failed,
            adapter_error(AdapterError::InvalidNativeResult,"seed.directory_cloexec"));
        const auto after=statx_metadata(fresh.get(),"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,expected.identity.scope);
        if(!after.value())return R::unavailable(after.unavailable_detail()->state,after.unavailable_detail()->error);
        const auto same=compare_target_identity(expected,*after.value(),"seed.prepared_directory_identity");
        if(!same.value())return R::unavailable(same.unavailable_detail()->state,same.unavailable_detail()->error);
        return R::available(std::move(fresh));
    }
    PosixOpenedEntry* target_;
    std::shared_ptr<const PosixDirectoryCursor> directory_;
    std::shared_ptr<const NativeMetadataProof> proof_;
    MetadataCaptureLimits limits_;
    std::shared_ptr<MetadataCaptureBudget> budget_;
    std::shared_ptr<const MetadataCaptureFailureLatch> latch_;
    std::shared_ptr<PosixOpenedEntry> source_;
    OwnedDescriptor enum_parent_{-1};
    std::shared_ptr<detail::NativeTargetReadBudget> base_budget_;
    std::optional<TargetBookend> target_bookend_;
    std::shared_ptr<NativeTargetReadCloneState> clone_state_;
    std::weak_ptr<const void> active_;
    mutable std::optional<MetadataCaptureCleanupError> close_error_;
    ObservationState failure_state_=ObservationState::Unknown;
    ErrorDomain failure_domain_=ErrorDomain::None;
    std::int64_t failure_code_=0;
    const char* failure_operation_="seed.failed";
    bool ready_=false,finished_=false,failed_=false;
};
#endif

Observation<bool> PosixOpenedEntry::publish_noreplace(const DirectoryCursor& destination, const NativeName& name) {
    if (!publication_)
        return OpenedEntry::publish_noreplace(destination, name);
    if (!publication_->anonymous)
        return Observation<bool>::unavailable(ObservationState::Unsupported,
            adapter_error(AdapterError::UnsupportedQuery, "publish_noreplace.named_source_unqualified"));
    const auto* cursor = dynamic_cast<const PosixDirectoryCursor*>(&destination);
    if (!cursor || !cursor->identity().value() || cursor->identity().value()->scope != scope_)
        return Observation<bool>::unavailable(ObservationState::Unsupported,
            adapter_error(AdapterError::UnsupportedQuery, "publish_noreplace.destination_adapter"));
    return cursor->publish_anonymous_noreplace(descriptor_.get(), name);
}

} // namespace

Observation<int> detail::duplicate_posix_journal_directory(const DirectoryCursor& cursor) {
    const auto* native=dynamic_cast<const PosixDirectoryCursor*>(&cursor);
    if(!native)return Observation<int>::unavailable(ObservationState::Unsupported,
        adapter_error(AdapterError::UnsupportedQuery,"journal_root.native_cursor_required"));
    return native->duplicate_journal_directory();
}

Observation<BasicMetadata> NativeFileSystem::inspect_basic(const std::filesystem::path& path) const {
    const auto address = NativeAbsolutePath::from_host(path);
    if (!address.value()) { const auto& e = *address.unavailable_detail(); return Observation<BasicMetadata>::unavailable(e.state, e.error); }
#if defined(__linux__)
    return statx_metadata(AT_FDCWD, path.c_str(), AT_SYMLINK_NOFOLLOW, scope_);
#else
    return stat_metadata(AT_FDCWD, path.c_str(), false, scope_);
#endif
}

Observation<std::unique_ptr<DirectoryCursor>> NativeFileSystem::open_directory(
    const std::filesystem::path& path, DirectoryLinkPolicy policy) const {
    using Result = Observation<std::unique_ptr<DirectoryCursor>>;
    const auto address = NativeAbsolutePath::from_host(path);
    if (!address.value()) { const auto& e = *address.unavailable_detail(); return Result::unavailable(e.state, e.error); }
    if (policy != DirectoryLinkPolicy::RejectFinalLink && policy != DirectoryLinkPolicy::FollowFinalLink)
        return Result::unavailable(ObservationState::Failed, adapter_error(AdapterError::InvalidPath, "open_directory"));
    auto spelling = path.native();
    // A trailing slash must not turn an explicitly rejected final symlink into
    // a followed parent component. Preserve all-slash root spellings verbatim.
    if (spelling.find_first_not_of('/') != std::string::npos)
        while (spelling.size() > 1 && spelling.back() == '/') spelling.pop_back();
    OwnedDescriptor fd(open(spelling.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC |
        (policy == DirectoryLinkPolicy::RejectFinalLink ? O_NOFOLLOW : 0)));
    if (fd.get() < 0) {
        const int code = errno;
        // The requested directory can instead be an existing non-directory
        // (or a refused final link). ENOTDIR here does not prove it vanished.
        const auto state = code == ENOTDIR ? ObservationState::Failed : errno_state(code);
        return Result::unavailable(state, {ErrorDomain::Posix, code, "open.directory"});
    }
    struct stat native{};
    if (fstat(fd.get(), &native) != 0) {
        const int code = errno;
        return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "fstat.directory"});
    }
    std::optional<std::uint64_t> generation;
#if defined(__APPLE__)
    generation = native.st_gen;
#endif
    auto identity = Observation<ObjectIdentity>::available({scope_, IdentityScheme::PosixDeviceInode,
        NativeIdentifier::from_u64(static_cast<std::uint64_t>(native.st_dev)),
        NativeIdentifier::from_u64(static_cast<std::uint64_t>(native.st_ino)), generation});
    OwnedDirectory directory(fdopendir(fd.get()));
    if (!directory) {
        const int code = errno;
        return Result::unavailable(errno_state(code), {ErrorDomain::Posix, code, "fdopendir"});
    }
    fd.release(); // fdopendir now owns the descriptor, including CLOEXEC.
    return Result::available(std::make_unique<PosixDirectoryCursor>(std::move(directory), std::move(identity), scope_));
}

namespace detail {
Observation<std::unique_ptr<DirectoryCursor>> open_posix_directory_reader(const DirectoryCursor& cursor) {
    auto* native=dynamic_cast<const PosixDirectoryCursor*>(&cursor);
    if(!native)return Observation<std::unique_ptr<DirectoryCursor>>::unavailable(ObservationState::Unsupported,
        adapter_error(AdapterError::ProviderReviewRequired,"directory_reader.native_cursor_required"));
    return native->open_current_directory_reader();
}
#if defined(__linux__)
Observation<NativeTargetReadSeed::Pointer> begin_native_target_read_seed(
    OpenedEntry& target,std::shared_ptr<const NativeMetadataProof> proof,MetadataCaptureLimits limits,
    std::shared_ptr<MetadataCaptureBudget> budget,std::shared_ptr<const MetadataCaptureFailureLatch> latch) {
    using R=Observation<NativeTargetReadSeed::Pointer>;
    auto* native=dynamic_cast<PosixOpenedEntry*>(&target);
    if(!native||!proof||!limits.valid()||!budget||!latch)
        return R::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"target_read.native_target_inputs"});
    return R::available(std::make_unique<PosixTargetReadSeed>(native,nullptr,std::move(proof),limits,std::move(budget),std::move(latch)));
}
Observation<NativeTargetReadSeed::Pointer> begin_native_directory_read_seed(
    std::shared_ptr<const DirectoryCursor> directory,std::shared_ptr<const NativeMetadataProof> proof,
    MetadataCaptureLimits limits,std::shared_ptr<MetadataCaptureBudget> budget,
    std::shared_ptr<const MetadataCaptureFailureLatch> latch) {
    using R=Observation<NativeTargetReadSeed::Pointer>;
    auto native=std::dynamic_pointer_cast<const PosixDirectoryCursor>(directory);
    if(!native||!proof||!limits.valid()||!budget||!latch)
        return R::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"target_read.native_directory_inputs"});
    return R::available(std::make_unique<PosixTargetReadSeed>(nullptr,std::move(native),std::move(proof),limits,std::move(budget),std::move(latch)));
}
#endif
Observation<bool> qualify_native_metadata_target(OpenedEntry& target,const NativeMetadataProof& proof) {
    auto* native=dynamic_cast<PosixOpenedEntry*>(&target);
    if(!native)return Observation<bool>::unavailable(ObservationState::Unsupported,
        adapter_error(AdapterError::ProviderReviewRequired,"metadata_stream.native_target_required"));
    return native->qualify_progressive_metadata_target(proof);
}
Observation<std::shared_ptr<const OpenedEntry>> open_native_main_content_source(
    std::shared_ptr<const OpenedEntry> source){
    using R=Observation<std::shared_ptr<const OpenedEntry>>;
    const auto* native=dynamic_cast<const PosixOpenedEntry*>(source.get());
    if(!native)return R::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"main_content.native_source_required"});
    return native->open_progressive_metadata_source();
}
Observation<std::shared_ptr<const OpenedEntry>> open_native_metadata_capture_source(
    std::shared_ptr<const OpenedEntry> source,const MetadataReplayPolicy& policy){
    using R=Observation<std::shared_ptr<const OpenedEntry>>;
    const auto* native=dynamic_cast<const PosixOpenedEntry*>(source.get());
    if(!native||!policy.valid())return R::unavailable(ObservationState::Unsupported,
        adapter_error(AdapterError::ProviderReviewRequired,"metadata_capture.native_source_required"));
    return native->open_progressive_metadata_source();
}
Observation<std::shared_ptr<const OpenedEntry>> open_native_directory_capture_source(
    std::shared_ptr<const DirectoryCursor> source,const MetadataReplayPolicy& policy){
    using R=Observation<std::shared_ptr<const OpenedEntry>>;
    const auto* native=dynamic_cast<const PosixDirectoryCursor*>(source.get());
    if(!native||!policy.valid())return R::unavailable(ObservationState::Unsupported,
        adapter_error(AdapterError::ProviderReviewRequired,"metadata_capture.native_directory_required"));
    return native->open_progressive_directory_source();
}
void finish_native_metadata_capture(const OpenedEntry* source,const MetadataReplaySnapshot& snapshot)noexcept {
#if defined(__linux__)
    if(const auto* proof=dynamic_cast<const LinuxPersistentSecurityProof*>(snapshot.security_coverage.get()))proof->finish_capture_reads();
#else
    (void)snapshot;
#endif
    if(!source)return;
    auto* native=const_cast<PosixOpenedEntry*>(dynamic_cast<const PosixOpenedEntry*>(source));
    if(native)native->finish_capture_reads();
    else record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"metadata_capture.native_source_close_required"});
}
Observation<bool> seal_native_metadata_capture(MetadataCaptureJob& job){
    using R=Observation<bool>;
    if(!job.ready_to_seal()||!dynamic_cast<const PosixOpenedEntry*>(job.sealing_source().get()))
        return R::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::ProviderReviewRequired,"metadata_capture.native_seal_required"));
    const auto& snapshot=job.sealing_snapshot();
#if defined(__linux__)
    if(snapshot.policy.scope==RegularMetadataScope::CompleteMetadataV1){
        const auto* native=dynamic_cast<const PosixOpenedEntry*>(job.sealing_source().get());
        auto issued=native->issue_linux_security_coverage(snapshot,job.sealing_lease());
        if(!issued.value()){const auto&e=*issued.unavailable_detail();return R::unavailable(e.state,e.error);}
        job.sealing_snapshot().security_coverage=std::move(issued).take_value();
        return R::available(true);
    }
#endif
    if(snapshot.channel_coverage!=DataChannelCoverage::Unknown||!snapshot.channels.empty()||snapshot.channel_evidence||
       snapshot.security_coverage||snapshot.policy.scope==RegularMetadataScope::CompleteMetadataV1)
        return R::unavailable(ObservationState::Unsupported,adapter_error(AdapterError::ProviderReviewRequired,"metadata_capture.posix_scope_unqualified"));
    return job.sealing_source()->qualify_metadata_replay(snapshot.policy);
}
} // namespace detail

Observation<std::shared_ptr<const MetadataReplayChannelEvidence>> issue_native_metadata_replay_channels(
    const OpenedEntry&,const MetadataReplaySnapshot&,std::stop_token) {
    return Observation<std::shared_ptr<const MetadataReplayChannelEvidence>>::unavailable(ObservationState::Unsupported,
        adapter_error(AdapterError::NotApplicable,"metadata_channels.native_windows_evidence_required"));
}
Observation<bool> verify_native_metadata_replay_channels(const MetadataReplaySnapshot&) {
    return Observation<bool>::unavailable(ObservationState::Unsupported,
        adapter_error(AdapterError::NotApplicable,"metadata_channels.native_windows_evidence_required"));
}
Observation<bool> qualify_native_directory_creation(const DirectoryCursor&,const MetadataReplayPolicy&) {
    return Observation<bool>::unavailable(ObservationState::Unsupported,
        adapter_error(AdapterError::ProviderReviewRequired,"directory_creation.posix_creator_identity_unproved"));
}
Observation<std::unique_ptr<NativeCreatedDirectory>> create_native_directory(
    std::shared_ptr<const DirectoryCursor>,NativeName,const MetadataReplayPolicy&) {
    return Observation<std::unique_ptr<NativeCreatedDirectory>>::unavailable(ObservationState::Unsupported,
        adapter_error(AdapterError::ProviderReviewRequired,"directory_creation.posix_creator_identity_unproved"));
}
Observation<bool> NativeCreatedDirectory::finish_io() {
    if(!finish_result_)finish_result_=writer_->finish_content_writes();
    return *finish_result_;
}

} // namespace ck::files
