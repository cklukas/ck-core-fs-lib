// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "../observation.hpp"
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include "legacy_native_fixture_posix.hpp"
#include <unistd.h>
#ifdef __APPLE__
#include <sys/acl.h>
#include <sys/mount.h>
#endif

namespace ck::files::detail {
enum class PosixPrivateStorageKind { Directory, RegularFile };
namespace private_storage_detail {
inline Observation<bool> failure(int code,const char* operation) {
    auto state=ObservationState::Failed;
    if(code==EACCES || code==EPERM) state=ObservationState::Denied;
    if(code==ENOENT || code==ENOTDIR) state=ObservationState::Gone;
    if(code==ENOSYS || code==ENOTSUP) state=ObservationState::Unsupported;
    return Observation<bool>::unavailable(state,{ErrorDomain::Posix,code,operation});
}
inline Observation<bool> reject(const char* operation,ObservationState state=ObservationState::Denied) {
    const auto code=state==ObservationState::Unsupported?AdapterError::UnsupportedQuery:AdapterError::InvalidAccess;
    return Observation<bool>::unavailable(state,{ErrorDomain::Adapter,static_cast<std::int64_t>(code),operation});
}
}

// Worker-only privacy qualification through the retained native descriptor.
// Named regular files must have exactly one link. Darwin mode bits alone do
// not establish privacy: local ownership enforcement AND successfully queried
// extended-security absence/empty ACL are required. Even inherit-only entries
// are refused. No failed/unsupported ACL query is treated as absence.
// require_mode=false is ONLY a preflight before tightening an app-owned root;
// ownership, type, mount and ACL checks still apply, before any chmod mutation.
inline Observation<bool> qualify_posix_private_storage(int fd,PosixPrivateStorageKind kind,
                                                       bool require_mode=true) {
    using namespace private_storage_detail;
    struct stat info{};
#ifdef __APPLE__
    struct statfs fs{};
    if(fstatfs(fd,&fs)) return failure(errno,"posix_private_storage.mount");
    if(!(fs.f_flags&MNT_LOCAL) || (fs.f_flags&MNT_IGNORE_OWNERSHIP))
        return reject("posix_private_storage.ownership_mount",ObservationState::Unsupported);
    struct Security {
        filesec_t value=filesec_init();
        ~Security() { if(value) filesec_free(value); }
    } security;
    if(!security.value) return failure(errno,"posix_private_storage.filesec");
    if(fstatx_np(fd,&info,security.value)) return failure(errno,"posix_private_storage.security");
    int present=0;
    if(filesec_query_property(security.value,FILESEC_ACL,&present))
        return failure(errno,"posix_private_storage.acl_query");
    if(!present) {
        errno=0;const auto support=fpathconf(fd,_PC_EXTENDED_SECURITY_NP);
        if(support<0 && errno) return failure(errno,"posix_private_storage.acl_support");
        if(support!=1) return reject("posix_private_storage.acl_unqualified",ObservationState::Unsupported);
    } else {
        struct Acl { acl_t value=nullptr; ~Acl() { if(value) acl_free(value); } } acl;
        if(filesec_get_property(security.value,FILESEC_ACL,&acl.value))
            return failure(errno,"posix_private_storage.acl_property");
        if(!acl.value || acl_valid(acl.value)) return reject("posix_private_storage.acl_invalid");
        acl_entry_t entry=nullptr;errno=0;
        const auto found=acl_get_entry(acl.value,ACL_FIRST_ENTRY,&entry);
        if(found==0) return reject("posix_private_storage.extended_acl");
        if(found!=-1 || errno!=EINVAL) return failure(errno?errno:EIO,"posix_private_storage.acl_entry");
    }
#else
    if(::ck::files::detail::legacy_fstat(fd,&info,"legacy.posix_private_storage.fstat.70")) return failure(errno,"posix_private_storage.stat");
    // POSIX access ACL masks are enforced by the exact 0700/0600 mode on the
    // existing Linux boundary. Darwin extended ACLs require the checks above.
#endif
    const bool directory=kind==PosixPrivateStorageKind::Directory;
    if(info.st_uid!=geteuid() || (directory?!S_ISDIR(info.st_mode):!S_ISREG(info.st_mode)) ||
        (!directory && (info.st_nlink!=1 || info.st_size<0)))
        return reject("posix_private_storage.owner_kind_links");
    const mode_t mode=directory?0700:0600;
    if(require_mode && (info.st_mode&07777)!=mode) return reject("posix_private_storage.mode");
    return Observation<bool>::available(true);
}
} // namespace ck::files::detail
