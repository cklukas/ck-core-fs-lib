// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif
#include "linux_anonymous_staging.hpp"

#if defined(__linux__)
#include <cerrno>
#include <fcntl.h>
#include <linux/magic.h>
#if __has_include(<linux/openat2.h>)
#include <linux/openat2.h>
#define CK_HAVE_STAGING_OPENAT2 1
#endif
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <utility>
#endif

namespace ck::files::detail {
namespace {
template<class T> Observation<T> unsupported(const char* op) {
    return Observation<T>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery), op});
}
#if defined(__linux__)
class Fd final {
public:
    explicit Fd(int fd) noexcept : fd_(fd) {}
    ~Fd() { if (fd_ >= 0) ::close(fd_); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    int get() const noexcept { return fd_; }
    int release() noexcept { return std::exchange(fd_, -1); }
private:
    int fd_;
};
ObservationState native_state(int code) {
    if (code == EACCES || code == EPERM) return ObservationState::Denied;
    if (code == EEXIST || code == ESTALE) return ObservationState::Changed;
    if (code == ENOENT || code == ENOTDIR) return ObservationState::Gone;
    if (code == ENOSYS || code == EOPNOTSUPP || code == ENOTSUP || code == EXDEV)
        return ObservationState::Unsupported;
    return ObservationState::Failed;
}
template<class T> Observation<T> error(int code, const char* op,
    ObservationState state = ObservationState::Available) {
    return Observation<T>::unavailable(state == ObservationState::Available ? native_state(code) : state,
        {ErrorDomain::Posix, code, op});
}
template<class T> Observation<T> invalid(AdapterError code, const char* op,
    ObservationState state = ObservationState::Failed) {
    return Observation<T>::unavailable(state,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(code), op});
}
bool same(const struct stat& a, const struct stat& b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && S_ISREG(a.st_mode) && S_ISREG(b.st_mode);
}
} // namespace

// The proc path is an acquisition route for an owning directory handle only.
// Kernel resolution must remain beneath an actual procfs root, without bind
// mount crossings or magic-link jumps. In that directory, the source component
// is a kernel-owned reference in THIS thread's fd table, not a user-writable
// basename. Worker ownership forbids concurrent close/reuse of the source fd.
// Administrative mutation of the process/mount namespace is outside this
// boundary, just as closing another worker's owned fd is outside its contract.
Observation<int> open_linux_thread_fd_directory() {
#if defined(CK_HAVE_STAGING_OPENAT2) && defined(SYS_openat2)
    Fd root(::open("/proc", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (root.get() < 0) return unsupported<int>("staging.proc_root_unavailable");
    struct statfs filesystem{};
    if (::fstatfs(root.get(), &filesystem) != 0) return error<int>(errno, "staging.proc_root_statfs");
    if (static_cast<unsigned long>(filesystem.f_type) != static_cast<unsigned long>(PROC_SUPER_MAGIC))
        return unsupported<int>("staging.proc_root_not_procfs");
    struct open_how how{};
    how.flags = O_PATH | O_DIRECTORY | O_CLOEXEC;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS;
    // thread-self is essential if a worker has unshared its descriptor table;
    // self/fd would refer to the group leader's independently mutable table.
    Fd directory(static_cast<int>(::syscall(SYS_openat2, root.get(), "thread-self/fd", &how, sizeof(how))));
    if (directory.get() < 0) return unsupported<int>("staging.proc_fd_anchor_unqualified");
    if (::fstatfs(directory.get(), &filesystem) != 0) return error<int>(errno, "staging.proc_fd_statfs");
    if (static_cast<unsigned long>(filesystem.f_type) != static_cast<unsigned long>(PROC_SUPER_MAGIC))
        return unsupported<int>("staging.proc_fd_not_procfs");
    return Observation<int>::available(directory.release());
#else
    return unsupported<int>("staging.proc_openat2_unavailable");
#endif
}

namespace {
Observation<bool> finish_publication(int file, int directory, const char* name, const struct stat& expected) {
    struct stat held{}, published{};
    if (::fstat(file, &held) != 0)
        return error<bool>(errno, "staging.link_held_after", ObservationState::Unknown);
    if (::fstatat(directory, name, &published, AT_SYMLINK_NOFOLLOW) != 0)
        return error<bool>(errno, "staging.link_destination_after", ObservationState::Unknown);
    if (!same(expected, held) || !same(expected, published) || held.st_nlink != 1 || published.st_nlink != 1)
        return invalid<bool>(AdapterError::MetadataChanged, "staging.link_identity_after", ObservationState::Unknown);
    // Preserve delayed data/metadata failures as well as the directory entry.
    // A read-only successor fd is sufficient for Linux fsync if one is used.
    if (::fsync(file) != 0) return error<bool>(errno, "staging.link_file_fsync", ObservationState::Unknown);
    if (::fsync(directory) != 0) return error<bool>(errno, "staging.link_directory_fsync", ObservationState::Unknown);
    return Observation<bool>::available(true);
}
#endif
} // namespace

Observation<int> create_linux_anonymous_staging(int directory) {
#if defined(__linux__) && defined(O_TMPFILE)
    struct stat parent{};
    if (::fstat(directory, &parent) != 0) return error<int>(errno, "staging.create_parent");
    if (!S_ISDIR(parent.st_mode) || parent.st_nlink == 0)
        return invalid<int>(AdapterError::NotDirectory, "staging.create_parent_kind", ObservationState::Changed);
    Fd file(::openat(directory, ".", O_TMPFILE | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (file.get() < 0) {
        const int code = errno;
        if (code == EINVAL || code == EISDIR) return error<int>(code, "staging.create_tmpfile", ObservationState::Unsupported);
        return error<int>(code, "staging.create_tmpfile");
    }
    struct stat held{};
    if (::fstat(file.get(), &held) != 0) return error<int>(errno, "staging.create_identity");
    if (!S_ISREG(held.st_mode) || held.st_nlink != 0 || held.st_dev != parent.st_dev)
        return invalid<int>(AdapterError::InvalidNativeResult, "staging.create_kind_links");
    return Observation<int>::available(file.release());
#else
    (void)directory;
    return unsupported<int>("staging.tmpfile_unavailable");
#endif
}

Observation<bool> publish_linux_anonymous_staging(int file, int directory, const NativeName& name) {
#if defined(__linux__) && defined(AT_EMPTY_PATH)
    if (!name.is_valid() || !name.posix_bytes()) return invalid<bool>(AdapterError::InvalidIdentifier, "staging.link_name");
    struct stat held{}, parent{};
    if (::fstat(file, &held) != 0) return error<bool>(errno, "staging.link_source");
    if (::fstat(directory, &parent) != 0) return error<bool>(errno, "staging.link_parent");
    if (!S_ISREG(held.st_mode) || held.st_nlink != 0)
        return invalid<bool>(AdapterError::MetadataChanged, "staging.link_source_not_anonymous", ObservationState::Changed);
    if (!S_ISDIR(parent.st_mode) || parent.st_nlink == 0)
        return invalid<bool>(AdapterError::NotDirectory, "staging.link_parent_kind", ObservationState::Changed);
    if (held.st_dev != parent.st_dev) return error<bool>(EXDEV, "staging.link_cross_volume");
    if (::fsync(file) != 0) return error<bool>(errno, "staging.link_file_before_fsync");
    const auto* destination = name.posix_bytes()->c_str();
    if (::linkat(file, "", directory, destination, AT_EMPTY_PATH) == 0)
        return finish_publication(file, directory, destination, held);
    const int direct_error = errno;
    // These are documented capability/empty-path refusals. Other failures,
    // especially EEXIST, never trigger an alternative publication attempt.
    if (direct_error != EPERM && direct_error != EACCES && direct_error != ENOENT)
        return error<bool>(direct_error, "staging.link_empty_path");
    auto opened = open_linux_thread_fd_directory();
    if (!opened.value()) return Observation<bool>::unavailable(opened.state(), opened.unavailable_detail()->error);
    Fd proc(std::move(opened).take_value());
    const auto number = std::to_string(file);
    struct stat reference{}, target{};
    if (::fstatat(proc.get(), number.c_str(), &reference, AT_SYMLINK_NOFOLLOW) != 0)
        return error<bool>(errno, "staging.proc_reference");
    if (!S_ISLNK(reference.st_mode)) return unsupported<bool>("staging.proc_reference_not_kernel_link");
    if (::fstatat(proc.get(), number.c_str(), &target, 0) != 0) return error<bool>(errno, "staging.proc_target");
    if (!same(held, target) || target.st_nlink != 0)
        return invalid<bool>(AdapterError::MetadataChanged, "staging.proc_target_changed", ObservationState::Changed);
    // Only this explicit procfs magic-link resolution follows a link. Neither
    // a source directory-entry name nor the recovery hint participates.
    if (::linkat(proc.get(), number.c_str(), directory, destination, AT_SYMLINK_FOLLOW) != 0)
        return error<bool>(errno, "staging.link_proc_fd");
    return finish_publication(file, directory, destination, held);
#else
    (void)file; (void)directory; (void)name;
    return unsupported<bool>("staging.fd_link_unavailable");
#endif
}
} // namespace ck::files::detail
