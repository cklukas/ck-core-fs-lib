// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "linux_mount_root.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <unistd.h>

namespace ck::files::detail {
namespace {
constexpr std::uint64_t kMaskSuperblockBasic = 0x00000001ULL;
constexpr std::uint64_t kMaskMountBasic = 0x00000002ULL;
constexpr std::uint64_t kMaskMountRoot = 0x00000008ULL;
constexpr std::uint64_t kRequiredMask = kMaskSuperblockBasic | kMaskMountBasic | kMaskMountRoot;
constexpr unsigned kStatmountByFd = 0x00000001U;

// Offsets from the v7.1 uapi struct statmount. The fixed header is exactly
// 512 bytes; fields are copied rather than read through a possibly unavailable
// libc linux/mount.h declaration.
constexpr std::size_t kSizeOffset = 0;
constexpr std::size_t kMaskOffset = 8;
constexpr std::size_t kDeviceMajorOffset = 16;
constexpr std::size_t kDeviceMinorOffset = 20;
constexpr std::size_t kMagicOffset = 24;
constexpr std::size_t kMountIdOffset = 40;
constexpr std::size_t kParentMountIdOffset = 48;
constexpr std::size_t kMountIdOldOffset = 56;
constexpr std::size_t kParentMountIdOldOffset = 60;
constexpr std::size_t kMountAttributesOffset = 64;
constexpr std::size_t kMountRootOffset = 104;
constexpr unsigned kStatxType = 0x00000001U;
constexpr unsigned kStatxNlink = 0x00000004U;
constexpr unsigned kStatxIno = 0x00000100U;
constexpr unsigned kStatxMntId = 0x00001000U;
constexpr unsigned kStatxMntIdUnique = 0x00004000U;
constexpr unsigned kStatxBasicStats = 0x000007ffU;
constexpr std::uint64_t kStatxAttrMountRoot = 0x00002000ULL;
constexpr unsigned kStatxBasicForMount = kStatxType | kStatxNlink | kStatxIno;
constexpr int kStatxFdFlags = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;

template <class T>
bool load(std::span<const std::byte> bytes, std::size_t offset, T& result) noexcept {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return false;
    std::memcpy(&result, bytes.data() + offset, sizeof(T));
    return true;
}

ObservationState errno_state(int code) noexcept {
    if (code == EACCES || code == EPERM) return ObservationState::Denied;
    if (code == ENOSYS || code == ENOTSUP || code == EOPNOTSUPP || code == EINVAL)
        return ObservationState::Unsupported;
    return ObservationState::Failed;
}

template <class T>
Observation<T> native_error(int code, const char* operation) {
    return Observation<T>::unavailable(errno_state(code), {ErrorDomain::Posix, code, operation});
}

template <class T>
Observation<T> invalid_query(const char* operation) {
    return Observation<T>::unavailable(ObservationState::Failed,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), operation});
}

template <class T>
Observation<T> unsupported_query(const char* operation) {
    return Observation<T>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery), operation});
}

#if defined(SYS_statmount)
constexpr long kStatmountSyscall = SYS_statmount;
#elif (defined(__x86_64__) || defined(__aarch64__)) && defined(__LP64__) && !defined(__ILP32__)
constexpr long kStatmountSyscall = 457;
#else
constexpr long kStatmountSyscall = -1;
#endif

struct MntIdRequestV1 final {
    std::uint32_t size = kLinuxMountIdRequestV1Bytes;
    std::uint32_t mount_fd = 0;
    std::uint64_t mount_id = 0;
    std::uint64_t parameter = kRequiredMask;
    std::uint64_t namespace_id = 0;
};
struct MntIdRequestV0 final {
    std::uint32_t size = kLinuxMountIdRequestV0Bytes;
    std::uint32_t mount_fd = 0;
    std::uint64_t mount_id = 0;
    std::uint64_t parameter = kRequiredMask;
};
static_assert(sizeof(MntIdRequestV1) == kLinuxMountIdRequestV1Bytes);
static_assert(sizeof(MntIdRequestV0) == kLinuxMountIdRequestV0Bytes);

struct StatxIds final {
    struct statx unique{};
    struct statx legacy{};
};
struct NativeBookend final {
    struct stat object{};
    struct statfs filesystem{};
    StatxIds ids{};
    bool fd_is_mount_root = false;
};

template <class T, class U>
Observation<T> propagate(const Observation<U>& value) {
    return Observation<T>::unavailable(value.state(), value.unavailable_detail()->error);
}

bool same_statx_basic(const struct statx& a, const struct statx& b) noexcept {
    return (a.stx_mode & S_IFMT) == (b.stx_mode & S_IFMT) && a.stx_ino == b.stx_ino &&
        a.stx_nlink == b.stx_nlink && a.stx_dev_major == b.stx_dev_major &&
        a.stx_dev_minor == b.stx_dev_minor;
}

bool same_object_basic(const struct stat& a, const struct stat& b) noexcept {
    return (a.st_mode & S_IFMT) == (b.st_mode & S_IFMT) && a.st_ino == b.st_ino &&
        a.st_nlink == b.st_nlink && a.st_dev == b.st_dev;
}

bool same_filesystem(const struct statfs& a, const struct statfs& b) noexcept {
    return a.f_type == b.f_type && std::memcmp(&a.f_fsid, &b.f_fsid, sizeof(a.f_fsid)) == 0;
}

Observation<bool> capture_bookend(int fd, NativeBookend& result) {
    if (fstat(fd, &result.object)) return native_error<bool>(errno, "linux_mount_root.fstat");
    if (fstatfs(fd, &result.filesystem)) return native_error<bool>(errno, "linux_mount_root.fstatfs");
    if (!S_ISDIR(result.object.st_mode) || !result.object.st_nlink)
        return invalid_query<bool>("linux_mount_root.directory");
    if (::statx(fd, "", kStatxFdFlags, kStatxBasicStats | kStatxMntIdUnique, &result.ids.unique))
        return native_error<bool>(errno, "linux_mount_root.statx_unique");
    if ((result.ids.unique.stx_mask & (kStatxBasicForMount | kStatxMntIdUnique)) !=
        (kStatxBasicForMount | kStatxMntIdUnique))
        return unsupported_query<bool>("linux_mount_root.statx_unique_unavailable");
    if (result.ids.unique.stx_mnt_id < kLinuxUniqueMountIdMinimum)
        return unsupported_query<bool>("linux_mount_root.statx_unique_range");
    if ((result.ids.unique.stx_attributes_mask & kStatxAttrMountRoot) == 0)
        return unsupported_query<bool>("linux_mount_root.statx_mount_root_attribute_unavailable");
    result.fd_is_mount_root = (result.ids.unique.stx_attributes & kStatxAttrMountRoot) != 0;
    if (::statx(fd, "", kStatxFdFlags, kStatxBasicForMount | kStatxMntId, &result.ids.legacy))
        return native_error<bool>(errno, "linux_mount_root.statx_legacy");
    if ((result.ids.legacy.stx_mask & (kStatxBasicForMount | kStatxMntId)) !=
        (kStatxBasicForMount | kStatxMntId))
        return unsupported_query<bool>("linux_mount_root.statx_legacy_unavailable");
    if (!result.ids.legacy.stx_mnt_id)
        return invalid_query<bool>("linux_mount_root.statx_legacy_zero");
    if (result.ids.unique.stx_dev_major == 0 && result.ids.unique.stx_dev_minor == 0)
        return invalid_query<bool>("linux_mount_root.statx_device_zero");
    if (!same_statx_basic(result.ids.unique, result.ids.legacy) ||
        makedev(result.ids.unique.stx_dev_major, result.ids.unique.stx_dev_minor) != result.object.st_dev ||
        result.ids.unique.stx_ino != result.object.st_ino || result.ids.unique.stx_nlink != result.object.st_nlink)
        return invalid_query<bool>("linux_mount_root.statx_native_mismatch");
    return Observation<bool>::available(true);
}

bool same_bookend(const NativeBookend& a, const NativeBookend& b) noexcept {
    return same_object_basic(a.object, b.object) && same_filesystem(a.filesystem, b.filesystem) &&
        same_statx_basic(a.ids.unique, b.ids.unique) && same_statx_basic(a.ids.legacy, b.ids.legacy) &&
        a.ids.unique.stx_mnt_id == b.ids.unique.stx_mnt_id &&
        a.ids.legacy.stx_mnt_id == b.ids.legacy.stx_mnt_id &&
        a.fd_is_mount_root == b.fd_is_mount_root;
}

template <class T>
Observation<T> changed_query(const char* operation) {
    return Observation<T>::unavailable(ObservationState::Changed,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), operation});
}

} // namespace

LinuxMountRootParseResult parse_linux_mount_root(std::span<const std::byte> bytes) noexcept {
    if (bytes.size() < kLinuxStatmountHeaderBytes)
        return {{}, LinuxMountRootParseError::ShortHeader};

    std::uint32_t size = 0;
    std::uint64_t mask = 0;
    if (!load(bytes, kSizeOffset, size) || !load(bytes, kMaskOffset, mask) ||
        size < kLinuxStatmountHeaderBytes || size > bytes.size())
        return {{}, LinuxMountRootParseError::InvalidSize};
    if ((mask & kRequiredMask) != kRequiredMask)
        return {{}, LinuxMountRootParseError::MissingMask};

    LinuxMountRootWitness result{};
    if (!load(bytes, kDeviceMajorOffset, result.sb_device_major) ||
        !load(bytes, kDeviceMinorOffset, result.sb_device_minor) ||
        (result.sb_device_major == 0 && result.sb_device_minor == 0))
        return {{}, LinuxMountRootParseError::InvalidDevice};
    if (!load(bytes, kMagicOffset, result.filesystem_magic) || !result.filesystem_magic)
        return {{}, LinuxMountRootParseError::InvalidMagic};
    if (!load(bytes, kMountIdOffset, result.mount_id) ||
        !load(bytes, kParentMountIdOffset, result.parent_mount_id) ||
        !load(bytes, kMountIdOldOffset, result.mount_id_old) ||
        !load(bytes, kParentMountIdOldOffset, result.parent_mount_id_old) ||
        result.mount_id < kLinuxUniqueMountIdMinimum ||
        result.parent_mount_id < kLinuxUniqueMountIdMinimum || !result.mount_id_old ||
        !result.parent_mount_id_old)
        return {{}, LinuxMountRootParseError::InvalidMountIds};
    if (!load(bytes, kMountAttributesOffset, result.mnt_attr))
        return {{}, LinuxMountRootParseError::ShortHeader};

    std::uint32_t root_offset = 0;
    if (!load(bytes, kMountRootOffset, root_offset) ||
        root_offset > size - kLinuxStatmountHeaderBytes ||
        size - kLinuxStatmountHeaderBytes - root_offset < 2)
        return {{}, LinuxMountRootParseError::InvalidRootOffset};
    const auto* root = reinterpret_cast<const char*>(bytes.data() + kLinuxStatmountHeaderBytes + root_offset);
    const auto root_bytes = size - kLinuxStatmountHeaderBytes - root_offset;
    const auto* end = static_cast<const char*>(std::memchr(root, 0, root_bytes));
    if (root[0] != '/' || !end)
        return {{}, LinuxMountRootParseError::InvalidRootString};
    // Valid kernel features/layouts are unqualified, not malformed replies.
    // Check the structural string before reporting unsupported attributes.
    if ((result.mnt_attr & kLinuxMountAttrIdmap) != 0 ||
        (result.mnt_attr & ~kLinuxMountAttrKnownMask) != 0)
        return {{}, LinuxMountRootParseError::InvalidMountAttributes};
    if (end != root + 1)
        return {{}, LinuxMountRootParseError::RootIsNotSlash};
    return {result, LinuxMountRootParseError::None};
}

Observation<LinuxMountRootWitness> query_linux_mount_root(int fd) {
#if !defined(__linux__)
    (void)fd;
    return unsupported_query<LinuxMountRootWitness>("linux_mount_root.platform");
#else
    if (fd < 0) return invalid_query<LinuxMountRootWitness>("linux_mount_root.fd");
    if (static_cast<unsigned long long>(fd) > std::numeric_limits<std::uint32_t>::max())
        return invalid_query<LinuxMountRootWitness>("linux_mount_root.fd_range");
    NativeBookend before{};
    auto captured = capture_bookend(fd, before);
    if (!captured.value()) return propagate<LinuxMountRootWitness>(captured);

    if constexpr (kStatmountSyscall < 0) {
        return unsupported_query<LinuxMountRootWitness>("linux_mount_root.syscall_unavailable");
    } else {
        std::array<std::byte, kLinuxStatmountBufferBytes> buffer{};
        MntIdRequestV1 request{};
        request.mount_fd = static_cast<std::uint32_t>(fd);
        errno = 0;
        const long rc = ::syscall(kStatmountSyscall, &request, buffer.data(), buffer.size(), kStatmountByFd);
        long result = rc;
        int code = result < 0 ? errno : 0;
        if (result < 0 && linux_mount_root_should_retry_v0(code)) {
            // The v0 request is the normal kernel API negotiation path for
            // Linux 6.x: it still identifies the held FD and requests the
            // same unique mnt_id fields, but omits the v1 namespace-id tail.
            MntIdRequestV0 legacy{};
            legacy.mount_id = before.ids.unique.stx_mnt_id;
            errno = 0;
            result = ::syscall(kStatmountSyscall, &legacy, buffer.data(), buffer.size(), 0U);
            code = result < 0 ? errno : 0;
        }
        if (result < 0) {
            if (code == ENOSYS || code == ENOTSUP || code == EOPNOTSUPP || code == EINVAL || code == EOVERFLOW)
                return unsupported_query<LinuxMountRootWitness>("linux_mount_root.statmount_unavailable");
            return native_error<LinuxMountRootWitness>(code, "linux_mount_root.statmount");
        }
        const auto parsed = parse_linux_mount_root(std::span<const std::byte>(buffer));
        if (!parsed.witness) {
            if (parsed.error == LinuxMountRootParseError::MissingMask)
                return unsupported_query<LinuxMountRootWitness>("linux_mount_root.fields_unavailable");
            if (parsed.error == LinuxMountRootParseError::RootIsNotSlash)
                return unsupported_query<LinuxMountRootWitness>("linux_mount_root.nonroot_mount_layout");
            if (parsed.error == LinuxMountRootParseError::InvalidMountAttributes)
                return unsupported_query<LinuxMountRootWitness>("linux_mount_root.mount_attributes_unqualified");
            return invalid_query<LinuxMountRootWitness>("linux_mount_root.parse");
        }
        auto witness = *parsed.witness;
        if (witness.mount_id != before.ids.unique.stx_mnt_id ||
            witness.mount_id_old != before.ids.legacy.stx_mnt_id ||
            witness.filesystem_magic != linux_statfs_magic(before.filesystem.f_type))
            return invalid_query<LinuxMountRootWitness>("linux_mount_root.native_mismatch");
        NativeBookend after{};
        captured = capture_bookend(fd, after);
        if (!captured.value()) return propagate<LinuxMountRootWitness>(captured);
        if (!same_bookend(before, after))
            return changed_query<LinuxMountRootWitness>("linux_mount_root.bookend_changed");
        if (witness.mount_id != after.ids.unique.stx_mnt_id ||
            witness.mount_id_old != after.ids.legacy.stx_mnt_id ||
            witness.parent_mount_id_old == 0 || witness.parent_mount_id < kLinuxUniqueMountIdMinimum)
            return changed_query<LinuxMountRootWitness>("linux_mount_root.reply_id_changed");
        // Only publish VFS identity after both native bookends agree.
        // statmount's sb_dev is deliberately retained in its own domain.
        witness.vfs_device_major = before.ids.unique.stx_dev_major;
        witness.vfs_device_minor = before.ids.unique.stx_dev_minor;
        witness.fd_is_mount_root = before.fd_is_mount_root;
        return Observation<LinuxMountRootWitness>::available(witness);
    }
#endif
}

} // namespace ck::files::detail
