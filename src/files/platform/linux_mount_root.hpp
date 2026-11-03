// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once

#include "../observation.hpp"

#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <optional>
#include <span>
#include <type_traits>

namespace ck::files::detail {

// Linux 7.1's statmount fixed header ends immediately before str[] at 512
// bytes. Keep this bound private: it is a kernel-query implementation detail,
// not a public filesystem ABI.
inline constexpr std::size_t kLinuxStatmountHeaderBytes = 512;
inline constexpr std::size_t kLinuxStatmountBufferBytes = 1024;
inline constexpr std::size_t kLinuxMountIdRequestV1Bytes = 32;
inline constexpr std::size_t kLinuxMountIdRequestV0Bytes = 24;
inline constexpr std::uint64_t kLinuxUniqueMountIdMinimum = 1ULL << 31;
// ID-mapped mounts change the ownership namespace presented by the mount.
// Future/unknown bits are fail-closed before a root witness is accepted.
inline constexpr std::uint64_t kLinuxMountAttrIdmap = 0x00100000ULL;
inline constexpr std::uint64_t kLinuxMountAttrKnownMask =
    0x00000001ULL | 0x00000002ULL | 0x00000004ULL | 0x00000008ULL |
    0x00000070ULL | 0x00200000ULL;

// statmount.sb_magic is a u64, while libc statfs.f_type may be a signed
// 32-bit or 64-bit word. Convert through the matching unsigned type so a
// negative signed 32-bit BTRFS magic is widened without sign extension, while
// a genuine 64-bit value retains all of its bits.
template <class T>
constexpr std::uint64_t linux_statfs_magic(T value) noexcept {
    static_assert(std::is_integral_v<T>);
    using Unsigned = std::make_unsigned_t<T>;
    return static_cast<std::uint64_t>(static_cast<Unsigned>(value));
}

enum class LinuxMountRootRequestVersion : std::uint8_t { V1, V0 };

constexpr std::size_t linux_mount_root_request_size(LinuxMountRootRequestVersion version) noexcept {
    return version == LinuxMountRootRequestVersion::V1 ? kLinuxMountIdRequestV1Bytes : kLinuxMountIdRequestV0Bytes;
}

// Linux 6.x statmount accepts the v0 mnt_id_req but may reject the v1
// namespace-id extension with EINVAL. No path/proc fallback is permitted.
constexpr bool linux_mount_root_should_retry_v0(int native_error) noexcept {
    return native_error == EINVAL;
}

enum class LinuxMountRootParseError {
    None,
    ShortHeader,
    InvalidSize,
    MissingMask,
    InvalidDevice,
    InvalidMagic,
    InvalidMountIds,
    InvalidMountAttributes,
    InvalidRootOffset,
    RootIsNotSlash,
    InvalidRootString,
};

struct LinuxMountRootWitness final {
    std::uint64_t mount_id = 0;
    std::uint64_t parent_mount_id = 0;
    std::uint32_t mount_id_old = 0;
    std::uint32_t parent_mount_id_old = 0;
    std::uint64_t mnt_attr = 0;
    // The superblock identity from statmount is distinct from the held
    // object's VFS st_dev (notably on Btrfs subvolumes). Retain both.
    std::uint32_t sb_device_major = 0;
    std::uint32_t sb_device_minor = 0;
    std::uint32_t vfs_device_major = 0;
    std::uint32_t vfs_device_minor = 0;
    std::uint64_t filesystem_magic = 0;
    // statmount.mnt_root describes the containing mount. This separate
    // native statx result proves that the held FD itself is that mount root.
    bool fd_is_mount_root = false;

    friend bool operator==(const LinuxMountRootWitness&, const LinuxMountRootWitness&) = default;
};

struct LinuxMountRootParseResult final {
    std::optional<LinuxMountRootWitness> witness;
    LinuxMountRootParseError error = LinuxMountRootParseError::None;
};

// Pure bounded parser used by native qualification tests. It never follows a
// string offset beyond the returned statmount buffer and accepts only a
// mount record whose filesystem-root string is "/\0". Native query callers
// must additionally require fd_is_mount_root for endpoint/transition use.
LinuxMountRootParseResult parse_linux_mount_root(std::span<const std::byte> bytes) noexcept;

// Query a held directory FD. No path, /proc text, namespace helper, or cached
// mount-table authority is involved. Older kernels return Unsupported.
Observation<LinuxMountRootWitness> query_linux_mount_root(int fd);

} // namespace ck::files::detail
