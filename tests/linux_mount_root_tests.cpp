// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "platform/linux_mount_root.hpp"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <span>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

using namespace ck::files;
using namespace ck::files::detail;

namespace {
constexpr std::size_t size_offset = 0;
constexpr std::size_t mask_offset = 8;
constexpr std::size_t device_major_offset = 16;
constexpr std::size_t device_minor_offset = 20;
constexpr std::size_t magic_offset = 24;
constexpr std::size_t mount_id_offset = 40;
constexpr std::size_t parent_mount_id_offset = 48;
constexpr std::size_t mount_id_old_offset = 56;
constexpr std::size_t parent_mount_id_old_offset = 60;
constexpr std::size_t mount_attributes_offset = 64;
constexpr std::size_t mount_root_offset = 104;
constexpr std::uint64_t required_mask = 0x0000000bULL;
constexpr std::uint64_t unique_base = kLinuxUniqueMountIdMinimum;

void statfs_magic_width_controls() {
    constexpr std::uint64_t btrfs_magic = 0x000000009123683eULL;
    constexpr auto signed32_btrfs = std::int32_t{-0x6edc97c2};
    constexpr auto unsigned32_btrfs = std::uint32_t{0x9123683eU};
    constexpr auto signed64_magic = std::int64_t{-0x7edcba9876543211LL};
    constexpr auto signed64_expected = 0x8123456789abcdefULL;
    constexpr auto unknown64 = std::int64_t{0x000000019123683eLL};

    assert(linux_statfs_magic(signed32_btrfs) == btrfs_magic);
    assert(linux_statfs_magic(unsigned32_btrfs) == btrfs_magic);
    assert(linux_statfs_magic(signed64_magic) == signed64_expected);
    assert(linux_statfs_magic(unknown64) == 0x000000019123683eULL);
    assert(linux_statfs_magic(unknown64) != linux_statfs_magic(signed32_btrfs));
}

template <class T>
void put(std::array<std::byte, kLinuxStatmountBufferBytes>& bytes, std::size_t offset, T value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

std::array<std::byte, kLinuxStatmountBufferBytes> valid_record() {
    std::array<std::byte, kLinuxStatmountBufferBytes> bytes{};
    put(bytes, size_offset, std::uint32_t{514});
    put(bytes, mask_offset, required_mask);
    put(bytes, device_major_offset, std::uint32_t{8});
    put(bytes, device_minor_offset, std::uint32_t{1});
    put(bytes, magic_offset, std::uint64_t{0xef53});
    put(bytes, mount_id_offset, unique_base + 19);
    put(bytes, parent_mount_id_offset, unique_base + 23);
    put(bytes, mount_id_old_offset, std::uint32_t{7});
    put(bytes, parent_mount_id_old_offset, std::uint32_t{8});
    put(bytes, mount_attributes_offset, kLinuxMountAttrKnownMask);
    put(bytes, mount_root_offset, std::uint32_t{0});
    bytes[kLinuxStatmountHeaderBytes] = std::byte{0x2f};
    bytes[kLinuxStatmountHeaderBytes + 1] = std::byte{0};
    return bytes;
}

void parser_controls() {
    auto valid = valid_record();
    auto parsed = parse_linux_mount_root(std::span<const std::byte>(valid));
    assert(parsed.witness && parsed.error == LinuxMountRootParseError::None);
    assert(parsed.witness->mount_id == unique_base + 19 && parsed.witness->parent_mount_id == unique_base + 23);
    assert(parsed.witness->mount_id_old == 7 && parsed.witness->parent_mount_id_old == 8);
    assert(parsed.witness->mnt_attr == kLinuxMountAttrKnownMask);
    assert(parsed.witness->sb_device_major == 8 && parsed.witness->filesystem_magic == 0xef53);

    auto check = [&](auto mutate, LinuxMountRootParseError expected) {
        auto bytes = valid; mutate(bytes);
        const auto result = parse_linux_mount_root(std::span<const std::byte>(bytes));
        assert(!result.witness && result.error == expected);
    };
    check([](auto& bytes) { put(bytes, size_offset, std::uint32_t{511}); }, LinuxMountRootParseError::InvalidSize);
    check([](auto& bytes) { put(bytes, size_offset, std::uint32_t{1025}); }, LinuxMountRootParseError::InvalidSize);
    check([](auto& bytes) { put(bytes, device_major_offset, std::uint32_t{0}); put(bytes, device_minor_offset, std::uint32_t{0}); }, LinuxMountRootParseError::InvalidDevice);
    check([](auto& bytes) { put(bytes, mask_offset, std::uint64_t{required_mask & ~0x8ULL}); }, LinuxMountRootParseError::MissingMask);
    check([](auto& bytes) { put(bytes, magic_offset, std::uint64_t{0}); }, LinuxMountRootParseError::InvalidMagic);
    check([](auto& bytes) { put(bytes, mount_id_offset, std::uint64_t{20}); }, LinuxMountRootParseError::InvalidMountIds);
    check([](auto& bytes) { put(bytes, parent_mount_id_offset, std::uint64_t{20}); }, LinuxMountRootParseError::InvalidMountIds);
    check([](auto& bytes) { put(bytes, mount_id_old_offset, std::uint32_t{0}); }, LinuxMountRootParseError::InvalidMountIds);
    check([](auto& bytes) { put(bytes, mount_attributes_offset, kLinuxMountAttrIdmap); }, LinuxMountRootParseError::InvalidMountAttributes);
    check([](auto& bytes) { put(bytes, mount_attributes_offset, kLinuxMountAttrKnownMask | (1ULL << 63)); }, LinuxMountRootParseError::InvalidMountAttributes);
    auto differing_parent = valid;
    put(differing_parent, parent_mount_id_old_offset, std::uint32_t{9});
    const auto differing_result = parse_linux_mount_root(std::span<const std::byte>(differing_parent));
    assert(differing_result.witness && differing_result.witness->parent_mount_id_old == 9);
    check([](auto& bytes) { bytes[kLinuxStatmountHeaderBytes] = std::byte{0x78}; }, LinuxMountRootParseError::RootIsNotSlash);
    check([](auto& bytes) { put(bytes, mount_root_offset, std::uint32_t{512}); }, LinuxMountRootParseError::InvalidRootOffset);
    auto short_bytes = valid;
    const auto short_result = parse_linux_mount_root(std::span<const std::byte>(short_bytes.data(), 511));
    assert(!short_result.witness && short_result.error == LinuxMountRootParseError::ShortHeader);
}

void superblock_device_is_independent_from_vfs_device() {
    // Btrfs may expose a per-subvolume VFS st_dev (for example 0:58) while
    // statmount.sb_dev is the superblock's s_dev (for example 0:57). The
    // parser must retain the statmount fields without treating a different
    // held-FD fstat device as a native mismatch. The native query separately
    // binds that held-FD VFS identity through fstat/statx bookends.
    auto bytes = valid_record();
    put(bytes, device_major_offset, std::uint32_t{0});
    put(bytes, device_minor_offset, std::uint32_t{57});
    constexpr std::uint32_t vfs_device_major = 0;
    constexpr std::uint32_t vfs_device_minor = 58;
    const auto parsed = parse_linux_mount_root(std::span<const std::byte>(bytes));
    assert(parsed.witness && parsed.error == LinuxMountRootParseError::None);
    assert(parsed.witness->sb_device_major == 0 && parsed.witness->sb_device_minor == 57);
    assert(parsed.witness->sb_device_major != vfs_device_major ||
        parsed.witness->sb_device_minor != vfs_device_minor);
}

void request_version_controls() {
    assert(linux_mount_root_request_size(LinuxMountRootRequestVersion::V1) == 32);
    assert(linux_mount_root_request_size(LinuxMountRootRequestVersion::V0) == 24);
    assert(linux_mount_root_should_retry_v0(EINVAL));
    assert(!linux_mount_root_should_retry_v0(ENOSYS));
    assert(!linux_mount_root_should_retry_v0(EIO));
}
}

int main(int argc, char** argv) {
    assert(argc == 2);
    statfs_magic_width_controls();
    parser_controls();
    superblock_device_is_independent_from_vfs_device();
    request_version_controls();

    const int fd = ::open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    struct stat before{}, after{};
    struct statx before_statx{}, after_statx{};
    assert(::fstat(fd, &before) == 0);
    const int before_statx_result = ::statx(fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
        STATX_BASIC_STATS, &before_statx);
    const auto native = query_linux_mount_root(fd);
    assert(::fstat(fd, &after) == 0);
    const int after_statx_result = ::statx(fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
        STATX_BASIC_STATS, &after_statx);
    const int close_result = ::close(fd);
    assert(close_result == 0);
    if (!native.value()) {
        // A pre-statmount kernel is a deliberate qualification result, never
        // a guessed fallback to /proc or a path-derived root.
        assert(native.state() == ObservationState::Unsupported);
        std::puts("linux mount-root parser passed; statmount unavailable (explicit Unsupported)");
        return 0;
    }
    assert(native.value()->mount_id >= kLinuxUniqueMountIdMinimum &&
        native.value()->parent_mount_id >= kLinuxUniqueMountIdMinimum);
    assert(native.value()->mount_id_old != 0 && native.value()->parent_mount_id_old != 0);
    assert(before_statx_result == 0 && after_statx_result == 0);
    assert(before.st_dev == after.st_dev && before.st_ino == after.st_ino);
    assert(before_statx.stx_dev_major == after_statx.stx_dev_major &&
        before_statx.stx_dev_minor == after_statx.stx_dev_minor);
    assert(makedev(before_statx.stx_dev_major, before_statx.stx_dev_minor) == before.st_dev);
    assert(makedev(after_statx.stx_dev_major, after_statx.stx_dev_minor) == after.st_dev);
    assert(native.value()->vfs_device_major == major(before.st_dev) &&
        native.value()->vfs_device_minor == minor(before.st_dev));
    assert(native.value()->vfs_device_major == before_statx.stx_dev_major &&
        native.value()->vfs_device_minor == before_statx.stx_dev_minor);
    assert(native.value()->vfs_device_major != 0 || native.value()->vfs_device_minor != 0);
    // The raw statmount superblock device is deliberately NOT equated with
    // this held object's VFS device. The same checks apply to every provider.
    std::printf("native mount witness sb=%u:%u vfs=%u:%u fstat=%u:%u statx=%u:%u magic=%016llx mount=%llu parent=%llu fd_mount_root=%u\n",
        native.value()->sb_device_major, native.value()->sb_device_minor,
        native.value()->vfs_device_major, native.value()->vfs_device_minor,
        major(before.st_dev), minor(before.st_dev), before_statx.stx_dev_major, before_statx.stx_dev_minor,
        static_cast<unsigned long long>(native.value()->filesystem_magic),
        static_cast<unsigned long long>(native.value()->mount_id),
        static_cast<unsigned long long>(native.value()->parent_mount_id), unsigned(native.value()->fd_is_mount_root));
    std::puts("linux mount-root parser and native statmount witness passed");
}
