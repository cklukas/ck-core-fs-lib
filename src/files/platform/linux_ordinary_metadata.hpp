// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#if defined(__linux__)
#include <cstdint>
#include <linux/fs.h>
#include <linux/magic.h>
namespace ck::files::detail {
// Only native fstatfs evidence from an identity-checked held descriptor selects
// a provider. This does not qualify ownership, xattrs, ACLs, security, storage
// attributes, read access or layout; the caller still checks every one.
enum class LinuxOrdinaryMetadataProvider { Unknown, Ext4, Xfs, Btrfs };
constexpr LinuxOrdinaryMetadataProvider linux_ordinary_metadata_provider(std::int64_t type) noexcept {
    if(type==EXT4_SUPER_MAGIC)return LinuxOrdinaryMetadataProvider::Ext4;
    if(type==XFS_SUPER_MAGIC)return LinuxOrdinaryMetadataProvider::Xfs;
    if(type==BTRFS_SUPER_MAGIC)return LinuxOrdinaryMetadataProvider::Btrfs;
    return LinuxOrdinaryMetadataProvider::Unknown;
}
constexpr bool linux_ordinary_inode_flags(LinuxOrdinaryMetadataProvider provider,
    std::uint32_t flags,bool directory=false) noexcept {
    if(provider==LinuxOrdinaryMetadataProvider::Unknown)return false;
    // Ext4 extents and directory indexing are representation. XFS/Btrfs have
    // no accepted policy flags: compression, NOCOW, DAX, inheritance and every
    // unknown bit require review rather than implied loss or replay.
    const auto allowed=provider==LinuxOrdinaryMetadataProvider::Ext4?
        static_cast<std::uint32_t>(FS_EXTENT_FL|(directory?FS_INDEX_FL:0)):0U;
    return (flags&~allowed)==0;
}
constexpr bool linux_ordinary_storage_policy(LinuxOrdinaryMetadataProvider provider,
    const fsxattr& storage) noexcept {
    if(provider==LinuxOrdinaryMetadataProvider::Unknown)return false;
    // HASATTR only reports XFS's attribute fork, including an empty retained
    // fork. Its contents still need the full native caller-visible inventory.
    // nextents is physical allocation, not a replayable policy. All other
    // xflags and nonzero project/extent/COW policies remain refused.
    const auto allowed=provider==LinuxOrdinaryMetadataProvider::Xfs?
        static_cast<std::uint32_t>(FS_XFLAG_HASATTR):0U;
    return (storage.fsx_xflags&~allowed)==0&&storage.fsx_projid==0&&
        storage.fsx_extsize==0&&storage.fsx_cowextsize==0;
}
} // namespace ck::files::detail
#endif
