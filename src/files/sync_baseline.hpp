// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once

#include "observation.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ck::files {

using SyncDigest = std::array<std::byte, 32>;
enum class SyncPresence : std::uint8_t { Unknown, Absent, Present };
enum class SyncKind : std::uint8_t { Unknown, File, Directory, Other };

// Present asserts a COMPLETE STABLE digest, not an mtime/size inference. The
// adapter must bind both digests to the same observed object/version. Required
// metadata participates in change detection: a one-sided edit propagates from
// a trusted equal baseline. Unbased or concurrent disagreement requires conflict
// review even when content is identical.
// Absent asserts qualified absence, never a failed/partial inventory lookup.
// Unknown/Absent have Unknown kind and zero digests (canonical wire form).
struct SyncEntryStatus final {
    SyncPresence presence = SyncPresence::Unknown;
    SyncKind kind = SyncKind::Unknown;
    SyncDigest content_digest{};
    SyncDigest required_metadata_digest{};
    friend bool operator==(const SyncEntryStatus&, const SyncEntryStatus&) = default;
};

struct SyncBaselineRow final {
    // Exact lossless adapter key, '/' separated relative components. No empty,
    // '.', '..', NUL, '\\' or ':' components; no normalization/case folding.
    // Nonrepresentable native names must be encoded losslessly by the adapter.
    std::string relative_path;
    SyncEntryStatus left;
    SyncEntryStatus right;
    friend bool operator==(const SyncBaselineRow&, const SyncBaselineRow&) = default;
};

struct SyncBaseline final {
    // Must bind ORDERED root identities/namespaces, digest schema, exclusions,
    // required metadata and comparison/deletion policy. Never just a pair ID.
    SyncDigest policy_fingerprint{};
    std::vector<SyncBaselineRow> rows; // strictly sorted exact keys; no duplicates
    friend bool operator==(const SyncBaseline&, const SyncBaseline&) = default;
};

struct SyncBaselineLimits final {
    std::size_t max_rows = 100'000;
    std::size_t max_path_bytes = 4096;
    std::size_t max_total_path_bytes = 8 * 1024 * 1024;
    std::size_t max_wire_bytes = 32 * 1024 * 1024;
    static constexpr std::size_t hard_max_rows = 1'000'000;
    static constexpr std::size_t hard_max_path_bytes = 65'536;
    static constexpr std::size_t hard_max_total_path_bytes = 64 * 1024 * 1024;
    static constexpr std::size_t hard_max_wire_bytes = 256 * 1024 * 1024;
};

struct SyncCurrent final {
    // CompleteStable assertions cover the WHOLE respective root, including
    // exclusions and absence qualification. Neither is inferred from the rows.
    bool left_complete_stable = false;
    bool right_complete_stable = false;
    std::span<const SyncBaselineRow> rows;
};

struct SyncDeletionGuard final {
    std::size_t max_deletions = 0; // combined left + right; defaults prohibit deletes
    std::uint32_t max_basis_points = 0; // 0..10,000, separately for EACH side
    // Ratio denominator: baseline Present rows on the affected side. A large
    // opposite root cannot dilute mass deletion on the smaller root.
};

enum class SyncAction { Unchanged, CopyLeftToRight, CopyRightToLeft, DeleteLeft, DeleteRight, Conflict, Blocked };
enum class SyncReason {
    None, UnknownStatus, IncompleteInventory, InitialDifference, ConcurrentEdit,
    DeleteEdit, BaselineDiverged, RequiredMetadataDifference, PolicyChanged,
    DirectoryDeleteChangedSubtree, AncestorConflict, DeletionGuard
};
enum class SyncReconcileState { Ready, Blocked, ReconcileRequired, DeletionGuardExceeded };
struct SyncReconcileRow final {
    std::string relative_path;
    SyncAction action = SyncAction::Blocked;
    SyncReason reason = SyncReason::UnknownStatus;
};
struct SyncReconcilePlan final {
    SyncReconcileState state = SyncReconcileState::Ready;
    std::vector<SyncReconcileRow> rows;
    std::size_t proposed_deletions_left = 0; // includes proposals blocked by guard
    std::size_t proposed_deletions_right = 0;
};

// Pure proposals, not native operation authority. Null baseline means first
// merge: additions may be copied, never deleted. Missing current rows are
// Unknown, not Absent. Directory copies mean creating/merging a directory;
// deletes mean EMPTY directory removal, never recursive deletion. Descendants
// must be processed independently, with child-before-parent retirement.
// Any policy fingerprint mismatch requires explicit reconcile (no proposals).
// Callers must separately qualify topology, preservation and native identities,
// review conflicts and revalidate before mutation. Execution locks MUST cover
// overlapping roots across DIFFERENT pair IDs; no locking/storage is supplied.
Observation<SyncReconcilePlan> reconcile_sync(const SyncBaseline* baseline,
    const SyncCurrent& current, const SyncDigest& policy_fingerprint,
    SyncDeletionGuard guard = {}, SyncBaselineLimits limits = {});

enum class SyncBaselineUpdateState { Pending, ConfirmedEqual };
struct SyncBaselineUpdate final {
    SyncBaselineRow observed;
    SyncBaselineUpdateState state = SyncBaselineUpdateState::Pending;
};
struct SyncBaselineAdvance final {
    SyncBaseline baseline;
    std::vector<std::string> pending_paths;
};
// Pure baseline advancement after separately verified execution/observation.
// ConfirmedEqual requires both known, identical statuses. Pending (including a
// skipped deletion), or an omitted update, RETAINS the old baseline row and
// reports it pending; a new pending key gets no invented baseline. This cannot
// commit a store or prove execution. No policy-change rebase is implicit.
Observation<SyncBaselineAdvance> advance_sync_baseline(const SyncBaseline* previous,
    std::span<const SyncBaselineUpdate> updates, const SyncDigest& policy_fingerprint,
    SyncBaselineLimits limits = {});

// Version 1, canonical little endian, bounded lengths/counts, SHA-256 checksum.
// Corruption, unknown versions/enums/reserved bits, duplicate/unsafe keys and
// trailing bytes fail closed without a partial baseline. Checksum provides NO
// authentication, rollback protection, durable storage, locking or authority.
// Allocation failures may throw at this internal C++ boundary.
Observation<std::vector<std::byte>> encode_sync_baseline(const SyncBaseline& baseline,
    SyncBaselineLimits limits = {});
Observation<SyncBaseline> decode_sync_baseline(std::span<const std::byte> wire,
    SyncBaselineLimits limits = {});

} // namespace ck::files
