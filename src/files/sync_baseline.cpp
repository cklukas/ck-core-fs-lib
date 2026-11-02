// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "sync_baseline.hpp"
#include "sha256.hpp"

#include <algorithm>
#include <optional>
#include <string_view>
#include <utility>

namespace ck::files {
namespace {
constexpr std::size_t header_bytes = 64, checksum_bytes = 32, row_bytes = 140;
constexpr std::array<std::byte, 8> magic{std::byte{'C'}, std::byte{'K'}, std::byte{'S'}, std::byte{'Y'},
    std::byte{'N'}, std::byte{'C'}, std::byte{'B'}, std::byte{0}};

template <class T> Observation<T> fail(AdapterError code, const char* operation) {
    return Observation<T>::unavailable(ObservationState::Failed,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(code), operation});
}
bool valid_limits(const SyncBaselineLimits& l) {
    return l.max_rows && l.max_rows <= l.hard_max_rows && l.max_path_bytes &&
        l.max_path_bytes <= l.hard_max_path_bytes && l.max_total_path_bytes &&
        l.max_total_path_bytes <= l.hard_max_total_path_bytes &&
        l.max_wire_bytes >= header_bytes + checksum_bytes && l.max_wire_bytes <= l.hard_max_wire_bytes;
}
bool valid_status(const SyncEntryStatus& s) {
    switch (s.presence) {
    case SyncPresence::Unknown:
    case SyncPresence::Absent:
        return s.kind == SyncKind::Unknown && s.content_digest == SyncDigest{} &&
            s.required_metadata_digest == SyncDigest{};
    case SyncPresence::Present:
        return s.kind == SyncKind::File || s.kind == SyncKind::Directory || s.kind == SyncKind::Other;
    }
    return false;
}
bool known(const SyncEntryStatus& s) { return s.presence != SyncPresence::Unknown; }
bool present(const SyncEntryStatus& s) { return s.presence == SyncPresence::Present; }
bool valid_path(std::string_view p, const SyncBaselineLimits& l) {
    if (p.empty() || p.size() > l.max_path_bytes || p.find_first_of("\\:") != p.npos ||
        p.find('\0') != p.npos) return false;
    std::size_t start = 0;
    for (;;) {
        const auto slash = p.find('/', start);
        const auto part = p.substr(start, slash == p.npos ? p.npos : slash - start);
        if (part.empty() || part == "." || part == "..") return false;
        if (slash == p.npos) return true;
        start = slash + 1;
    }
}
bool permitted_child(const SyncEntryStatus& parent, const SyncEntryStatus& child) {
    return !present(child) || parent.presence == SyncPresence::Unknown ||
        (present(parent) && parent.kind == SyncKind::Directory);
}
// A lexical predecessor is not necessarily the parent ("a-" sorts between
// "a" and "a/b"). Exact prefix lookup avoids that trap without a size*depth
// scan of all prior rows. Every component prefix is looked up independently.
template <class Row, class Evidence>
bool valid_rows(std::span<const Row> rows, const SyncBaselineLimits& l, Evidence evidence) {
    if (rows.size() > l.max_rows) return false;
    std::size_t total = 0;
    std::string_view previous;
    bool first = true;
    for (const auto& item : rows) {
        const auto& r = evidence(item);
        if (!valid_path(r.relative_path, l) || !valid_status(r.left) || !valid_status(r.right) ||
            (!first && previous >= r.relative_path) || r.relative_path.size() > l.max_total_path_bytes - total)
            return false;
        total += r.relative_path.size();
        previous = r.relative_path;
        first = false;
    }
    for (const auto& item : rows) {
        const auto& r = evidence(item);
        for (auto slash = r.relative_path.find('/'); slash != std::string::npos;
            slash = r.relative_path.find('/', slash + 1)) {
            const std::string_view prefix(r.relative_path.data(), slash);
            auto it = std::lower_bound(rows.begin(), rows.end(), prefix,
                [&](const Row& row, std::string_view key) { return evidence(row).relative_path < key; });
            if (it != rows.end() && evidence(*it).relative_path == prefix) {
                const auto& parent = evidence(*it);
                if (!permitted_child(parent.left, r.left) || !permitted_child(parent.right, r.right)) return false;
            }
        }
    }
    return true;
}
bool valid_rows(std::span<const SyncBaselineRow> rows, const SyncBaselineLimits& l) {
    return valid_rows(rows, l, [](const SyncBaselineRow& r) -> const auto& { return r; });
}
bool equal_known(const SyncBaselineRow& r) { return known(r.left) && known(r.right) && r.left == r.right; }

SyncReconcileRow classify(const SyncBaselineRow* old, const SyncBaselineRow* now, std::string key) {
    SyncReconcileRow out{std::move(key)};
    if (!now || !known(now->left) || !known(now->right)) return out;
    const auto& l = now->left;
    const auto& r = now->right;
    if (l == r) { out.action = SyncAction::Unchanged; out.reason = SyncReason::None; return out; }
    out.action = SyncAction::Conflict;
    const bool metadata_disagrees = present(l) && present(r) &&
        l.required_metadata_digest != r.required_metadata_digest;
    if (!old) {
        out.reason = SyncReason::None;
        if (!present(r)) out.action = SyncAction::CopyLeftToRight;
        else if (!present(l)) out.action = SyncAction::CopyRightToLeft;
        else out.reason = metadata_disagrees ? SyncReason::RequiredMetadataDifference : SyncReason::InitialDifference;
        return out;
    }
    if (!known(old->left) || !known(old->right)) {
        out.action = SyncAction::Blocked; out.reason = SyncReason::UnknownStatus; return out;
    }
    if (old->left != old->right) {
        out.reason = metadata_disagrees ? SyncReason::RequiredMetadataDifference : SyncReason::BaselineDiverged;
        return out;
    }
    const bool lc = l != old->left, rc = r != old->right;
    if (lc && rc) {
        out.reason = metadata_disagrees ? SyncReason::RequiredMetadataDifference :
            (present(l) != present(r) ? SyncReason::DeleteEdit : SyncReason::ConcurrentEdit);
    } else if (lc) {
        out.action = present(l) ? SyncAction::CopyLeftToRight : SyncAction::DeleteRight;
        out.reason = SyncReason::None;
    } else if (rc) {
        out.action = present(r) ? SyncAction::CopyRightToLeft : SyncAction::DeleteLeft;
        out.reason = SyncReason::None;
    } else out.reason = SyncReason::BaselineDiverged;
    return out;
}
struct Facts {
    bool left_changed = false, right_changed = false, left_unknown = false, right_unknown = false;
    void merge(const Facts& f) {
        left_changed |= f.left_changed; right_changed |= f.right_changed;
        left_unknown |= f.left_unknown; right_unknown |= f.right_unknown;
    }
};
Facts facts(const SyncBaselineRow* old, const SyncBaselineRow* now) {
    const SyncEntryStatus absent{SyncPresence::Absent};
    const auto& l = old ? old->left : absent;
    const auto& r = old ? old->right : absent;
    return {!now || now->left != l, !now || now->right != r,
        !now || !known(now->left) || !known(l), !now || !known(now->right) || !known(r)};
}
void put(std::vector<std::byte>& out, std::uint64_t value, unsigned bytes) {
    for (unsigned i = 0; i < bytes; ++i) out.push_back(static_cast<std::byte>((value >> (8 * i)) & 0xff));
}
void put_digest(std::vector<std::byte>& out, const SyncDigest& digest) {
    out.insert(out.end(), digest.begin(), digest.end());
}
void put_status(std::vector<std::byte>& out, const SyncEntryStatus& s) {
    put(out, static_cast<std::uint8_t>(s.presence), 1);
    put(out, static_cast<std::uint8_t>(s.kind), 1);
    put(out, 0, 2);
    put_digest(out, s.content_digest);
    put_digest(out, s.required_metadata_digest);
}
class Reader {
public:
    explicit Reader(std::span<const std::byte> bytes) : bytes_(bytes) {}
    bool take(std::size_t count, std::span<const std::byte>& out) {
        if (count > bytes_.size() - offset_) return false;
        out = bytes_.subspan(offset_, count); offset_ += count; return true;
    }
    bool get(std::uint64_t& out, unsigned count) {
        std::span<const std::byte> b;
        if (!take(count, b)) return false;
        out = 0;
        for (unsigned i = 0; i < count; ++i) out |= std::uint64_t(std::to_integer<unsigned>(b[i])) << (8 * i);
        return true;
    }
    bool digest(SyncDigest& out) {
        std::span<const std::byte> b;
        if (!take(out.size(), b)) return false;
        std::copy(b.begin(), b.end(), out.begin()); return true;
    }
    bool status(SyncEntryStatus& out) {
        std::uint64_t p = 0, k = 0, reserved = 0;
        if (!get(p, 1) || !get(k, 1) || !get(reserved, 2) || reserved ||
            !digest(out.content_digest) || !digest(out.required_metadata_digest)) return false;
        out.presence = static_cast<SyncPresence>(p); out.kind = static_cast<SyncKind>(k);
        return valid_status(out);
    }
    bool empty() const { return offset_ == bytes_.size(); }
private:
    std::span<const std::byte> bytes_;
    std::size_t offset_ = 0;
};
SyncDigest checksum(std::span<const std::byte> wire) {
    Sha256 h; h.update(wire); return h.digest();
}
} // namespace

Observation<SyncReconcilePlan> reconcile_sync(const SyncBaseline* baseline, const SyncCurrent& current,
    const SyncDigest& policy, SyncDeletionGuard guard, SyncBaselineLimits limits) {
    using Result = Observation<SyncReconcilePlan>;
    if (!valid_limits(limits) || guard.max_basis_points > 10'000 || guard.max_deletions > limits.hard_max_rows * 2)
        return fail<SyncReconcilePlan>(AdapterError::InvalidLimit, "sync.reconcile.limits");
    if (!valid_rows(current.rows, limits) || (baseline && !valid_rows(baseline->rows, limits)))
        return fail<SyncReconcilePlan>(AdapterError::InvalidNativeResult, "sync.reconcile.rows");
    const std::span<const SyncBaselineRow> old = baseline ? std::span<const SyncBaselineRow>(baseline->rows) :
        std::span<const SyncBaselineRow>{};
    SyncReconcilePlan out;
    std::vector<Facts> all;
    std::vector<std::optional<std::size_t>> parents;
    std::size_t a = 0, b = 0, total_paths = 0, population_l = 0, population_r = 0;
    // Complete evidence for a path is never inferred by its omission.
    while (a < old.size() || b < current.rows.size()) {
        const SyncBaselineRow *before = nullptr, *now = nullptr;
        if (b == current.rows.size() || (a < old.size() && old[a].relative_path < current.rows[b].relative_path))
            before = &old[a++];
        else if (a == old.size() || current.rows[b].relative_path < old[a].relative_path) now = &current.rows[b++];
        else { before = &old[a++]; now = &current.rows[b++]; }
        const auto& key = now ? now->relative_path : before->relative_path;
        if (out.rows.size() == limits.max_rows || key.size() > limits.max_total_path_bytes - total_paths)
            return fail<SyncReconcilePlan>(AdapterError::InventoryLimit, "sync.reconcile.union");
        total_paths += key.size();
        population_l += before && present(before->left); population_r += before && present(before->right);
        out.rows.push_back(classify(before, now, key));
        all.push_back(facts(before, now));
    }
    // Resolve exact ancestry, not lexical adjacency. Propagate descendant
    // facts bottom-up so a deletion cannot hide an edited/unknown subtree.
    parents.resize(out.rows.size());
    for (std::size_t i = 0; i < out.rows.size(); ++i) {
        const auto& key = out.rows[i].relative_path;
        for (auto slash = key.rfind('/'); slash != std::string::npos;
            slash = slash == 0 ? std::string::npos : key.rfind('/', slash - 1)) {
            std::string_view prefix(key.data(), slash);
            auto it = std::lower_bound(out.rows.begin(), out.rows.end(), prefix,
                [](const auto& row, std::string_view p) { return row.relative_path < p; });
            if (it != out.rows.end() && it->relative_path == prefix) {
                parents[i] = static_cast<std::size_t>(it - out.rows.begin()); break;
            }
        }
    }
    for (std::size_t i = out.rows.size(); i-- > 0;) {
        auto& row = out.rows[i];
        const auto& f = all[i];
        const bool dl = row.action == SyncAction::DeleteLeft, dr = row.action == SyncAction::DeleteRight;
        if ((dl || dr) && (f.left_unknown || f.right_unknown)) {
            row.action = SyncAction::Blocked; row.reason = SyncReason::UnknownStatus;
        } else if ((dl && f.left_changed) || (dr && f.right_changed)) {
            row.action = SyncAction::Conflict; row.reason = SyncReason::DirectoryDeleteChangedSubtree;
        }
        if (parents[i]) all[*parents[i]].merge(f);
    }
    const bool changed_policy = baseline && baseline->policy_fingerprint != policy;
    const bool incomplete = !current.left_complete_stable || !current.right_complete_stable;
    // Top-down conflict propagation also prevents resurrecting a deleted parent
    // via a child copy while its directory delete/edit conflict is unresolved.
    for (std::size_t i = 0; i < out.rows.size(); ++i) {
        auto& row = out.rows[i];
        if (changed_policy || incomplete) {
            row.action = SyncAction::Blocked;
            row.reason = changed_policy ? SyncReason::PolicyChanged : SyncReason::IncompleteInventory;
        } else if (parents[i] && (out.rows[*parents[i]].action == SyncAction::Conflict ||
            out.rows[*parents[i]].action == SyncAction::Blocked)) {
            row.action = SyncAction::Blocked; row.reason = SyncReason::AncestorConflict;
        }
        if (row.action == SyncAction::Conflict || row.action == SyncAction::Blocked) out.state = SyncReconcileState::Blocked;
        out.proposed_deletions_left += row.action == SyncAction::DeleteLeft;
        out.proposed_deletions_right += row.action == SyncAction::DeleteRight;
    }
    if (changed_policy) out.state = SyncReconcileState::ReconcileRequired;
    else if (incomplete) out.state = SyncReconcileState::Blocked;
    const auto dl = out.proposed_deletions_left, dr = out.proposed_deletions_right;
    if (dl + dr > guard.max_deletions || dl * std::uint64_t{10'000} > population_l * std::uint64_t{guard.max_basis_points} ||
        dr * std::uint64_t{10'000} > population_r * std::uint64_t{guard.max_basis_points}) {
        out.state = SyncReconcileState::DeletionGuardExceeded;
        for (auto& row : out.rows) if (row.action == SyncAction::DeleteLeft || row.action == SyncAction::DeleteRight) {
            row.action = SyncAction::Blocked; row.reason = SyncReason::DeletionGuard;
        }
    }
    return Result::available(std::move(out));
}

Observation<SyncBaselineAdvance> advance_sync_baseline(const SyncBaseline* previous,
    std::span<const SyncBaselineUpdate> updates, const SyncDigest& policy, SyncBaselineLimits limits) {
    if (!valid_limits(limits)) return fail<SyncBaselineAdvance>(AdapterError::InvalidLimit, "sync.advance.limits");
    if (previous && previous->policy_fingerprint != policy)
        return fail<SyncBaselineAdvance>(AdapterError::PlanDecisionStale, "sync.advance.policy_changed");
    if ((previous && !valid_rows(previous->rows, limits)) || !valid_rows(updates, limits,
        [](const SyncBaselineUpdate& u) -> const auto& { return u.observed; }))
        return fail<SyncBaselineAdvance>(AdapterError::InvalidNativeResult, "sync.advance.rows");
    for (const auto& u : updates) {
        if ((u.state != SyncBaselineUpdateState::Pending && u.state != SyncBaselineUpdateState::ConfirmedEqual) ||
            (u.state == SyncBaselineUpdateState::ConfirmedEqual && !equal_known(u.observed)))
            return fail<SyncBaselineAdvance>(AdapterError::PlanInvalid, "sync.advance.unconfirmed");
    }
    const std::span<const SyncBaselineRow> old = previous ? std::span<const SyncBaselineRow>(previous->rows) :
        std::span<const SyncBaselineRow>{};
    SyncBaselineAdvance out;
    out.baseline.policy_fingerprint = policy;
    std::size_t a = 0, b = 0, total = 0, count = 0;
    while (a < old.size() || b < updates.size()) {
        const SyncBaselineRow* before = nullptr;
        const SyncBaselineUpdate* update = nullptr;
        if (b == updates.size() || (a < old.size() && old[a].relative_path < updates[b].observed.relative_path))
            before = &old[a++];
        else if (a == old.size() || updates[b].observed.relative_path < old[a].relative_path) update = &updates[b++];
        else { before = &old[a++]; update = &updates[b++]; }
        const auto& key = update ? update->observed.relative_path : before->relative_path;
        if (count++ == limits.max_rows || key.size() > limits.max_total_path_bytes - total)
            return fail<SyncBaselineAdvance>(AdapterError::InventoryLimit, "sync.advance.union");
        total += key.size();
        if (update && update->state == SyncBaselineUpdateState::ConfirmedEqual) out.baseline.rows.push_back(update->observed);
        else {
            if (before) out.baseline.rows.push_back(*before);
            out.pending_paths.push_back(key);
        }
    }
    // Mixed old/pending and new confirmed rows may form an impossible tree.
    // Refuse that advancement instead of persisting contradictory facts.
    if (!valid_rows(out.baseline.rows, limits))
        return fail<SyncBaselineAdvance>(AdapterError::PlanInvalid, "sync.advance.tree");
    return Observation<SyncBaselineAdvance>::available(std::move(out));
}

Observation<std::vector<std::byte>> encode_sync_baseline(const SyncBaseline& baseline, SyncBaselineLimits limits) {
    if (!valid_limits(limits)) return fail<std::vector<std::byte>>(AdapterError::InvalidLimit, "sync.codec.limits");
    if (!valid_rows(baseline.rows, limits))
        return fail<std::vector<std::byte>>(AdapterError::InvalidNativeResult, "sync.codec.rows");
    std::size_t size = header_bytes + checksum_bytes;
    for (const auto& row : baseline.rows) {
        if (row_bytes > limits.max_wire_bytes - size || row.relative_path.size() > limits.max_wire_bytes - size - row_bytes)
            return fail<std::vector<std::byte>>(AdapterError::InventoryLimit, "sync.codec.wire_limit");
        size += row_bytes + row.relative_path.size();
    }
    std::vector<std::byte> out;
    out.reserve(size);
    out.insert(out.end(), magic.begin(), magic.end());
    put(out, 1, 4); put(out, 0, 4); put(out, size, 8); put(out, baseline.rows.size(), 8);
    put_digest(out, baseline.policy_fingerprint);
    for (const auto& row : baseline.rows) {
        put(out, row.relative_path.size(), 4); put_status(out, row.left); put_status(out, row.right);
        for (const unsigned char ch : row.relative_path) out.push_back(static_cast<std::byte>(ch));
    }
    put_digest(out, checksum(out));
    return Observation<std::vector<std::byte>>::available(std::move(out));
}

Observation<SyncBaseline> decode_sync_baseline(std::span<const std::byte> wire, SyncBaselineLimits limits) {
    if (!valid_limits(limits)) return fail<SyncBaseline>(AdapterError::InvalidLimit, "sync.codec.limits");
    if (wire.size() < header_bytes + checksum_bytes || wire.size() > limits.max_wire_bytes)
        return fail<SyncBaseline>(AdapterError::InventoryLimit, "sync.codec.wire_size");
    const auto body = wire.first(wire.size() - checksum_bytes);
    const auto sum = checksum(body);
    if (!std::equal(sum.begin(), sum.end(), wire.end() - checksum_bytes))
        return fail<SyncBaseline>(AdapterError::InvalidNativeResult, "sync.codec.checksum");
    Reader in(body);
    std::span<const std::byte> m;
    std::uint64_t version = 0, flags = 0, bytes = 0, count = 0;
    SyncBaseline out;
    if (!in.take(magic.size(), m) || !std::equal(m.begin(), m.end(), magic.begin()) ||
        !in.get(version, 4) || version != 1 || !in.get(flags, 4) || flags || !in.get(bytes, 8) || bytes != wire.size() ||
        !in.get(count, 8) || count > limits.max_rows || count > (body.size() - header_bytes) / (row_bytes + 1) ||
        !in.digest(out.policy_fingerprint))
        return fail<SyncBaseline>(AdapterError::InvalidNativeResult, "sync.codec.header");
    out.rows.reserve(static_cast<std::size_t>(count));
    std::size_t paths = 0;
    for (std::uint64_t i = 0; i < count; ++i) {
        SyncBaselineRow row;
        std::uint64_t length = 0;
        std::span<const std::byte> key;
        if (!in.get(length, 4) || !length || length > limits.max_path_bytes || length > limits.max_total_path_bytes - paths ||
            !in.status(row.left) || !in.status(row.right) || !in.take(static_cast<std::size_t>(length), key))
            return fail<SyncBaseline>(AdapterError::InvalidNativeResult, "sync.codec.row");
        paths += static_cast<std::size_t>(length);
        row.relative_path.assign(reinterpret_cast<const char*>(key.data()), key.size());
        out.rows.push_back(std::move(row));
    }
    if (!in.empty() || !valid_rows(out.rows, limits))
        return fail<SyncBaseline>(AdapterError::InvalidNativeResult, "sync.codec.tree");
    return Observation<SyncBaseline>::available(std::move(out));
}

} // namespace ck::files
