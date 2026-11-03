// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "comparison_plan.hpp"

#include <algorithm>
#include <limits>
#include <set>
#include <string_view>
#include <utility>

namespace ck::files {
struct ComparisonIdentityState final {};
namespace {

constexpr std::uint64_t second_ns = 1'000'000'000;
constexpr std::size_t maximum_key_depth = 1024;

template<class T> Observation<T> failure(AdapterError code) {
    return Observation<T>::unavailable(ObservationState::Failed,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(code), "comparison-plan"});
}

template<class E> bool in_range(E value, E last) noexcept {
    return static_cast<unsigned>(value) <= static_cast<unsigned>(last);
}

bool quantum_valid(std::uint64_t q) noexcept {
    return q != 0 && (q <= second_ns ? second_ns % q == 0 :
        q <= 86'400 * second_ns && q % second_ns == 0);
}

int exact_time(const FileTimestamp& a, const FileTimestamp& b) noexcept {
    if (a.seconds() != b.seconds()) return a.seconds() < b.seconds() ? -1 : 1;
    return a.nanoseconds() < b.nanoseconds() ? -1 : a.nanoseconds() != b.nanoseconds();
}

std::int64_t floor_seconds(std::int64_t seconds, std::int64_t quantum) noexcept {
    return seconds / quantum - (seconds % quantum < 0 ? 1 : 0);
}

int rounded_time(const FileTimestamp& a, const FileTimestamp& b, std::uint64_t q) noexcept {
    if (q < second_ns) {
        if (a.seconds() != b.seconds()) return a.seconds() < b.seconds() ? -1 : 1;
        const auto an = a.nanoseconds() / q, bn = b.nanoseconds() / q;
        return an < bn ? -1 : an != bn;
    }
    const auto seconds = static_cast<std::int64_t>(q / second_ns);
    const auto av = floor_seconds(a.seconds(), seconds), bv = floor_seconds(b.seconds(), seconds);
    return av < bv ? -1 : av != bv;
}

bool qualified(const std::optional<ObjectIdentity>& id) noexcept {
    return id && compare_identity(*id, *id) == IdentityComparison::Same;
}

bool same_identity(const std::optional<ObjectIdentity>& a, const std::optional<ObjectIdentity>& b) noexcept {
    if (!a || !b) return !a && !b;
    return a->scope == b->scope && a->scheme == b->scheme && a->volume == b->volume &&
        a->object == b->object && a->generation == b->generation;
}

bool same_object(const ComparisonObject& a, const ComparisonObject& b) noexcept {
    return a.state == b.state && same_identity(a.identity, b.identity) && a.kind == b.kind &&
        a.size == b.size && a.modified == b.modified && a.timestamp_quantum_ns == b.timestamp_quantum_ns &&
        a.change_cookie == b.change_cookie;
}

bool same_digest(const std::optional<ComparisonDigest>& a, const std::optional<ComparisonDigest>& b) noexcept {
    if (!a || !b) return !a && !b;
    return a->state == b->state && a->algorithm == b->algorithm && a->bytes == b->bytes &&
        a->bytes_read == b->bytes_read && same_object(a->before, b->before) && same_object(a->after, b->after);
}

bool same_metadata_digest(const std::optional<ComparisonMetadataDigest>& a,
    const std::optional<ComparisonMetadataDigest>& b) noexcept {
    if (!a || !b) return !a && !b;
    return a->state == b->state && a->algorithm == b->algorithm && a->schema == b->schema &&
        a->policy_binding == b->policy_binding && a->bytes == b->bytes && a->ownership == b->ownership &&
        a->canonical_owner_digest == b->canonical_owner_digest &&
        same_object(a->before, b->before) && same_object(a->after, b->after);
}

bool same_entry(const ComparisonEntry& a, const ComparisonEntry& b) noexcept {
    return a.relative_path == b.relative_path && same_object(a.object, b.object) &&
        same_digest(a.digest, b.digest) && same_metadata_digest(a.metadata_digest, b.metadata_digest) &&
        a.excluded == b.excluded && a.name_collision == b.name_collision;
}

bool same_options(const ComparisonOptions& a, const ComparisonOptions& b) noexcept {
    const auto& x = a.filters; const auto& y = b.filters;
    return a.profile == b.profile && a.mode == b.mode && a.topology == b.topology &&
        a.timestamp_quantum_ns == b.timestamp_quantum_ns && a.compare_preserved_metadata == b.compare_preserved_metadata &&
        x.minimum_size == y.minimum_size &&
        x.maximum_size == y.maximum_size && x.modified_not_before == y.modified_not_before &&
        x.modified_before == y.modified_before && x.allowed_kind_mask == y.allowed_kind_mask &&
        x.maximum_depth == y.maximum_depth;
}

bool object_fields_valid(const ComparisonObject& o) noexcept {
    return in_range(o.state, ComparisonObjectState::Failed) &&
        (!o.kind || in_range(*o.kind, ObjectKind::Other)) &&
        (!o.timestamp_quantum_ns || quantum_valid(o.timestamp_quantum_ns));
}

bool entry_fields_valid(const ComparisonEntry& e) noexcept {
    return object_fields_valid(e.object) && (!e.digest ||
        (in_range(e.digest->state, ComparisonDigestState::Failed) &&
         in_range(e.digest->algorithm, ComparisonDigestAlgorithm::Sha256) &&
         object_fields_valid(e.digest->before) && object_fields_valid(e.digest->after))) &&
        (!e.metadata_digest ||
         (in_range(e.metadata_digest->state, ComparisonDigestState::Failed) &&
          in_range(e.metadata_digest->algorithm, ComparisonDigestAlgorithm::Sha256) &&
          in_range(e.metadata_digest->ownership, ComparisonMetadataOwnership::CurrentCaller) &&
          object_fields_valid(e.metadata_digest->before) && object_fields_valid(e.metadata_digest->after)));
}

bool options_valid(const ComparisonOptions& o) noexcept {
    const auto& f = o.filters;
    return in_range(o.profile, ComparisonProfile::Compare) && in_range(o.mode, ComparisonMode::CompleteDigest) &&
        in_range(o.topology, ComparisonTopology::Overlap) && quantum_valid(o.timestamp_quantum_ns) &&
        !(f.allowed_kind_mask >> 10) && f.maximum_depth <= maximum_key_depth &&
        (!f.minimum_size || !f.maximum_size || *f.minimum_size <= *f.maximum_size) &&
        (!f.modified_not_before || !f.modified_before || exact_time(*f.modified_not_before, *f.modified_before) < 0);
}

bool limits_valid(const ComparisonLimits& l) noexcept {
    return l.max_entries && l.max_entries <= ComparisonLimits::hard_max_entries &&
        l.max_path_bytes && l.max_path_bytes <= ComparisonLimits::hard_max_path_bytes &&
        l.max_total_path_bytes && l.max_total_path_bytes <= ComparisonLimits::hard_max_total_path_bytes &&
        l.max_exclusions <= ComparisonLimits::hard_max_exclusions && l.max_page_rows &&
        l.max_page_rows <= ComparisonLimits::hard_max_page_rows;
}

bool path_valid(std::string_view p, const ComparisonLimits& l) noexcept {
    if (p.empty() || p.size() > l.max_path_bytes || p.front() == '/' || p.back() == '/' ||
        p.find('\0') != p.npos || p.find('\\') != p.npos || (p.size() > 1 && p[1] == ':')) return false;
    std::size_t start = 0, depth = 0;
    for (;;) {
        const auto slash = p.find('/', start);
        const auto part = p.substr(start, slash == p.npos ? p.size() - start : slash - start);
        if (part.empty() || part == "." || part == ".." || ++depth > maximum_key_depth) return false;
        if (slash == p.npos) return true;
        start = slash + 1;
    }
}

bool add_bounded(std::uint64_t& total, std::uint64_t n, std::uint64_t cap) noexcept {
    if (n > cap || total > cap - n) return false;
    total += n;
    return true;
}

// Validate bounds BEFORE allocating/copying caller collections.
bool input_valid(const ComparisonOptions& o, const ComparisonInventory& s, const ComparisonInventory& d,
    std::span<const std::string> exclusions, const ComparisonLimits& l) noexcept {
    if (!options_valid(o) || !limits_valid(l) || !in_range(s.state, ComparisonInventoryState::Failed) ||
        !in_range(d.state, ComparisonInventoryState::Failed) || s.entries.size() > l.max_entries ||
        d.entries.size() > l.max_entries - s.entries.size() || exclusions.size() > l.max_exclusions) return false;
    std::uint64_t path_bytes = 0;
    for (const auto* inventory : {&s, &d}) {
        for (const auto& e : inventory->entries) {
            if (!path_valid(e.relative_path, l) || !entry_fields_valid(e) ||
                !add_bounded(path_bytes, e.relative_path.size(), l.max_total_path_bytes)) return false;
        }
    }
    for (const auto& p : exclusions)
        if (!path_valid(p, l) || !add_bounded(path_bytes, p.size(), l.max_total_path_bytes)) return false;
    return true;
}

const ComparisonEntry* find_entry(const std::vector<ComparisonEntry>& entries, std::string_view path) {
    const auto it = std::lower_bound(entries.begin(), entries.end(), path,
        [](const auto& entry, auto key) { return entry.relative_path < key; });
    return it != entries.end() && it->relative_path == path ? &*it : nullptr;
}

bool sort_tree(std::vector<ComparisonEntry>& entries) {
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) { return a.relative_path < b.relative_path; });
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& key = entries[i].relative_path;
        if (i && key == entries[i - 1].relative_path) return false;
        // Every lexical parent must be represented; an unavailable parent's
        // kind remains unknown and will block its subtree during classification.
        for (auto slash = key.find('/'); slash != key.npos; slash = key.find('/', slash + 1)) {
            const auto* parent = find_entry(entries, std::string_view(key).substr(0, slash));
            if (!parent || (parent->object.kind && *parent->object.kind != ObjectKind::Directory)) return false;
        }
    }
    return true;
}

using PathSet = std::set<std::string, std::less<>>;

bool covered(const PathSet& paths, const std::string& key) {
    if (paths.contains(key)) return true;
    for (auto slash = key.find('/'); slash != key.npos; slash = key.find('/', slash + 1))
        if (paths.contains(std::string_view(key).substr(0, slash))) return true;
    return false;
}

bool has_descendant(const PathSet& paths, const std::string& key) {
    const auto prefix = key + '/';
    const auto it = paths.lower_bound(prefix);
    return it != paths.end() && it->starts_with(prefix);
}

enum class FilterResult { Included, Excluded, Unknown };
FilterResult filter(const ComparisonEntry& e, const ComparisonFilters& f) {
    const auto& o = e.object;
    const auto depth = 1 + static_cast<std::size_t>(std::count(e.relative_path.begin(), e.relative_path.end(), '/'));
    if (depth > f.maximum_depth) return FilterResult::Excluded;
    if (!o.kind) return FilterResult::Unknown;
    if (!(f.allowed_kind_mask & (1ULL << static_cast<unsigned>(*o.kind)))) return FilterResult::Excluded;
    if (*o.kind != ObjectKind::RegularFile) return FilterResult::Included;
    if ((f.minimum_size || f.maximum_size) && !o.size) return FilterResult::Unknown;
    if ((f.minimum_size && *o.size < *f.minimum_size) || (f.maximum_size && *o.size > *f.maximum_size))
        return FilterResult::Excluded;
    if ((f.modified_not_before || f.modified_before) &&
        (!o.modified || o.state != ComparisonObjectState::Stable || !o.timestamp_quantum_ns)) return FilterResult::Unknown;
    if ((f.modified_not_before && exact_time(*o.modified, *f.modified_not_before) < 0) ||
        (f.modified_before && exact_time(*o.modified, *f.modified_before) >= 0)) return FilterResult::Excluded;
    return FilterResult::Included;
}

std::optional<ComparisonReason> object_problem(const ComparisonObject& o) {
    if (o.state != ComparisonObjectState::Stable || !o.kind) return ComparisonReason::UnknownObject;
    if (!qualified(o.identity)) return ComparisonReason::UnqualifiedIdentity;
    if (*o.kind != ObjectKind::Directory && *o.kind != ObjectKind::RegularFile) return ComparisonReason::UnsupportedKind;
    if (*o.kind == ObjectKind::RegularFile && !o.size) return ComparisonReason::MissingSize;
    return {};
}

std::optional<ComparisonReason> time_problem(const ComparisonObject& a, const ComparisonObject& b, std::uint64_t q) {
    if (!a.modified || !b.modified) return ComparisonReason::MissingTimestamp;
    if (!a.timestamp_quantum_ns || !b.timestamp_quantum_ns || q % a.timestamp_quantum_ns || q % b.timestamp_quantum_ns)
        return ComparisonReason::PrecisionUnavailable;
    return {};
}

std::optional<ComparisonReason> digest_problem(const ComparisonEntry& e) {
    if (!e.digest || e.digest->algorithm != ComparisonDigestAlgorithm::Sha256) return ComparisonReason::DigestUnavailable;
    const auto& d = *e.digest;
    if (d.state == ComparisonDigestState::Changed) return ComparisonReason::DigestChanged;
    if (d.state != ComparisonDigestState::CompleteStable || !e.object.size || d.bytes_read != *e.object.size)
        return ComparisonReason::DigestIncomplete;
    if ((!e.object.modified && !e.object.change_cookie) || !same_object(d.before, e.object) || !same_object(d.after, e.object))
        return ComparisonReason::DigestBindingMismatch;
    return {};
}

std::optional<ComparisonReason> metadata_digest_problem(const ComparisonEntry& e) {
    if (!e.metadata_digest || e.metadata_digest->algorithm != ComparisonDigestAlgorithm::Sha256)
        return ComparisonReason::MetadataDigestUnavailable;
    const auto& d = *e.metadata_digest;
    if (d.state == ComparisonDigestState::Changed) return ComparisonReason::MetadataDigestChanged;
    if (d.state != ComparisonDigestState::CompleteStable) return ComparisonReason::MetadataDigestIncomplete;
    if (d.schema == std::array<std::byte, 32>{}) return ComparisonReason::MetadataSchemaMismatch;
    if (d.policy_binding == std::array<std::byte, 32>{} || d.ownership == ComparisonMetadataOwnership::Unknown)
        return ComparisonReason::MetadataPolicyMismatch;
    if ((!e.object.modified && !e.object.change_cookie) ||
        !same_object(d.before, e.object) || !same_object(d.after, e.object))
        return ComparisonReason::MetadataDigestBindingMismatch;
    if (d.ownership == ComparisonMetadataOwnership::CurrentCaller && !d.canonical_owner_digest)
        return ComparisonReason::MetadataOwnerUnavailable;
    return {};
}

void unknown(ComparisonRow& row, ComparisonReason reason) {
    row.relation = ComparisonRelation::Unknown;
    row.reason = reason;
    row.action = ComparisonAction::Review;
    row.destination_protected = true;
    row.requires_review = true;
}

void classify(ComparisonRow& row, const ComparisonEntry* s, const ComparisonEntry* d, const ComparisonOptions& o) {
    if (s) if (auto problem = object_problem(s->object)) { unknown(row, *problem); return; }
    if (d) if (auto problem = object_problem(d->object)) { unknown(row, *problem); return; }
    if (o.mode == ComparisonMode::CompleteDigest) {
        if (s && s->object.kind == ObjectKind::RegularFile) if (auto problem = digest_problem(*s)) { unknown(row, *problem); return; }
        if (d && d->object.kind == ObjectKind::RegularFile) if (auto problem = digest_problem(*d)) { unknown(row, *problem); return; }
    }
    if (o.compare_preserved_metadata) {
        for (const auto* entry : {s, d}) if (entry) {
            if (entry->object.kind == ObjectKind::Directory) {
                unknown(row, ComparisonReason::DirectoryMetadataUnsupported); return;
            }
            if (auto problem = metadata_digest_problem(*entry)) { unknown(row, *problem); return; }
        }
    }
    if (!s) { row.relation = ComparisonRelation::DestinationOnly; row.reason = ComparisonReason::SourceMissing; return; }
    if (!d) { row.relation = ComparisonRelation::SourceOnly; row.reason = ComparisonReason::DestinationMissing; return; }
    const auto& a = s->object; const auto& b = d->object;
    if (compare_identity(*a.identity, *b.identity) == IdentityComparison::Same) {
        unknown(row, ComparisonReason::SameObject); return;
    }
    if (a.kind != b.kind) { row.relation = ComparisonRelation::TypeConflict; row.reason = ComparisonReason::TypeMismatch; return; }
    if (*a.kind == ObjectKind::Directory) {
        row.relation = ComparisonRelation::DirectoryPair; row.reason = ComparisonReason::DirectoryPair; return;
    }
    if (o.compare_preserved_metadata) {
        const auto& x = *s->metadata_digest; const auto& y = *d->metadata_digest;
        if (x.schema != y.schema) { unknown(row, ComparisonReason::MetadataSchemaMismatch); return; }
        if (x.policy_binding != y.policy_binding || x.ownership != y.ownership) {
            unknown(row, ComparisonReason::MetadataPolicyMismatch); return;
        }
        if (x.bytes != y.bytes || (x.ownership == ComparisonMetadataOwnership::CurrentCaller &&
            x.canonical_owner_digest != y.canonical_owner_digest)) {
            row.relation = ComparisonRelation::MetadataDifferent;
            row.reason = ComparisonReason::MetadataMismatch; return;
        }
    }
    if (o.mode == ComparisonMode::CompleteDigest) {
        const auto same_size = a.size == b.size;
        const auto same_content = same_size && s->digest->bytes == d->digest->bytes;
        row.relation = same_content ? ComparisonRelation::Identical :
            (same_size ? ComparisonRelation::ContentDifferent : ComparisonRelation::SizeDifferent);
        row.reason = same_content ? ComparisonReason::SameContent :
            (same_size ? ComparisonReason::DigestMismatch : ComparisonReason::SizeMismatch);
    } else if (o.mode == ComparisonMode::Size) {
        row.relation = a.size == b.size ? ComparisonRelation::SameSize : ComparisonRelation::SizeDifferent;
        row.reason = a.size == b.size ? ComparisonReason::SameSize : ComparisonReason::SizeMismatch;
    } else {
        if (auto problem = time_problem(a, b, o.timestamp_quantum_ns)) { unknown(row, *problem); return; }
        const auto time = rounded_time(*a.modified, *b.modified, o.timestamp_quantum_ns);
        if (time) {
            row.relation = time > 0 ? ComparisonRelation::SourceNewer : ComparisonRelation::DestinationNewer;
            row.reason = time > 0 ? ComparisonReason::SourceNewer : ComparisonReason::DestinationNewer;
        } else {
            row.relation = a.size == b.size ? ComparisonRelation::SameSizeAndMtime : ComparisonRelation::SizeDifferent;
            row.reason = a.size == b.size ? ComparisonReason::SameSizeAndMtime : ComparisonReason::SizeMismatch;
        }
    }
}

bool matches(ComparisonRelation r) noexcept {
    return r == ComparisonRelation::Identical || r == ComparisonRelation::SameSize || r == ComparisonRelation::SameSizeAndMtime;
}

void propose(ComparisonRow& row, const ComparisonEntry* s, const ComparisonEntry* d, const ComparisonOptions& o) {
    if (o.profile == ComparisonProfile::Compare) {
        row.action = ComparisonAction::Report;
        row.requires_review = false;
        return;
    }
    if (row.relation == ComparisonRelation::Unknown || row.relation == ComparisonRelation::Protected) return;
    if (row.relation == ComparisonRelation::TypeConflict) {
        row.action = o.profile == ComparisonProfile::MissingOnly ? ComparisonAction::Skip : ComparisonAction::Review;
    } else if (row.relation == ComparisonRelation::SourceOnly) {
        row.action = o.profile == ComparisonProfile::Move ? ComparisonAction::MoveAfterCommit :
            (*s->object.kind == ObjectKind::Directory ? ComparisonAction::CreateDestinationDirectory : ComparisonAction::CopyToDestination);
    } else if (row.relation == ComparisonRelation::DestinationOnly) {
        row.action = o.profile == ComparisonProfile::Mirror ?
            (*d->object.kind == ObjectKind::Directory ? ComparisonAction::RemoveDestinationDirectory : ComparisonAction::RemoveDestinationFile) :
            ComparisonAction::Skip;
    } else if (row.relation == ComparisonRelation::DirectoryPair) {
        row.action = o.profile == ComparisonProfile::Move ? ComparisonAction::MoveAfterCommit : ComparisonAction::MergeDirectories;
    } else if (o.profile == ComparisonProfile::MissingOnly || (matches(row.relation) && o.profile != ComparisonProfile::Move)) {
        row.action = ComparisonAction::Skip;
    } else if (o.profile == ComparisonProfile::Copy || o.profile == ComparisonProfile::Move) {
        row.action = ComparisonAction::Review;
        if (row.relation != ComparisonRelation::MetadataDifferent) row.reason = ComparisonReason::ExistingDestination;
    } else if (o.profile == ComparisonProfile::Update) {
        if (auto problem = time_problem(s->object, d->object, o.timestamp_quantum_ns)) { unknown(row, *problem); return; }
        const auto time = rounded_time(*s->object.modified, *d->object.modified, o.timestamp_quantum_ns);
        row.action = time > 0 ? ComparisonAction::ReplaceDestination : time < 0 ? ComparisonAction::Skip : ComparisonAction::Review;
        if (row.relation != ComparisonRelation::MetadataDifferent)
            row.reason = time > 0 ? ComparisonReason::SourceNewer : time < 0 ? ComparisonReason::DestinationNewer : ComparisonReason::EqualTimeConflict;
    } else {
        row.action = ComparisonAction::ReplaceDestination;
    }
    row.requires_review = row.action == ComparisonAction::Review;
}

bool write_action(ComparisonAction action) noexcept {
    return action == ComparisonAction::CopyToDestination || action == ComparisonAction::MoveAfterCommit ||
        action == ComparisonAction::CreateDestinationDirectory || action == ComparisonAction::ReplaceDestination;
}

bool remove_action(ComparisonAction action) noexcept {
    return action == ComparisonAction::RemoveDestinationFile || action == ComparisonAction::RemoveDestinationDirectory;
}

bool inventory_bytes(const std::vector<ComparisonEntry>& entries, ComparisonInventoryState state,
    std::uint64_t& total, bool& complete, std::uint64_t cap) {
    complete = state == ComparisonInventoryState::CompleteStable;
    for (const auto& e : entries) {
        if (!e.object.kind || !qualified(e.object.identity) || e.object.state != ComparisonObjectState::Stable) { complete = false; continue; }
        if (*e.object.kind != ObjectKind::RegularFile) continue;
        if (!e.object.size) { complete = false; continue; }
        if (!add_bounded(total, *e.object.size, cap)) return false;
    }
    return true;
}

} // namespace

Observation<ComparisonPlan::Pointer> ComparisonPlan::create(const ComparisonOptions& options,
    const ComparisonInventory& source, const ComparisonInventory& destination,
    std::span<const std::string> excluded_paths, ComparisonLimits limits) {
    if (!limits_valid(limits)) return failure<Pointer>(AdapterError::InvalidLimit);
    if (!input_valid(options, source, destination, excluded_paths, limits)) return failure<Pointer>(AdapterError::PlanInvalid);
    if (options.topology != ComparisonTopology::Disjoint ||
        (qualified(source.root) && qualified(destination.root) && compare_identity(*source.root, *destination.root) == IdentityComparison::Same))
        return failure<Pointer>(AdapterError::PlanTopologyUnsafe);
    auto plan = std::shared_ptr<ComparisonPlan>(new ComparisonPlan);
    plan->options_ = options; plan->limits_ = limits;
    plan->identity_ = ComparisonPlanIdentity(std::make_shared<const ComparisonIdentityState>());
    plan->source_state_ = source.state; plan->destination_state_ = destination.state;
    plan->source_root_ = source.root; plan->destination_root_ = destination.root;
    plan->source_.assign(source.entries.begin(), source.entries.end());
    plan->destination_.assign(destination.entries.begin(), destination.entries.end());
    plan->exclusions_.assign(excluded_paths.begin(), excluded_paths.end());
    if (!sort_tree(plan->source_) || !sort_tree(plan->destination_)) return failure<Pointer>(AdapterError::PlanInvalid);
    std::sort(plan->exclusions_.begin(), plan->exclusions_.end());
    plan->exclusions_.erase(std::unique(plan->exclusions_.begin(), plan->exclusions_.end()), plan->exclusions_.end());
    auto& aggregate = plan->aggregate_;
    if (!inventory_bytes(plan->source_, source.state, aggregate.source_bytes, aggregate.source_bytes_complete, limits.max_aggregate_bytes) ||
        !inventory_bytes(plan->destination_, destination.state, aggregate.destination_bytes, aggregate.destination_bytes_complete, limits.max_aggregate_bytes))
        return failure<Pointer>(AdapterError::InventoryLimit);

    PathSet excluded(plan->exclusions_.begin(), plan->exclusions_.end()), filtered, uncertain, collision;
    for (const auto* entries : {&plan->source_, &plan->destination_}) {
        for (const auto& e : *entries) {
            if (e.excluded) excluded.insert(e.relative_path);
            if (e.name_collision) collision.insert(e.relative_path);
            const auto result = filter(e, options.filters);
            if (result == FilterResult::Excluded) filtered.insert(e.relative_path);
            if (result == FilterResult::Unknown || object_problem(e.object)) uncertain.insert(e.relative_path);
        }
    }
    const bool inventory_qualified = source.state == ComparisonInventoryState::CompleteStable &&
        destination.state == ComparisonInventoryState::CompleteStable;
    const bool roots_qualified = qualified(source.root) && qualified(destination.root);
    if (!roots_qualified || !excluded.empty()) {
        aggregate.source_bytes_complete = false;
        aggregate.destination_bytes_complete = false;
    }
    plan->rows_.reserve(plan->source_.size() + plan->destination_.size());
    std::size_t si = 0, di = 0;
    while (si < plan->source_.size() || di < plan->destination_.size()) {
        const auto* s = si < plan->source_.size() ? &plan->source_[si] : nullptr;
        const auto* d = di < plan->destination_.size() ? &plan->destination_[di] : nullptr;
        if (s && d) {
            if (s->relative_path < d->relative_path) d = nullptr;
            else if (d->relative_path < s->relative_path) s = nullptr;
        }
        ComparisonRow row;
        row.id = plan->rows_.size() + 1;
        row.relative_path = s ? s->relative_path : d->relative_path;
        if (s) row.source_index = si++;
        if (d) row.destination_index = di++;
        row.token = ComparisonDecisionToken(plan->identity_, row.id);
        const auto& key = row.relative_path;
        if (covered(excluded, key) || covered(filtered, key)) {
            row.relation = ComparisonRelation::Protected;
            row.reason = covered(excluded, key) ? ComparisonReason::Excluded : ComparisonReason::Filtered;
            row.destination_protected = true;
            row.action = ComparisonAction::Skip;
        } else if (covered(collision, key)) {
            unknown(row, ComparisonReason::NameCollision);
        } else if (!inventory_qualified) {
            unknown(row, ComparisonReason::IncompleteInventory);
        } else if (!roots_qualified) {
            unknown(row, ComparisonReason::UnqualifiedIdentity);
        } else {
            classify(row, s, d, options);
            // A missing/unknown ancestor or unknown filter cannot qualify a
            // descendant. Preserve the more specific direct-object diagnostic.
            if (row.relation != ComparisonRelation::Unknown && covered(uncertain, key))
                unknown(row, filter(s ? *s : *d, options.filters) == FilterResult::Unknown ?
                    ComparisonReason::FilterUnknown : ComparisonReason::AncestorConflict);
        }
        if (row.relation == ComparisonRelation::Unknown || row.relation == ComparisonRelation::TypeConflict) uncertain.insert(key);
        propose(row, s, d, options);
        plan->rows_.push_back(std::move(row));
    }

    // Protect removal of an ancestor even when the excluded/unknown descendant
    // was omitted from the scan, or when the ancestor sorts before its children.
    PathSet protected_paths = excluded;
    protected_paths.insert(filtered.begin(), filtered.end());
    protected_paths.insert(uncertain.begin(), uncertain.end());
    protected_paths.insert(collision.begin(), collision.end());
    for (const auto& row : plan->rows_)
        if (row.destination_protected || row.action == ComparisonAction::Review) protected_paths.insert(row.relative_path);
    for (auto& row : plan->rows_) {
        if (row.action == ComparisonAction::RemoveDestinationDirectory && has_descendant(protected_paths, row.relative_path)) {
            row.relation = ComparisonRelation::Protected;
            row.reason = ComparisonReason::ProtectedDescendant;
            row.action = ComparisonAction::Skip;
            row.destination_protected = true;
        }
        ++aggregate.rows;
        aggregate.unknown_rows += row.relation == ComparisonRelation::Unknown;
        aggregate.protected_rows += row.destination_protected;
        aggregate.review_rows += row.requires_review;
        aggregate.proposed_writes += write_action(row.action);
        aggregate.proposed_removals += remove_action(row.action);
        if (write_action(row.action) && row.source_index) {
            const auto& object = plan->source_[*row.source_index].object;
            if (object.kind == ObjectKind::RegularFile) {
                if (!object.size) aggregate.proposed_copy_bytes_complete = false;
                else if (!add_bounded(aggregate.proposed_copy_bytes, *object.size, limits.max_aggregate_bytes))
                    return failure<Pointer>(AdapterError::InventoryLimit);
            }
        }
    }
    return Observation<Pointer>::available(std::move(plan));
}

Observation<ComparisonPage> ComparisonPlan::page(std::size_t offset, std::size_t limit) const {
    if (!limit || limit > limits_.max_page_rows || offset > rows_.size()) return failure<ComparisonPage>(AdapterError::InvalidLimit);
    ComparisonPage result;
    result.identity = identity_;
    result.total_rows = rows_.size();
    const auto count = std::min(limit, rows_.size() - offset);
    result.rows.assign(rows_.begin() + static_cast<std::ptrdiff_t>(offset),
        rows_.begin() + static_cast<std::ptrdiff_t>(offset + count));
    if (offset + count < rows_.size()) result.next_offset = offset + count;
    return Observation<ComparisonPage>::available(std::move(result));
}

ComparisonRevalidation ComparisonPlan::revalidate(const ComparisonDecisionToken& token,
    const ComparisonOptions& options, const ComparisonInventory& source, const ComparisonInventory& destination,
    std::span<const std::string> excluded_paths) const {
    if (!token.is_valid() || token.plan_identity() != identity_ || token.row_id() > rows_.size())
        return ComparisonRevalidation::ForeignToken;
    if (!input_valid(options, source, destination, excluded_paths, limits_)) return ComparisonRevalidation::InvalidInput;
    if (!same_options(options, options_) || source.state != source_state_ || destination.state != destination_state_ ||
        !same_identity(source.root, source_root_) || !same_identity(destination.root, destination_root_))
        return ComparisonRevalidation::EvidenceChanged;
    std::vector<ComparisonEntry> s(source.entries.begin(), source.entries.end()), d(destination.entries.begin(), destination.entries.end());
    if (!sort_tree(s) || !sort_tree(d)) return ComparisonRevalidation::InvalidInput;
    std::vector<std::string> exclusions(excluded_paths.begin(), excluded_paths.end());
    std::sort(exclusions.begin(), exclusions.end());
    exclusions.erase(std::unique(exclusions.begin(), exclusions.end()), exclusions.end());
    if (exclusions != exclusions_ || s.size() != source_.size() || d.size() != destination_.size() ||
        !std::equal(s.begin(), s.end(), source_.begin(), same_entry) || !std::equal(d.begin(), d.end(), destination_.begin(), same_entry))
        return ComparisonRevalidation::EvidenceChanged;
    return ComparisonRevalidation::Matches;
}

} // namespace ck::files
