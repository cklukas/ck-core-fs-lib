// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "reviewed_tree_plan.hpp"
#include "sha256.hpp"
#include "native_delete_recovery_evidence.hpp"
#include "retained_target.hpp"
#include "directory_name_rules.hpp"
#include <algorithm>
#include <map>
#include <set>

namespace ck::files {
namespace {
UnavailableObservation error(AdapterError code, const char* op,
    ObservationState state = ObservationState::Failed) {
    return {state, {ErrorDomain::Adapter, static_cast<std::int64_t>(code), op}};
}
template<class T> Observation<T> unavailable(const UnavailableObservation& e) {
    return Observation<T>::unavailable(e.state, e.error);
}
template<class T> Observation<T> invalid(const char* op) {
    return unavailable<T>(error(AdapterError::PlanInvalid, op));
}
template<class Cursor> Observation<bool> qualify_namespace(const Cursor& cursor) {
    // Older pinned adapters have no qualification boundary; absence is never
    // inferred support. Current adapters supply the native provider check.
    if constexpr (requires { cursor.qualify_identity_bound_rename(); })
        return cursor.qualify_identity_bound_rename();
    else return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.native_namespace_qualification", ObservationState::Unsupported));
}
template<class Policy> Observation<RegularMetadataPreservation::Pointer> preservation_for(
    const HeldChild::Pointer& source, const Policy& policy, std::stop_token stop) {
    if constexpr (requires { policy.metadata_policy; }) {
        if (policy.metadata_policy) return RegularMetadataPreservation::create_with_policy(
            source, policy.allow_unhandled_metadata_loss, *policy.metadata_policy, stop);
    }
    return RegularMetadataPreservation::create(source, policy.allow_unhandled_metadata_loss, policy.metadata_scope, stop);
}
bool same(const ObjectIdentity& a, const ObjectIdentity& b) {
    return compare_identity(a, b) == IdentityComparison::Same;
}
template<class T> bool equal(const Observation<T>& a, const Observation<T>& b) {
    if (a.value() && b.value()) return *a.value() == *b.value();
    return !a.value() && !b.value() && a.state() == b.state() &&
        a.unavailable_detail()->error == b.unavailable_detail()->error;
}
bool qualified(const BasicMetadata& m) {
    return m.identity.value() && same(*m.identity.value(), *m.identity.value()) &&
        m.kind.value() && m.mount_id.value() && m.modified.value() && m.changed.value() &&
        (*m.kind.value() == ObjectKind::Directory ||
         (*m.kind.value() == ObjectKind::RegularFile && m.logical_size.value()));
}
bool unchanged(const BasicMetadata& a, const BasicMetadata& b) {
    return qualified(a) && qualified(b) && same(*a.identity.value(), *b.identity.value()) &&
        equal(a.kind, b.kind) && equal(a.mount_id, b.mount_id) &&
        equal(a.modified, b.modified) && equal(a.changed, b.changed) &&
        (*a.kind.value() == ObjectKind::Directory || equal(a.logical_size, b.logical_size)) &&
        equal(a.posix_permissions, b.posix_permissions) && equal(a.posix_uid, b.posix_uid) &&
        equal(a.posix_gid, b.posix_gid) && equal(a.link_count, b.link_count) &&
        equal(a.bsd_flags, b.bsd_flags) && equal(a.windows_attributes, b.windows_attributes);
}
std::string key_component(const NativeName& name, bool fold = false) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string key = name.posix_bytes() ? "p" : "w";
    auto unit = [&](unsigned value, unsigned digits) {
        if (fold && value >= 'A' && value <= 'Z') value += 'a' - 'A';
        for (unsigned n = digits; n; --n) key += hex[(value >> (4 * (n - 1))) & 15];
    };
    if (name.posix_bytes()) for (unsigned char c : *name.posix_bytes()) unit(c, 2);
    else for (char16_t c : *name.windows_units()) unit(c, 4);
    return key;
}
std::string key_path(const std::vector<NativeName>& names, bool fold = false) {
    std::string out;
    for (const auto& n : names) { if (!out.empty()) out += '/'; out += key_component(n, fold); }
    return out;
}
bool ascii_units(const NativeName& n) {
    if (n.posix_bytes()) return std::all_of(n.posix_bytes()->begin(), n.posix_bytes()->end(), [](unsigned char c) { return c < 128; });
    return std::all_of(n.windows_units()->begin(), n.windows_units()->end(), [](char16_t c) { return c < 128; });
}
ComparisonObject comparison_object(const BasicMetadata& m) {
    ComparisonObject out;
    out.state = ComparisonObjectState::Stable;
    out.identity = *m.identity.value(); out.kind = *m.kind.value();
    if (m.logical_size.value() && *m.kind.value() == ObjectKind::RegularFile) out.size = *m.logical_size.value();
    out.modified = *m.modified.value(); out.timestamp_quantum_ns = 1;
    return out;
}
struct Node {
    std::vector<NativeName> names;
    HeldChild::Pointer held;
    std::shared_ptr<const DirectoryCursor> directory;
    BasicMetadata metadata;
    ComparisonEntry entry;
};
struct Tree {
    BasicMetadata root_metadata;
    std::shared_ptr<const DirectoryCursor> root;
    std::map<std::string, Node> nodes;
};
// This scanner consumes one native enumeration record or at most one bounded
// content read per step. Directory version brackets qualify absence; files are
// read completely with exact identity/version brackets. A second independent
// full scan is required before the immutable comparison plan is published.
class Scanner {
public:
    Scanner(HeldChild::Pointer root, const ReviewedTreePlanRequest& request)
        : root_(std::move(root)), request_(request) {}
    bool complete = false;
    std::optional<UnavailableObservation> failure;
    Tree tree;
    void step(std::stop_token stop) {
        if (complete || failure || stop.stop_requested()) return;
        if (!tree.root) { start(); return; }
        if (reading_) { read_step(stop); return; }
        if (frames_.empty()) { complete = true; return; }
        auto& frame = frames_.back();
        auto read = frame.cursor->read(1, stop);
        if (read.state == DirectoryReadState::Error) {
            failure = read.error.value_or(error(AdapterError::InvalidNativeResult, "reviewed_tree.enumerate")); return;
        }
        if (read.state == DirectoryReadState::Cancelled) return;
        if (!read.names.empty()) {
            auto name = std::move(read.names.front());
            if (!name.is_valid()) { fail(AdapterError::InvalidIdentifier, "reviewed_tree.native_name"); return; }
            auto names = frame.names; names.push_back(name);
            auto key = key_path(names), folded = key_path(names, true);
            if (names.size() > request_.comparison.filters.maximum_depth || names.size() > 1024 ||
                key.size() > request_.limits.max_path_bytes || tree.nodes.size() >= request_.limits.max_entries ||
                key.size() > request_.limits.max_total_path_bytes - path_bytes_) {
                fail(AdapterError::InventoryLimit, "reviewed_tree.inventory_limit"); return;
            }
            path_bytes_ += key.size();
            if (!folded_.insert(folded).second) { fail(AdapterError::PlanTopologyUnsafe, "reviewed_tree.case_collision"); return; }
            auto held = HeldChild::observe(frame.cursor, name, stop);
            if (!held.value()) { failure = *held.unavailable_detail(); return; }
            const auto m = (*held.value())->metadata();
            if (!qualified(m)) { fail(AdapterError::UnsupportedQuery, "reviewed_tree.kind_or_version", ObservationState::Unsupported); return; }
            if (*m.mount_id.value() != *tree.root_metadata.mount_id.value()) { fail(AdapterError::PlanTopologyUnsafe, "reviewed_tree.mount_crossing"); return; }
            if (*m.kind.value() == ObjectKind::RegularFile) {
                auto readable = HeldChild::observe_with_access(frame.cursor, name, EntryAccess::ContentRead, stop);
                if (!readable.value()) { failure = *readable.unavailable_detail(); return; }
                if (!unchanged(m, (*readable.value())->metadata())) { fail(AdapterError::MetadataChanged, "reviewed_tree.read_open_changed", ObservationState::Changed); return; }
                held = std::move(readable);
            }
            Node node{names, *held.value(), {}, m, {}};
            node.entry.relative_path = key; node.entry.object = comparison_object(m);
            if (*m.kind.value() == ObjectKind::Directory) {
                auto opened = frame.cursor->open_directory_child(name);
                if (!opened.value()) { failure = *opened.unavailable_detail(); return; }
                node.directory = std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value());
                auto live = node.directory->inspect_basic();
                if (!live.value() || !unchanged(m, *live.value())) { fail(AdapterError::MetadataChanged, "reviewed_tree.directory_changed", ObservationState::Changed); return; }
                for (const auto& f : frames_) if (same(*f.before.identity.value(), *m.identity.value())) {
                    fail(AdapterError::PlanTopologyUnsafe, "reviewed_tree.directory_cycle"); return;
                }
                auto cursor = std::const_pointer_cast<DirectoryCursor>(node.directory);
                tree.nodes.emplace(key, std::move(node));
                frames_.push_back({std::move(cursor), std::move(names), m});
            } else {
                if (*m.logical_size.value() > request_.copy_policy.copy_limits.max_bytes) {
                    fail(AdapterError::InventoryLimit, "reviewed_tree.file_bytes"); return;
                }
                tree.nodes.emplace(key, std::move(node));
                reading_ = key; hash_.reset(); offset_ = 0;
            }
            return;
        }
        if (read.state == DirectoryReadState::End) {
            auto now = frame.cursor->inspect_basic();
            if (!now.value() || !unchanged(frame.before, *now.value())) {
                fail(AdapterError::MetadataChanged, "reviewed_tree.directory_version", ObservationState::Changed); return;
            }
            frames_.pop_back();
        }
    }
private:
    struct Frame { std::shared_ptr<DirectoryCursor> cursor; std::vector<NativeName> names; BasicMetadata before; };
    void fail(AdapterError c, const char* op, ObservationState s = ObservationState::Failed) { failure = error(c, op, s); }
    void start() {
        auto now = root_->refresh();
        if (!now.value()) { failure = *now.unavailable_detail(); return; }
        if (!qualified((*now.value())->metadata()) || !root_->metadata().identity.value() ||
            !same(*root_->metadata().identity.value(), *(*now.value())->metadata().identity.value()) ||
            *(*now.value())->metadata().kind.value() != ObjectKind::Directory) {
            fail(AdapterError::PlanDecisionStale, "reviewed_tree.root_membership", ObservationState::Changed); return;
        }
        auto opened = root_->parent()->open_directory_child(root_->name());
        if (!opened.value()) { failure = *opened.unavailable_detail(); return; }
        auto cursor = std::shared_ptr<DirectoryCursor>(std::move(opened).take_value());
        auto metadata = cursor->inspect_basic();
        if (!metadata.value() || !unchanged((*now.value())->metadata(), *metadata.value())) {
            fail(AdapterError::PlanDecisionStale, "reviewed_tree.root_open", ObservationState::Changed); return;
        }
        tree.root_metadata = *metadata.value(); tree.root = cursor;
        frames_.push_back({std::move(cursor), {}, tree.root_metadata});
    }
    void read_step(std::stop_token stop) {
        auto& n = tree.nodes.at(*reading_);
        auto data = n.held->read_content({request_.digest_chunk_bytes}, offset_, stop);
        if (!data.value()) { failure = *data.unavailable_detail(); return; }
        const auto& value = *data.value();
        const auto size = *n.metadata.logical_size.value();
        if (offset_ > size || value.bytes.size() > size - offset_ || (value.bytes.empty() && !value.complete)) {
            fail(AdapterError::MetadataChanged, "reviewed_tree.digest_length", ObservationState::Changed); return;
        }
        hash_.update(value.bytes); offset_ += value.bytes.size();
        if (!value.complete) return;
        auto now = n.held->inspect_basic();
        auto member = n.held->refresh(stop);
        if (offset_ != size || !now.value() || !member.value() ||
            !unchanged(n.metadata, *now.value()) || !unchanged(n.metadata, (*member.value())->metadata())) {
            fail(AdapterError::MetadataChanged, "reviewed_tree.digest_version", ObservationState::Changed); return;
        }
        ComparisonDigest digest;
        digest.state = ComparisonDigestState::CompleteStable;
        digest.algorithm = ComparisonDigestAlgorithm::Sha256;
        digest.bytes = hash_.digest(); digest.bytes_read = offset_;
        digest.before = n.entry.object; digest.after = comparison_object(*now.value());
        n.entry.digest = digest; reading_.reset();
    }
    HeldChild::Pointer root_;
    const ReviewedTreePlanRequest& request_;
    std::vector<Frame> frames_;
    std::set<std::string> folded_;
    std::optional<std::string> reading_;
    std::size_t path_bytes_ = 0;
    Sha256 hash_;
    std::uint64_t offset_ = 0;
};
bool equal_tree(const Tree& a, const Tree& b) {
    if (!unchanged(a.root_metadata, b.root_metadata) || a.nodes.size() != b.nodes.size()) return false;
    auto i = a.nodes.begin(), j = b.nodes.begin();
    for (; i != a.nodes.end(); ++i, ++j) {
        if (i->first != j->first || i->second.names != j->second.names || !unchanged(i->second.metadata, j->second.metadata)) return false;
        const auto& x = i->second.entry.digest; const auto& y = j->second.entry.digest;
        if (x.has_value() != y.has_value() || (x && (x->bytes != y->bytes || x->bytes_read != y->bytes_read))) return false;
    }
    return true;
}
std::vector<ComparisonEntry> entries(const Tree& t) {
    std::vector<ComparisonEntry> out; out.reserve(t.nodes.size());
    for (const auto& [key, n] : t.nodes) out.push_back(n.entry);
    return out;
}
ReviewedTreeAction action(ComparisonAction a) {
    switch (a) {
    case ComparisonAction::Report: return ReviewedTreeAction::Report;
    case ComparisonAction::Skip: return ReviewedTreeAction::Skip;
    case ComparisonAction::CopyToDestination: return ReviewedTreeAction::Copy;
    case ComparisonAction::CreateDestinationDirectory: return ReviewedTreeAction::CreateDirectory;
    case ComparisonAction::MergeDirectories: return ReviewedTreeAction::MergeDirectory;
    case ComparisonAction::ReplaceDestination: return ReviewedTreeAction::Replace;
    case ComparisonAction::RemoveDestinationFile: return ReviewedTreeAction::RemoveFile;
    case ComparisonAction::RemoveDestinationDirectory: return ReviewedTreeAction::RemoveDirectory;
    default: return ReviewedTreeAction::Report;
    }
}
bool removal(ReviewedTreeAction a) { return a == ReviewedTreeAction::RemoveFile || a == ReviewedTreeAction::RemoveDirectory; }
bool mutation(ReviewedTreeAction a) {
    return a == ReviewedTreeAction::Copy || a == ReviewedTreeAction::CreateDirectory || a == ReviewedTreeAction::Replace || removal(a);
}
}

struct ReviewedTreeReceiptState {
    ComparisonPlanIdentity plan;
    std::vector<ReviewedTreeItem> items;
    std::shared_ptr<const ReviewedTreeDeletionState> deletion;
    std::shared_ptr<const unsigned char> revision;
};
struct ReviewedTreeDeletionState { ComparisonPlanIdentity plan; std::vector<ComparisonDecisionToken> rows; };

struct ReviewedTreePlanJob::Impl {
    explicit Impl(ReviewedTreePlanRequest r) : request(std::move(r)) {}
    ReviewedTreePlanRequest request;
    ReviewedTreeProgress progress;
    ComparisonPlan::Pointer plan;
    Tree source, target;
    std::unique_ptr<Scanner> scanner;
    unsigned scan_phase = 0;
    std::optional<std::map<std::string, Node>::const_iterator> name_check;
    // Held ancestry: two full native walks, both must reach the same actual
    // self-parent namespace endpoint. Repeated non-endpoint ancestors fail.
    std::unique_ptr<OpenedEntry> ancestor;
    std::vector<ObjectIdentity> ancestors;
    std::optional<ObjectIdentity> endpoint;
    unsigned ancestry_side = 0;
    bool topology_done = false;
    std::vector<ReviewedTreeItem> items;
    std::shared_ptr<const ReviewedTreeReceiptState> receipt;
    std::shared_ptr<const unsigned char> revision = std::make_shared<const unsigned char>(0);
    std::vector<ConflictRule> assessed_rules;
    bool assessed = false;
    std::vector<ReviewedTreeNameChoice> assessed_names;
    std::optional<std::vector<ReviewedTreeItem>> last_assessment;
    RetainedTarget::Pointer retained;
    bool replacement_prepared = false;
    std::size_t current = 0;
    std::vector<std::size_t> order;
    std::size_t index() const { return order.empty() ? current : (current < order.size() ? order[current] : items.size()); }
    struct Deletion {
        Node node;
        std::shared_ptr<const DirectoryCursor> parent;
        OperationJournal::Pointer journal;
        std::shared_ptr<OperationJournalFile> file;
        std::vector<std::byte> evidence;
        unsigned phase = 0;
    };
    std::optional<Deletion> deleting;
    bool mutated = false;
    NativeOperationCopyJob::Pointer copy;
    OpenedEntry* staging = nullptr;
    OperationMetadataJob* metadata_phase = nullptr;
    Sha256 staging_hash;
    std::uint64_t staging_offset = 0;
    std::optional<BasicMetadata> staging_before;
    bool staging_hashed = false;
    std::optional<UnavailableObservation> failure;

    void fail(UnavailableObservation e, bool reconcile = false) {
        failure = e; progress.failure = e;
        progress.partial = mutated;
        progress.recovery_required = progress.recovery_required || reconcile || mutated;
        progress.state = reconcile ? ReviewedTreeState::NeedsReconciliation :
            mutated ? ReviewedTreeState::Partial : ReviewedTreeState::Failed;
        if (current < items.size()) {
            items[index()].failure = std::move(e);
            items[index()].state = reconcile ? ReviewedTreeItemState::NeedsReconciliation : ReviewedTreeItemState::Failed;
            items[index()].recovery_required = progress.recovery_required;
            ++progress.failed_items;
        }
    }
    bool roots_current() const {
        for (const auto& root : {request.source_root, request.destination_root}) {
            auto live = root->refresh();
            if (!live.value() || !(*live.value())->metadata().identity.value() ||
                !(*live.value())->metadata().mount_id.value() ||
                !same(*root->metadata().identity.value(), *(*live.value())->metadata().identity.value()) ||
                !equal(root->metadata().mount_id, (*live.value())->metadata().mount_id)) return false;
        }
        return true;
    }
    void topology_step() {
        const auto& root = ancestry_side == 0 ? request.source_root : request.destination_root;
        const auto& other = ancestry_side == 0 ? request.destination_root : request.source_root;
        if (!ancestor) {
            auto opened = root->parent()->open_directory_child(root->name());
            if (!opened.value()) { fail(*opened.unavailable_detail()); return; }
            auto metadata = (*opened.value())->inspect_basic();
            if (!metadata.value() || !qualified(*metadata.value()) ||
                !same(*root->metadata().identity.value(), *metadata.value()->identity.value())) {
                fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.root_identity")); return;
            }
            ancestors.push_back(*metadata.value()->identity.value());
            auto parent = (*opened.value())->open_parent_directory();
            if (!parent.value()) { fail(*parent.unavailable_detail()); return; }
            ancestor = std::move(parent).take_value(); return;
        }
        auto metadata = ancestor->inspect_basic();
        if (!metadata.value() || !qualified(*metadata.value())) {
            fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.ancestry_metadata")); return;
        }
        const auto id = *metadata.value()->identity.value();
        if (same(id, *other->metadata().identity.value())) {
            fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.overlap")); return;
        }
        if (same(id, ancestors.back())) {
            if (ancestors.size() == 1) { fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.namespace_root")); return; }
            if (ancestry_side == 1) {
                if (!endpoint || !same(*endpoint, id)) { fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.namespace_boundary")); return; }
                topology_done = true;
            } else { endpoint = id; ++ancestry_side; }
            ancestor.reset(); ancestors.clear(); return;
        }
        if (ancestors.size() >= 1024 || std::any_of(ancestors.begin(), ancestors.end(), [&](const auto& old) { return same(old, id); })) {
            fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.ancestry_cycle")); return;
        }
        ancestors.push_back(id);
        auto parent = ancestor->open_parent_directory();
        if (!parent.value()) { fail(*parent.unavailable_detail()); return; }
        ancestor = std::move(parent).take_value();
    }
    void reset_topology() {
        topology_done = false; ancestor.reset(); ancestors.clear(); endpoint.reset(); ancestry_side = 0;
    }
    void start_scan(unsigned phase) {
        scan_phase = phase;
        scanner = std::make_unique<Scanner>((phase % 2 == 0) ? request.source_root : request.destination_root, request);
    }
    void scan_step(std::stop_token stop) {
        if (!scanner) {
            if (name_check) { check_one_name(); return; }
            start_scan(0); return;
        }
        scanner->step(stop);
        if (scanner->failure) { fail(*scanner->failure); return; }
        if (!scanner->complete) return;
        auto observed = std::move(scanner->tree);
        if (progress.state == ReviewedTreeState::Inventory) {
            if (scan_phase == 0) { source = std::move(observed); start_scan(1); }
            else if (scan_phase == 1) { target = std::move(observed); start_scan(2); }
            else if (scan_phase == 2) {
                if (!equal_tree(source, observed)) { fail(error(AdapterError::PlanDecisionStale, "reviewed_tree.source_unstable", ObservationState::Changed)); return; }
                source = std::move(observed); start_scan(3);
            } else {
                if (!equal_tree(target, observed) || !roots_current()) { fail(error(AdapterError::PlanDecisionStale, "reviewed_tree.target_unstable", ObservationState::Changed)); return; }
                target = std::move(observed); scanner.reset(); name_check = source.nodes.cbegin();
            }
            return;
        }
        if (!equal_tree(scan_phase == 0 ? source : target, observed) || !roots_current()) {
            fail(error(AdapterError::PlanDecisionStale, "reviewed_tree.receipt_evidence_changed", ObservationState::Changed)); return;
        }
        if (scan_phase == 0) { start_scan(1); return; }
        scanner.reset();
        progress.state = ReviewedTreeState::Executing;
        if (current == items.size()) { progress.state = ReviewedTreeState::Complete; progress.partial = false; progress.recovery_required = false; }
    }
    void check_one_name() {
        if (*name_check == source.nodes.cend()) { name_check.reset(); seal(); return; }
        const auto& [key, n] = **name_check;
        ++*name_check;
        auto parent = parent_for(n, false);
        if (!parent.value()) {
            // A missing reviewed destination ancestor is expected for a new
            // subtree; any failure along an existing parent chain is not.
            std::vector<NativeName> prefix;
            for (std::size_t i = 0; i + 1 < n.names.size(); ++i) {
                prefix.push_back(n.names[i]);
                if (!target.nodes.contains(key_path(prefix))) return;
            }
            fail(*parent.unavailable_detail()); return;
        }
        auto lookup = (*parent.value())->lookup_child(n.names.back(), ChildLookupMode::NativeDefault);
        if (!lookup.value()) { fail(*lookup.unavailable_detail()); return; }
        if (lookup.value()->state() == ChildLookupState::Found) {
            auto exact = target.nodes.find(key);
            auto metadata = lookup.value()->entry()->inspect_basic();
            if (!metadata.value() || !metadata.value()->identity.value() || exact == target.nodes.end() ||
                !same(*exact->second.metadata.identity.value(), *metadata.value()->identity.value()))
                fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.native_name_collision"));
        } else if (lookup.value()->state() != ChildLookupState::Missing)
            fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.name_lookup_unknown"));
    }
    void seal() {
        if (source.nodes.size() > request.limits.max_entries - target.nodes.size()) {
            fail(error(AdapterError::InventoryLimit, "reviewed_tree.combined_entries")); return;
        }
        std::map<std::string, std::string> folded;
        for (const auto* t : {&source, &target}) for (const auto& [key, n] : t->nodes) {
            const auto f = key_path(n.names, true);
            const auto [it, added] = folded.emplace(f, key);
            if (!added && it->second != key) { fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.cross_tree_case_collision")); return; }
        }
        using IdentityKey = std::tuple<IdentityScheme, std::array<std::byte,16>, std::array<std::byte,16>>;
        std::set<IdentityKey> source_ids;
        for (const auto& [key, n] : source.nodes) {
            const auto& id = *n.metadata.identity.value();
            source_ids.emplace(id.scheme, id.volume.bytes, id.object.bytes);
        }
        for (const auto& [key, n] : target.nodes) {
            const auto& id = *n.metadata.identity.value();
            if (source_ids.contains({id.scheme, id.volume.bytes, id.object.bytes})) {
                fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.cross_tree_alias")); return;
            }
        }
        auto s = entries(source), d = entries(target);
        request.comparison.topology = ComparisonTopology::Disjoint;
        auto created = ComparisonPlan::create(request.comparison,
            {ComparisonInventoryState::CompleteStable, *source.root_metadata.identity.value(), s},
            {ComparisonInventoryState::CompleteStable, *target.root_metadata.identity.value(), d}, {}, request.limits);
        if (!created.value()) { fail(*created.unavailable_detail()); return; }
        plan = *created.value();
        for (std::size_t offset = 0;;) {
            auto page = plan->page(offset, request.limits.max_page_rows);
            if (!page.value()) { fail(*page.unavailable_detail()); return; }
            for (const auto& row : page.value()->rows) {
                const auto& tree = source.nodes.contains(row.relative_path) ? source : target;
                ReviewedTreeItem item;
                item.row = row; item.relative_components = tree.nodes.at(row.relative_path).names;
                item.action = action(row.action);
                fill_facts(item);
                items.push_back(std::move(item));
            }
            if (!page.value()->next_offset) break;
            offset = *page.value()->next_offset;
        }
        progress.known_items = items.size(); progress.counts_complete = true;
        progress.known_copy_bytes = plan->aggregate().proposed_copy_bytes;
        progress.state = ReviewedTreeState::AwaitingReview;
    }
    // Rewalk exact native components from the held root; a retained child ID
    // alone cannot certify that its reviewed ancestor/name chain still exists.
    Observation<std::shared_ptr<const DirectoryCursor>> parent_for(const Node& n, bool incoming) const {
        const auto& t = incoming ? source : target;
        auto cursor = t.root;
        std::vector<NativeName> prefix;
        for (std::size_t i = 0; i + 1 < n.names.size(); ++i) {
            prefix.push_back(n.names[i]);
            auto known = t.nodes.find(key_path(prefix));
            if (known == t.nodes.end() || !known->second.directory) return invalid<std::shared_ptr<const DirectoryCursor>>("reviewed_tree.parent_map");
            auto opened = cursor->open_directory_child(n.names[i]);
            if (!opened.value()) return unavailable<std::shared_ptr<const DirectoryCursor>>(*opened.unavailable_detail());
            cursor = std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value());
            auto m = cursor->inspect_basic();
            if (!m.value() || !m.value()->identity.value() || !m.value()->mount_id.value() ||
                !same(*known->second.metadata.identity.value(), *m.value()->identity.value()) ||
                *m.value()->mount_id.value() != *t.root_metadata.mount_id.value())
                return unavailable<std::shared_ptr<const DirectoryCursor>>(error(AdapterError::PlanDecisionStale, "reviewed_tree.parent_substituted", ObservationState::Changed));
        }
        return Observation<std::shared_ptr<const DirectoryCursor>>::available(std::move(cursor));
    }
    const NativeName& publication_name(const Node& n) const {
        const auto& item = items[index()];
        return item.name_side == ReviewedTreeNameSide::Incoming && item.proposed_name ? *item.proposed_name : n.names.back();
    }
    Observation<bool> guard(const Node& n) const {
        if (!roots_current_const()) return unavailable<bool>(error(AdapterError::PlanDecisionStale, "reviewed_tree.root_substituted", ObservationState::Changed));
        auto s = parent_for(n, true), d = parent_for(n, false);
        if (!s.value()) return unavailable<bool>(*s.unavailable_detail());
        if (!d.value()) return unavailable<bool>(*d.unavailable_detail());
        auto now = HeldChild::observe_with_access(*s.value(), n.names.back(), EntryAccess::ContentRead);
        if (!now.value()) return unavailable<bool>(*now.unavailable_detail());
        if (!unchanged(n.metadata, (*now.value())->metadata()))
            return unavailable<bool>(error(AdapterError::PlanDecisionStale, "reviewed_tree.source_changed", ObservationState::Changed));
        if (items[index()].action == ReviewedTreeAction::Replace && !replacement_prepared) {
            const auto old = target.nodes.find(n.entry.relative_path);
            if (old == target.nodes.end()) return invalid<bool>("reviewed_tree.replacement_target");
            return target_guard(old->second);
        }
        if (items[index()].name_side == ReviewedTreeNameSide::Incoming && items[index()].row.destination_index) {
            const auto old = target.nodes.find(n.entry.relative_path);
            if (old == target.nodes.end()) return invalid<bool>("reviewed_tree.incoming_target_evidence");
            auto valid = target_guard(old->second, false);
            if (!valid.value()) return valid;
        }
        auto missing = (*d.value())->lookup_child(publication_name(n), ChildLookupMode::NativeDefault);
        if (!missing.value()) return unavailable<bool>(*missing.unavailable_detail());
        if (missing.value()->state() != ChildLookupState::Missing)
            return unavailable<bool>(error(AdapterError::PlanDecisionStale, "reviewed_tree.destination_occupied", ObservationState::Changed));
        return Observation<bool>::available(true);
    }
    bool roots_current_const() const { return roots_current(); }
    static bool expected_directory_change(const BasicMetadata& before, const BasicMetadata& now) {
        return qualified(now) && *now.kind.value() == ObjectKind::Directory &&
            same(*before.identity.value(), *now.identity.value()) && equal(before.mount_id, now.mount_id) &&
            equal(before.posix_permissions, now.posix_permissions) && equal(before.posix_uid, now.posix_uid) &&
            equal(before.posix_gid, now.posix_gid) && equal(before.bsd_flags, now.bsd_flags) &&
            equal(before.windows_attributes, now.windows_attributes);
    }
    void refresh_target_ancestors(const Node& n) {
        auto metadata = target.root->inspect_basic();
        if (!metadata.value()) { fail(*metadata.unavailable_detail(), true); return; }
        if (!expected_directory_change(target.root_metadata, *metadata.value())) {
            fail(error(AdapterError::PlanDecisionStale, "reviewed_tree.destination_metadata_changed", ObservationState::Changed), true); return;
        }
        target.root_metadata = *metadata.value();
        std::vector<NativeName> prefix;
        for (std::size_t i = 0; i + 1 < n.names.size(); ++i) {
            prefix.push_back(n.names[i]); auto& parent = target.nodes.at(key_path(prefix));
            auto now = parent.directory->inspect_basic();
            if (!now.value()) { fail(*now.unavailable_detail(), true); return; }
            if (!expected_directory_change(parent.metadata, *now.value())) {
                fail(error(AdapterError::PlanDecisionStale, "reviewed_tree.parent_metadata_changed", ObservationState::Changed), true); return;
            }
            parent.metadata = *now.value(); parent.entry.object = comparison_object(parent.metadata);
        }
    }
    bool record_retained(const Node& incoming) {
        auto found = target.nodes.find(incoming.entry.relative_path);
        if (found == target.nodes.end() || !items[index()].retained_name) {
            fail(error(AdapterError::InvalidNativeResult, "reviewed_tree.retained_record"), true); return false;
        }
        Node old = found->second;
        auto parent = parent_for(old, false);
        if (!parent.value()) { fail(*parent.unavailable_detail(), true); return false; }
        auto observed = HeldChild::observe_with_access(*parent.value(), *items[index()].retained_name, EntryAccess::ContentRead);
        if (!observed.value()) { fail(*observed.unavailable_detail(), true); return false; }
        const auto metadata = (*observed.value())->metadata();
        if (!qualified(metadata) || !same(*old.metadata.identity.value(), *metadata.identity.value()) ||
            !equal(old.metadata.logical_size, metadata.logical_size) || !equal(old.metadata.mount_id, metadata.mount_id)) {
            fail(error(AdapterError::MetadataChanged, "reviewed_tree.retained_identity", ObservationState::Changed), true); return false;
        }
        old.names.back() = *items[index()].retained_name;
        old.held = *observed.value(); old.metadata = metadata;
        old.entry.relative_path = key_path(old.names); old.entry.object = comparison_object(metadata);
        if (old.entry.digest) { old.entry.digest->before = old.entry.object; old.entry.digest->after = old.entry.object; }
        target.nodes.erase(found);
        const auto key = old.entry.relative_path;
        if (!target.nodes.emplace(key, std::move(old)).second) {
            fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.retained_collision"), true); return false;
        }
        return true;
    }
    void record_created(const Node& incoming, bool directory) {
        auto parent = parent_for(incoming, false);
        if (!parent.value()) { fail(*parent.unavailable_detail(), true); return; }
        auto held = directory ? HeldChild::observe(*parent.value(), publication_name(incoming)) :
            HeldChild::observe_with_access(*parent.value(), publication_name(incoming), EntryAccess::ContentRead);
        if (!held.value()) { fail(*held.unavailable_detail(), true); return; }
        Node n{incoming.names, *held.value(), {}, (*held.value())->metadata(), {}};
        n.names.back() = publication_name(incoming);
        if (!qualified(n.metadata) || *n.metadata.mount_id.value() != *target.root_metadata.mount_id.value() ||
            *n.metadata.kind.value() != (directory ? ObjectKind::Directory : ObjectKind::RegularFile)) {
            fail(error(AdapterError::MetadataChanged, "reviewed_tree.created_kind", ObservationState::Changed), true); return;
        }
        n.entry.relative_path = key_path(n.names); n.entry.object = comparison_object(n.metadata);
        if (directory) {
            auto opened = (*parent.value())->open_directory_child(incoming.names.back());
            if (!opened.value()) { fail(*opened.unavailable_detail(), true); return; }
            n.directory = std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value());
            if (!n.directory->identity().value() || !same(*n.directory->identity().value(), *n.metadata.identity.value())) {
                fail(error(AdapterError::MetadataChanged, "reviewed_tree.created_identity", ObservationState::Changed), true); return;
            }
        } else {
            if (!staging_before || !same(*staging_before->identity.value(), *n.metadata.identity.value()) ||
                !equal(staging_before->logical_size, n.metadata.logical_size)) {
                fail(error(AdapterError::MetadataChanged, "reviewed_tree.published_identity", ObservationState::Changed), true); return;
            }
            ComparisonDigest digest = *incoming.entry.digest;
            digest.before = n.entry.object; digest.after = n.entry.object;
            n.entry.digest = digest;
        }
        const auto created_key = n.entry.relative_path;
        if (!target.nodes.emplace(created_key, std::move(n)).second) {
            fail(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.output_name_occupied"), true); return;
        }
        items[index()].resulting_name = publication_name(incoming);
        refresh_target_ancestors(incoming);
    }
    void finish_item() {
        items[index()].state = ReviewedTreeItemState::Complete; ++progress.completed_items;
        ++current; progress.current_row.reset();
        progress.state = ReviewedTreeState::Revalidating;
        reset_topology(); start_scan(0);
    }
    void staging_step(std::stop_token stop) {
        if (!staging_before) {
            auto m = staging->inspect_basic();
            if (!m.value()) { fail(*m.unavailable_detail(), true); return; }
            staging_before = *m.value(); return;
        }
        auto data = staging->read_content({request.digest_chunk_bytes}, staging_offset, stop);
        if (!data.value()) { fail(*data.unavailable_detail(), true); return; }
        const auto& source_node = source.nodes.at(items[index()].row.relative_path);
        auto size = *source_node.metadata.logical_size.value();
        if (staging_offset > size || data.value()->bytes.size() > size - staging_offset ||
            (data.value()->bytes.empty() && !data.value()->complete)) {
            fail(error(AdapterError::MetadataChanged, "reviewed_tree.staging_size", ObservationState::Changed), true); return;
        }
        staging_hash.update(data.value()->bytes); staging_offset += data.value()->bytes.size();
        if (!data.value()->complete) return;
        auto after = staging->inspect_basic();
        if (staging_offset != size || staging_hash.digest() != source_node.entry.digest->bytes ||
            !after.value() || !unchanged(*staging_before, *after.value())) {
            fail(error(AdapterError::PlanDecisionStale, "reviewed_tree.staging_digest", ObservationState::Changed), true); return;
        }
        staging_hashed = true;
    }
    std::optional<NativeAbsolutePath> address_for(const Node& n) const {
        auto address = request.destination_address;
        if (address) for (std::size_t i = 0; i + 1 < n.names.size(); ++i) {
            auto child = address->child_address(n.names[i]);
            if (!child.value()) return std::nullopt;
            address = std::move(child).take_value();
        }
        return address;
    }
    void start_copy(const Node& n, std::stop_token stop) {
        auto parent = parent_for(n, false);
        if (!parent.value()) { fail(*parent.unavailable_detail()); return; }
        auto preservation = preservation_for(n.held, request.copy_policy, stop);
        if (!preservation.value()) { fail(*preservation.unavailable_detail()); return; }
        auto id = request.journal_id;
        for (unsigned i = 0; i < 8; ++i) id.bytes[8 + i] = std::byte((items[index()].row.id >> (8 * i)) & 255);
        std::string suffix;
        constexpr char hex[] = "0123456789abcdef";
        for (auto b : id.bytes) { unsigned v = std::to_integer<unsigned>(b); suffix += hex[v >> 4]; suffix += hex[v & 15]; }
        auto name = [&](std::string prefix) -> NativeName {
            prefix += suffix;
            if (n.names.back().posix_bytes()) return *NativeName::from_posix(std::move(prefix));
            return *NativeName::from_windows(std::u16string(prefix.begin(), prefix.end()));
        };
        if (items[index()].action == ReviewedTreeAction::Replace && !retained) {
            const auto& old = target.nodes.at(n.entry.relative_path);
            const auto retention_id = items[index()].retention_journal_id;
            if (!items[index()].retained_name || !retention_id) {
                fail(error(AdapterError::PlanInvalid, "reviewed_tree.retained_receipt_name")); return;
            }
            RetainedTargetRequest retention{old.held, *items[index()].retained_name, old.entry.digest->bytes,
                *request.journal_root, *retention_id, address_for(old), [this, &old] { return target_guard(old); }, request.digest_chunk_bytes};
            auto prepared = RetainedTarget::create(std::move(retention));
            if (!prepared.value()) { fail(*prepared.unavailable_detail(), prepared.state() == ObservationState::Unknown); return; }
            retained = *prepared.value(); progress.recovery_required = true; items[index()].recovery_required = true;
            return;
        }
        items[index()].journal_id = id;
        items[index()].journal_name = name(".ck-reviewed-journal-");
        items[index()].staging_name = name(".ck-reviewed-staging-");
        items[index()].recovery_required = true;
        auto file = request.open_journal(*request.journal_root, *items[index()].journal_name, true);
        if (!file.value()) { fail(*file.unavailable_detail(), true); return; }
        auto journal = OperationJournal::create(FileOperation::Copy, id, request.copy_policy.journal_limits);
        if (!journal.value()) { fail(*journal.unavailable_detail(), true); return; }
        auto appended = append_operation_journal_file(**file.value(), **journal.value(), {1, 0, OperationJournalState::Planned, {}});
        if (!appended.value()) { fail(*appended.unavailable_detail(), true); return; }
        std::optional<NativeAbsolutePath> address = request.destination_address;
        if (address) for (std::size_t i = 0; i + 1 < n.names.size(); ++i) {
            auto child = address->child_address(n.names[i]);
            if (!child.value()) { fail(*child.unavailable_detail(), true); return; }
            address = std::move(child).take_value();
        }
        NativeOperationCopyRequest r{
            .journal = *journal.value(),
            .journal_file = std::shared_ptr<OperationJournalFile>(std::move(file).take_value()),
            .item = 0,
            .source_parent = n.held->parent(),
            .source_parent_identity = *n.held->parent_identity().value(),
            .source_name = n.names.back(),
            .source_identity = *n.metadata.identity.value(),
            .destination = *parent.value(),
            .destination_identity = *(*parent.value())->identity().value(),
            .destination_address = address,
            .staging_name = name(".ck-reviewed-staging-"),
            .destination_name = publication_name(n),
            .copy_limits = request.copy_policy.copy_limits,
            .prepare_metadata = {},
            .operation = FileOperation::Copy,
            .verify_metadata_before_publication = {}};
        auto policy = *preservation.value();
        r.prepare_metadata = [this, policy](OpenedEntry& stage, std::stop_token token) {
            staging = &stage;
            auto prepared = policy->prepare(stage, token);
            if (prepared.value()) metadata_phase = prepared.value()->get();
            return prepared;
        };
        r.verify_metadata_before_publication = [this, policy, &n](OpenedEntry& stage, std::stop_token token) {
            auto valid = guard(n);
            if (!valid.value()) return valid;
            if (!staging_hashed || !staging_before) return invalid<bool>("reviewed_tree.staging_not_verified");
            auto now = stage.inspect_basic();
            if (!now.value() || !unchanged(*staging_before, *now.value()))
                return unavailable<bool>(error(AdapterError::PlanDecisionStale, "reviewed_tree.staging_changed", ObservationState::Changed));
            return policy->verify(stage, token);
        };
        if (items[index()].action == ReviewedTreeAction::Replace) {
            r.prepare_destination_before_publication = [this](std::stop_token token) {
                if (!retained || retained->state() != RetainedTargetState::Ready) return invalid<bool>("reviewed_tree.retention_not_ready");
                auto retained_result = retained->retain(token);
                if (retained_result.value() && *retained_result.value()) {
                    replacement_prepared = true; mutated = true; progress.partial = true;
                    items[index()].target_retained = true;
                }
                return retained_result;
            };
        }
        auto job = NativeOperationCopyJob::create(std::move(r));
        if (!job.value()) { fail(*job.unavailable_detail(), true); return; }
        copy = std::move(job).take_value(); progress.recovery_required = true;
    }
    Observation<bool> qualify_new_names(std::span<const ReviewedTreeItem> resolved) const {
        struct Candidate { NativeName name; const Node* context; };
        std::map<std::string, std::vector<Candidate>> groups;
        std::set<std::string> exact, folded;
        for (const auto& item : resolved) {
            if (item.action != ReviewedTreeAction::Copy && item.action != ReviewedTreeAction::CreateDirectory && item.action != ReviewedTreeAction::Replace) continue;
            const auto& n = source.nodes.at(item.row.relative_path);
            if (item.action == ReviewedTreeAction::Replace && !item.retained_name) return invalid<bool>("reviewed_tree.retained_receipt_name");
            const auto& candidate = item.action == ReviewedTreeAction::Replace ? *item.retained_name :
                (item.name_side == ReviewedTreeNameSide::Incoming && item.proposed_name ? *item.proposed_name : n.names.back());
            auto names = n.names; names.back() = candidate;
            if (key_path(names).size() > request.limits.max_path_bytes) return invalid<bool>("reviewed_tree.proposed_name_limit");
            if (!exact.insert(key_path(names)).second || !folded.insert(key_path(names, true)).second)
                return unavailable<bool>(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.planned_name_collision"));
            names.pop_back(); groups[key_path(names)].push_back({candidate, &n});
            auto parent = parent_for(n, false);
            if (parent.value()) {
                auto lookup = (*parent.value())->lookup_child(candidate, ChildLookupMode::NativeDefault);
                if (!lookup.value()) return unavailable<bool>(*lookup.unavailable_detail());
                if (lookup.value()->state() != ChildLookupState::Missing)
                    return unavailable<bool>(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.native_name_collision", ObservationState::Changed));
            }
        }
        for (const auto& [key, nodes] : groups) {
            if (nodes.size() < 2 || std::all_of(nodes.begin(), nodes.end(), [](const Candidate& n) { return ascii_units(n.name); })) continue;
            auto parent = parent_for(*nodes.front().context, false);
            if (!parent.value()) return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.future_directory_name_policy", ObservationState::Unsupported));
            auto policy = DirectoryNameRulesProbe::inspect(*parent.value());
            if (!policy.value()) return unavailable<bool>(*policy.unavailable_detail());
            if (!(*policy.value())->rule().value()) return unavailable<bool>(*(*policy.value())->rule().unavailable_detail());
            if ((*policy.value())->rule().value()->rule != DirectoryNameRule::LinuxExtendedFsBytewise)
                return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.unqualified_name_policy", ObservationState::Unsupported));
        }
        return Observation<bool>::available(true);
    }
    void update_rules(std::span<const ConflictRule> rules, std::span<const ReviewedTreeNameChoice> names) {
        const auto equal_rule = [](const ConflictRule& a, const ConflictRule& b) {
            return a.plan == b.plan && a.kind == b.kind && a.choice == b.choice && a.tie == b.tie &&
                a.scope == b.scope && a.selected_rows == b.selected_rows && a.subtree == b.subtree &&
                a.protect_nonempty == b.protect_nonempty && a.retain_replaced == b.retain_replaced && a.direction == b.direction;
        };
        const auto equal_name = [](const ReviewedTreeNameChoice& a, const ReviewedTreeNameChoice& b) {
            return a.token == b.token && a.name == b.name && a.side == b.side;
        };
        if (!assessed || rules.size() != assessed_rules.size() || names.size() != assessed_names.size() ||
            !std::equal(rules.begin(), rules.end(), assessed_rules.begin(), equal_rule) ||
            !std::equal(names.begin(), names.end(), assessed_names.begin(), equal_name)) {
            revision = std::make_shared<const unsigned char>(0);
            assessed_rules.assign(rules.begin(), rules.end()); assessed_names.assign(names.begin(), names.end());
            assessed = true; last_assessment.reset();
        }
    }
    static std::uint64_t choice_bit(ConflictChoice c) { return std::uint64_t{1} << static_cast<unsigned>(c); }
    void fill_facts(ReviewedTreeItem& item) const {
        auto& out = item.facts;
        out = {}; out.timestamp_quantum_ns = request.comparison.timestamp_quantum_ns;
        const auto s = source.nodes.find(item.row.relative_path), d = target.nodes.find(item.row.relative_path);
        out.source_present = s != source.nodes.end(); out.destination_present = d != target.nodes.end();
        if (out.source_present) { out.source_kind = s->second.entry.object.kind; out.source_size = s->second.entry.object.size; out.source_modified = s->second.entry.object.modified; }
        if (out.destination_present) { out.destination_kind = d->second.entry.object.kind; out.destination_size = d->second.entry.object.size; out.destination_modified = d->second.entry.object.modified; }
        out.allowed_choices = choice_bit(ConflictChoice::Ask) | choice_bit(ConflictChoice::Skip) | choice_bit(ConflictChoice::Cancel) | choice_bit(ConflictChoice::Compare);
        if (out.destination_present) out.allowed_choices |= choice_bit(ConflictChoice::KeepTarget);
        if (out.source_kind == ObjectKind::RegularFile && (!out.destination_present || out.destination_kind == ObjectKind::RegularFile))
            out.allowed_choices |= choice_bit(ConflictChoice::KeepBothIncoming) | choice_bit(ConflictChoice::Rename);
        if (out.source_kind == ObjectKind::Directory && out.destination_kind == ObjectKind::Directory)
            out.allowed_choices |= choice_bit(ConflictChoice::MergeFolders);
    }
    const std::vector<ReviewedTreeItem>& assessment(std::span<const ConflictRule> rules,
        std::span<const ReviewedTreeNameChoice> names = {}) {
        update_rules(rules, names);
        if (last_assessment) return *last_assessment;
        auto resolved = items;
        bool invalid_selection = rules.size() > 100'000 || names.size() > items.size();
        std::map<std::uint64_t, const ReviewedTreeNameChoice*> chosen;
        for (const auto& name : names) {
            if (!name.token.is_valid() || name.token.plan_identity() != plan->identity() || name.token.row_id() > items.size() ||
                !name.name.is_valid() || name.name.encoding() != request.destination_root->name().encoding() ||
                static_cast<unsigned>(name.side) > static_cast<unsigned>(ReviewedTreeNameSide::Target) ||
                !chosen.emplace(name.token.row_id(), &name).second) invalid_selection = true;
        }
        for (const auto& rule : rules) {
            for (auto id : rule.selected_rows) if (!id || id > items.size()) invalid_selection = true;
            if (rule.scope == ConflictScope::Subtree && std::none_of(items.begin(), items.end(),
                [&](const auto& item) { return item.row.relative_path == rule.subtree; })) invalid_selection = true;
        }
        for (auto& item : resolved) {
            fill_facts(item);
            const auto d = target.nodes.find(item.row.relative_path);
            ConflictFacts facts;
            facts.token = item.row.token; facts.relative_path = item.row.relative_path;
            facts.relation = item.row.relation; facts.evidence_current = true;
            const bool both = item.facts.source_present && item.facts.destination_present;
            facts.kind = !both ? ConflictClass::Unavailable :
                item.row.relation == ComparisonRelation::DirectoryPair ? ConflictClass::DirectoryPair :
                item.row.relation == ComparisonRelation::TypeConflict ? ConflictClass::TypeMismatch : ConflictClass::ExistingRegular;
            item.facts.conflict_class = facts.kind;
            if (both) {
                facts.compatible_regular_files = item.facts.source_kind == ObjectKind::RegularFile && item.facts.destination_kind == ObjectKind::RegularFile;
                facts.compatible_directories = item.facts.source_kind == ObjectKind::Directory && item.facts.destination_kind == ObjectKind::Directory;
                facts.source_size = item.facts.source_size; facts.target_size = item.facts.destination_size;
                const auto quantum = request.comparison.timestamp_quantum_ns;
                const auto rounded = [quantum](const FileTimestamp& t) {
                    if (quantum <= 1'000'000'000) return std::pair(t.seconds(), std::uint64_t(t.nanoseconds()) / quantum);
                    const auto seconds = static_cast<std::int64_t>(quantum / 1'000'000'000);
                    auto count = t.seconds() / seconds; if (t.seconds() % seconds < 0) --count;
                    return std::pair(count, std::uint64_t{0});
                };
                const auto st = rounded(*item.facts.source_modified), dt = rounded(*item.facts.destination_modified);
                facts.time_order = st > dt ? ConflictTimeOrder::SourceNewer : st < dt ? ConflictTimeOrder::TargetNewer : ConflictTimeOrder::Equal;
                facts.equal_time = facts.time_order == ConflictTimeOrder::Equal;
                if (facts.compatible_regular_files && request.journal_root && request.open_journal) {
                    const auto qualified = qualify_namespace(*d->second.held->parent());
                    if (qualified.value() && *qualified.value() && d->second.metadata.link_count.value() && *d->second.metadata.link_count.value() == 1) {
                        // Provider rename support alone is not a content freeze.
                        // Probe the same owning guard required by RetainedTarget;
                        // execution reacquires/revalidates it before any hashing.
                        auto guard = HeldChild::observe_with_access(d->second.held->parent(), d->second.held->name(),
                            EntryAccess::ContentRead | EntryAccess::RenameSource);
                        if (guard.value() && unchanged(d->second.metadata, (*guard.value())->metadata())) {
                            const auto stable = (*guard.value())->qualify_stable_content();
                            if (stable.value() && *stable.value()) {
                                const auto current = (*guard.value())->inspect_basic();
                                const auto membership = d->second.held->refresh();
                                facts.retention_available = current.value() && membership.value() &&
                                    unchanged(d->second.metadata, *current.value()) &&
                                    unchanged(d->second.metadata, (*membership.value())->metadata());
                            }
                        }
                    }
                }
            }
            item.facts.retained_target_available = facts.retention_available;
            if (facts.retention_available) for (const auto c : {ConflictChoice::UseSource, ConflictChoice::KeepBothTarget,
                ConflictChoice::Newest, ConflictChoice::SourceIfNewer, ConflictChoice::NewerOrDifferentSizeAtEqualTime,
                ConflictChoice::SizeDiffers, ConflictChoice::PreferLarger, ConflictChoice::PreferSmaller}) item.facts.allowed_choices |= choice_bit(c);
            auto result = evaluate_conflict_rules(rules, facts);
            const auto selected = chosen.find(item.row.id);
            const auto* native = selected == chosen.end() ? nullptr : selected->second;
            if (native) { item.proposed_name = native->name; item.name_side = native->side; }
            if (!both && native && native->side == ReviewedTreeNameSide::Incoming && item.facts.source_kind == ObjectKind::RegularFile &&
                item.row.action == ComparisonAction::CopyToDestination &&
                (result.state == ConflictRuleState::NoMatch || result.choice == ConflictChoice::Rename || result.choice == ConflictChoice::KeepBothIncoming)) {
                result = {}; result.state = ConflictRuleState::Apply; result.choice = ConflictChoice::Rename;
            }
            if (result.state == ConflictRuleState::NoMatch && item.row.requires_review) {
                result.state = ConflictRuleState::NeedsReview; result.reason = ConflictRuleReason::NoMatchingRule;
            }
            if (result.state == ConflictRuleState::Apply) {
                switch (result.choice) {
                case ConflictChoice::KeepTarget: case ConflictChoice::Skip: item.action = ReviewedTreeAction::Skip; break;
                case ConflictChoice::UseSource: item.action = ReviewedTreeAction::Replace; break;
                case ConflictChoice::MergeFolders: item.action = ReviewedTreeAction::MergeDirectory; break;
                case ConflictChoice::KeepBothIncoming: case ConflictChoice::Rename: case ConflictChoice::KeepBothTarget: {
                    const auto side = result.choice == ConflictChoice::KeepBothTarget ? ReviewedTreeNameSide::Target : ReviewedTreeNameSide::Incoming;
                    if (!native || native->side != side || item.facts.source_kind != ObjectKind::RegularFile ||
                        (side == ReviewedTreeNameSide::Target && item.facts.destination_kind != ObjectKind::RegularFile)) {
                        result.state = ConflictRuleState::NeedsReview; result.reason = ConflictRuleReason::AwaitingChoice; break;
                    }
                    item.action = side == ReviewedTreeNameSide::Incoming ? ReviewedTreeAction::Copy : ReviewedTreeAction::Replace;
                    result.requires_native_name_allocation = false; break;
                }
                default: result.state = ConflictRuleState::NeedsReview; result.reason = ConflictRuleReason::SeparatePolicyRequired; break;
                }
            }
            if (native && result.choice != ConflictChoice::KeepBothIncoming && result.choice != ConflictChoice::KeepBothTarget && result.choice != ConflictChoice::Rename) {
                result.state = ConflictRuleState::Invalid; result.reason = ConflictRuleReason::InvalidRule;
            }
            const bool needs_retention = item.action == ReviewedTreeAction::Replace ||
                result.choice == ConflictChoice::UseSource || result.choice == ConflictChoice::KeepBothTarget;
            if (needs_retention && !facts.retention_available &&
                result.state != ConflictRuleState::Invalid && result.state != ConflictRuleState::Stale) {
                result.state = ConflictRuleState::NeedsReview; result.reason = ConflictRuleReason::RetentionUnavailable;
            }
            if (invalid_selection) { result.state = ConflictRuleState::Invalid; result.reason = ConflictRuleReason::InvalidRule; }
            item.decision = result;
        }
        for (auto& item : resolved) if (item.action == ReviewedTreeAction::Replace) {
            auto id = request.journal_id;
            for (unsigned i = 0; i < 8; ++i) id.bytes[8 + i] = std::byte((item.row.id >> (8 * i)) & 255);
            constexpr char hex[] = "0123456789abcdef";
            std::string text = ".ck-reviewed-retained-";
            for (auto b : id.bytes) { auto v = std::to_integer<unsigned>(b); text += hex[v >> 4]; text += hex[v & 15]; }
            if (item.name_side == ReviewedTreeNameSide::Target && item.proposed_name) item.retained_name = item.proposed_name;
            else item.retained_name = item.relative_components.back().posix_bytes() ? NativeName::from_posix(text) : NativeName::from_windows(std::u16string(text.begin(), text.end()));
            id.bytes[0] ^= std::byte{0x80}; item.retention_journal_id = id;
        }
        for (const auto& parent : resolved) if (parent.action == ReviewedTreeAction::Skip) {
            const auto n = source.nodes.find(parent.row.relative_path);
            if (n != source.nodes.end() && *n->second.metadata.kind.value() == ObjectKind::Directory)
                for (auto& child : resolved) if (child.row.relative_path.starts_with(parent.row.relative_path + '/')) child.action = ReviewedTreeAction::Skip;
        }
        last_assessment = std::move(resolved);
        return *last_assessment;
    }
    Observation<bool> target_guard(const Node& n, bool require_native_rename = true) const {
        if (!roots_current_const()) return unavailable<bool>(error(AdapterError::PlanDecisionStale, "reviewed_tree.deletion_root_changed", ObservationState::Changed));
        auto parent = parent_for(n, false);
        if (!parent.value()) return unavailable<bool>(*parent.unavailable_detail());
        auto now = HeldChild::observe(*parent.value(), n.names.back());
        if (!now.value()) return unavailable<bool>(*now.unavailable_detail());
        if (!unchanged(n.metadata, (*now.value())->metadata()))
            return unavailable<bool>(error(AdapterError::PlanDecisionStale, "reviewed_tree.deletion_changed", ObservationState::Changed));
        if (!require_native_rename) return Observation<bool>::available(true);
        auto capability = qualify_namespace(**parent.value());
        if (!capability.value()) return capability;
        if (!*capability.value()) return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.deletion_provider", ObservationState::Unsupported));
        return Observation<bool>::available(true);
    }
    void delete_step() {
        auto& item = items[index()];
        if (!deleting) {
            const auto& n = target.nodes.at(item.row.relative_path);
            auto valid = target_guard(n);
            if (!valid.value()) { fail(*valid.unavailable_detail()); return; }
            auto parent = parent_for(n, false);
            if (!parent.value()) { fail(*parent.unavailable_detail()); return; }
            auto id = request.journal_id;
            for (unsigned i = 0; i < 8; ++i) id.bytes[8 + i] = std::byte((item.row.id >> (8 * i)) & 255);
            constexpr char hex[] = "0123456789abcdef";
            std::string text = ".ck-reviewed-delete-";
            for (auto byte : id.bytes) { auto v = std::to_integer<unsigned>(byte); text += hex[v >> 4]; text += hex[v & 15]; }
            auto journal_name = n.names.back().posix_bytes() ? NativeName::from_posix(text) : NativeName::from_windows(std::u16string(text.begin(), text.end()));
            item.journal_id = id; item.journal_name = journal_name; item.recovery_required = true;
            auto file = request.open_journal(*request.journal_root, *journal_name, true);
            if (!file.value()) { fail(*file.unavailable_detail(), true); return; }
            auto journal = OperationJournal::create(FileOperation::Delete, id, request.copy_policy.journal_limits);
            if (!journal.value()) { fail(*journal.unavailable_detail(), true); return; }
            auto parent_id = NativeDurableIdentity::from_live(*(*parent.value())->identity().value());
            auto object_id = NativeDurableIdentity::from_live(*n.metadata.identity.value());
            if (!parent_id || !object_id) { fail(error(AdapterError::UnqualifiedIdentity, "reviewed_tree.deletion_identity"), true); return; }
            auto evidence = encode_native_delete_recovery_evidence({n.names.back(), *parent_id, *object_id});
            if (!evidence.value()) { fail(*evidence.unavailable_detail(), true); return; }
            deleting.emplace(Deletion{n, *parent.value(), *journal.value(),
                std::shared_ptr<OperationJournalFile>(std::move(file).take_value()), std::move(evidence).take_value(), 0});
            progress.recovery_required = true;
            return;
        }
        auto& d = *deleting;
        auto append = [&](OperationJournalState state) {
            auto written = append_operation_journal_file(*d.file, *d.journal,
                {d.journal->records().size() + 1, 0, state, d.evidence});
            if (!written.value()) { fail(*written.unavailable_detail(), true); return false; }
            ++d.phase; return true;
        };
        switch (d.phase) {
        case 0: append(OperationJournalState::Planned); return;
        case 1: append(OperationJournalState::Prepared); return;
        case 2: {
            auto valid = target_guard(d.node);
            if (!valid.value()) { fail(*valid.unavailable_detail(), true); return; }
            append(OperationJournalState::SourceRemovalIntended); return;
        }
        case 3: {
            auto valid = target_guard(d.node);
            if (!valid.value()) { fail(*valid.unavailable_detail(), true); return; }
            auto retired = d.parent->retire_child(d.node.names.back(), *d.node.metadata.identity.value());
            if (!retired.value() || !*retired.value()) {
                fail(retired.value() ? error(AdapterError::InvalidNativeResult, "reviewed_tree.retire_false") : *retired.unavailable_detail(), true); return;
            }
            mutated = true; progress.partial = true;
            target.nodes.erase(item.row.relative_path);
            // Windows disposition may remain pending until all our duplicate
            // child/directory handles are retired. No borrowed owner escapes.
            d.node.held.reset(); d.node.directory.reset();
            ++d.phase; return;
        }
        case 4: {
            auto missing = d.parent->lookup_child(d.node.names.back(), ChildLookupMode::NativeDefault);
            if (!missing.value() || missing.value()->state() != ChildLookupState::Missing) {
                fail(error(AdapterError::PlanDecisionStale, "reviewed_tree.retirement_not_confirmed", ObservationState::Unknown), true); return;
            }
            refresh_target_ancestors(d.node);
            if (progress.state == ReviewedTreeState::Executing) append(OperationJournalState::SourceRetired);
            return;
        }
        case 5: append(OperationJournalState::Complete); return;
        default:
            deleting.reset(); progress.recovery_required = false; item.recovery_required = false; finish_item(); return;
        }
    }
    void execute_step(std::stop_token stop) {
        if (current == items.size()) {
            // Even a plan containing only skips/reports must finish with a
            // fresh whole-tree check against the exact reviewed evidence.
            progress.state = ReviewedTreeState::Revalidating; reset_topology(); start_scan(0); return;
        }
        auto& item = items[index()]; progress.current_row = item.row.id;
        if (item.action == ReviewedTreeAction::Skip || item.action == ReviewedTreeAction::Report || item.action == ReviewedTreeAction::MergeDirectory) {
            item.state = item.action == ReviewedTreeAction::Skip ? ReviewedTreeItemState::Skipped : ReviewedTreeItemState::Complete;
            if (item.action == ReviewedTreeAction::Skip) ++progress.skipped_items; else ++progress.completed_items;
            ++current; return;
        }
        if (removal(item.action)) { delete_step(); return; }
        const auto& n = source.nodes.at(item.row.relative_path);
        if (retained && retained->state() == RetainedTargetState::Verifying) {
            const auto state = retained->advance(stop);
            if (state == RetainedTargetState::Failed || state == RetainedTargetState::Cancelled || state == RetainedTargetState::NeedsReconciliation)
                fail(retained->failure().value_or(error(AdapterError::InvalidNativeResult, "reviewed_tree.retention_failed")), state == RetainedTargetState::NeedsReconciliation);
            return;
        }
        if (copy) {
            // Observe the worker-owned metadata phase without advancing it;
            // hash the finalized staging object before native verify/commit.
            if (staging && metadata_phase && metadata_phase->state() == OperationMetadataState::Complete && !staging_hashed) {
                staging_step(stop); return;
            }
            auto state = copy->advance(stop);
            if (state == OperationExecutionState::Complete) {
                mutated = true; progress.partial = true;
                if (replacement_prepared && !record_retained(n)) return;
                record_created(n, false);
                if (progress.state != ReviewedTreeState::Executing) return;
                progress.copied_bytes += *n.metadata.logical_size.value();
                copy.reset(); retained.reset(); replacement_prepared = false; staging = nullptr; metadata_phase = nullptr; staging_before.reset(); staging_hashed = false; staging_offset = 0; staging_hash.reset();
                progress.recovery_required = false; items[index()].recovery_required = false;
                finish_item();
            } else if (state == OperationExecutionState::Failed || state == OperationExecutionState::Cancelled ||
                       state == OperationExecutionState::NeedsReconciliation || state == OperationExecutionState::RetainedSource) {
                fail(copy->result().failure.value_or(error(AdapterError::InvalidNativeResult, "reviewed_tree.copy_failed")), true);
            }
            return;
        }
        auto valid = guard(n);
        if (!valid.value()) { fail(*valid.unavailable_detail()); return; }
        if (item.action == ReviewedTreeAction::CreateDirectory) {
            auto parent = parent_for(n, false);
            if (!parent.value()) { fail(*parent.unavailable_detail()); return; }
            auto created = (*parent.value())->create_child_directory(n.names.back());
            if (!created.value()) { fail(*created.unavailable_detail(), true); return; }
            mutated = true; progress.partial = true;
            const auto created_identity = (*created.value())->identity();
            record_created(n, true);
            auto recorded = target.nodes.find(n.entry.relative_path);
            if (progress.state == ReviewedTreeState::Executing && (!created_identity.value() || recorded == target.nodes.end() ||
                !same(*created_identity.value(), *recorded->second.metadata.identity.value()))) {
                fail(error(AdapterError::MetadataChanged, "reviewed_tree.mkdir_substituted", ObservationState::Changed), true); return;
            }
            if (progress.state == ReviewedTreeState::Executing) finish_item();
            return;
        }
        start_copy(n, stop);
    }
};

ReviewedTreePlanJob::ReviewedTreePlanJob(std::unique_ptr<Impl> p) noexcept : impl_(std::move(p)) {}
ReviewedTreePlanJob::~ReviewedTreePlanJob() = default;
Observation<ReviewedTreePlanJob::Pointer> ReviewedTreePlanJob::create(ReviewedTreePlanRequest r) {
    if (!r.source_root || !r.destination_root || !r.source_root->parent() || !r.destination_root->parent() ||
        !qualified(r.source_root->metadata()) || !qualified(r.destination_root->metadata()) ||
        *r.source_root->metadata().kind.value() != ObjectKind::Directory || *r.destination_root->metadata().kind.value() != ObjectKind::Directory)
        return invalid<Pointer>("reviewed_tree.roots");
    for (const auto& root : {r.source_root, r.destination_root}) {
        auto parent = root->parent()->inspect_basic();
        if (!parent.value()) return unavailable<Pointer>(*parent.unavailable_detail());
        if (!parent.value()->mount_id.value() || !equal(parent.value()->mount_id, root->metadata().mount_id))
            return unavailable<Pointer>(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.mount_root", ObservationState::Unsupported));
    }
    if (compare_identity(*r.source_root->metadata().identity.value(), *r.destination_root->metadata().identity.value()) == IdentityComparison::Unknown)
        return unavailable<Pointer>(error(AdapterError::UnqualifiedIdentity, "reviewed_tree.root_namespace"));
    if (same(*r.source_root->metadata().identity.value(), *r.destination_root->metadata().identity.value()))
        return unavailable<Pointer>(error(AdapterError::PlanTopologyUnsafe, "reviewed_tree.same_root"));
    if (r.source_root->name().encoding() != r.destination_root->name().encoding())
        return unavailable<Pointer>(error(AdapterError::UnrepresentableName, "reviewed_tree.root_encoding", ObservationState::Unsupported));
    if (r.comparison.mode != ComparisonMode::CompleteDigest || r.comparison.profile == ComparisonProfile::Move)
        return unavailable<Pointer>(error(AdapterError::UnsupportedQuery, "reviewed_tree.profile_or_digest", ObservationState::Unsupported));
    if (!r.copy_policy.copy_limits.valid() || r.digest_chunk_bytes == 0 || r.digest_chunk_bytes > ContentReadLimits::hard_max_bytes ||
        r.limits.max_entries == 0 || r.limits.max_entries > ComparisonLimits::hard_max_entries ||
        r.limits.max_page_rows == 0 || r.limits.max_page_rows > ComparisonLimits::hard_max_page_rows ||
        r.limits.max_path_bytes == 0 || r.limits.max_path_bytes > ComparisonLimits::hard_max_path_bytes ||
        r.limits.max_total_path_bytes == 0 || r.limits.max_total_path_bytes > ComparisonLimits::hard_max_total_path_bytes ||
        r.comparison.filters.maximum_depth == 0 || r.comparison.filters.maximum_depth > 1024)
        return invalid<Pointer>("reviewed_tree.limits");
    return Observation<Pointer>::available(Pointer(new ReviewedTreePlanJob(std::make_unique<Impl>(std::move(r)))));
}
ReviewedTreeState ReviewedTreePlanJob::state() const noexcept { return impl_->progress.state; }
ReviewedTreeProgress ReviewedTreePlanJob::progress() const {
    auto out = impl_->progress;
    if (impl_->copy) out.copied_bytes += impl_->copy->progress().observed_bytes;
    return out;
}
ComparisonPlan::Pointer ReviewedTreePlanJob::preview() const noexcept { return impl_->plan; }
Observation<ReviewedTreePage> ReviewedTreePlanJob::page(std::size_t offset, std::size_t limit) const {
    if (!impl_->plan) return invalid<ReviewedTreePage>("reviewed_tree.preview_not_ready");
    auto p = impl_->plan->page(offset, limit);
    if (!p.value()) return unavailable<ReviewedTreePage>(*p.unavailable_detail());
    ReviewedTreePage out{impl_->plan->identity(), {}, p.value()->total_rows, p.value()->next_offset};
    for (std::size_t i = 0; i < p.value()->rows.size(); ++i) out.items.push_back(impl_->items[offset + i]);
    return Observation<ReviewedTreePage>::available(std::move(out));
}
Observation<ReviewedTreePage> ReviewedTreePlanJob::reviewed_page(const ReviewedTreeReceipt& receipt,
    std::size_t offset, std::size_t limit) const {
    if (!impl_->plan || !receipt.state_ || receipt.state_->plan != impl_->plan->identity() || receipt.state_->revision != impl_->revision)
        return invalid<ReviewedTreePage>("reviewed_tree.foreign_receipt_page");
    auto p = impl_->plan->page(offset, limit);
    if (!p.value()) return unavailable<ReviewedTreePage>(*p.unavailable_detail());
    ReviewedTreePage out{impl_->plan->identity(), {}, p.value()->total_rows, p.value()->next_offset};
    for (std::size_t i = 0; i < p.value()->rows.size(); ++i) out.items.push_back(receipt.state_->items[offset + i]);
    return Observation<ReviewedTreePage>::available(std::move(out));
}
Observation<ReviewedTreeNativeBinding> ReviewedTreePlanJob::native_binding(const ComparisonDecisionToken& token) const {
    if (impl_->mutated) return unavailable<ReviewedTreeNativeBinding>(error(AdapterError::PlanDecisionStale, "reviewed_tree.native_binding_after_mutation", ObservationState::Changed));
    if (!impl_->plan || !token.is_valid() || token.plan_identity() != impl_->plan->identity() ||
        token.row_id() > impl_->items.size()) return invalid<ReviewedTreeNativeBinding>("reviewed_tree.native_binding_token");
    const auto& item = impl_->items[token.row_id() - 1];
    if (item.row.token != token) return invalid<ReviewedTreeNativeBinding>("reviewed_tree.native_binding_row");
    ReviewedTreeNativeBinding out; out.token = token;
    auto source = impl_->source.nodes.find(item.row.relative_path), target = impl_->target.nodes.find(item.row.relative_path);
    if (source != impl_->source.nodes.end()) {
        out.source = source->second.held; out.source_parent = source->second.held->parent();
        out.relative_components = source->second.names;
        if (source->second.entry.digest) out.source_digest = source->second.entry.digest->bytes;
    }
    if (target != impl_->target.nodes.end()) {
        out.destination = target->second.held; out.destination_parent = target->second.held->parent();
        out.relative_components = target->second.names;
        if (target->second.entry.digest) out.destination_digest = target->second.entry.digest->bytes;
    } else if (source != impl_->source.nodes.end()) {
        auto parent = impl_->parent_for(source->second, false);
        if (!parent.value()) return unavailable<ReviewedTreeNativeBinding>(*parent.unavailable_detail());
        out.destination_parent = *parent.value();
    }
    return Observation<ReviewedTreeNativeBinding>::available(std::move(out));
}
Observation<std::vector<NativeName>> ReviewedTreePlanJob::native_components(std::uint64_t id, bool incoming) const {
    if (!impl_->plan || !id || id > impl_->items.size()) return invalid<std::vector<NativeName>>("reviewed_tree.native_components_row");
    const auto& item = impl_->items[id - 1];
    if (!(incoming ? item.row.source_index : item.row.destination_index))
        return unavailable<std::vector<NativeName>>(error(AdapterError::NotApplicable, "reviewed_tree.native_components_absent", ObservationState::Gone));
    return Observation<std::vector<NativeName>>::available(item.relative_components);
}
Observation<ReviewedTreeDeletionReceipt> ReviewedTreePlanJob::review_deletions(std::span<const ComparisonDecisionToken> rows) const {
    if (state() != ReviewedTreeState::AwaitingReview) return invalid<ReviewedTreeDeletionReceipt>("reviewed_tree.review_state");
    std::vector<ComparisonDecisionToken> expected;
    for (const auto& item : impl_->items) if (removal(item.action)) expected.push_back(item.row.token);
    if (rows.size() != expected.size()) return invalid<ReviewedTreeDeletionReceipt>("reviewed_tree.deletion_set");
    std::set<std::uint64_t> ids;
    for (const auto& row : rows) if (std::find(expected.begin(), expected.end(), row) == expected.end() || !ids.insert(row.row_id()).second)
        return invalid<ReviewedTreeDeletionReceipt>("reviewed_tree.deletion_token");
    ReviewedTreeDeletionReceipt out;
    out.state_ = std::make_shared<const ReviewedTreeDeletionState>(ReviewedTreeDeletionState{impl_->plan->identity(), std::move(expected)});
    return Observation<ReviewedTreeDeletionReceipt>::available(std::move(out));
}
Observation<ReviewedTreePage> ReviewedTreePlanJob::assess_rules(std::span<const ConflictRule> rules,
    std::size_t offset, std::size_t limit) const {
    return assess_rules(rules,{},offset,limit);
}
Observation<ReviewedTreePage> ReviewedTreePlanJob::assess_rules(std::span<const ConflictRule> rules,
    std::span<const ReviewedTreeNameChoice> names, std::size_t offset, std::size_t limit) const {
    if (state() != ReviewedTreeState::AwaitingReview || rules.size() > 100'000 || names.size() > impl_->items.size())
        return invalid<ReviewedTreePage>("reviewed_tree.assessment_state_or_limit");
    impl_->assessment(rules,names);
    return assessment_page(offset,limit);
}
Observation<ReviewedTreePage> ReviewedTreePlanJob::assessment_page(std::size_t offset,std::size_t limit) const {
    if (!impl_->plan || !impl_->last_assessment) return invalid<ReviewedTreePage>("reviewed_tree.assessment_not_ready");
    auto p = impl_->plan->page(offset, limit);
    if (!p.value()) return unavailable<ReviewedTreePage>(*p.unavailable_detail());
    ReviewedTreePage out{impl_->plan->identity(), {}, p.value()->total_rows, p.value()->next_offset};
    for (std::size_t i = 0; i < p.value()->rows.size(); ++i) out.items.push_back((*impl_->last_assessment)[offset + i]);
    return Observation<ReviewedTreePage>::available(std::move(out));
}
Observation<ReviewedTreeReceipt> ReviewedTreePlanJob::review(std::span<const ConflictRule> rules, const ReviewedTreeDeletionReceipt& deletion) const {
    return review(rules,{},deletion);
}
Observation<ReviewedTreeReceipt> ReviewedTreePlanJob::review(std::span<const ConflictRule> rules,
    std::span<const ReviewedTreeNameChoice> names,const ReviewedTreeDeletionReceipt& deletion) const {
    if (state() != ReviewedTreeState::AwaitingReview || rules.size() > 100'000 || names.size() > impl_->items.size())
        return invalid<ReviewedTreeReceipt>("reviewed_tree.review_state_or_limit");
    impl_->revision = std::make_shared<const unsigned char>(0); // every review supersedes older receipts, even on rejection
    if (deletion.state_ && deletion.state_->plan != impl_->plan->identity()) return invalid<ReviewedTreeReceipt>("reviewed_tree.foreign_deletion_receipt");
    if (!rules.empty() && impl_->items.empty()) return invalid<ReviewedTreeReceipt>("reviewed_tree.rules_without_rows");
    const auto& resolved = impl_->assessment(rules,names);
    for (const auto& item : resolved) {
        if (removal(item.action) && !deletion.state_) return invalid<ReviewedTreeReceipt>("reviewed_tree.deletion_receipt_required");
        if (item.decision && item.decision->state != ConflictRuleState::Apply && item.decision->state != ConflictRuleState::NoMatch)
            return unavailable<ReviewedTreeReceipt>(error(AdapterError::ProviderReviewRequired, "reviewed_tree.unresolved_choice", ObservationState::Unsupported));
    }
    ReviewedTreeReceipt out;
    out.state_ = std::make_shared<const ReviewedTreeReceiptState>(ReviewedTreeReceiptState{impl_->plan->identity(), resolved, deletion.state_, impl_->revision});
    return Observation<ReviewedTreeReceipt>::available(std::move(out));
}
Observation<bool> ReviewedTreePlanJob::begin_execution(const ReviewedTreeReceipt& receipt) {
    if (state() != ReviewedTreeState::AwaitingReview || !receipt.state_ || receipt.state_->plan != impl_->plan->identity() || receipt.state_->revision != impl_->revision)
        return unavailable<bool>(error(AdapterError::PlanDecisionStale, "reviewed_tree.receipt", ObservationState::Changed));
    for (const auto& item : receipt.state_->items) {
        if (item.action == ReviewedTreeAction::Replace) {
            const auto s = impl_->source.nodes.find(item.row.relative_path), d = impl_->target.nodes.find(item.row.relative_path);
            if (s == impl_->source.nodes.end() || d == impl_->target.nodes.end() || !s->second.entry.digest || !d->second.entry.digest ||
                *s->second.metadata.kind.value() != ObjectKind::RegularFile || *d->second.metadata.kind.value() != ObjectKind::RegularFile)
                return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.replacement_kind", ObservationState::Unsupported));
            const auto qualified = qualify_namespace(*d->second.held->parent());
            if (!qualified.value()) return qualified;
            if (!*qualified.value()) return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.retention_unqualified", ObservationState::Unsupported));
        }
        if (removal(item.action)) {
            auto binding = native_binding(item.row.token);
            if (!binding.value()) return unavailable<bool>(*binding.unavailable_detail());
            auto capability = qualify_namespace(*binding.value()->destination_parent);
            if (!capability.value()) return capability;
            if (!*capability.value()) return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.identity_bound_deletion_unavailable", ObservationState::Unsupported));
        }
        if ((item.action == ReviewedTreeAction::CreateDirectory && !impl_->request.copy_policy.allow_unhandled_metadata_loss) ||
            (mutation(item.action) && (!impl_->request.journal_root || !impl_->request.open_journal)))
            return unavailable<bool>(error(AdapterError::UnsupportedQuery, "reviewed_tree.tree_metadata_or_journal_contract", ObservationState::Unsupported));
    }
    auto names = impl_->qualify_new_names(receipt.state_->items);
    if (!names.value()) return names;
    impl_->receipt = receipt.state_; impl_->items = receipt.state_->items;
    for (std::size_t i = 0; i < impl_->items.size(); ++i) if (!removal(impl_->items[i].action)) impl_->order.push_back(i);
    // Children sort after their parent. Reverse order retires files and empty
    // directories only after their explicitly reviewed descendants.
    for (std::size_t i = impl_->items.size(); i; --i) if (removal(impl_->items[i - 1].action)) impl_->order.push_back(i - 1);
    impl_->progress.known_copy_bytes = 0;
    for (const auto& item : impl_->items) if (item.action == ReviewedTreeAction::Copy || item.action == ReviewedTreeAction::Replace)
        impl_->progress.known_copy_bytes += *impl_->source.nodes.at(item.row.relative_path).metadata.logical_size.value();
    impl_->progress.state = ReviewedTreeState::Revalidating;
    impl_->reset_topology(); impl_->start_scan(0);
    return Observation<bool>::available(true);
}
ReviewedTreeState ReviewedTreePlanJob::advance(std::stop_token stop) {
    auto& p = *impl_;
    const auto state = p.progress.state;
    if (state >= ReviewedTreeState::Complete || (state == ReviewedTreeState::AwaitingReview && !stop.stop_requested())) return state;
    if (stop.stop_requested()) {
        auto copy_state = p.copy ? p.copy->advance(stop) : OperationExecutionState::Cancelled;
        const bool ambiguous = copy_state == OperationExecutionState::NeedsReconciliation || copy_state == OperationExecutionState::Complete ||
            (p.deleting && p.deleting->phase >= 3);
        p.progress.state = ambiguous ? ReviewedTreeState::NeedsReconciliation : p.mutated ? ReviewedTreeState::Partial : ReviewedTreeState::Cancelled;
        p.progress.partial = p.mutated;
        p.progress.recovery_required = p.progress.recovery_required || p.mutated;
        if (p.current < p.items.size()) {
            p.items[p.index()].state = ambiguous ? ReviewedTreeItemState::NeedsReconciliation : ReviewedTreeItemState::Cancelled;
            p.items[p.index()].recovery_required = p.progress.recovery_required;
        }
        return p.progress.state;
    }
    if (!p.topology_done) p.topology_step();
    else if (state == ReviewedTreeState::Inventory || state == ReviewedTreeState::Revalidating) p.scan_step(stop);
    else p.execute_step(stop);
    return p.progress.state;
}
} // namespace ck::files
