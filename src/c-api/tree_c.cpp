// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_fs_tree.h"
#include "native_handles.hpp"
#include "reviewed_tree_plan.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <thread>

using namespace ck::files;
namespace {
static_assert(static_cast<std::uint32_t>(ReviewedTreeState::NeedsReconciliation) == CKFET_NEEDS_RECONCILIATION);
static_assert(static_cast<std::uint32_t>(ReviewedTreeAction::RemoveDirectory) == CKFET_REMOVE_DIRECTORY);
static_assert(static_cast<std::uint32_t>(ConflictChoice::DeleteEdited) == CKFET_DELETE_EDITED);
static_assert(static_cast<std::uint32_t>(ConflictRuleReason::RetryNotQualified) == CKFET_RULE_RETRY_UNQUALIFIED);
static_assert(static_cast<std::uint32_t>(MetadataOwnership::Original) == CKFE_OWNERSHIP_ORIGINAL);
static_assert(static_cast<std::uint32_t>(MetadataOwnership::CurrentCaller) == CKFE_OWNERSHIP_CURRENT_CALLER);
std::atomic<std::uint64_t> generation_ids{1}, receipt_ids{1};
std::atomic<unsigned> active_workers{0};
struct WorkerSlot {
    bool held = false;
    bool acquire() noexcept {
        auto count = active_workers.load(std::memory_order_relaxed);
        while (count < CKFET_MAX_JOBS) {
            if (active_workers.compare_exchange_weak(count,count + 1,std::memory_order_relaxed)) { held = true; return true; }
        }
        return false;
    }
    ~WorkerSlot() { if (held) active_workers.fetch_sub(1,std::memory_order_relaxed); }
};
std::uint64_t next_id(std::atomic<std::uint64_t>& ids) {
    auto id = ids.load(std::memory_order_relaxed);
    for (;;) {
        if (!id || id == UINT64_MAX) throw std::overflow_error("native tree IDs exhausted");
        if (ids.compare_exchange_weak(id,id + 1,std::memory_order_relaxed)) return id;
    }
}
void require(bool b) { if (!b) throw std::invalid_argument("native tree argument"); }
template<class F> ckfe_api_status boundary(F&& f) noexcept {
    try { return f(); } catch (const std::bad_alloc&) { return CKFE_API_OUT_OF_MEMORY; }
    catch (const std::invalid_argument&) { return CKFE_API_INVALID_ARGUMENT; }
    catch (...) { return CKFE_API_EXCEPTION; }
}
void clear(ckfe_error* e) { if (e) ckfe_error_free(e); }
UnavailableObservation invalid(const char* op) {
    return {ObservationState::Changed, {ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::PlanDecisionStale), op}};
}
NativeAbsolutePath path(const ckfet_native& p) {
    require(p.reserved == 0 && p.data && p.units && p.units <= NativePathLimits::hard_native_bytes && p.encoding <= 1);
    if (p.encoding == CKFET_POSIX_BYTES) {
        auto value = NativeAbsolutePath::from_posix({static_cast<const char*>(p.data), static_cast<std::size_t>(p.units)});
        require(value.value()); return std::move(value).take_value();
    }
    require(p.units <= NativePathLimits::hard_native_bytes / 2);
    // memcpy avoids alignment and char16_t aliasing assumptions at the C ABI.
    std::u16string units(static_cast<std::size_t>(p.units), u'\0');
    std::memcpy(units.data(), p.data, units.size() * sizeof(char16_t));
    auto value = NativeAbsolutePath::from_windows(units);
    require(value.value()); return std::move(value).take_value();
}
ComparisonLimits limits(const ckfsp_limits& l) {
    require(l.max_entries && l.max_entries <= ComparisonLimits::hard_max_entries &&
        l.max_path_bytes && l.max_path_bytes <= ComparisonLimits::hard_max_path_bytes &&
        l.max_total_path_bytes && l.max_total_path_bytes <= ComparisonLimits::hard_max_total_path_bytes &&
        l.max_exclusions <= ComparisonLimits::hard_max_exclusions && l.max_page_rows &&
        l.max_page_rows <= ComparisonLimits::hard_max_page_rows);
    return {static_cast<std::size_t>(l.max_entries), static_cast<std::size_t>(l.max_path_bytes),
        static_cast<std::size_t>(l.max_total_path_bytes), static_cast<std::size_t>(l.max_exclusions),
        static_cast<std::size_t>(l.max_page_rows), l.max_aggregate_bytes};
}
ComparisonFilters filters(const ckfsp_filters& f) {
    require(f.has_minimum_size <= 1 && f.has_maximum_size <= 1 && f.has_modified_not_before <= 1 &&
        f.has_modified_before <= 1 && !f.modified_not_before.reserved && !f.modified_before.reserved &&
        f.maximum_depth <= std::numeric_limits<std::size_t>::max());
    ComparisonFilters r;
    if (f.has_minimum_size) r.minimum_size = f.minimum_size;
    if (f.has_maximum_size) r.maximum_size = f.maximum_size;
    auto stamp = [](const ckfsp_timestamp& t) { auto v = FileTimestamp::from_unix(t.seconds, t.nanoseconds); require(v.has_value()); return *v; };
    if (f.has_modified_not_before) r.modified_not_before = stamp(f.modified_not_before);
    if (f.has_modified_before) r.modified_before = stamp(f.modified_before);
    r.allowed_kind_mask = f.allowed_kind_mask;
    r.maximum_depth = static_cast<std::size_t>(f.maximum_depth);
    return r;
}
struct Command {
    enum Kind { Review, Execute } kind = Review;
    std::uint64_t id = 0, generation = 0, receipt = 0;
    std::vector<ConflictRule> rules;
    std::vector<std::uint64_t> deletions;
    struct Name { std::uint64_t row; NativeName name; ReviewedTreeNameSide side; };
    std::vector<Name> names;
};
struct CachedRow {
    ckfet_row_v1 value{};
    std::string key;
    std::vector<NativeName> components;
    std::optional<NativeName> journal, staging, retained, proposed, resulting;
};
struct Shared {
    mutable std::mutex mutex;
    std::condition_variable cv;
    std::stop_source stop;
    bool paused = false, terminal = false, worker_drained = false;
    std::uint64_t next_command = 1;
    std::optional<Command> command;
    ckfet_snapshot_v1 snapshot = [] {
        ckfet_snapshot_v1 s{}; s.version = CKFET_VERSION; s.struct_size = sizeof(s); s.state = CKFET_INVENTORY; return s;
    }();
    std::array<ckfet_snapshot_v1, 64> events{};
    std::size_t event_head = 0, event_count = 0;
    std::uint64_t coalesced = 0;
    std::vector<CachedRow> rows;
    std::vector<ckfet_rule_counts_v1> rule_counts;
    std::size_t page_limit = 256;
    std::optional<UnavailableObservation> failure;
    void publish() noexcept {
        ++snapshot.sequence;
        if (event_count == events.size()) {
            event_head = (event_head + 1) % events.size(); --event_count; ++coalesced;
        }
        events[(event_head + event_count) % events.size()] = snapshot;
        ++event_count;
    }
    void set_failure(const UnavailableObservation& f) {
        failure = f;
        snapshot.failure_state = static_cast<std::uint32_t>(f.state);
        snapshot.failure_domain = static_cast<std::uint32_t>(f.error.domain);
        snapshot.failure_code = f.error.code;
    }
    void clear_failure() noexcept {
        failure.reset(); snapshot.failure_state = snapshot.failure_domain = 0; snapshot.failure_code = 0;
    }
};
bool terminal(ReviewedTreeState s) { return s >= ReviewedTreeState::Complete; }
ckfet_observed_v1 observed(const std::vector<ComparisonEntry>& entries, std::optional<std::size_t> index) {
    ckfet_observed_v1 r{};
    r.metadata_assessment = CKFE_OBSERVATION_UNKNOWN;
    if (!index) { r.presence = CKFET_PRESENCE_ABSENT; return r; }
    const auto& o = entries.at(*index).object;
    r.presence = o.state == ComparisonObjectState::Stable ? CKFET_PRESENCE_PRESENT : CKFET_PRESENCE_UNKNOWN;
    if (o.kind) { r.known_fields |= CKFSP_FIELD_KIND; r.kind = static_cast<std::uint32_t>(*o.kind); }
    if (o.size) { r.known_fields |= CKFSP_FIELD_SIZE; r.size = *o.size; }
    if (o.modified) {
        r.known_fields |= CKFSP_FIELD_MODIFIED;
        r.modified = {o.modified->seconds(),o.modified->nanoseconds(),0};
    }
    r.timestamp_quantum_ns = o.timestamp_quantum_ns;
    return r;
}
CachedRow row(const ReviewedTreeItem& item, const ComparisonPlan& plan) {
    CachedRow result;
    auto& r = result.value;
    r.source = observed(plan.source_entries(),item.row.source_index);
    r.destination = observed(plan.destination_entries(),item.row.destination_index);
    r.row_id = item.row.id;
    result.key = item.row.relative_path;
    result.components = item.relative_components;
    result.journal = item.journal_name; result.staging = item.staging_name;
    result.retained = item.retained_name; result.proposed = item.proposed_name; result.resulting = item.resulting_name;
    r.allowed_choices = item.facts.allowed_choices;
    r.conflict_class = static_cast<std::uint32_t>(item.facts.conflict_class);
    r.retention_available = item.facts.retained_target_available; r.target_retained = item.target_retained;
    r.has_name_side = item.name_side.has_value(); r.name_side = static_cast<std::uint32_t>(item.name_side.value_or(ReviewedTreeNameSide::Incoming));
    if (item.retention_journal_id) { r.has_retention_journal = 1; std::memcpy(r.retention_journal_id,item.retention_journal_id->bytes.data(),16); }
    r.component_count = result.components.size();
    r.recovery_required = item.recovery_required;
    if (item.journal_id) {
        r.has_journal = 1;
        std::memcpy(r.journal_id,item.journal_id->bytes.data(),16);
    }
    r.key_bytes = result.key.size();
    r.relation = static_cast<std::uint32_t>(item.row.relation);
    r.reason = static_cast<std::uint32_t>(item.row.reason);
    r.proposed_action = static_cast<std::uint32_t>(item.row.action);
    r.action = static_cast<std::uint32_t>(item.action);
    r.state = static_cast<std::uint32_t>(item.state);
    if (item.decision) {
        r.has_decision = 1;
        r.decision_state = static_cast<std::uint32_t>(item.decision->state);
        r.decision_choice = static_cast<std::uint32_t>(item.decision->choice);
        r.decision_reason = static_cast<std::uint32_t>(item.decision->reason);
        r.decision_fallback = item.decision->used_fallback;
        r.retain_replaced = item.decision->retain_replaced;
        r.has_rule_index = item.decision->rule_index.has_value();
        r.rule_index = item.decision->rule_index.value_or(0);
    }
    if (item.failure) {
        r.failure_state = static_cast<std::uint32_t>(item.failure->state);
        r.failure_domain = static_cast<std::uint32_t>(item.failure->error.domain);
        r.failure_code = item.failure->error.code;
    }
    return result;
}
void refresh_rows(Shared& s, const ReviewedTreePlanJob& job, const ReviewedTreeReceipt* receipt = nullptr,
    bool assessment = false, std::optional<std::size_t> rules = {}) {
    if (!job.preview()) return;
    std::vector<CachedRow> rows;
    for (std::size_t offset = 0;;) {
        auto p = receipt ? job.reviewed_page(*receipt,offset,s.page_limit) :
            assessment ? job.assessment_page(offset,s.page_limit) : job.page(offset,s.page_limit);
        if (!p.value()) throw std::logic_error("native tree page unavailable");
        for (const auto& item : p.value()->items) rows.push_back(row(item,*job.preview()));
        if (!p.value()->next_offset) break;
        offset = *p.value()->next_offset;
    }
    std::size_t rule_count = 0;
    { std::lock_guard lock(s.mutex); rule_count = rules.value_or(s.rule_counts.size()); }
    std::vector<ckfet_rule_counts_v1> counts(rule_count);
    std::uint64_t unresolved = 0;
    for (const auto& row : rows) {
        const auto& r = row.value;
        const bool needs_review = r.has_decision && r.decision_state != CKFET_DECISION_APPLY && r.decision_state != CKFET_DECISION_NO_MATCH;
        unresolved += needs_review;
        if (!r.has_rule_index || r.rule_index >= counts.size()) continue;
        auto& c = counts[r.rule_index]; ++c.matched_rows;
        c.applied_rows += r.decision_state == CKFET_DECISION_APPLY;
        c.unresolved_rows += needs_review; c.skipped_rows += r.action == CKFET_SKIP;
        c.copy_rows += r.action == CKFET_COPY; c.replacement_rows += r.action == CKFET_REPLACE;
        c.protected_zero_length_rows += r.decision_reason == CKFET_RULE_ZERO_LENGTH;
        c.retention_rows += r.retain_replaced;
    }
    {
        std::lock_guard lock(s.mutex); s.rows.swap(rows); s.rule_counts.swap(counts);
        s.snapshot.rule_count = rule_count; s.snapshot.unresolved_rows = unresolved;
    }
}
void progress(Shared& s, const ReviewedTreePlanJob& job) {
    const auto p = job.progress();
    std::optional<CachedRow> current;
    if (p.current_row && *p.current_row) {
        const auto page = job.page(static_cast<std::size_t>(*p.current_row - 1), 1);
        if (page.value() && !page.value()->items.empty()) current = row(page.value()->items.front(),*job.preview());
    }
    std::lock_guard lock(s.mutex);
    auto& r = s.snapshot;
    r.state = static_cast<std::uint32_t>(p.state);
    r.known_items = p.known_items; r.completed_items = p.completed_items;
    r.skipped_items = p.skipped_items; r.failed_items = p.failed_items;
    r.known_copy_bytes = p.known_copy_bytes; r.copied_bytes = p.copied_bytes;
    r.counts_complete = p.counts_complete; r.partial = p.partial; r.recovery_required = p.recovery_required;
    r.has_current_row = p.current_row.has_value(); r.current_row = p.current_row.value_or(0);
    if (current && current->value.row_id <= s.rows.size()) s.rows[current->value.row_id - 1] = std::move(*current);
    if (p.failure) s.set_failure(*p.failure);
    s.terminal = terminal(p.state);
    s.publish();
}
void worker_body(std::shared_ptr<Shared> s, ReviewedTreePlanRequest request) noexcept {
    try {
        auto prepared = prepare_native_operation_journal_root(*request.journal_root);
        if (!prepared.value()) {
            std::lock_guard lock(s->mutex); s->set_failure(*prepared.unavailable_detail());
            s->snapshot.state = CKFET_FAILED; s->terminal = true; s->publish(); return;
        }
        auto made = ReviewedTreePlanJob::create(std::move(request));
        if (!made.value()) {
            std::lock_guard lock(s->mutex); s->set_failure(*made.unavailable_detail());
            s->snapshot.state = CKFET_FAILED; s->terminal = true; s->publish(); return;
        }
        auto job = std::move(made).take_value();
        std::optional<ReviewedTreeReceipt> receipt;
        std::uint64_t generation = 0, receipt_id = 0;
        bool captured = false;
        for (;;) {
            std::optional<Command> command;
            {
                std::unique_lock lock(s->mutex);
                const bool paused = s->paused && !s->stop.stop_requested();
                if (s->snapshot.paused != paused) { s->snapshot.paused = paused; s->publish(); }
                s->cv.wait(lock, [&] { return s->stop.stop_requested() ||
                    (!s->paused && (job->state() != ReviewedTreeState::AwaitingReview || s->command.has_value())); });
                if (s->command) { command = std::move(s->command); s->command.reset(); }
                if (s->snapshot.paused) { s->snapshot.paused = 0; s->publish(); }
            }
            if (command) {
                Observation<bool> accepted;
                bool assessed = false;
                if (command->generation != generation || job->state() != ReviewedTreeState::AwaitingReview)
                    accepted = Observation<bool>::unavailable(invalid("tree.command_generation").state, invalid("tree.command_generation").error);
                else if (command->kind == Command::Review) {
                    receipt.reset(); receipt_id = 0;
                    std::vector<ComparisonDecisionToken> deletions;
                    const auto preview = job->preview();
                    bool valid_deletions = true;
                    for (const auto id : command->deletions) {
                        if (!id || id > s->rows.size()) { valid_deletions = false; break; }
                        const auto p = job->page(static_cast<std::size_t>(id - 1), 1);
                        if (!p.value() || p.value()->items.empty()) { valid_deletions = false; break; }
                        deletions.push_back(p.value()->items.front().row.token);
                    }
                    if (!valid_deletions) {
                        const auto failure = invalid("tree.deletion_rows");
                        accepted = Observation<bool>::unavailable(failure.state, failure.error);
                    } else {
                    auto deletion = job->review_deletions(deletions);
                    if (!deletion.value()) accepted = Observation<bool>::unavailable(deletion.state(), deletion.unavailable_detail()->error);
                    else {
                        for (auto& r : command->rules) r.plan = preview->identity();
                        std::vector<ReviewedTreeNameChoice> names;
                        for (auto& n : command->names) {
                            const auto p = job->page(static_cast<std::size_t>(n.row - 1),1);
                            if (!p.value() || p.value()->items.empty()) throw std::logic_error("tree native name row missing");
                            names.push_back({p.value()->items.front().row.token,std::move(n.name),n.side});
                        }
                        auto reviewed = job->review(command->rules,names,*deletion.value());
                        assessed = true;
                        if (reviewed.value()) {
                            receipt = std::move(reviewed).take_value();
                            receipt_id = next_id(receipt_ids);
                            accepted = Observation<bool>::available(true);
                        } else accepted = Observation<bool>::unavailable(reviewed.state(), reviewed.unavailable_detail()->error);
                    }
                    }
                } else if (!receipt || command->receipt != receipt_id)
                    accepted = Observation<bool>::unavailable(invalid("tree.receipt").state, invalid("tree.receipt").error);
                else accepted = job->begin_execution(*receipt);
                refresh_rows(*s,*job,receipt ? &*receipt : nullptr,assessed,
                    command->kind == Command::Review ? std::optional<std::size_t>(assessed ? command->rules.size() : 0) : std::nullopt);
                std::lock_guard lock(s->mutex);
                s->snapshot.command_id = command->id;
                s->snapshot.command_state = accepted.value() ? CKFET_COMMAND_ACCEPTED : CKFET_COMMAND_REJECTED;
                s->snapshot.receipt_id = receipt_id;
                if (!accepted.value()) s->set_failure(*accepted.unavailable_detail());
                else s->clear_failure();
                s->publish();
            }
            if (s->stop.stop_requested() || job->state() != ReviewedTreeState::AwaitingReview)
                job->advance(s->stop.get_token());
            if (!captured && job->state() == ReviewedTreeState::AwaitingReview) {
                generation = next_id(generation_ids);
                captured = true;
                const auto assessed = job->assess_rules({},0,s->page_limit);
                if (!assessed.value()) throw std::logic_error("tree initial assessment unavailable");
                refresh_rows(*s,*job,nullptr,true);
                std::lock_guard lock(s->mutex); s->snapshot.plan_generation = generation;
            }
            if (terminal(job->state())) refresh_rows(*s, *job);
            progress(*s, *job);
            if (terminal(job->state())) break;
        }
    } catch (...) {
        // No allocation in the emergency terminal path. Native resources remain
        // owned by this worker while unwinding, never by the releasing UI.
        std::lock_guard lock(s->mutex);
        s->snapshot.state = CKFET_NEEDS_RECONCILIATION; s->snapshot.recovery_required = 1;
        s->snapshot.failure_state = CKFE_OBSERVATION_FAILED;
        s->snapshot.failure_domain = CKFE_ERROR_ADAPTER;
        s->snapshot.failure_code = CKFE_ADAPTER_INVALID_NATIVE_RESULT;
        s->terminal = true;
        s->snapshot.paused = 0;
        s->publish();
    }
}
void worker(std::shared_ptr<Shared> s, std::optional<ReviewedTreePlanRequest> request,
    std::unique_ptr<WorkerSlot> slot) noexcept {
    worker_body(s, std::move(*request));
    // The body's job, receipt, journal and native owners have been destroyed.
    // Clear even moved-from request owners and release admission before telling
    // a helper process that it may exit. No native work follows this point.
    request.reset();
    slot.reset();
    std::lock_guard lock(s->mutex);
    s->worker_drained = true;
}
}
struct ckfet_job { std::shared_ptr<Shared> state; };

extern "C" {
void ckfet_options_init_v1(ckfet_options_v1* o) {
    if (!o) return;
    *o = {}; o->version = CKFET_VERSION; o->struct_size = sizeof(*o);
    o->profile = CKFSP_COMPARE; o->metadata_scope = CKFE_METADATA_COMPLETE_V1; o->timestamp_quantum_ns = 1;
    const ComparisonLimits l;
    o->limits = {l.max_entries, l.max_path_bytes, l.max_total_path_bytes, l.max_exclusions, l.max_page_rows, l.max_aggregate_bytes};
    o->filters.allowed_kind_mask = CKFSP_ALL_KINDS; o->filters.maximum_depth = 1024;
}
ckfe_api_status ckfet_start_v1(const ckfe_entry* src, const ckfe_entry* dst,
    const ckfet_options_v1* o, ckfet_job** out, ckfe_error* e) {
    if (out) *out = nullptr; clear(e);
    return boundary([&] {
        require(out && src && src->child && dst && dst->child && o && o->version == CKFET_VERSION &&
            o->struct_size == sizeof(*o) && o->profile <= CKFSP_COMPARE && o->metadata_scope <= 1 &&
            o->allow_metadata_loss <= 1 && !o->reserved && o->metadata_ownership <= 1 && o->allow_privilege_metadata <= 1 &&
            std::any_of(std::begin(o->operation_id), std::end(o->operation_id), [](auto b) { return b != 0; }));
        ReviewedTreePlanRequest r;
        r.source_root = src->child; r.destination_root = dst->child;
        r.destination_address = dst->address;
        r.comparison.profile = static_cast<ComparisonProfile>(o->profile);
        r.comparison.mode = ComparisonMode::CompleteDigest;
        r.comparison.timestamp_quantum_ns = o->timestamp_quantum_ns;
        r.comparison.filters = filters(o->filters); r.limits = limits(o->limits);
        r.copy_policy.metadata_scope = static_cast<RegularMetadataScope>(o->metadata_scope);
        r.copy_policy.allow_unhandled_metadata_loss = o->allow_metadata_loss;
        MetadataReplayPolicy metadata;
        metadata.scope = r.copy_policy.metadata_scope;
        metadata.ownership = static_cast<MetadataOwnership>(o->metadata_ownership);
        metadata.allow_privilege_metadata = o->allow_privilege_metadata;
        r.copy_policy.metadata_policy = metadata;
        r.journal_root = path(o->journal_root);
        std::memcpy(r.journal_id.bytes.data(), o->operation_id, sizeof(o->operation_id));
        r.open_journal = open_native_operation_journal_file;
        auto result = std::make_unique<ckfet_job>(); result->state = std::make_shared<Shared>();
        result->state->page_limit = r.limits.max_page_rows;
        auto slot = std::make_unique<WorkerSlot>();
        if (!slot->acquire()) return CKFE_API_BUSY;
        std::thread t(worker, result->state, std::move(r),std::move(slot));
        try { t.detach(); } catch (...) { result->state->stop.request_stop(); result->state->cv.notify_all(); t.join(); throw; }
        *out = result.release(); return CKFE_API_OK;
    });
}
ckfe_api_status ckfet_poll_v1(const ckfet_job* j, ckfet_snapshot_v1* out) {
    if (out) *out = {};
    return boundary([&] { require(j && out); std::lock_guard lock(j->state->mutex); *out = j->state->snapshot; return CKFE_API_OK; });
}
ckfe_api_status ckfet_worker_drained_v1(const ckfet_job* j, uint32_t* out) {
    if (out) *out = 0;
    return boundary([&] {
        require(j && out);
        std::lock_guard lock(j->state->mutex);
        *out = j->state->worker_drained;
        return CKFE_API_OK;
    });
}
ckfe_api_status ckfet_drain_v1(ckfet_job* j, ckfet_snapshot_v1* events, uint64_t capacity, uint64_t* count, uint64_t* coalesced) {
    if (count) *count = 0; if (coalesced) *coalesced = 0;
    return boundary([&] {
        require(j && count && coalesced && capacity <= 64 && (!capacity || events));
        std::lock_guard lock(j->state->mutex);
        while (*count < capacity && j->state->event_count) {
            events[(*count)++] = j->state->events[j->state->event_head];
            j->state->event_head = (j->state->event_head + 1) % j->state->events.size();
            --j->state->event_count;
        }
        *coalesced = j->state->coalesced; j->state->coalesced = 0;
        return CKFE_API_OK;
    });
}
ckfe_api_status ckfet_page_v1_get(const ckfet_job* j, uint64_t generation, uint64_t offset,
    ckfet_row_v1* rows, uint64_t capacity, ckfet_page_v1* out) {
    if (out) *out = {};
    return boundary([&] {
        require(j && out && capacity && rows); std::lock_guard lock(j->state->mutex);
        const auto& s = *j->state;
        require(generation && capacity <= s.page_limit && offset <= s.rows.size());
        if (!s.snapshot.plan_generation) return CKFE_API_NOT_READY;
        if (generation != s.snapshot.plan_generation) return CKFE_API_STALE_PLAN;
        const auto n = std::min<std::uint64_t>(capacity, s.rows.size() - offset);
        for (std::uint64_t i = 0; i < n; ++i) rows[i] = s.rows[offset + i].value;
        *out = {generation, n, s.rows.size(), offset + n, static_cast<std::uint32_t>(offset + n < s.rows.size()), 0};
        return CKFE_API_OK;
    });
}
ckfe_api_status ckfet_key_copy_v1(const ckfet_job* j, uint64_t generation, uint64_t id,
    void* buffer, uint64_t capacity, uint64_t* required) {
    if (required) *required = 0;
    return boundary([&] {
        require(j && required && (!capacity || buffer)); std::lock_guard lock(j->state->mutex);
        const auto& s = *j->state;
        require(generation && id);
        if (!s.snapshot.plan_generation) return CKFE_API_NOT_READY;
        if (generation != s.snapshot.plan_generation) return CKFE_API_STALE_PLAN;
        require(id <= s.rows.size());
        const auto& key = s.rows[id - 1].key; *required = key.size();
        if (capacity < key.size()) return CKFE_API_BUFFER_TOO_SMALL;
        if (!key.empty()) std::memcpy(buffer, key.data(), key.size());
        return CKFE_API_OK;
    });
}
ckfe_api_status ckfet_native_copy_v1(const ckfet_job* j, uint64_t generation, uint64_t id,
    uint32_t kind, uint64_t index, void* buffer, uint64_t capacity, uint64_t* required, uint32_t* encoding) {
    if (required) *required = 0; if (encoding) *encoding = 0;
    return boundary([&] {
        require(j && required && encoding && kind <= CKFET_NATIVE_RESULTING_NAME && (!capacity || buffer));
        std::lock_guard lock(j->state->mutex); const auto& s = *j->state;
        require(generation && id);
        if (!s.snapshot.plan_generation) return CKFE_API_NOT_READY;
        if (generation != s.snapshot.plan_generation) return CKFE_API_STALE_PLAN;
        require(id <= s.rows.size());
        const auto& r = s.rows[id - 1]; const NativeName* n = nullptr;
        if (kind == CKFET_NATIVE_COMPONENT) { require(index < r.components.size()); n = &r.components[index]; }
        else { require(index == 0); const auto& v = kind == CKFET_NATIVE_JOURNAL_NAME ? r.journal :
            kind == CKFET_NATIVE_STAGING_NAME ? r.staging : kind == CKFET_NATIVE_RETAINED_NAME ? r.retained :
            kind == CKFET_NATIVE_PROPOSED_NAME ? r.proposed : r.resulting;
            if (!v) return CKFE_API_OPERATION_UNAVAILABLE; n = &*v; }
        const void* bytes = nullptr; std::size_t unit_size = 1;
        if (const auto* p = n->posix_bytes()) { bytes = p->data(); *required = p->size(); *encoding = CKFET_POSIX_BYTES; }
        else { bytes = n->windows_units()->data(); *required = n->windows_units()->size(); *encoding = CKFET_UTF16; unit_size = 2; }
        if (capacity < *required) return CKFE_API_BUFFER_TOO_SMALL;
        if (*required) std::memcpy(buffer,bytes,static_cast<std::size_t>(*required) * unit_size);
        return CKFE_API_OK;
    });
}
ckfe_api_status ckfet_rule_counts_get_v1(const ckfet_job* j,uint64_t index,ckfet_rule_counts_v1* out) {
    if (out) *out = {};
    return boundary([&] {
        require(j && out); std::lock_guard lock(j->state->mutex);
        require(index < j->state->rule_counts.size()); *out = j->state->rule_counts[index]; return CKFE_API_OK;
    });
}
ckfe_api_status ckfet_review_v1(ckfet_job* j, uint64_t generation, const ckfet_rule_v1* input,
    uint64_t count, const uint64_t* deletions, uint64_t deletion_count, uint64_t* out) {
    return ckfet_review_names_v1(j,generation,input,count,nullptr,0,deletions,deletion_count,out);
}
ckfe_api_status ckfet_review_names_v1(ckfet_job* j, uint64_t generation, const ckfet_rule_v1* input,
    uint64_t count, const ckfet_name_choice_v1* names, uint64_t name_count,
    const uint64_t* deletions, uint64_t deletion_count, uint64_t* out) {
    if (out) *out = 0;
    return boundary([&] {
        require(j && out && count <= CKFET_MAX_RULES && name_count <= CKFET_MAX_RULES &&
            (!count || input) && (!deletion_count || deletions) && (!name_count || names));
        auto& s = *j->state; require(generation);
        std::size_t row_count = 0;
        auto admission = [&]() {
            if (s.snapshot.command_state != CKFET_COMMAND_NONE) return CKFE_API_BUSY;
            if (s.terminal || s.snapshot.state != CKFET_AWAITING_REVIEW) return CKFE_API_NOT_READY;
            if (generation != s.snapshot.plan_generation) return CKFE_API_STALE_PLAN;
            return CKFE_API_OK;
        };
        {
            std::lock_guard lock(s.mutex);
            const auto status = admission(); if (status != CKFE_API_OK) return status;
            row_count = s.rows.size();
        }
        require(deletion_count <= row_count);
        Command c; c.kind = Command::Review; c.generation = generation;
        std::uint64_t selected_total = 0, key_total = 0;
        for (std::uint64_t i = 0; i < count; ++i) {
            const auto& r = input[i];
            require(r.version == CKFET_VERSION && r.struct_size == sizeof(r) && !r.reserved &&
                r.kind <= CKFET_CONFLICT_CAPACITY && r.choice <= CKFET_DELETE_EDITED && r.tie <= CKFET_DELETE_EDITED &&
                r.scope <= CKFET_SCOPE_JOB && r.direction <= CKFET_RIGHT_TO_LEFT && r.protect_nonempty <= 1 &&
                r.retain_replaced <= 1 && r.plan_generation == generation && r.selected_count <= row_count &&
                r.selected_count <= UINT64_C(1000000) &&
                selected_total <= UINT64_C(1000000) - r.selected_count && (!r.selected_count || r.selected_rows) &&
                r.subtree_key.length <= 65536 && key_total <= UINT64_C(16777216) - r.subtree_key.length &&
                (!r.subtree_key.length || r.subtree_key.data));
            selected_total += r.selected_count; key_total += r.subtree_key.length;
            ConflictRule v;
            v.kind = static_cast<ConflictClass>(r.kind); v.choice = static_cast<ConflictChoice>(r.choice);
            v.tie = static_cast<ConflictChoice>(r.tie); v.scope = static_cast<ConflictScope>(r.scope);
            v.direction = static_cast<ConflictDirection>(r.direction); v.protect_nonempty = r.protect_nonempty;
            v.retain_replaced = r.retain_replaced;
            if (r.selected_count) v.selected_rows.assign(r.selected_rows, r.selected_rows + r.selected_count);
            if (r.subtree_key.length) v.subtree.assign(static_cast<const char*>(r.subtree_key.data), static_cast<std::size_t>(r.subtree_key.length));
            c.rules.push_back(std::move(v));
        }
        if (deletion_count) c.deletions.assign(deletions, deletions + deletion_count);
        std::uint64_t name_bytes = 0;
        for (std::uint64_t i = 0; i < name_count; ++i) {
            const auto& n = names[i]; const auto& p = n.component;
            require(n.row_id && n.row_id <= row_count && n.side <= CKFET_NAME_TARGET && !n.reserved &&
                p.data && p.units && p.units <= 32767 && p.encoding <= 1 && !p.reserved);
            const auto bytes = p.units * (p.encoding == CKFET_UTF16 ? 2 : 1);
            require(name_bytes <= UINT64_C(16777216) - bytes); name_bytes += bytes;
            std::optional<NativeName> component;
            if (p.encoding == CKFET_POSIX_BYTES) component = NativeName::from_posix({static_cast<const char*>(p.data),static_cast<std::size_t>(p.units)});
            else { std::u16string units(static_cast<std::size_t>(p.units),u'\0'); std::memcpy(units.data(),p.data,static_cast<std::size_t>(bytes)); component = NativeName::from_windows(units); }
            require(component.has_value()); c.names.push_back({n.row_id,std::move(*component),static_cast<ReviewedTreeNameSide>(n.side)});
        }
        std::lock_guard lock(s.mutex);
        const auto status = admission(); if (status != CKFE_API_OK) return status;
        if (s.next_command == UINT64_MAX) throw std::overflow_error("tree command IDs exhausted");
        c.id = s.next_command++;
        *out = c.id; s.command = std::move(c); s.snapshot.command_id = *out; s.clear_failure();
        s.snapshot.command_state = CKFET_COMMAND_PENDING; s.snapshot.receipt_id = 0; s.publish(); s.cv.notify_all();
        return CKFE_API_OK;
    });
}
ckfe_api_status ckfet_execute_v1(ckfet_job* j, uint64_t generation, uint64_t receipt, uint64_t* out) {
    if (out) *out = 0;
    return boundary([&] {
        require(j && out); std::lock_guard lock(j->state->mutex); auto& s = *j->state;
        require(generation && receipt);
        if (s.snapshot.command_state != CKFET_COMMAND_NONE) return CKFE_API_BUSY;
        if (s.terminal || s.snapshot.state != CKFET_AWAITING_REVIEW) return CKFE_API_NOT_READY;
        if (generation != s.snapshot.plan_generation || receipt != s.snapshot.receipt_id) return CKFE_API_STALE_PLAN;
        if (s.next_command == UINT64_MAX) throw std::overflow_error("tree command IDs exhausted");
        Command c; c.kind = Command::Execute; c.id = s.next_command++; c.generation = generation; c.receipt = receipt;
        *out = c.id; s.command = std::move(c); s.snapshot.command_id = *out; s.clear_failure();
        s.snapshot.command_state = CKFET_COMMAND_PENDING; s.publish(); s.cv.notify_all(); return CKFE_API_OK;
    });
}
ckfe_api_status ckfet_acknowledge_command_v1(ckfet_job* j, uint64_t id) {
    return boundary([&] {
        require(j && id); std::lock_guard lock(j->state->mutex); auto& s = *j->state;
        if (s.snapshot.command_id != id) return CKFE_API_STALE_PLAN;
        if (s.snapshot.command_state == CKFET_COMMAND_PENDING) return CKFE_API_BUSY;
        if (s.snapshot.command_state == CKFET_COMMAND_NONE) return CKFE_API_NOT_READY;
        s.snapshot.command_state = CKFET_COMMAND_NONE; s.publish(); return CKFE_API_OK;
    });
}
void ckfet_request_cancel(ckfet_job* j) { if (j) { j->state->stop.request_stop(); j->state->cv.notify_all(); } }
void ckfet_request_pause(ckfet_job* j, uint32_t paused) {
    if (!j || paused > 1) return;
    try {
        std::lock_guard lock(j->state->mutex); j->state->paused = paused;
        j->state->snapshot.pause_requested = paused; j->state->publish(); j->state->cv.notify_all();
    } catch (...) { }
}
void ckfet_release(ckfet_job* j) { if (j) { ckfet_request_cancel(j); delete j; } }
}
