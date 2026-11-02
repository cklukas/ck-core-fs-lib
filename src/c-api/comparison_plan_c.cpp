// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_fs_plan.h"
#include "comparison_plan.hpp"

#include <atomic>
#include <cstring>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <utility>

using namespace ck::files;
using ScopeMap = std::map<std::uint64_t, AdapterScope>;
struct ckfsp_plan {
    ComparisonPlan::Pointer value;
    ScopeMap scopes;
    ComparisonLimits limits;
    std::uint64_t id = 0;
};
namespace {
static_assert(static_cast<unsigned>(ObjectKind::Other) == CKFSP_OTHER);
static_assert(static_cast<unsigned>(ComparisonReason::SameObject) == CKFSP_REASON_SAME_OBJECT);
static_assert(static_cast<unsigned>(ComparisonAction::RemoveDestinationDirectory) == CKFSP_ACTION_REMOVE_EMPTY_DIRECTORY);
static_assert(static_cast<unsigned>(ComparisonRelation::Protected) == CKFSP_REL_PROTECTED);

void require(bool condition) { if (!condition) throw std::invalid_argument("invalid preview input"); }
bool boolean(std::uint32_t v) noexcept { return v <= 1; }
std::size_t count(std::uint64_t v) {
    require(v <= std::numeric_limits<std::size_t>::max());
    return static_cast<std::size_t>(v);
}
template<class F> ckfsp_status boundary(F&& f) noexcept {
    try { return f(); }
    catch (const std::bad_alloc&) { return CKFSP_OUT_OF_MEMORY; }
    catch (const std::invalid_argument&) { return CKFSP_INVALID_ARGUMENT; }
    catch (...) { return CKFSP_EXCEPTION; }
}
FileTimestamp timestamp(const ckfsp_timestamp& t) {
    require(t.reserved == 0);
    const auto value = FileTimestamp::from_unix(t.seconds, t.nanoseconds);
    require(value.has_value()); return *value;
}
ObjectIdentity identity(const ckfsp_identity& id, ScopeMap& scopes) {
    require(id.namespace_id && id.scheme <= CKFSP_ID_WINDOWS_64 && boolean(id.has_generation));
    ObjectIdentity result;
    result.scope = scopes.try_emplace(id.namespace_id).first->second;
    result.scheme = static_cast<IdentityScheme>(id.scheme);
    std::memcpy(result.volume.bytes.data(), id.volume, 16);
    std::memcpy(result.object.bytes.data(), id.object, 16);
    if (id.has_generation) result.generation = id.generation;
    return result;
}
ComparisonObject object(const ckfsp_object& o, ScopeMap& scopes) {
    require(o.state <= CKFSP_OBJECT_FAILED && !(o.known_fields & ~UINT32_C(31)) && o.reserved == 0);
    ComparisonObject result;
    result.state = static_cast<ComparisonObjectState>(o.state);
    if (o.known_fields & CKFSP_FIELD_IDENTITY) result.identity = identity(o.identity, scopes);
    if (o.known_fields & CKFSP_FIELD_KIND) {
        require(o.kind <= CKFSP_OTHER); result.kind = static_cast<ObjectKind>(o.kind);
    }
    if (o.known_fields & CKFSP_FIELD_SIZE) result.size = o.size;
    if (o.known_fields & CKFSP_FIELD_MODIFIED) result.modified = timestamp(o.modified);
    else require(o.modified.reserved == 0);
    result.timestamp_quantum_ns = o.timestamp_quantum_ns;
    if (o.known_fields & CKFSP_FIELD_CHANGE_COOKIE) result.change_cookie = o.change_cookie;
    return result;
}
ComparisonLimits limits(const ckfsp_limits& l) {
    require(l.max_entries && l.max_entries <= ComparisonLimits::hard_max_entries &&
        l.max_path_bytes && l.max_path_bytes <= ComparisonLimits::hard_max_path_bytes &&
        l.max_total_path_bytes && l.max_total_path_bytes <= ComparisonLimits::hard_max_total_path_bytes &&
        l.max_exclusions <= ComparisonLimits::hard_max_exclusions &&
        l.max_page_rows && l.max_page_rows <= ComparisonLimits::hard_max_page_rows);
    return {count(l.max_entries), count(l.max_path_bytes), count(l.max_total_path_bytes),
        count(l.max_exclusions), count(l.max_page_rows), l.max_aggregate_bytes};
}
ComparisonOptions options(const ckfsp_options& o) {
    require(o.version == CKFSP_VERSION && o.struct_size == sizeof(o) && !o.reserved &&
        o.profile <= CKFSP_COMPARE && o.comparison_mode <= CKFSP_COMPLETE_DIGEST && o.topology <= CKFSP_OVERLAP);
    ComparisonOptions result;
    result.profile = static_cast<ComparisonProfile>(o.profile);
    result.mode = static_cast<ComparisonMode>(o.comparison_mode);
    result.topology = static_cast<ComparisonTopology>(o.topology);
    result.timestamp_quantum_ns = o.timestamp_quantum_ns;
    const auto& f = o.filters;
    require(boolean(f.has_minimum_size) && boolean(f.has_maximum_size) &&
        boolean(f.has_modified_not_before) && boolean(f.has_modified_before) &&
        f.modified_not_before.reserved == 0 && f.modified_before.reserved == 0);
    if (f.has_minimum_size) result.filters.minimum_size = f.minimum_size;
    if (f.has_maximum_size) result.filters.maximum_size = f.maximum_size;
    if (f.has_modified_not_before) result.filters.modified_not_before = timestamp(f.modified_not_before);
    if (f.has_modified_before) result.filters.modified_before = timestamp(f.modified_before);
    result.filters.allowed_kind_mask = f.allowed_kind_mask;
    result.filters.maximum_depth = count(f.maximum_depth);
    return result;
}
std::string key(const ckfsp_bytes& b, const ComparisonLimits& l, std::uint64_t& total) {
    require(b.data && b.length && b.length <= l.max_path_bytes && b.length <= l.max_total_path_bytes &&
        total <= l.max_total_path_bytes - b.length);
    total += b.length;
    return std::string(static_cast<const char*>(b.data), count(b.length));
}
std::vector<ComparisonEntry> entries(const ckfsp_inventory& inventory, const ComparisonLimits& l,
    ScopeMap& scopes, std::uint64_t& total) {
    require(inventory.state <= CKFSP_INVENTORY_FAILED && boolean(inventory.has_root) &&
        inventory.entry_count <= l.max_entries && (!inventory.entry_count || inventory.entries));
    std::vector<ComparisonEntry> result;
    result.reserve(count(inventory.entry_count));
    for (std::size_t i = 0; i < inventory.entry_count; ++i) {
        const auto& e = inventory.entries[i];
        require(e.version == CKFSP_VERSION && e.struct_size == sizeof(e) && !(e.flags & ~UINT32_C(3)) && boolean(e.has_digest));
        ComparisonEntry converted;
        converted.relative_path = key(e.relative_key, l, total);
        converted.object = object(e.object, scopes);
        converted.excluded = e.flags & CKFSP_ENTRY_EXCLUDED;
        converted.name_collision = e.flags & CKFSP_ENTRY_NAME_COLLISION;
        if (e.has_digest) {
            require(e.digest.state <= CKFSP_DIGEST_FAILED && e.digest.algorithm <= CKFSP_SHA256);
            ComparisonDigest d;
            d.state = static_cast<ComparisonDigestState>(e.digest.state);
            d.algorithm = static_cast<ComparisonDigestAlgorithm>(e.digest.algorithm);
            std::memcpy(d.bytes.data(), e.digest.bytes, sizeof(e.digest.bytes));
            d.bytes_read = e.digest.bytes_read;
            d.before = object(e.digest.before, scopes); d.after = object(e.digest.after, scopes);
            converted.digest = std::move(d);
        }
        result.push_back(std::move(converted));
    }
    return result;
}
struct Converted {
    ComparisonOptions options;
    ComparisonLimits limits;
    std::vector<ComparisonEntry> source, destination;
    std::vector<std::string> exclusions;
    std::optional<ObjectIdentity> sr, dr;
    ComparisonInventoryState ss, ds;
    ComparisonInventory s() const { return {ss, sr, source}; }
    ComparisonInventory d() const { return {ds, dr, destination}; }
};
Converted convert(const ckfsp_input& in, ScopeMap& scopes) {
    require(in.version == CKFSP_VERSION && in.struct_size == sizeof(in));
    Converted result;
    result.options = options(in.options); result.limits = limits(in.options.limits);
    const auto& l = result.limits;
    require(in.source.entry_count <= l.max_entries && in.destination.entry_count <= l.max_entries - in.source.entry_count &&
        in.exclusion_count <= l.max_exclusions && (!in.exclusion_count || in.excluded_paths));
    std::uint64_t total = 0;
    result.source = entries(in.source, l, scopes, total);
    result.destination = entries(in.destination, l, scopes, total);
    result.exclusions.reserve(count(in.exclusion_count));
    for (std::size_t i = 0; i < in.exclusion_count; ++i) result.exclusions.push_back(key(in.excluded_paths[i], l, total));
    result.ss = static_cast<ComparisonInventoryState>(in.source.state);
    result.ds = static_cast<ComparisonInventoryState>(in.destination.state);
    if (in.source.has_root) result.sr = identity(in.source.root, scopes);
    if (in.destination.has_root) result.dr = identity(in.destination.root, scopes);
    return result;
}
std::uint64_t next_id() noexcept {
    static std::atomic<std::uint64_t> sequence{1};
    auto n = sequence.load(std::memory_order_relaxed);
    while (n != std::numeric_limits<std::uint64_t>::max())
        if (sequence.compare_exchange_weak(n, n + 1, std::memory_order_relaxed)) return n;
    return 0; // exhausted; never reuse identities
}
ComparisonRow get_row(const ckfsp_plan* plan, std::uint64_t id) {
    require(plan && id && id <= plan->value->aggregate().rows);
    auto page = plan->value->page(count(id - 1), 1);
    require(page.value() && page.value()->rows.size() == 1);
    return page.value()->rows.front();
}
}
extern "C" {
void ckfsp_input_init(ckfsp_input* in) {
    if (!in) return;
    *in = {};
    in->version = CKFSP_VERSION; in->struct_size = sizeof(*in);
    auto& o = in->options;
    o.version = CKFSP_VERSION; o.struct_size = sizeof(o);
    o.profile = CKFSP_COMPARE; o.comparison_mode = CKFSP_SIZE_MTIME;
    o.timestamp_quantum_ns = 1; o.filters.allowed_kind_mask = CKFSP_ALL_KINDS; o.filters.maximum_depth = 1024;
    const ComparisonLimits l;
    o.limits = {l.max_entries, l.max_path_bytes, l.max_total_path_bytes, l.max_exclusions, l.max_page_rows, l.max_aggregate_bytes};
}
void ckfsp_entry_init(ckfsp_entry* entry) {
    if (!entry) return;
    *entry = {}; entry->version = CKFSP_VERSION; entry->struct_size = sizeof(*entry);
}
ckfsp_status ckfsp_plan_create(const ckfsp_input* input, ckfsp_plan** out) {
    if (out) *out = nullptr;
    return boundary([&]() -> ckfsp_status {
        require(input && out);
        auto handle = std::make_unique<ckfsp_plan>();
        const auto converted = convert(*input, handle->scopes);
        auto result = ComparisonPlan::create(converted.options, converted.s(), converted.d(), converted.exclusions, converted.limits);
        if (!result.value()) return CKFSP_PLAN_UNAVAILABLE;
        handle->limits = converted.limits;
        handle->value = *result.value(); handle->id = next_id();
        if (!handle->id) return CKFSP_PLAN_UNAVAILABLE;
        *out = handle.release(); return CKFSP_OK;
    });
}
void ckfsp_plan_destroy(ckfsp_plan* plan) { delete plan; }
ckfsp_status ckfsp_plan_get_summary(const ckfsp_plan* plan, ckfsp_summary* out) {
    if (out) *out = {};
    return boundary([&]() -> ckfsp_status {
        require(plan && out);
        const auto& a = plan->value->aggregate();
        *out = {plan->id, a.rows, a.unknown_rows, a.protected_rows, a.review_rows, a.proposed_writes,
            a.proposed_removals, a.source_bytes, a.destination_bytes, a.proposed_copy_bytes,
            a.source_bytes_complete, a.destination_bytes_complete, a.proposed_copy_bytes_complete, 0};
        return CKFSP_OK;
    });
}
ckfsp_status ckfsp_plan_page(const ckfsp_plan* plan, std::uint64_t offset, ckfsp_row* out_rows,
    std::uint32_t capacity, ckfsp_page* out) {
    if (out) *out = {};
    if (out_rows && capacity <= ComparisonLimits::hard_max_page_rows)
        std::memset(out_rows, 0, sizeof(*out_rows) * capacity);
    return boundary([&]() -> ckfsp_status {
        require(plan && out && out_rows && capacity && capacity <= ComparisonLimits::hard_max_page_rows);
        auto result = plan->value->page(count(offset), capacity);
        if (!result.value()) return CKFSP_INVALID_ARGUMENT;
        const auto& p = *result.value();
        for (std::size_t i = 0; i < p.rows.size(); ++i) {
            const auto& r = p.rows[i];
            out_rows[i] = {{plan->id, r.id}, r.source_index ? *r.source_index : CKFSP_NO_INDEX,
                r.destination_index ? *r.destination_index : CKFSP_NO_INDEX, r.relative_path.size(),
                static_cast<std::uint32_t>(r.relation), static_cast<std::uint32_t>(r.reason),
                static_cast<std::uint32_t>(r.action), r.destination_protected, r.requires_review, 0};
        }
        *out = {plan->id, p.total_rows, p.rows.size(), p.next_offset.value_or(0), p.next_offset.has_value(), 0};
        return CKFSP_OK;
    });
}
ckfsp_status ckfsp_plan_path_length(const ckfsp_plan* plan, std::uint64_t id, std::uint64_t* out) {
    if (out) *out = 0;
    return boundary([&]() -> ckfsp_status {
        require(out); const auto r = get_row(plan, id); *out = r.relative_path.size(); return CKFSP_OK;
    });
}
ckfsp_status ckfsp_plan_copy_path(const ckfsp_plan* plan, std::uint64_t id, void* buffer,
    std::uint64_t capacity, std::uint64_t* out) {
    if (out) *out = 0;
    if (buffer && capacity) *static_cast<unsigned char*>(buffer) = 0;
    return boundary([&]() -> ckfsp_status {
        require(out); const auto r = get_row(plan, id);
        if (capacity < r.relative_path.size()) return CKFSP_BUFFER_TOO_SMALL;
        require(buffer);
        std::memcpy(buffer, r.relative_path.data(), r.relative_path.size());
        *out = r.relative_path.size(); return CKFSP_OK;
    });
}
ckfsp_status ckfsp_plan_revalidate(const ckfsp_plan* plan, const ckfsp_token* token,
    const ckfsp_input* input, std::uint32_t* out) {
    if (out) *out = CKFSP_REVALIDATION_NOT_CHECKED;
    return boundary([&]() -> ckfsp_status {
        require(plan && token && input && out);
        if (token->plan_id != plan->id || !token->row_id || token->row_id > plan->value->aggregate().rows) {
            *out = CKFSP_REVALIDATION_FOREIGN_TOKEN; return CKFSP_OK;
        }
        auto scopes = plan->scopes; // fresh namespaces cannot change the frozen map
        const auto converted = convert(*input, scopes);
        const auto& a = plan->limits; const auto& b = converted.limits;
        if (a.max_entries != b.max_entries || a.max_path_bytes != b.max_path_bytes ||
            a.max_total_path_bytes != b.max_total_path_bytes || a.max_exclusions != b.max_exclusions ||
            a.max_page_rows != b.max_page_rows || a.max_aggregate_bytes != b.max_aggregate_bytes) {
            *out = CKFSP_REVALIDATION_EVIDENCE_CHANGED; return CKFSP_OK;
        }
        const auto row = get_row(plan, token->row_id);
        const auto r = plan->value->revalidate(row.token, converted.options, converted.s(), converted.d(), converted.exclusions);
        *out = static_cast<std::uint32_t>(r) + 1;
        return CKFSP_OK;
    });
}
}
