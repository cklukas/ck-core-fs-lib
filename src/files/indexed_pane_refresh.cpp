// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "indexed_pane.hpp"
#include "directory_index_observation.hpp"
#include "pane_page_budget.hpp"

#include <limits>

namespace ck::files {
namespace {
Observation<bool> refuse(ObservationState state, AdapterError code, const char *operation) {
    return Observation<bool>::unavailable(state, {ErrorDomain::Adapter, static_cast<std::int64_t>(code), operation});
}

template <class T> Observation<bool> forward_failure(const Observation<T> &value) {
    const auto &error = *value.unavailable_detail();
    return Observation<bool>::unavailable(error.state, error.error);
}

Observation<bool> match_parent(const Observation<ObjectIdentity> &expected, const BasicMetadata &actual) {
    if (!expected.value())
        return forward_failure(expected);
    if (!actual.identity.value())
        return forward_failure(actual.identity);
    if (!actual.kind.value())
        return forward_failure(actual.kind);
    if (*actual.kind.value() != ObjectKind::Directory)
        return refuse(ObservationState::Changed, AdapterError::NotDirectory, "indexed_refresh.parent_kind");
    const auto match = compare_identity(*expected.value(), *actual.identity.value());
    if (match == IdentityComparison::Same)
        return Observation<bool>::available(true);
    if (match == IdentityComparison::Different)
        return refuse(ObservationState::Changed, AdapterError::MetadataChanged, "indexed_refresh.parent_changed");
    return refuse(ObservationState::Unknown, AdapterError::UnqualifiedIdentity, "indexed_refresh.parent_identity");
}

bool matches_scan(const BasicMetadata &bound, const Observation<BasicMetadata> &scanned) {
    const auto *row = scanned.value();
    return row && row->identity.value() && bound.identity.value() && row->kind.value() && bound.kind.value() &&
           *row->kind.value() == *bound.kind.value() &&
           compare_identity(*row->identity.value(), *bound.identity.value()) == IdentityComparison::Same;
}
} // namespace

Observation<bool> IndexedPane::reconcile_refresh_marks(const IndexedPane &previous,
                                                       const PaneStateStamp &previous_stamp,
                                                       const PaneStateStamp &candidate_stamp, std::stop_token stop) {
    const auto current_selection = [&] {
        return previous.accepts(previous_stamp) && accepts(candidate_stamp);
    };
    const auto cancelled = [] {
        return refuse(ObservationState::Unknown, AdapterError::InterruptedRead, "indexed_refresh.cancelled");
    };
    if (this == &previous || !current_selection() || !data_ || !previous.data_ || pending_ ||
        mark_pending_ || previous.pending_ || previous.mark_pending_ || marks_ || mark_bindings_ ||
        invalidated_refresh_marks_ || retained_mark_limit_ != previous.retained_mark_limit_ ||
        data_->row_scope() == previous.data_->row_scope() || data_->source_scope_ != previous.data_->source_scope_)
        return refuse(ObservationState::Changed, AdapterError::InvalidAccess, "indexed_refresh.selection_state");
    if (stop.stop_requested())
        return cancelled();

    const auto candidate = data_;
    const auto prior = previous.data_;
    const auto slots = previous.mark_binding_slots_;
    const auto old_bitmap = previous.marks_;
    const auto old_bindings = previous.mark_bindings_;
    const auto verify_parents = [&]() -> Observation<bool> {
        auto held = prior->pin_->inspect_basic();
        if (!held.value())
            return forward_failure(held);
        auto fresh = candidate->pin_->inspect_basic();
        if (!fresh.value())
            return forward_failure(fresh);
        for (const auto *expected : {&prior->directory_, &candidate->directory_})
            for (const auto *actual : {held.value(), fresh.value()}) {
                auto matched = match_parent(*expected, *actual);
                if (!matched.value())
                    return matched;
            }
        return detail::check_index_directory(candidate->source_scope_, candidate->directory_, candidate->after_, held);
    };
    if (auto verified = verify_parents(); !verified.value())
        return verified;

    std::uint64_t old_count = 0;
    if (old_bitmap) {
        auto checked = old_bitmap->checked_count(stop);
        if (!checked.value())
            return forward_failure(checked);
        old_count = *checked.value();
    }
    using Completed = CompletedIndexedMarkChange;
    std::map<NativeName, const HeldChild *, NativeNameLess> names;
    if (old_bindings) {
        if (!old_bitmap || !slots || old_bindings->size() > old_count)
            return refuse(ObservationState::Failed, AdapterError::InvalidNativeResult, "indexed_refresh.binding_count");
        for (const auto &[number, binding] : *old_bindings) {
            if (stop.stop_requested())
                return cancelled();
            auto marked = old_bitmap->contains({prior->row_scope(), number});
            if (!marked.value())
                return forward_failure(marked);
            if (!*marked.value() || !binding || !binding->child ||
                !names.emplace(binding->child->name(), binding->child.get()).second)
                return refuse(ObservationState::Failed, AdapterError::InvalidNativeResult, "indexed_refresh.binding");
        }
    }

    auto survivors = std::make_shared<Completed::Bindings>();
    if (!names.empty()) {
        auto scan = candidate->store_->begin_scan();
        if (!scan.value())
            return forward_failure(scan);
        auto cursor = *scan.value();
        for (;;) {
            auto page = candidate->store_->read_page(cursor, {}, stop);
            if (!page.value())
                return forward_failure(page);
            for (const auto &row : page.value()->rows) {
                if (stop.stop_requested())
                    return cancelled();
                const auto &record = row.record;
                const auto found = names.find(record.name);
                if (found == names.end() || slots->load(std::memory_order_relaxed) >= 2 * retained_mark_limit_)
                    continue;
                const auto *old = found->second;
                if (!old->parent_identity().value() ||
                    compare_identity(*old->parent_identity().value(), *prior->directory_.value()) != IdentityComparison::Same)
                    continue;
                auto binding = std::make_shared<Completed::Binding>(slots);
                auto observed = old->refresh(stop);
                if (stop.stop_requested())
                    return cancelled();
                if (!observed.value() || !(*observed.value())->continues(*old) ||
                    !matches_scan((*observed.value())->metadata(), record.metadata))
                    continue;
                std::size_t diagnostics = 0;
                if (!detail::charge((*observed.value())->metadata(), diagnostics,
                                    IndexedDirectoryOpenLimits{}.diagnostic_bytes))
                    continue;
                binding->child = std::move(observed).take_value();
                if (!survivors->emplace(record.row_id, std::move(binding)).second)
                    return refuse(ObservationState::Failed, AdapterError::InvalidNativeResult, "indexed_refresh.duplicate_row");
                names.erase(found);
            }
            if (page.value()->end)
                break;
            cursor = page.value()->next;
        }
    }

    std::shared_ptr<DirectoryIndexMarks> bitmap;
    std::uint64_t visible = 0;
    if (!survivors->empty()) {
        auto writer = DirectoryIndexMarks::create_writer(*candidate->store_, 64ULL * 1024 * 1024, stop);
        if (!writer.value())
            return forward_failure(writer);
        bitmap = std::move(writer).take_value();
        const auto block_rows = DirectoryIndexMarks::block_rows;
        const auto blocks = bitmap->rows() / block_rows + (bitmap->rows() % block_rows != 0);
        auto selected = survivors->begin();
        for (std::uint64_t block = 0; block < blocks; ++block) {
            if (stop.stop_requested())
                return cancelled();
            DirectoryIndexMarks::Bits bits{};
            while (selected != survivors->end() && (selected->first - 1) / block_rows == block) {
                const auto number = selected->first;
                auto rank = candidate->lookup_->locate_row({candidate->row_scope(), number}, stop);
                if (!rank.value())
                    return forward_failure(rank);
                visible += rank.value()->has_value();
                DirectoryIndexMarks::set(bits, (number - 1) % block_rows, true);
                ++selected;
            }
            if (auto wrote = bitmap->write_block(block, bits, stop); !wrote.value())
                return wrote;
        }
        if (selected != survivors->end())
            return refuse(ObservationState::Failed, AdapterError::InvalidNativeResult, "indexed_refresh.unwritten_mark");
        if (auto sealed = bitmap->finish(survivors->size(), stop); !sealed.value())
            return sealed;
    }

    // Reuse the original parent anchor. A retained mark can survive many scans
    // without keeping an enumeration cursor from each previous generation.
    auto anchored = std::shared_ptr<CompletedIndexedPaneData>(new CompletedIndexedPaneData(*candidate));
    anchored->pin_ = prior->pin_;
    if (auto verified = verify_parents(); !verified.value())
        return verified;
    if (stop.stop_requested())
        return cancelled();
    if (!current_selection())
        return refuse(ObservationState::Changed, AdapterError::InvalidAccess, "indexed_refresh.superseded");

    const auto lost = old_count - survivors->size();
    const auto older_loss = previous.invalidated_refresh_marks_;
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    invalidate();
    data_ = std::move(anchored);
    marks_ = std::move(bitmap);
    mark_binding_slots_ = slots;
    mark_bindings_ = survivors->empty() ? nullptr : std::move(survivors);
    visible_marks_ = visible;
    invalidated_refresh_marks_ = lost > maximum - older_loss ? maximum : lost + older_loss;
    return Observation<bool>::available(true);
}
} // namespace ck::files
