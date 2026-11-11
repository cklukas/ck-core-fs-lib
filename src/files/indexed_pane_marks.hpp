// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "directory_index_marks.hpp"
#include "held_child.hpp"
#include "pane_page.hpp"
#include <atomic>
#include <map>
#include <variant>
namespace ck::files {
class CompletedIndexedPaneData;
class IndexedPane;
struct IndexedMarkRow {
    PaneRowId row;
    bool marked;
};
struct IndexedMarkRange {
    PaneRowId first, last;
    bool marked;
};
struct IndexedMarkVisible {
    bool marked;
};
struct IndexedInvertVisible {};
struct IndexedClearMarks {};
using IndexedMarkCommand =
    std::variant<IndexedMarkRow, IndexedMarkRange, IndexedMarkVisible, IndexedInvertVisible, IndexedClearMarks>;
class CompletedIndexedMarkChange final {
  public:
    const PaneStateStamp &stamp() const noexcept {
        return stamp_;
    }
    const IndexedPaneMarkCounts &counts() const noexcept {
        return counts_;
    }

  private:
    friend class IndexedPaneMarkJob;
    friend class IndexedPane;
    // Charge a native owner until its last staged or published reference
    // retires, including abandoned results still held by their worker caller.
    struct Binding {
        explicit Binding(std::shared_ptr<std::atomic_size_t> slots) : slots_(std::move(slots)) {
            slots_->fetch_add(1, std::memory_order_relaxed);
        }
        Binding(const Binding &) = delete;
        Binding &operator=(const Binding &) = delete;
        ~Binding() {
            child.reset();
            slots_->fetch_sub(1, std::memory_order_relaxed);
        }
        HeldChild::Pointer child;
      private:
        std::shared_ptr<std::atomic_size_t> slots_;
    };
    using Bindings = std::map<std::uint64_t, std::shared_ptr<const Binding>>;
    CompletedIndexedMarkChange(PaneStateStamp stamp, AdapterScope dataset, std::optional<AdapterScope> base,
                               std::shared_ptr<DirectoryIndexMarks> target, IndexedPaneMarkCounts counts,
                               std::shared_ptr<const Bindings> bindings)
        : stamp_(std::move(stamp)), dataset_(std::move(dataset)), base_(std::move(base)), target_(std::move(target)),
          counts_(counts), bindings_(std::move(bindings)) {
    }
    PaneStateStamp stamp_;
    AdapterScope dataset_;
    std::optional<AdapterScope> base_;
    std::shared_ptr<DirectoryIndexMarks> target_;
    IndexedPaneMarkCounts counts_;
    std::shared_ptr<const Bindings> bindings_;
};
enum class IndexedMarkJobState { Running, Complete, Failed, Cancelled, Abandoned };
// Prepared only by the serialized pane. Copy-on-write bitmap blocks provide
// atomic publication, not in-place partial mutation. Individual marks copy
// bitmap blocks and update a validated visible-count delta; bulk/range commands
// inspect at most rows_per_step original IDs per advance through the disk view.
class IndexedPaneMarkJob final {
  public:
    using Result = std::shared_ptr<const CompletedIndexedMarkChange>;
    IndexedPaneMarkJob(const IndexedPaneMarkJob &) = delete;
    IndexedPaneMarkJob &operator=(const IndexedPaneMarkJob &) = delete;
    IndexedMarkJobState advance(std::stop_token stop = {});
    bool abandon() noexcept;
    IndexedMarkJobState state() const noexcept {
        return state_;
    }
    const PaneStateStamp &stamp() const noexcept {
        return stamp_;
    }
    const std::optional<UnavailableObservation> &failure() const noexcept {
        return failure_;
    }
    Observation<Result> completed() const;

  private:
    friend class IndexedPane;
    IndexedPaneMarkJob(std::shared_ptr<const CompletedIndexedPaneData> data,
                       std::shared_ptr<DirectoryIndexMarks> previous, std::uint64_t visible, PaneStateStamp stamp,
                       const IndexedMarkCommand &command, std::size_t rows_per_step, std::uint64_t max_bytes,
                       std::shared_ptr<const CompletedIndexedMarkChange::Bindings> bindings,
                       std::size_t retained_mark_limit, std::shared_ptr<std::atomic_size_t> binding_slots);
    bool bind_mark(std::uint64_t number, std::stop_token stop);
    void release() noexcept;
    void fail(UnavailableObservation detail);
    void cancel() noexcept;
    std::shared_ptr<const CompletedIndexedPaneData> data_;
    std::shared_ptr<DirectoryIndexMarks> previous_, target_;
    std::shared_ptr<CompletedIndexedMarkChange::Bindings> bindings_;
    std::shared_ptr<std::atomic_size_t> binding_slots_;
    PaneStateStamp stamp_;
    IndexedMarkCommand command_;
    AdapterScope dataset_;
    std::optional<AdapterScope> base_;
    std::optional<DirectoryIndexMarks::Bits> bits_;
    std::uint64_t block_ = 0, previous_total_ = 0, total_ = 0, visible_ = 0, low_ = 0, high_ = 0;
    std::size_t at_ = 0, step_;
    std::size_t retained_mark_limit_;
    std::size_t binding_attempts_ = 0;
    IndexedMarkJobState state_ = IndexedMarkJobState::Running;
    std::optional<UnavailableObservation> failure_;
    Result result_;
};
struct IndexedPaneSelection {
    PaneSourcesState state = PaneSourcesState::Empty;
    PaneSourcesOrigin origin = PaneSourcesOrigin::Cursor;
    std::uint64_t candidates = 0;
    std::optional<IndexedPaneMarkCounts> marks;
    std::uint64_t invalidated_refresh_marks = 0;
    bool invalidated_refresh_focus = false;
};
} // namespace ck::files
