// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "indexed_pane.hpp"
#include "native_filesystem.hpp"
#include "native_index_file.hpp"

#include <cstdio>
#include <filesystem>
#include <stdexcept>

namespace {
using namespace ck::files;

void check(bool value, const char *message) {
    if (!value)
        throw std::runtime_error(message);
}

template <class T> T take(Observation<T> result) {
    if (!result.value())
        throw std::runtime_error(result.unavailable_detail()->error.operation);
    return std::move(result).take_value();
}

NativeName name(const char *posix, const char16_t *windows) {
#if defined(_WIN32)
    (void)posix;
    return *NativeName::from_windows(windows);
#else
    (void)windows;
    return *NativeName::from_posix(posix);
#endif
}

void mark(IndexedPane &pane, const IndexedMarkCommand &command) {
    auto job = take(pane.begin_mark_change(pane.state_stamp(), command, 1));
    while (job->advance() == IndexedMarkJobState::Running) {
    }
    check(pane.publish_marks(take(job->completed())) == IndexedPanePublish::Applied, "publish marks");
}

NativeAbsolutePath address(const std::filesystem::path &path) {
    return take(NativeAbsolutePath::from_host(path));
}

void list(IndexedPane &pane, std::unique_ptr<DirectoryCursor> directory,
          const std::shared_ptr<IndexFileFactory> &factory, const std::shared_ptr<IndexStorageBudget> &budget,
          std::byte serial, const PaneView &view = {}) {
#if defined(_WIN32)
    constexpr auto model = StorageModel::WindowsHandleAttributes;
#elif defined(__APPLE__)
    constexpr auto model = StorageModel::DarwinStatFlags;
#else
    constexpr auto model = StorageModel::LinuxStatx;
#endif
    const auto request = pane.begin_listing(view);
    std::array<std::byte, 16> generation{serial};
    DirectoryIndexListingJob collection(request, std::make_unique<DirectoryListing>(std::move(directory)),
                                        model, factory, budget, generation);
    auto collection_state = collection.advance();
    while (collection_state == DirectoryIndexListingState::Collecting ||
           collection_state == DirectoryIndexListingState::SortingNames ||
           collection_state == DirectoryIndexListingState::CheckingNames)
        collection_state = collection.advance();
    IndexedPaneDataJob preparation(take(collection.completed()), view);
    auto preparation_state = preparation.advance();
    while (preparation_state == IndexedPaneDataJobState::Sorting ||
           preparation_state == IndexedPaneDataJobState::Indexing ||
           preparation_state == IndexedPaneDataJobState::CountingMarks)
        preparation_state = preparation.advance();
    check(pane.publish(take(preparation.completed())) == IndexedPanePublish::Applied, "publish indexed listing");
}

void create_file(const DirectoryCursor &directory, const NativeName &entry) {
    auto file = take(directory.create_child_file(entry));
    (void)take(file->finish_content_writes());
}

void run(const std::filesystem::path &fixture) {
    NativeFileSystem fs;
    auto parent = take(fs.open_native_directory(address(fixture)));
    auto source = take(parent->create_child_directory(name("source", u"source")));
    auto cache = take(parent->create_child_directory(name("cache", u"cache")));
    for (const auto &entry : {name("one", u"one"), name("two", u"two")})
        create_file(*source, entry);
    cache.reset();
    auto factory = take(open_native_index_workspace(address(fixture / "cache")));
    auto budget = std::make_shared<IndexStorageBudget>(1024 * 1024, 16);
    IndexedPane pane(1);
    const auto source_path = address(fixture / "source");
    list(pane, take(fs.open_native_directory(source_path)), factory, budget, std::byte{1});
    const auto captured = pane.capture_page(pane.state_stamp(), 0);
    check(captured.page && captured.page->rows().size() == 2, "read two native rows");
    const auto first = captured.page->rows()[0].id;
    const auto second = captured.page->rows()[1].id;

    mark(pane, IndexedMarkRow{first, true});
    check(pane.retained_mark_bindings() == 1 && pane.selection().marks->total == 1, "bind first mark");
    mark(pane, IndexedMarkRow{second, true});
    check(pane.retained_mark_bindings() == 1 && pane.selection().marks->total == 2, "keep bitmap marks at cap");
    mark(pane, IndexedMarkRow{first, false});
    check(pane.retained_mark_bindings() == 0 && pane.selection().marks->total == 1, "release removed binding");
    mark(pane, IndexedMarkVisible{true});
    check(pane.retained_mark_bindings() == 1 && pane.selection().marks->total == 2, "bind only the newly marked row");
    mark(pane, IndexedMarkRow{first, false});
    check(pane.retained_mark_bindings() == 0 && pane.selection().marks->total == 1, "do not rebind the old bitmap mark");

    auto job = take(pane.begin_mark_change(pane.state_stamp(), IndexedMarkRow{first, true}, 1));
    std::stop_source stop;
    stop.request_stop();
    check(job->advance(stop.get_token()) == IndexedMarkJobState::Cancelled && pane.cancel_marks(job->stamp()),
          "cancel pending mark binding");
    check(pane.retained_mark_bindings() == 0 && pane.selection().marks->total == 1, "cancel preserves prior selection");
    mark(pane, IndexedClearMarks{});
    check(pane.retained_mark_bindings() == 0 && pane.selection().marks->total == 0, "clear marks and bindings");

    const auto abandon_ready_mark = [&] {
        auto pending = take(pane.begin_mark_change(pane.state_stamp(), IndexedMarkRow{first, true}, 1));
        while (pending->advance() == IndexedMarkJobState::Running) {
        }
        auto result = take(pending->completed());
        check(pane.cancel_marks(pending->stamp()), "cancel a prepared mark");
        check(pane.publish_marks(result) == IndexedPanePublish::Stale, "reject superseded bound mark");
        return result;
    };
    auto abandoned_first = abandon_ready_mark();
    auto abandoned_second = abandon_ready_mark();
    mark(pane, IndexedMarkRow{first, true});
    check(pane.retained_mark_bindings() == 0 && pane.selection().marks->total == 1, "charge abandoned results");
    abandoned_first.reset();
    mark(pane, IndexedMarkRow{second, true});
    check(pane.retained_mark_bindings() == 1 && pane.selection().marks->total == 2, "retiring a result returns its slot");
    abandoned_second.reset();

    create_file(*source, name("earlier", u"earlier"));
    IndexedPane refreshed(1);
    list(refreshed, take(fs.open_native_directory(source_path)), factory, budget, std::byte{2});
    const auto previous_stamp = pane.state_stamp();
    const auto candidate_stamp = refreshed.state_stamp();
    check(!refreshed.reconcile_refresh_selection(pane, previous_stamp, candidate_stamp, stop.get_token()).value(),
          "cancel refresh before publication");
    check(previous_stamp.current() && candidate_stamp.current() && !refreshed.retained_mark_bindings(),
          "cancel leaves both panes unchanged");
    check(take(refreshed.reconcile_refresh_selection(pane, previous_stamp, candidate_stamp)), "reconcile fresh scan");
    check(previous_stamp.current() && !candidate_stamp.current(), "revoke only the changed candidate");
    const auto page = refreshed.capture_page(refreshed.state_stamp(), 0).page;
    check(page && page->rows().size() == 3 && page->rows()[0].display_name == "earlier" &&
          page->rows()[2].display_name == "two" && page->rows()[2].id.scope != second.scope &&
          page->rows()[2].marked && !page->rows()[1].marked,
          "carry the held mark to its new row ID");
    check(refreshed.focused_position() == 1 && refreshed.focused() == page->rows()[1].id &&
          !refreshed.selection().invalidated_refresh_focus, "carry the held focus to its new rank");
    check(refreshed.selection().marks->total == 1 && refreshed.selection().invalidated_refresh_marks == 1 &&
          refreshed.selection().state == PaneSourcesState::SelectionInvalidated &&
          !refreshed.begin_source_acquisition(refreshed.state_stamp()).value(),
          "unbound mark requires acknowledgement before using sources");

    IndexedPane unrelated(1);
    auto foreign = take(parent->create_child_directory(name("other", u"other")));
    list(unrelated, std::move(foreign), factory, budget, std::byte{3});
    check(!unrelated.reconcile_refresh_selection(pane, previous_stamp, unrelated.state_stamp()).value() &&
          previous_stamp.current() && !unrelated.retained_mark_bindings(), "refuse a different held parent");
    mark(pane, IndexedClearMarks{}); // Model retirement of the predecessor.
    {
        IndexedPane hidden(1);
        PaneView filtered;
        filtered.display_substring = "earlier";
        list(hidden, take(fs.open_native_directory(source_path)), factory, budget, std::byte{4}, filtered);
        check(take(hidden.reconcile_refresh_selection(refreshed, refreshed.state_stamp(), hidden.state_stamp())),
              "reconcile another scan");
        const auto selected = hidden.selection();
        check(selected.marks && selected.marks->total == 1 && selected.marks->hidden == 1 &&
              selected.invalidated_refresh_marks == 1 && hidden.focused() && !hidden.focused_position() &&
              !selected.invalidated_refresh_focus, "retain filtered mark and focus and prior loss");
    }
#if !defined(_WIN32)
    // Keep the original marked handle open while changing its name and
    // inserting a different native object under the original basename.
    std::filesystem::rename(fixture / "source" / "two", fixture / "source" / "retired-two");
    create_file(*source, name("two", u"two"));
    std::filesystem::rename(fixture / "source" / "one", fixture / "source" / "retired-one");
    create_file(*source, name("one", u"one"));
    {
        IndexedPane replaced(1);
        list(replaced, take(fs.open_native_directory(source_path)), factory, budget, std::byte{5});
        check(take(replaced.reconcile_refresh_selection(refreshed, refreshed.state_stamp(), replaced.state_stamp())),
              "reconcile a replaced mark");
        const auto selected = replaced.selection();
        check(selected.marks && selected.marks->total == 0 && selected.invalidated_refresh_marks == 2 &&
              selected.state == PaneSourcesState::SelectionInvalidated && !selected.candidates &&
              selected.invalidated_refresh_focus && !replaced.focused(),
              "refuse to transfer marks or focus to a replacement or renamed object");
        mark(replaced, IndexedClearMarks{});
        check(replaced.selection().state == PaneSourcesState::SelectionInvalidated,
              "clearing lost marks does not choose a new cursor");
        const auto first_visible = replaced.capture_page(replaced.state_stamp(), 0).page;
        check(first_visible && !first_visible->rows().empty() &&
              replaced.focus(replaced.state_stamp(), first_visible->rows().front().id) == IndexedPaneFocus::Applied &&
              replaced.selection().state == PaneSourcesState::Ready,
              "binding a new explicit cursor restores source selection");
    }
#endif
    mark(refreshed, IndexedClearMarks{});
    check(refreshed.selection().invalidated_refresh_marks == 0, "explicit mark command acknowledges refresh losses");
}
} // namespace

#if defined(_WIN32)
int wmain(int argc, wchar_t **argv) {
#else
int main(int argc, char **argv) {
#endif
    try {
        check(argc == 2, "one absolute native fixture directory is required");
        run(std::filesystem::path(argv[1]));
        std::puts("PASS indexed native mark binding and refresh reconciliation");
        return 0;
    } catch (const std::exception &failure) {
        std::fprintf(stderr, "FAIL indexed native mark binding: %s\n", failure.what());
        return 1;
    }
}
