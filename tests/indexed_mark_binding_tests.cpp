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

void run(const std::filesystem::path &fixture) {
    const auto address = [](const std::filesystem::path &path) { return take(NativeAbsolutePath::from_host(path)); };
    NativeFileSystem fs;
    auto parent = take(fs.open_native_directory(address(fixture)));
    auto source = take(parent->create_child_directory(name("source", u"source")));
    auto cache = take(parent->create_child_directory(name("cache", u"cache")));
    for (const auto &entry : {name("one", u"one"), name("two", u"two")}) {
        auto file = take(source->create_child_file(entry));
        (void)take(file->finish_content_writes());
    }
    source.reset();
    cache.reset();
    auto factory = take(open_native_index_workspace(address(fixture / "cache")));
    auto budget = std::make_shared<IndexStorageBudget>(1024 * 1024, 16);
    IndexedPane pane(1);
#if defined(_WIN32)
    constexpr auto model = StorageModel::WindowsHandleAttributes;
#elif defined(__APPLE__)
    constexpr auto model = StorageModel::DarwinStatFlags;
#else
    constexpr auto model = StorageModel::LinuxStatx;
#endif
    const PaneView view;
    const auto request = pane.begin_listing(view);
    std::array<std::byte, 16> generation{std::byte{1}};
    DirectoryIndexListingJob collection(request, std::make_unique<DirectoryListing>(
        take(fs.open_native_directory(address(fixture / "source")))), model, factory, budget, generation);
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
        std::puts("PASS indexed native mark bindings, cap and cancellation");
        return 0;
    } catch (const std::exception &failure) {
        std::fprintf(stderr, "FAIL indexed native mark binding: %s\n", failure.what());
        return 1;
    }
}
