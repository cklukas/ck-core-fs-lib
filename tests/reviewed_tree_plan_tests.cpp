// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "../src/files/reviewed_tree_plan.hpp"
#include "native_filesystem.hpp"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
using namespace ck::files;
namespace {
unsigned checks = 0;
void check(bool ok, const char* message, int line) {
    ++checks;
    if (!ok) throw std::runtime_error(std::string("line ") + std::to_string(line) + ": " + message);
}
#define CHECK(x) check(bool(x), #x, __LINE__)
template<class T> T take(Observation<T> o) {
    if (!o.value()) throw std::runtime_error(o.unavailable_detail()->error.operation + " state=" + std::to_string(int(o.state())));
    return std::move(o).take_value();
}
NativeName name(std::string s) {
#ifdef _WIN32
    return *NativeName::from_windows(std::u16string(s.begin(), s.end()));
#else
    return *NativeName::from_posix(std::move(s));
#endif
}
#ifdef _WIN32
std::wstring extended(const std::filesystem::path& p) {
    auto s = p.native();
    std::replace(s.begin(), s.end(), L'/', L'\\');
    if (s.starts_with(L"\\\\?\\")) return s;
    if (s.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + s.substr(2);
    CHECK(s.size() > 2 && s[1] == L':' && s[2] == L'\\');
    return L"\\\\?\\" + s;
}
void mkdir_new(const std::filesystem::path& p) { CHECK(CreateDirectoryW(extended(p).c_str(), nullptr)); }
void write_file(const std::filesystem::path& p, const std::string& data, bool replace = false) {
    HANDLE h = CreateFileW(extended(p).c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, replace ? TRUNCATE_EXISTING : CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    CHECK(h != INVALID_HANDLE_VALUE);
    DWORD size = 0;
    CHECK(WriteFile(h, data.data(), DWORD(data.size()), &size, nullptr) && size == data.size());
    CHECK(CloseHandle(h));
}
void rename_exact(const std::filesystem::path& a, const std::filesystem::path& b) {
    CHECK(MoveFileExW(extended(a).c_str(), extended(b).c_str(), 0));
}
void cleanup(const std::filesystem::path& root) {
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW((extended(root) + L"\\*").c_str(), &data);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            std::wstring component(data.cFileName);
            if (component == L"." || component == L"..") continue;
            auto child = root / component;
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) cleanup(child);
            else if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) RemoveDirectoryW(extended(child).c_str());
            else DeleteFileW(extended(child).c_str());
        } while (FindNextFileW(find, &data));
        FindClose(find);
    }
    RemoveDirectoryW(extended(root).c_str());
}
#else
void mkdir_new(const std::filesystem::path& p) { CHECK(::mkdir(p.c_str(), 0700) == 0); }
void write_file(const std::filesystem::path& p, const std::string& data, bool replace = false) {
    int fd = ::open(p.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW | (replace ? O_TRUNC : O_CREAT | O_EXCL), 0600);
    if (fd < 0) std::fprintf(stderr, "fixture open failed: %s errno=%d\n", p.c_str(), errno);
    CHECK(fd >= 0);
    CHECK(::write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size()));
    CHECK(::close(fd) == 0);
}
void rename_exact(const std::filesystem::path& a, const std::filesystem::path& b) { CHECK(::rename(a.c_str(), b.c_str()) == 0); }
void cleanup(const std::filesystem::path& p) { std::filesystem::remove_all(p); }
#endif
struct Fixture {
    std::filesystem::path root;
    NativeFileSystem fs;
    std::shared_ptr<const DirectoryCursor> parent;
    static unsigned sequence;
    Fixture(bool long_path = false) {
#ifdef _WIN32
        const auto* tmp = std::getenv("TMPDIR");
        if (!tmp || !*tmp) tmp = std::getenv("TEMP");
        CHECK(tmp && *tmp && std::getenv("TEMP") && std::getenv("TMP"));
        root = std::filesystem::path(tmp);
        const auto* require_v = std::getenv("CK_FS_REQUIRE_V_DEV_DRIVE");
        if (require_v && std::string(require_v) == "1") {
            CHECK(GetFileAttributesW(L"V:\\") != INVALID_FILE_ATTRIBUTES);
            CHECK(root.native().starts_with(L"V:\\tmp\\") || root.native().starts_with(L"V:/tmp/"));
        }
        root /= L"reviewed-tree-tests-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(++sequence);
        mkdir_new(root);
#else
        const auto* tmp = std::getenv("TMPDIR"); CHECK(tmp && *tmp);
#ifdef __APPLE__
        CHECK(std::string(tmp).starts_with("/Volumes/S8T/tmp/") || std::string(tmp).starts_with("/Volumes/PRO-BLADE/tmp/"));
#endif
        std::string pattern = std::string(tmp) + "/reviewed-tree-tests.XXXXXX";
        CHECK(mkdtemp(pattern.data())); root = pattern;
#endif
        auto base = root;
        if (long_path) for (unsigned i = 0; i < 18; ++i) { base /= "long-component-0123456789"; mkdir_new(base); }
        parent = std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(base)));
        // Test paths and all Windows fixture I/O use extended native paths.
        work = base;
        mkdir_new(path("s")); mkdir_new(path("d")); mkdir_new(path("journals"));
    }
    ~Fixture() { parent.reset(); cleanup(root); }
    std::filesystem::path work;
    std::filesystem::path path(const char* p) const { return work / p; }
    ReviewedTreePlanRequest request(ComparisonProfile profile = ComparisonProfile::Copy) {
        ReviewedTreePlanRequest r;
        r.source_root = take(HeldChild::observe(parent, name("s")));
        r.destination_root = take(HeldChild::observe(parent, name("d")));
        r.destination_address = take(NativeAbsolutePath::from_host(path("d")));
        r.comparison.profile = profile; r.comparison.mode = ComparisonMode::CompleteDigest;
        r.copy_policy.allow_unhandled_metadata_loss = true;
        r.copy_policy.metadata_scope = RegularMetadataScope::OrdinaryCallerVisibleV1;
        r.journal_root = take(NativeAbsolutePath::from_host(path("journals")));
        r.open_journal = open_native_operation_journal_file;
        r.digest_chunk_bytes = 7;
        r.journal_id.bytes[0] = std::byte(static_cast<unsigned char>(++sequence));
        return r;
    }
    ReviewedTreePlanJob::Pointer job(ComparisonProfile p = ComparisonProfile::Copy) {
        return take(ReviewedTreePlanJob::create(request(p)));
    }
    bool exists(const char* p) const { return fs.inspect_basic(path(p)).value() != nullptr; }
    std::string read(const char* path_name) const {
        auto path = path_name;
        const bool incoming = path[0] == 's';
        auto dir = std::shared_ptr<const DirectoryCursor>(take(parent->open_directory_child(name(incoming ? "s" : "d"))));
        std::string relative(path + 2);
        for (;;) {
            auto pos = relative.find('/');
            if (pos == std::string::npos) break;
            dir = std::shared_ptr<const DirectoryCursor>(take(dir->open_directory_child(name(relative.substr(0, pos)))));
            relative.erase(0, pos + 1);
        }
        auto entry = take(dir->open_child(name(relative), EntryAccess::ContentRead));
        auto data = take(entry->read_content({4096}));
        return {reinterpret_cast<const char*>(data.bytes.data()), data.bytes.size()};
    }
};
unsigned Fixture::sequence = 0;
bool active(ReviewedTreeState s) { return s == ReviewedTreeState::Inventory || s == ReviewedTreeState::Revalidating || s == ReviewedTreeState::Executing; }
void run(ReviewedTreePlanJob& job) {
    for (unsigned i = 0; i < 100000 && active(job.state()); ++i) job.advance();
    CHECK(!active(job.state()));
}
void preview(ReviewedTreePlanJob& job) {
    run(job);
    if (job.state() != ReviewedTreeState::AwaitingReview && job.progress().failure)
        std::fprintf(stderr, "preview: %s\n", job.progress().failure->error.operation.c_str());
    CHECK(job.state() == ReviewedTreeState::AwaitingReview);
    CHECK(job.preview()); CHECK(job.progress().counts_complete);
}
ConflictRule keep_rule(ReviewedTreePlanJob& job, ConflictScope scope = ConflictScope::MatchingClassInJob) {
    ConflictRule r;
    r.plan = job.preview()->identity(); r.choice = ConflictChoice::KeepTarget;
    r.kind = ConflictClass::ExistingRegular; r.scope = scope;
    return r;
}
void start(ReviewedTreePlanJob& job) { CHECK(take(job.begin_execution(take(job.review({}))))); }
void test_copy(bool long_path = false) {
    Fixture f(long_path);
    mkdir_new(f.path("s/folder")); mkdir_new(f.path("s/folder/empty"));
    write_file(f.path("s/folder/data"), std::string(299, 'a'));
    write_file(f.path("s/zero"), "");
    auto job = f.job(); preview(*job);
    auto immutable = job->preview();
    CHECK(immutable->source_entries().size() == 4);
    CHECK(immutable->aggregate().source_bytes == 299);
    CHECK(!job->page(0, 0).value());
    CHECK(!job->page(0, ComparisonLimits::hard_max_page_rows + 1).value());
    CHECK(take(job->page(0, 1)).items.size() == 1);
    start(*job); run(*job);
    if (job->state() != ReviewedTreeState::Complete && job->progress().failure)
        std::fprintf(stderr, "copy: %s state=%d\n", job->progress().failure->error.operation.c_str(), int(job->state()));
    CHECK(job->state() == ReviewedTreeState::Complete);
    CHECK(job->preview() == immutable);
    CHECK(immutable->destination_entries().empty());
    CHECK(f.exists("d/folder/empty")); CHECK(f.read("d/folder/data") == std::string(299, 'a'));
    CHECK(f.read("d/zero").empty());
    auto progress = job->progress();
    CHECK(progress.known_copy_bytes == 299 && progress.copied_bytes == 299);
    CHECK(progress.completed_items == 4 && !progress.recovery_required);
    CHECK(!job->review({}).value()); // terminal review is rejected
}
void test_receipts_and_rules() {
    Fixture f;
    mkdir_new(f.path("s/folder")); mkdir_new(f.path("d/folder"));
    write_file(f.path("s/folder/a"), "source"); write_file(f.path("d/folder/a"), "target");
    write_file(f.path("s/b"), "source-b"); write_file(f.path("d/b"), "target-b");
    write_file(f.path("s/new"), "fresh");
    auto job = f.job(); preview(*job);
    CHECK(!job->review({}).value());
    auto rule = keep_rule(*job);
    auto receipt = take(job->review(std::span(&rule, 1)));
    const auto resolved = take(job->reviewed_page(receipt, 0, 32));
    for (const auto& item : resolved.items) {
        CHECK(!item.relative_components.empty());
        if (item.row.requires_review) CHECK(item.action == ReviewedTreeAction::Skip);
        auto binding = job->native_binding(item.row.token);
        CHECK(binding.value());
        CHECK(binding.value()->relative_components == item.relative_components);
    }
    // Mutating caller rules after review must not change the resolved receipt.
    rule.choice = ConflictChoice::UseSource;
    CHECK(take(job->begin_execution(receipt))); run(*job);
    CHECK(job->state() == ReviewedTreeState::Complete);
    CHECK(f.read("d/folder/a") == "target" && f.read("d/b") == "target-b" && f.read("d/new") == "fresh");
    CHECK(job->progress().skipped_items == 2);
    auto foreign = f.job(); preview(*foreign);
    CHECK(!foreign->begin_execution(receipt).value());
    CHECK(!foreign->review(std::span(&rule, 1)).value());
    auto selected = keep_rule(*foreign, ConflictScope::Selected);
    auto rows = take(foreign->page(0, 32)).items;
    for (const auto& item : rows) if (item.row.requires_review) selected.selected_rows.push_back(item.row.id);
    CHECK(foreign->review(std::span(&selected, 1)).value());
    auto bad_selected = selected; bad_selected.selected_rows = {999999};
    CHECK(!foreign->review(std::span(&bad_selected, 1)).value());
    auto bad_kind = keep_rule(*foreign); bad_kind.kind = static_cast<ConflictClass>(999);
    CHECK(!foreign->review(std::span(&bad_kind, 1)).value());
    auto narrow = keep_rule(*foreign, ConflictScope::Subtree);
    for (const auto& item : rows) if (item.row.relation == ComparisonRelation::DirectoryPair) narrow.subtree = item.row.relative_path;
    auto all = keep_rule(*foreign);
    std::vector<ConflictRule> rules{all, narrow};
    CHECK(foreign->review(rules).value());
}
void test_deletions_and_unsupported() {
    Fixture f;
    write_file(f.path("s/new"), "fresh"); write_file(f.path("d/extra"), "keep");
    auto mirror = f.job(ComparisonProfile::Mirror); preview(*mirror);
    CHECK(!mirror->review({}).value());
    CHECK(!mirror->review_deletions({}).value());
    std::vector<ComparisonDecisionToken> deletions;
    for (const auto& item : take(mirror->page(0, 32)).items) if (item.action == ReviewedTreeAction::RemoveFile) deletions.push_back(item.row.token);
    CHECK(deletions.size() == 1);
    auto deletion = take(mirror->review_deletions(deletions));
    auto receipt = take(mirror->review({}, deletion));
    auto begin = mirror->begin_execution(receipt);
#ifdef _WIN32
    CHECK(take(std::move(begin))); run(*mirror);
    CHECK(mirror->state() == ReviewedTreeState::Complete);
    CHECK(f.read("d/new") == "fresh" && !f.exists("d/extra"));
#else
    CHECK(begin.state() == ObservationState::Unsupported);
    CHECK(!f.exists("d/new") && f.read("d/extra") == "keep");
#endif
    auto foreign = f.job(ComparisonProfile::Mirror); preview(*foreign);
    CHECK(!foreign->review_deletions(deletions).value());
    CHECK(!foreign->review({}, deletion).value());
    deletions.push_back(deletions.front()); CHECK(!mirror->review_deletions(deletions).value());

    write_file(f.path("d/new"), "old", f.exists("d/new"));
    auto replace = f.job(ComparisonProfile::Sync); preview(*replace);
    auto reviewed = replace->review({});
    if (reviewed.value()) {
        auto replace_receipt = take(std::move(reviewed));
        auto replaced = replace->begin_execution(replace_receipt);
        CHECK(take(std::move(replaced))); run(*replace);
        CHECK(replace->state() == ReviewedTreeState::Complete && f.read("d/new") == "fresh");
        bool saw_retained = false;
        for (const auto& item : take(replace->page(0, 32)).items) if (item.action == ReviewedTreeAction::Replace) {
            CHECK(item.retained_name && item.retention_journal_id);
            auto d = take(f.parent->open_directory_child(name("d")));
            auto old = take(d->open_child(*item.retained_name, EntryAccess::ContentRead));
            auto bytes = take(old->read_content({1024}));
            CHECK(std::string(reinterpret_cast<const char*>(bytes.bytes.data()), bytes.bytes.size()) == "old");
            saw_retained = true;
        }
        CHECK(saw_retained);
    } else {
        CHECK(reviewed.state() == ObservationState::Unsupported);
        auto assessment = take(replace->assessment_page(0,32));
        bool retention_refused = false;
        for (const auto& item : assessment.items) if (item.action == ReviewedTreeAction::Replace) {
            CHECK(item.decision && item.decision->reason == ConflictRuleReason::RetentionUnavailable);
            CHECK(!item.facts.retained_target_available);
            CHECK(!(item.facts.allowed_choices & (std::uint64_t{1} << static_cast<unsigned>(ConflictChoice::KeepBothTarget))));
            retention_refused = true;
        }
        CHECK(retention_refused);
        CHECK(f.read("d/new") == "old");
    }

}
void test_changed_receipts() {
    for (unsigned variant = 0; variant < 6; ++variant) {
        Fixture f;
        mkdir_new(f.path("s/folder")); write_file(f.path("s/folder/a"), "original");
        auto job = f.job(); preview(*job); auto receipt = take(job->review({}));
        if (variant == 0) write_file(f.path("s/folder/a"), "modified", true);
        if (variant == 1) { rename_exact(f.path("s/folder/a"), f.path("s/old")); write_file(f.path("s/folder/a"), "original"); }
        if (variant == 2) write_file(f.path("d/foreign"), "target changed");
        if (variant == 3) { rename_exact(f.path("d"), f.path("old-d")); mkdir_new(f.path("d")); }
        if (variant == 4) { rename_exact(f.path("s/folder"), f.path("s/old")); mkdir_new(f.path("s/folder")); write_file(f.path("s/folder/a"), "original"); }
        if (variant == 5) { rename_exact(f.path("s"), f.path("old-s")); mkdir_new(f.path("s")); }
        CHECK(take(job->begin_execution(receipt))); run(*job);
        CHECK(job->state() == ReviewedTreeState::Failed);
        CHECK(job->progress().failure.has_value());
        CHECK(!f.exists("d/folder"));
    }
}
void test_overlap_collision_and_limits() {
    Fixture f;
    mkdir_new(f.path("s/inside"));
    auto r = f.request();
    auto s = std::shared_ptr<const DirectoryCursor>(take(f.parent->open_directory_child(name("s"))));
    r.destination_root = take(HeldChild::observe(s, name("inside")));
    auto overlap = take(ReviewedTreePlanJob::create(std::move(r))); run(*overlap);
    CHECK(overlap->state() == ReviewedTreeState::Failed);
    CHECK(overlap->progress().failure->error.code == static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe));
    auto same_root = f.request(); same_root.destination_root = same_root.source_root;
    CHECK(!ReviewedTreePlanJob::create(std::move(same_root)).value());
    write_file(f.path("s/Alpha"), "a"); write_file(f.path("d/alpha"), "b");
    auto collision = f.job(); run(*collision);
    CHECK(collision->state() == ReviewedTreeState::Failed);
    CHECK(collision->progress().failure->error.operation == "reviewed_tree.cross_tree_case_collision");
    auto bad = f.request(); bad.digest_chunk_bytes = 0; CHECK(!ReviewedTreePlanJob::create(std::move(bad)).value());
    bad = f.request(); bad.comparison.profile = ComparisonProfile::Move;
    CHECK(ReviewedTreePlanJob::create(std::move(bad)).state() == ObservationState::Unsupported);
    bad = f.request(); bad.limits.max_entries = 1;
    auto limit = take(ReviewedTreePlanJob::create(std::move(bad))); run(*limit);
    CHECK(limit->state() == ReviewedTreeState::Failed);
}
void test_cancellation() {
    Fixture f;
    write_file(f.path("s/a"), "data");
    auto inventory = f.job(); std::stop_source cancel; cancel.request_stop();
    CHECK(inventory->advance(cancel.get_token()) == ReviewedTreeState::Cancelled);
    CHECK(!inventory->progress().counts_complete && !f.exists("d/a"));
    auto reviewed = f.job(); preview(*reviewed);
    CHECK(reviewed->advance(cancel.get_token()) == ReviewedTreeState::Cancelled);
    CHECK(!f.exists("d/a"));
    mkdir_new(f.path("s/folder"));
    auto execution = f.job(); preview(*execution); start(*execution);
    for (unsigned i = 0; i < 10000 && execution->progress().completed_items == 0 && active(execution->state()); ++i) execution->advance();
    CHECK(execution->progress().completed_items > 0);
    execution->advance(cancel.get_token());
    CHECK(execution->state() == ReviewedTreeState::Partial);
    CHECK(execution->progress().partial && execution->progress().recovery_required);
}
void test_changes_during_execution() {
    Fixture f;
    write_file(f.path("s/a"), std::string(333, 'x'));
    auto copy = f.job(); preview(*copy); start(*copy);
    for (unsigned i = 0; i < 10000 && active(copy->state()); ++i) {
        copy->advance();
        auto item = take(copy->page(0, 1)).items.front();
        if (item.journal_name) break;
    }
    CHECK(take(copy->page(0, 1)).items.front().journal_name.has_value());
    write_file(f.path("s/a"), std::string(333, 'y'), true);
    run(*copy);
    CHECK(copy->state() == ReviewedTreeState::NeedsReconciliation);
    CHECK(copy->progress().recovery_required && !f.exists("d/a"));
    CHECK(f.read("s/a") == std::string(333, 'y'));
    CHECK(take(copy->page(0, 1)).items.front().recovery_required);

    Fixture g;
    mkdir_new(g.path("s/folder")); write_file(g.path("s/folder/a"), "content");
    auto ancestor = g.job(); preview(*ancestor); start(*ancestor);
    for (unsigned i = 0; i < 10000 && ancestor->progress().completed_items == 0 && active(ancestor->state()); ++i) ancestor->advance();
    CHECK(ancestor->progress().completed_items == 1);
    rename_exact(g.path("d/folder"), g.path("d/old")); mkdir_new(g.path("d/folder"));
    run(*ancestor);
    CHECK(ancestor->state() == ReviewedTreeState::Partial);
    CHECK(!g.exists("d/folder/a"));
}
void test_parent_move_into_source() {
    Fixture f;
    mkdir_new(f.path("q")); mkdir_new(f.path("q/target"));
    auto r = f.request();
    auto q = std::shared_ptr<const DirectoryCursor>(take(f.parent->open_directory_child(name("q"))));
    r.destination_root = take(HeldChild::observe(q, name("target")));
    auto job = take(ReviewedTreePlanJob::create(std::move(r))); preview(*job);
    auto receipt = take(job->review({}));
    rename_exact(f.path("q"), f.path("s/q"));
    CHECK(take(job->begin_execution(receipt))); run(*job);
    CHECK(job->state() == ReviewedTreeState::Failed);
    CHECK(job->progress().failure->error.operation == "reviewed_tree.overlap");
}
void test_assessment_and_receipt_revocation() {
    Fixture f; write_file(f.path("s/a"), "incoming"); write_file(f.path("d/a"), "existing");
    auto job = f.job(); preview(*job);
    auto unresolved = take(job->assess_rules({}, 0, 1));
    CHECK(unresolved.items.front().decision.has_value());
    CHECK(unresolved.items.front().decision->state == ConflictRuleState::NeedsReview);
    CHECK(unresolved.items.front().decision->reason == ConflictRuleReason::NoMatchingRule);
    CHECK(!job->review({}).value());
    auto keep = keep_rule(*job);
    auto receipt = take(job->review(std::span(&keep, 1)));
    auto unchanged = take(job->assess_rules(std::span(&keep, 1), 0, 1));
    CHECK(unchanged.items.front().decision->rule_index == 0);
    CHECK(unchanged.items.front().action == ReviewedTreeAction::Skip);
    auto replace = keep; replace.choice = ConflictChoice::UseSource;
    auto changed = take(job->assess_rules(std::span(&replace, 1), 0, 1));
    CHECK(changed.items.front().action == ReviewedTreeAction::Replace);
    CHECK(job->begin_execution(receipt).state() == ObservationState::Changed);
    auto invalid_rule = keep; invalid_rule.kind = static_cast<ConflictClass>(999);
    auto invalid = take(job->assess_rules(std::span(&invalid_rule, 1), 0, 1));
    CHECK(invalid.items.front().decision->state == ConflictRuleState::Invalid);
    CHECK(invalid.items.front().decision->reason == ConflictRuleReason::InvalidRule);
    CHECK(f.read("d/a") == "existing");
    auto current = take(job->review(std::span(&keep, 1)));
    CHECK(take(job->begin_execution(current))); run(*job);
    CHECK(job->state() == ReviewedTreeState::Complete);
}
#ifndef _WIN32
void test_lossless_native_names() {
    std::vector<std::string> native_names{std::string("\xc3\xa9")};
#ifdef __linux__
    native_names.push_back(std::string("invalid-\xff"));
#endif
    for (const std::string& native : native_names) {
        Fixture f; auto source = std::filesystem::path("s") / native;
        write_file(f.work / source, "exact native payload");
        auto job = f.job(); preview(*job);
        const auto row = take(job->page(0, 1)).items.front();
        const auto components = take(job->native_components(row.row.id, true));
        CHECK(components.size() == 1 && *components.front().posix_bytes() == native);
        CHECK(job->native_components(row.row.id, false).state() == ObservationState::Gone);
        start(*job); run(*job);
        CHECK(job->state() == ReviewedTreeState::Complete);
        auto directory = std::shared_ptr<const DirectoryCursor>(take(f.parent->open_directory_child(name("d"))));
        auto held = take(directory->open_child(*NativeName::from_posix(native), EntryAccess::ContentRead));
        auto bytes = take(held->read_content({1024}));
        CHECK(std::string(reinterpret_cast<const char*>(bytes.bytes.data()), bytes.bytes.size()) == "exact native payload");
    }
    Fixture f; write_file(f.work / "s" / "\xc3\xa9", "one"); write_file(f.work / "s" / "\xce\xb2", "two");
    auto job = f.job(); preview(*job);
    auto receipt = take(job->review({}));
    const auto started = job->begin_execution(receipt);
    if (!started.value()) {
        CHECK(started.state() == ObservationState::Unsupported);
        auto target = take(f.parent->open_directory_child(name("d")));
        CHECK(target->read(1).state == DirectoryReadState::End);
    } else { run(*job); CHECK(job->state() == ReviewedTreeState::Complete); }
}
#endif
void test_retention_capabilities_and_incoming_copy() {
    Fixture f;
    write_file(f.path("s/a"), "incoming data"); write_file(f.path("d/a"), "existing data");
    auto job = f.job(); preview(*job);
    const auto token = take(job->page(0, 1)).items.front().row.token;
    auto rule = keep_rule(*job); rule.choice = ConflictChoice::UseSource;
    auto replace = take(job->assess_rules(std::span(&rule, 1), 0, 1));
    const auto& fact = replace.items.front().facts;
    const auto bit = [](ConflictChoice choice) { return std::uint64_t{1} << static_cast<unsigned>(choice); };
    CHECK(fact.source_kind == ObjectKind::RegularFile && fact.destination_kind == ObjectKind::RegularFile);
    CHECK(fact.conflict_class == ConflictClass::ExistingRegular);
    CHECK(fact.allowed_choices & bit(ConflictChoice::KeepBothIncoming));
    if (!fact.retained_target_available) {
        CHECK(!(fact.allowed_choices & bit(ConflictChoice::UseSource)));
        CHECK(!(fact.allowed_choices & bit(ConflictChoice::KeepBothTarget)));
        CHECK(replace.items.front().decision->state == ConflictRuleState::NeedsReview);
        CHECK(replace.items.front().decision->reason == ConflictRuleReason::RetentionUnavailable);
        rule.choice = ConflictChoice::KeepBothTarget;
        // Retention failure is visible even before the user supplies a name.
        auto missing_name = take(job->assess_rules(std::span(&rule, 1), 0, 1));
        CHECK(missing_name.items.front().decision->reason == ConflictRuleReason::RetentionUnavailable);
        ReviewedTreeNameChoice keep_old{token, name("old-version"), ReviewedTreeNameSide::Target};
        auto named = take(job->assess_rules(std::span(&rule, 1), std::span(&keep_old, 1), 0, 1));
        CHECK(named.items.front().decision->reason == ConflictRuleReason::RetentionUnavailable);
        CHECK(!job->review(std::span(&rule, 1), std::span(&keep_old, 1)).value());
    }
    // The assessment owns facts only. A temporary DELETE/data-write guard
    // must have been released before control returns to the frontend.
#ifdef _WIN32
    HANDLE mutable_target = CreateFileW(extended(f.path("d/a")).c_str(), GENERIC_READ | GENERIC_WRITE | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    CHECK(mutable_target != INVALID_HANDLE_VALUE);
    CHECK(CloseHandle(mutable_target));
#else
    int mutable_target = ::open(f.path("d/a").c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    CHECK(mutable_target >= 0); CHECK(::close(mutable_target) == 0);
#endif
    rule.choice = ConflictChoice::KeepBothIncoming;
    ReviewedTreeNameChoice incoming{token, name("incoming-copy"), ReviewedTreeNameSide::Incoming};
    auto assessed = take(job->assess_rules(std::span(&rule, 1), std::span(&incoming, 1), 0, 1));
    CHECK(assessed.items.front().decision->state == ConflictRuleState::Apply);
    CHECK(assessed.items.front().action == ReviewedTreeAction::Copy);
    CHECK(assessed.items.front().facts.allowed_choices & bit(ConflictChoice::KeepBothIncoming));
    auto receipt = take(job->review(std::span(&rule, 1), std::span(&incoming, 1)));
    CHECK(take(job->begin_execution(receipt))); run(*job);
    CHECK(job->state() == ReviewedTreeState::Complete);
    CHECK(f.read("d/a") == "existing data");
    CHECK(f.read("d/incoming-copy") == "incoming data");
    CHECK(take(job->page(0, 1)).items.front().resulting_name == name("incoming-copy"));
}
void test_profiles() {
    for (auto profile : {ComparisonProfile::Update, ComparisonProfile::MissingOnly, ComparisonProfile::Sync, ComparisonProfile::Mirror, ComparisonProfile::Compare}) {
        Fixture f; write_file(f.path("s/a"), "content");
        auto job = f.job(profile); preview(*job); start(*job); run(*job);
        CHECK(job->state() == ReviewedTreeState::Complete);
        CHECK(f.exists("d/a") == (profile != ComparisonProfile::Compare));
    }
}
#ifndef _WIN32
void test_exact_names_links_and_fifo() {
    Fixture f;
    write_file(f.path("s/back\\slash"), "exact");
    auto exact = f.job(); preview(*exact); start(*exact); run(*exact);
    CHECK(exact->state() == ReviewedTreeState::Complete && f.read("d/back\\slash") == "exact");
    CHECK(::symlink("back\\slash", f.path("s/link").c_str()) == 0);
    auto link = f.job(); run(*link);
    CHECK(link->state() == ReviewedTreeState::Failed && link->progress().failure->state == ObservationState::Unsupported);
    CHECK(::unlink(f.path("s/link").c_str()) == 0);
    CHECK(::mkfifo(f.path("s/pipe").c_str(), 0600) == 0);
    auto fifo = f.job(); run(*fifo);
    CHECK(fifo->state() == ReviewedTreeState::Failed && fifo->progress().failure->state == ObservationState::Unsupported);
}
#endif
}
int main() {
    try {
        test_copy(); test_copy(true); test_receipts_and_rules(); test_deletions_and_unsupported();
        test_changed_receipts(); test_overlap_collision_and_limits(); test_cancellation(); test_profiles();
        test_changes_during_execution(); test_parent_move_into_source(); test_assessment_and_receipt_revocation(); test_retention_capabilities_and_incoming_copy();
#ifndef _WIN32
        test_exact_names_links_and_fifo(); test_lossless_native_names();
#endif
        std::printf("reviewed_tree_plan: %u checks passed\n", checks);
        return 0;
    } catch (const std::exception& e) { std::fprintf(stderr, "reviewed_tree_plan: %s\n", e.what()); return 1; }
}
