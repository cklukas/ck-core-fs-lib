// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_file_engine.h"

// Keep every check (including calls with side effects) active in RelWithDebInfo.
#undef NDEBUG
#include <cassert>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <memory>
#include <thread>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {
constexpr size_t block_size = 64 * 1024;
constexpr uint64_t fixture_size = 80 * 1024 * 1024;
using Block = std::array<unsigned char, block_size>;

#ifdef _WIN32
std::wstring extended(const std::string &path) {
    const int units = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.c_str(), -1, nullptr, 0);
    assert(units > 1);
    std::wstring wide(static_cast<size_t>(units), L'\0');
    assert(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.c_str(), -1, wide.data(), units) == units);
    wide.pop_back();
    for (auto &unit : wide) if (unit == L'/') unit = L'\\';
    if (wide.starts_with(L"\\\\?\\")) return wide;
    if (wide.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + wide.substr(2);
    assert(wide.size() >= 3 && wide[1] == L':' && wide[2] == L'\\');
    return L"\\\\?\\" + wide;
}
void make_directory(const std::string &path) {
    assert(CreateDirectoryW(extended(path).c_str(), nullptr));
}
class File {
    HANDLE handle_;
public:
    File(const std::string &path, bool create)
        : handle_(CreateFileW(extended(path).c_str(), create ? GENERIC_WRITE : GENERIC_READ,
              FILE_SHARE_READ, nullptr, create ? CREATE_NEW : OPEN_EXISTING,
              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)) {
        assert(handle_ != INVALID_HANDLE_VALUE);
        FILE_ATTRIBUTE_TAG_INFO info{};
        assert(GetFileInformationByHandleEx(handle_, FileAttributeTagInfo, &info, sizeof(info)));
        assert(!(info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT));
    }
    ~File() { assert(CloseHandle(handle_)); }
    File(const File &) = delete;
    File &operator=(const File &) = delete;
    void write(const Block &block) {
        DWORD count = 0;
        assert(WriteFile(handle_, block.data(), static_cast<DWORD>(block.size()), &count, nullptr));
        assert(count == block.size());
    }
    size_t read(Block &block) {
        DWORD count = 0;
        assert(ReadFile(handle_, block.data(), static_cast<DWORD>(block.size()), &count, nullptr));
        return count;
    }
};
unsigned long process_id() { return GetCurrentProcessId(); }
#else
void make_directory(const std::string &path) { assert(mkdir(path.c_str(), 0700) == 0); }
class File {
    int fd_;
public:
    File(const std::string &path, bool create)
        : fd_(open(path.c_str(), (create ? O_WRONLY | O_CREAT | O_EXCL : O_RDONLY) | O_CLOEXEC | O_NOFOLLOW, 0600)) {
        assert(fd_ >= 0);
        struct stat info{};
        assert(fstat(fd_, &info) == 0 && S_ISREG(info.st_mode));
    }
    ~File() { assert(close(fd_) == 0); }
    File(const File &) = delete;
    File &operator=(const File &) = delete;
    void write(const Block &block) {
        size_t offset = 0;
        while (offset < block.size()) {
            const auto count = ::write(fd_, block.data() + offset, block.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            assert(count > 0);
            offset += static_cast<size_t>(count);
        }
    }
    size_t read(Block &block) {
        size_t offset = 0;
        while (offset < block.size()) {
            const auto count = ::read(fd_, block.data() + offset, block.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            assert(count >= 0);
            if (count == 0) break;
            offset += static_cast<size_t>(count);
        }
        return offset;
    }
};
unsigned long process_id() { return static_cast<unsigned long>(getpid()); }
#endif

// The root is created exclusively for this run. Retain its native handle so
// cleanup is confined to that scope, and never traverse a reparse point/link.
class OwnedTree {
    std::string path_;
#ifdef _WIN32
    HANDLE root_;
    static HANDLE open(const std::wstring &path) {
        const auto handle = CreateFileW(path.c_str(), DELETE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        assert(handle != INVALID_HANDLE_VALUE);
        return handle;
    }
    static void remove_contents(HANDLE handle, const std::wstring &path) {
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        assert(GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes)));
        assert(!(attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT));
        if (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            for (;;) {
                alignas(FILE_ID_EXTD_DIR_INFO) std::array<unsigned char, 64 * 1024> buffer{};
                if (!GetFileInformationByHandleEx(handle, FileIdExtdDirectoryRestartInfo,
                        buffer.data(), static_cast<DWORD>(buffer.size()))) {
                    assert(GetLastError() == ERROR_NO_MORE_FILES);
                    break;
                }
                bool found = false;
                auto *entry = reinterpret_cast<FILE_ID_EXTD_DIR_INFO *>(buffer.data());
                for (;;) {
                    const std::wstring name(entry->FileName, entry->FileNameLength / sizeof(wchar_t));
                    if (name != L"." && name != L"..") {
                        assert(name.find_first_of(L"\\/") == std::wstring::npos);
                        const auto child_path = path + L"\\" + name;
                        const auto child = open(child_path);
                        FILE_ID_INFO identity{};
                        assert(GetFileInformationByHandleEx(child, FileIdInfo, &identity, sizeof(identity)));
                        assert(std::memcmp(identity.FileId.Identifier, entry->FileId.Identifier,
                            sizeof(identity.FileId.Identifier)) == 0);
                        remove_contents(child, child_path);
                        assert(CloseHandle(child));
                        found = true;
                    }
                    if (!entry->NextEntryOffset) break;
                    entry = reinterpret_cast<FILE_ID_EXTD_DIR_INFO *>(
                        reinterpret_cast<unsigned char *>(entry) + entry->NextEntryOffset);
                }
                if (!found) break;
            }
        }
        FILE_DISPOSITION_INFO disposition{TRUE};
        assert(SetFileInformationByHandle(handle, FileDispositionInfo, &disposition, sizeof(disposition)));
    }
#else
    int root_;
    static void remove_contents(int fd) {
        auto *directory = fdopendir(dup(fd));
        assert(directory);
        errno = 0;
        while (auto *entry = readdir(directory)) {
            const std::string name(entry->d_name);
            if (name == "." || name == "..") continue;
            struct stat info{};
            assert(fstatat(fd, name.c_str(), &info, AT_SYMLINK_NOFOLLOW) == 0);
            if (S_ISDIR(info.st_mode)) {
                const int child = openat(fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
                assert(child >= 0);
                struct stat held{};
                assert(fstat(child, &held) == 0 && held.st_dev == info.st_dev && held.st_ino == info.st_ino);
                remove_contents(child);
                assert(close(child) == 0);
                assert(unlinkat(fd, name.c_str(), AT_REMOVEDIR) == 0);
            } else {
                assert(S_ISREG(info.st_mode));
                assert(unlinkat(fd, name.c_str(), 0) == 0);
            }
            errno = 0;
        }
        assert(errno == 0);
        assert(closedir(directory) == 0);
    }
#endif
public:
    explicit OwnedTree(const std::string &path) : path_(path) {
#ifdef _WIN32
        root_ = open(extended(path));
#else
        root_ = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        assert(root_ >= 0);
#endif
    }
    ~OwnedTree() {
#ifdef _WIN32
        remove_contents(root_, extended(path_));
        assert(CloseHandle(root_));
#else
        remove_contents(root_);
        assert(close(root_) == 0);
        assert(rmdir(path_.c_str()) == 0);
#endif
    }
    OwnedTree(const OwnedTree &) = delete;
    OwnedTree &operator=(const OwnedTree &) = delete;
};

Block pattern(uint64_t index) {
    Block block{};
    for (size_t i = 0; i < block.size(); ++i)
        block[i] = static_cast<unsigned char>((i * 37 + index * 13 + (index >> 8)) & 255);
    return block;
}
void create_source(const std::string &path) {
    File file(path, true);
    for (uint64_t index = 0; index < fixture_size / block_size; ++index) file.write(pattern(index));
}
void verify_contents(const std::string &path) {
    File file(path, false);
    Block block{};
    for (uint64_t index = 0; index < fixture_size / block_size; ++index) {
        assert(file.read(block) == block.size());
        assert(block == pattern(index));
    }
    assert(file.read(block) == 0);
}

struct Error {
    ckfe_error value{};
    Error() { ckfe_error_init(&value); }
    ~Error() { ckfe_error_free(&value); }
};
void ok(ckfe_api_status status, const Error &error) {
    if (status != CKFE_API_OK)
        std::fprintf(stderr, "API status=%s domain=%d code=%lld operation=%s\n",
            ckfe_api_status_name(status), static_cast<int>(error.value.domain),
            static_cast<long long>(error.value.code), error.value.operation ? error.value.operation : "");
    assert(status == CKFE_API_OK);
}
bool active(ckfe_job_state state) { return state == CKFE_JOB_READY || state == CKFE_JOB_RUNNING; }

struct Progress {
    uint64_t bytes = 0;
    uint64_t items = 0;
    bool known = false;
    void check(const ckfe_job_snapshot &snapshot) {
        assert(snapshot.processed_bytes >= bytes && snapshot.processed_bytes <= fixture_size);
        assert(snapshot.processed_items >= items && snapshot.processed_items <= 1);
        assert(snapshot.total_items_known && snapshot.total_items == 1);
        if (known) assert(snapshot.total_bytes_known);
        if (snapshot.total_bytes_known) {
            assert(snapshot.total_bytes == fixture_size);
            known = true;
        }
        bytes = snapshot.processed_bytes;
        items = snapshot.processed_items;
    }
};

struct Events {
    uint64_t sequence = 0;
    uint64_t count = 0;
    uint64_t lost = 0;
    ckfe_job_state last_state = CKFE_JOB_READY;
    Progress progress;
    void drain(ckfe_job *job) {
        Error error;
        std::array<ckfe_job_event, 7> events{}; // Exercise partial drains as well as overflow.
        size_t received = 0;
        uint64_t coalesced = 0;
        ok(ckfe_job_drain_events(job, events.data(), events.size(), &received, &coalesced, &error.value), error);
        assert(received <= events.size());
        lost += coalesced;
        for (size_t i = 0; i < received; ++i) {
            assert(events[i].sequence > sequence);
            sequence = events[i].sequence;
            progress.check(events[i].snapshot);
            last_state = events[i].snapshot.state;
        }
        count += received;
    }
    void finish(ckfe_job *job, ckfe_job_state terminal) {
        uint64_t previous;
        do { previous = count; drain(job); } while (previous != count);
        assert(count > 0 && last_state == terminal);
        // Every published event was either delivered once or explicitly coalesced.
        assert(sequence == count + lost);
        Error error;
        size_t received = 99;
        uint64_t coalesced = 99;
        ok(ckfe_job_drain_events(job, nullptr, 0, &received, &coalesced, &error.value), error);
        assert(received == 0 && coalesced == 0);
    }
};

ckfe_job_snapshot poll(ckfe_job *job) {
    Error error;
    ckfe_job_snapshot snapshot{};
    ok(ckfe_job_poll(job, &snapshot, &error.value), error);
    if (!active(snapshot.state) && snapshot.state != CKFE_JOB_COMPLETED && snapshot.state != CKFE_JOB_CANCELLED)
        std::fprintf(stderr, "Unexpected job state=%s domain=%d code=%lld operation=%s\n",
            ckfe_job_state_name(snapshot.state), static_cast<int>(error.value.domain),
            static_cast<long long>(error.value.code), error.value.operation ? error.value.operation : "");
    return snapshot;
}
ckfe_job_snapshot wait(ckfe_job *job, Events *events) {
    Progress progress;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(90);
    for (;;) {
        const auto snapshot = poll(job);
        progress.check(snapshot);
        if (events) events->drain(job);
        if (!active(snapshot.state)) return snapshot;
        assert(std::chrono::steady_clock::now() < deadline);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

struct Fixture {
    std::string root;
    std::string source_path;
    std::string destination_path;
    std::string journal;
    std::unique_ptr<OwnedTree> owned;
    ckfe_engine *engine = nullptr;
    ckfe_directory *source_directory = nullptr;
    ckfe_directory *destination = nullptr;
    ckfe_entry *source = nullptr;
    explicit Fixture(const std::string &parent)
        : root(parent + "/lifecycle-" + std::to_string(process_id()) + "-" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())),
          source_path(root + "/source"), destination_path(root + "/destination"), journal(root + "/journal") {
        make_directory(root);
        owned = std::make_unique<OwnedTree>(root);
        make_directory(source_path);
        make_directory(destination_path);
        make_directory(journal);
        create_source(source_path + "/payload.bin");
        Error error;
        ok(ckfe_engine_create(&engine), error);
        ok(ckfe_directory_open_utf8(engine, source_path.c_str(), 0, &source_directory, &error.value), error);
        ok(ckfe_directory_open_utf8(engine, destination_path.c_str(), 0, &destination, &error.value), error);
        ok(ckfe_entry_open_utf8(source_directory, "payload.bin", &source, &error.value), error);
    }
    ~Fixture() {
        ckfe_entry_destroy(source);
        ckfe_directory_destroy(source_directory);
        ckfe_directory_destroy(destination);
        ckfe_engine_destroy(engine);
    }
    ckfe_job *start(const char *name) {
        Error error;
        ckfe_job *job = nullptr;
        // Lifecycle qualification explicitly consents to metadata loss. Strict policy
        // rejection is covered separately; never turn unsupported into a skipped test.
        ok(ckfe_job_start_copy_regular(source, destination, name, journal.c_str(), 1, &job, &error.value), error);
        assert(job);
        return job;
    }
    void verify_source() {
        verify_contents(source_path + "/payload.bin");
        Error error;
        ckfe_metadata metadata{};
        ok(ckfe_entry_metadata(source, &metadata, &error.value), error);
        assert(metadata.available_fields & CKFE_METADATA_LOGICAL_SIZE);
        assert(metadata.logical_size == fixture_size);
    }
};

void completed_copy(Fixture &fixture, bool concurrent_drain) {
    const char *name = concurrent_drain ? "concurrent.bin" : "overflow.bin";
    auto *job = fixture.start(name);
    Events events;
    const auto terminal = wait(job, concurrent_drain ? &events : nullptr);
    assert(terminal.state == CKFE_JOB_COMPLETED);
    assert(terminal.total_bytes_known && terminal.total_bytes == fixture_size);
    assert(terminal.processed_bytes == fixture_size && terminal.processed_items == 1);
    events.finish(job, CKFE_JOB_COMPLETED);
    if (!concurrent_drain) assert(events.lost > 0 && events.count == 64);
    const auto after_drain = poll(job);
    assert(after_drain.state == terminal.state && after_drain.processed_bytes == terminal.processed_bytes);
    ckfe_job_destroy(job);
    verify_contents(fixture.destination_path + "/" + name);
    fixture.verify_source();
    std::printf("copy %s events=%llu coalesced=%llu bytes=%llu\n", name,
        static_cast<unsigned long long>(events.count), static_cast<unsigned long long>(events.lost),
        static_cast<unsigned long long>(terminal.processed_bytes));
}
void cancelled_copy(Fixture &fixture) {
    auto *job = fixture.start("cancelled.bin");
    assert(active(poll(job).state));
    ckfe_job_cancel(job);
    ckfe_job_cancel(job); // Repeated cancellation must remain safe.
    Events events;
    const auto terminal = wait(job, &events);
    assert(terminal.state == CKFE_JOB_CANCELLED);
    events.finish(job, terminal.state);
    ckfe_job_destroy(job);
    fixture.verify_source();
}
void destroy_running(Fixture &fixture) {
    // Repeated start/destroy covers worker ownership and cancellation during teardown.
    for (unsigned iteration = 0; iteration != 4; ++iteration) {
        const auto name = "destroy-" + std::to_string(iteration) + ".bin";
        auto *job = fixture.start(name.c_str());
        assert(active(poll(job).state));
        ckfe_job_destroy(job);
    }
    fixture.verify_source();
}
} // namespace

int main(int argc, char **argv) {
    assert(argc == 2 && argv[1][0]);
    std::printf("job lifecycle fixture parent: %s\n", argv[1]);
    Fixture fixture(argv[1]); // Parent is explicitly created by CMake under build/tasks.
    completed_copy(fixture, false);
    completed_copy(fixture, true);
    cancelled_copy(fixture);
    destroy_running(fixture);
    std::puts("native copy, progress, events, cancellation, and worker teardown passed");
}
