// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// Standalone installed-library qualification. See tools/platform_qualification.py.
#include "ck_file_engine.h"
#include "native_filesystem.hpp"
#include <algorithm>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace ck::files;
namespace {
void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
struct Gap : std::runtime_error { using std::runtime_error::runtime_error; };
template<class T> T take(Observation<T> value) {
    if (const auto* e = value.unavailable_detail())
        throw std::runtime_error("native state=" + std::to_string(int(e->state)) +
            " domain=" + std::to_string(int(e->error.domain)) + " code=" +
            std::to_string(e->error.code) + " operation=" + e->error.operation);
    return std::move(value).take_value();
}
struct Error {
    ckfe_error value{};
    ~Error() { ckfe_error_free(&value); }
    void ok(ckfe_api_status status) const {
        require(status == CKFE_API_OK, "C API status=" + std::to_string(status) +
            " state=" + std::to_string(value.state) + " domain=" + std::to_string(value.domain) +
            " code=" + std::to_string(value.code) + " operation=" +
            (value.operation ? value.operation : ""));
    }
};
using Engine = std::unique_ptr<ckfe_engine, decltype(&ckfe_engine_destroy)>;
using Directory = std::unique_ptr<ckfe_directory, decltype(&ckfe_directory_destroy)>;
using Entry = std::unique_ptr<ckfe_entry, decltype(&ckfe_entry_destroy)>;
#ifdef _WIN32
using Path = std::wstring;
const Path sep = L"\\";
Path wide(const char* text) {
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, nullptr, 0);
    require(n > 1, "invalid UTF-8 command argument");
    Path result(n, L'\0');
    require(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, result.data(), n) == n, "UTF-8 conversion");
    result.pop_back();
    std::replace(result.begin(), result.end(), L'/', L'\\');
    return result;
}
Path extended(const Path& p) {
    if (p.starts_with(L"\\\\?\\")) return p;
    if (p.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + p.substr(2);
    require(p.size() > 2 && p[1] == L':' && p[2] == L'\\', "absolute DOS or UNC path required");
    return L"\\\\?\\" + p;
}
std::u16string units(const Path& p) { return {p.begin(), p.end()}; }
NativeName name(const Path& p) { auto n = NativeName::from_windows(units(p)); require(n.has_value(), "native name"); return *n; }
void mkdir_new(const Path& p) {
    const bool ok = CreateDirectoryW(extended(p).c_str(), nullptr) != 0;
    const DWORD code = ok ? ERROR_SUCCESS : GetLastError();
    require(ok, "CreateDirectoryW code=" + std::to_string(code));
}
void file_new(const Path& p, size_t size) {
    HANDLE h = CreateFileW(extended(p).c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    require(h != INVALID_HANDLE_VALUE, "CreateFileW fixture code=" + std::to_string(GetLastError()));
    std::string data(size, 'q'); DWORD written = 0;
    const bool ok = WriteFile(h, data.data(), static_cast<DWORD>(size), &written, nullptr) && written == size;
    CloseHandle(h); require(ok, "fixture WriteFile");
}
void rename_exact(const Path& a, const Path& b) {
    const bool ok = MoveFileExW(extended(a).c_str(), extended(b).c_str(), 0) != 0;
    const DWORD code = ok ? ERROR_SUCCESS : GetLastError();
    require(ok, "MoveFileExW code=" + std::to_string(code));
}
bool remove_exact(const Path& p, bool directory) { return directory ? RemoveDirectoryW(extended(p).c_str()) != 0 : DeleteFileW(extended(p).c_str()) != 0; }
Path ascii(const char* p) { return wide(p); }
Directory directory(ckfe_engine* e, const Path& p, int follow = 0) {
    Error error; ckfe_directory* out = nullptr; auto u = units(p);
    error.ok(ckfe_directory_open_utf16(e, reinterpret_cast<const uint16_t*>(u.data()), u.size(), follow, &out, &error.value));
    return {out, ckfe_directory_destroy};
}
Entry entry(ckfe_directory* d, const Path& p) {
    Error error; ckfe_entry* out = nullptr; auto u = units(p);
    error.ok(ckfe_entry_open_utf16(d, reinterpret_cast<const uint16_t*>(u.data()), u.size(), &out, &error.value));
    return {out, ckfe_entry_destroy};
}
#else
using Path = std::string;
const Path sep = "/";
Path ascii(const char* p) { return p; }
NativeName name(const Path& p) { auto n = NativeName::from_posix(p); require(n.has_value(), "native name"); return *n; }
void mkdir_new(const Path& p) {
    const int result = ::mkdir(p.c_str(), 0700); const int code = result == 0 ? 0 : errno;
    require(result == 0, "mkdir errno=" + std::to_string(code));
}
void file_new(const Path& p, size_t size) {
    int fd = ::open(p.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    require(fd >= 0, "open fixture errno=" + std::to_string(errno));
    std::string data(size, 'q'); size_t offset = 0;
    while (offset < size) {
        auto n = ::write(fd, data.data() + offset, size - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ::close(fd); throw std::runtime_error("fixture write"); }
        offset += size_t(n);
    }
    require(::close(fd) == 0, "close fixture");
}
void rename_exact(const Path& a, const Path& b) { require(::rename(a.c_str(), b.c_str()) == 0, "rename fixture"); }
bool remove_exact(const Path& p, bool directory) { return (directory ? ::rmdir(p.c_str()) : ::unlink(p.c_str())) == 0; }
Directory directory(ckfe_engine* e, const Path& p, int follow = 0) {
    Error error; ckfe_directory* out = nullptr;
    error.ok(ckfe_directory_open_utf8(e, p.c_str(), follow, &out, &error.value));
    return {out, ckfe_directory_destroy};
}
Entry entry(ckfe_directory* d, const Path& p) {
    Error error; ckfe_entry* out = nullptr;
    error.ok(ckfe_entry_open_utf8(d, p.c_str(), &out, &error.value));
    return {out, ckfe_entry_destroy};
}
#endif
// Cleanup only the exact entries recorded by this process, in reverse order.
// Never enumerate or recursively remove a caller's tree; links are removed as links.
struct Fixtures {
    std::vector<std::pair<Path, bool>> created;
    Path root;
    explicit Fixtures(Path p) : root(std::move(p)) { dir(root); }
    ~Fixtures() { if (!created.empty()) cleanup(); }
    void dir(const Path& p) { mkdir_new(p); created.emplace_back(p, true); }
    void file(const Path& p, size_t n) { file_new(p, n); created.emplace_back(p, false); }
    void moved(const Path& a, const Path& b) {
        rename_exact(a, b);
        relocated(a, b);
    }
    void relocated(const Path& a, const Path& b) {
        for (auto& [p, d] : created) if (p == a || p.starts_with(a + sep)) p = b + p.substr(a.size());
    }
    bool cleanup() {
        bool ok = true;
        for (auto it = created.rbegin(); it != created.rend(); ++it)
            if (!remove_exact(it->first, it->second)) { std::cerr << "FAIL exact fixture cleanup\n"; ok = false; }
        created.clear(); return ok;
    }
};
ckfe_metadata metadata(ckfe_entry* e) {
    Error error; ckfe_metadata m{}; error.ok(ckfe_entry_metadata(e, &m, &error.value)); return m;
}
void regular(ckfe_entry* e, uint64_t size) {
    const auto m = metadata(e);
    require((m.available_fields & (CKFE_METADATA_KIND | CKFE_METADATA_LOGICAL_SIZE | CKFE_METADATA_IDENTITY)) ==
        (CKFE_METADATA_KIND | CKFE_METADATA_LOGICAL_SIZE | CKFE_METADATA_IDENTITY), "missing kind/size/identity");
    require(m.kind == CKFE_OBJECT_REGULAR_FILE && m.logical_size == size, "wrong object/size");
}
void native_regular(DirectoryCursor& d, const Path& n, uint64_t size) {
    auto e = take(d.open_child(name(n), EntryAccess::ContentRead));
    auto m = take(e->inspect_basic());
    require(take(m.kind) == ObjectKind::RegularFile && take(m.logical_size) == size, "native kind/size");
    auto bytes = take(e->read_content({7}, 0));
    require(bytes.bytes.size() == std::min<uint64_t>(7, size), "bounded native read length");
    for (auto b : bytes.bytes) require(b == std::byte{'q'}, "native read content");
}
void check_directory(ckfe_engine* engine, NativeFileSystem& fs, const Path& path, const Path& leaf, uint64_t size) {
    auto d = directory(engine, path); auto e = entry(d.get(), leaf); regular(e.get(), size);
    auto n = take(fs.open_directory(std::filesystem::path(path))); native_regular(*n, leaf, size);
}
void retained(ckfe_engine* engine, NativeFileSystem& fs, Fixtures& f) {
    const auto a = f.root + sep + ascii("held"); const auto b = f.root + sep + ascii("moved");
    const auto leaf = ascii("record"); f.dir(a); f.file(a + sep + leaf, 13);
    auto d = directory(engine, a);
    auto n = take(fs.open_directory(std::filesystem::path(a)));
    // Rename the parent before opening descendants. Windows MoveFileExW can
    // reject an ancestor rename with open descendant handles (ERROR_ACCESS_DENIED)
    // even when those handles share DELETE. Parent and child continuity are
    // separate checks; neither requires overriding that native namespace rule.
    f.moved(a, b); f.dir(a); f.file(a + sep + leaf, 29);
    auto still_old = entry(d.get(), leaf); regular(still_old.get(), 13); native_regular(*n, leaf, 13);
    auto e = entry(d.get(), leaf); const auto before = metadata(e.get());
    auto held = take(n->open_child(name(leaf), EntryAccess::ContentRead));
    auto old = take(held->inspect_basic());
    f.moved(b + sep + leaf, b + sep + ascii("retained")); f.file(b + sep + leaf, 41);
    regular(e.get(), 13);
    const auto after = metadata(e.get());
    require(before.identity_scheme == after.identity_scheme &&
        std::memcmp(before.identity_volume, after.identity_volume, 16) == 0 &&
        std::memcmp(before.identity_object, after.identity_object, 16) == 0, "held C identity changed");
    auto now = take(held->inspect_basic());
    require(compare_identity(take(old.identity), take(now.identity)) == IdentityComparison::Same, "held native identity changed");
    require(take(now.logical_size) == 13, "held native entry reopened a path");
    auto fresh = entry(d.get(), leaf); regular(fresh.get(), 41);
}
void cursor_checks(NativeFileSystem& fs, const Path& p, const Path& expected) {
    auto d = take(fs.open_directory(std::filesystem::path(p)));
    std::stop_source stop; stop.request_stop();
    require(d->read(1, stop.get_token()).state == DirectoryReadState::Cancelled, "pre-cancelled cursor");
    bool found = false, ended = false;
    for (int i = 0; i < 128; ++i) {
        auto batch = d->read(1);
        require(batch.names.size() <= 1 && batch.state != DirectoryReadState::Error, "bounded cursor read");
        for (const auto& n : batch.names) if (n == name(expected)) found = true;
        if (batch.state == DirectoryReadState::End) { ended = true; break; }
    }
    require(found && ended, "exact native enumeration/resume");
    require(d->read(1).state == DirectoryReadState::End, "sticky cursor end");
}
void rejection(ckfe_engine* engine, const Path& p) {
    auto d = directory(engine, p); Error error;
    for (const char* invalid : {"..", "a/b", ".", ""}) {
        ckfe_entry* e = reinterpret_cast<ckfe_entry*>(uintptr_t(1));
        require(ckfe_entry_open_utf8(d.get(), invalid, &e, &error.value) == CKFE_API_OPERATION_UNAVAILABLE && e == nullptr,
            "invalid basename/output reset");
    }
    ckfe_metadata m; std::memset(&m, 0xff, sizeof(m));
    require(ckfe_entry_metadata(nullptr, &m, &error.value) == CKFE_API_INVALID_ARGUMENT && m.available_fields == 0, "failed metadata reset");
    ckfe_entry* success = nullptr;
    error.ok(ckfe_entry_open_utf8(d.get(), "ordinary", &success, &error.value));
    Entry e(success, ckfe_entry_destroy); regular(e.get(), 11);
    require(error.value.operation == nullptr && error.value.domain == CKFE_ERROR_NONE, "error reuse clears owned diagnostic");
#ifdef _WIN32
    const uint16_t embedded[] = {'a', 0, 'b'};
    ckfe_entry* invalid = reinterpret_cast<ckfe_entry*>(uintptr_t(1));
    require(ckfe_entry_open_utf16(d.get(), embedded, 3, &invalid, &error.value) == CKFE_API_OPERATION_UNAVAILABLE && !invalid, "embedded UTF-16 NUL accepted");
    for (const char* bad : {"ordinary:stream", "a\\b"}) {
        invalid = reinterpret_cast<ckfe_entry*>(uintptr_t(1));
        require(ckfe_entry_open_utf8(d.get(), bad, &invalid, &error.value) == CKFE_API_OPERATION_UNAVAILABLE && !invalid, "stream/path accepted as basename");
    }
    ckfe_directory* device = reinterpret_cast<ckfe_directory*>(uintptr_t(1));
    auto status = ckfe_directory_open_utf8(engine, "\\\\.\\PhysicalDrive0", 0, &device, &error.value);
    require((status == CKFE_API_INVALID_ARGUMENT || status == CKFE_API_OPERATION_UNAVAILABLE) && !device, "device namespace accepted");
#endif
}
void mutation_guards(ckfe_engine* engine, NativeFileSystem& fs, Fixtures& f) {
    const auto source = ascii("guard-source"), occupied = ascii("guard-occupied");
    f.file(f.root + sep + source, 43); f.file(f.root + sep + occupied, 47);
    auto parent = take(fs.open_directory(std::filesystem::path(f.root)));
    auto a = take(parent->open_child(name(source))); auto b = take(parent->open_child(name(occupied)));
    auto aid = take(take(a->inspect_basic()).identity), bid = take(take(b->inspect_basic()).identity);
    require(compare_identity(aid, bid) == IdentityComparison::Different, "distinct fixture identities");
    auto no_replace = parent->rename_child_noreplace(name(source), aid, *parent, name(occupied));
    require(!no_replace.value() && no_replace.state() == ObservationState::Changed, "occupied destination not refused as Changed");
    auto wrong = parent->discard_child(name(source), bid);
    require(!wrong.value(), "wrong-identity discard accepted");
    if (wrong.state() != ObservationState::Unsupported)
        require(wrong.state() == ObservationState::Changed, "wrong-identity discard lost typed Changed");
    auto retire = parent->retire_child(name(source), bid);
    require(!retire.value(), "wrong-identity retirement accepted");
    if (retire.state() != ObservationState::Unsupported)
        require(retire.state() == ObservationState::Changed, "wrong-identity retirement lost typed Changed");
    check_directory(engine, fs, f.root, source, 43);
    check_directory(engine, fs, f.root, occupied, 47);
    if (wrong.state() == ObservationState::Unsupported || retire.state() == ObservationState::Unsupported) {
        std::string detail;
        for (const auto* result : {&wrong, &retire}) {
            if (result->state() != ObservationState::Unsupported) continue;
            const auto& e = *result->unavailable_detail();
            detail += e.error.operation + " state=Unsupported domain=" + std::to_string(int(e.error.domain)) +
                " code=" + std::to_string(e.error.code) + "; ";
        }
        throw Gap(detail + "both fixture files survived; no pathname deletion substituted");
    }
}
void native_create(ckfe_engine* engine, NativeFileSystem& fs, Fixtures& f) {
    auto parent = take(fs.open_directory(std::filesystem::path(f.root)));
    const auto leaf = ascii("native-staging");
    auto made = take(parent->create_child_file(name(leaf)));
    f.created.emplace_back(f.root + sep + leaf, false);
    std::vector<std::byte> bytes(19, std::byte{'q'});
    require(take(made->write_content(0, bytes)) == bytes.size(), "native staging write");
    require(take(made->flush_content()), "native staging flush");
    auto duplicate = parent->create_child_file(name(leaf));
    require(!duplicate.value(), "exclusive native creation replaced existing file");
    made.reset();
    check_directory(engine, fs, f.root, leaf, 19);
}
#ifdef _WIN32
void raw_directory_flush(Fixtures& f) {
    const auto p = f.root + L"\\raw-directory-flush"; f.dir(p);
    HANDLE h = CreateFileW(extended(p).c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        throw Gap("native directory write-open Win32=" + std::to_string(GetLastError()));
    const bool flushed = FlushFileBuffers(h) != 0;
    const DWORD code = flushed ? ERROR_SUCCESS : GetLastError();
    CloseHandle(h);
    std::cout << "OBSERVE directory FlushFileBuffers GENERIC_WRITE result=" << flushed << " Win32=" << code
              << " (API acceptance only; no crash/power-loss qualification)\n";
    if (!flushed) throw Gap("directory FlushFileBuffers unavailable Win32=" + std::to_string(code));
}
void native_directory_flush(NativeFileSystem& fs, Fixtures& f) {
    auto parent = take(fs.open_directory(std::filesystem::path(f.root)));
    const auto leaf = name(L"native-directory-flush");
    auto made = parent->create_child_directory(leaf);
    // Creation can precede a failed directory flush. Record that real partial
    // mutation for exact cleanup and report it; never promote existence to success.
    auto probe = parent->open_directory_child(leaf);
    if (probe.value()) f.created.emplace_back(f.root + L"\\native-directory-flush", true);
    std::cout << "OBSERVE native create_child_directory state=" << int(made.state())
              << " directory_present=" << (probe.value() != nullptr) << '\n';
    auto created = take(std::move(made));
    require(take(take(created->inspect_basic()).kind) == ObjectKind::Directory, "native created directory kind");
    auto duplicate = parent->create_child_directory(leaf);
    require(!duplicate.value() && duplicate.state() == ObservationState::Changed, "native directory creation not exclusive");
    std::cout << "OBSERVE pinned create_child_directory passed its parent FlushFileBuffers gate; API acceptance only\n";
}
void native_rename_flush(ckfe_engine* engine, NativeFileSystem& fs, Fixtures& f) {
    const auto source = Path(L"flush-rename-source"), target = Path(L"flush-rename-target");
    f.file(f.root + sep + source, 61);
    auto parent = take(fs.open_directory(std::filesystem::path(f.root)));
    auto opened = take(parent->open_child(name(source)));
    auto identity = take(take(opened->inspect_basic()).identity); opened.reset();
    auto renamed = parent->rename_child_noreplace(name(source), identity, *parent, name(target));
    auto destination = parent->open_child(name(target));
    auto old = parent->open_child(name(source));
    if (destination.value()) {
        // Both addresses are exclusively owned fixtures. Track a mutation even
        // when the adapter correctly reports an ambiguous post-rename flush.
        if (old.state() == ObservationState::Gone) f.relocated(f.root + sep + source, f.root + sep + target);
        else f.created.emplace_back(f.root + sep + target, false);
    }
    std::cout << "OBSERVE native rename state=" << int(renamed.state()) << " source_present=" << (old.value() != nullptr)
              << " destination_present=" << (destination.value() != nullptr) << '\n';
    require(take(std::move(renamed)), "native no-replace rename result");
    require(old.state() == ObservationState::Gone && destination.value(), "native rename namespace result");
    auto actual = take(take((*destination.value())->inspect_basic()).identity);
    require(compare_identity(identity, actual) == IdentityComparison::Same, "native rename identity continuity");
    check_directory(engine, fs, f.root, target, 61);
    std::cout << "OBSERVE pinned rename passed both directory FlushFileBuffers gates; API acceptance only\n";
}
void sharing_denied(ckfe_engine* engine, NativeFileSystem& fs, Fixtures& f) {
    auto path = f.root + L"\\sharing"; f.file(path, 59);
    auto d = directory(engine, f.root); auto parent = take(fs.open_directory(std::filesystem::path(f.root)));
    HANDLE lock = CreateFileW(extended(path).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    require(lock != INVALID_HANDLE_VALUE, "exclusive sharing fixture");
    Error error; ckfe_entry* out = nullptr;
    auto status = ckfe_entry_open_utf8(d.get(), "sharing", &out, &error.value);
    auto native = parent->open_child(name(L"sharing"), EntryAccess::ContentRead);
    CloseHandle(lock);
    Entry owned(out, ckfe_entry_destroy);
    require(status == CKFE_API_OPERATION_UNAVAILABLE && !out && error.value.state == CKFE_OBSERVATION_DENIED,
        "C sharing violation lost typed Denied");
    require(!native.value() && native.state() == ObservationState::Denied, "native sharing violation lost typed Denied");
    check_directory(engine, fs, f.root, L"sharing", 59);
}
#endif
void reparse(ckfe_engine* engine, NativeFileSystem& fs, Fixtures& f) {
    const auto target = f.root + sep + ascii("target"); const auto link = f.root + sep + ascii("link");
    f.dir(target); f.file(target + sep + ascii("sentinel"), 37);
#ifdef _WIN32
    f.dir(link);
    HANDLE h = CreateFileW(extended(link).c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    require(h != INVALID_HANDLE_VALUE, "open junction fixture");
    struct Mount { DWORD tag; WORD length, reserved, sub_offset, sub_length, print_offset, print_length; wchar_t names[2048]; } data{};
    auto substitute = L"\\??\\" + target;
    require(substitute.size() + target.size() + 2 < 2048, "junction payload bound");
    data.tag = IO_REPARSE_TAG_MOUNT_POINT; data.sub_length = WORD(substitute.size() * 2);
    data.print_offset = WORD((substitute.size() + 1) * 2); data.print_length = WORD(target.size() * 2);
    std::copy(substitute.begin(), substitute.end(), data.names);
    std::copy(target.begin(), target.end(), data.names + substitute.size() + 1);
    data.length = WORD(8 + data.print_offset + data.print_length + 2);
    DWORD returned = 0;
    bool made = DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, &data, DWORD(data.length + 8), nullptr, 0, &returned, nullptr) != 0;
    DWORD code = GetLastError(); CloseHandle(h);
    if (!made) throw Gap("real junction creation unavailable Win32=" + std::to_string(code));
    const auto expected_kind = ObjectKind::Junction;
#else
    require(::symlink(target.c_str(), link.c_str()) == 0, "real symlink fixture");
    f.created.emplace_back(link, false);
    const auto expected_kind = ObjectKind::SymbolicLink;
#endif
    auto observed = take(fs.inspect_basic(std::filesystem::path(link)));
    require(take(observed.kind) == expected_kind, "link inspected as target");
    auto refused = fs.open_directory(std::filesystem::path(link), DirectoryLinkPolicy::RejectFinalLink);
    require(!refused.value(), "native final-link unexpectedly followed");
    const auto& native_error = refused.unavailable_detail()->error;
#ifdef _WIN32
    require(native_error.domain == ErrorDomain::Adapter && native_error.code == int64_t(AdapterError::FinalLinkRejected), "native final-link rejection");
#else
    require(native_error.domain == ErrorDomain::Posix && (native_error.code == ELOOP || native_error.code == ENOTDIR), "native no-follow errno");
#endif
    Error error; ckfe_directory* out = nullptr;
#ifdef _WIN32
    auto u = units(link);
    auto status = ckfe_directory_open_utf16(engine, reinterpret_cast<const uint16_t*>(u.data()), u.size(), 0, &out, &error.value);
#else
    auto status = ckfe_directory_open_utf8(engine, link.c_str(), 0, &out, &error.value);
#endif
    Directory owned(out, ckfe_directory_destroy);
    require(status == CKFE_API_OPERATION_UNAVAILABLE && !out, "C final-link unexpectedly followed");
#ifdef _WIN32
    require(error.value.domain == CKFE_ERROR_ADAPTER && error.value.code == CKFE_ADAPTER_FINAL_LINK_REJECTED, "C final-link rejection");
#else
    require(error.value.domain == CKFE_ERROR_POSIX && (error.value.code == ELOOP || error.value.code == ENOTDIR), "C no-follow errno");
#endif
    auto parent = take(fs.open_directory(std::filesystem::path(f.root)));
    auto held = take(parent->open_child(name(ascii("link"))));
    auto payload = take(held->read_link_metadata());
#ifdef _WIN32
    auto* w = std::get_if<WindowsReparseData>(&payload.payload);
    require(w && w->tag == IO_REPARSE_TAG_MOUNT_POINT && w->names &&
        w->names->substitute == units(substitute), "exact junction payload");
#else
    auto* l = std::get_if<PosixSymlinkData>(&payload.payload);
    require(l && l->target == target, "exact symlink payload");
#endif
    auto followed = directory(engine, link, 1); auto sentinel = entry(followed.get(), ascii("sentinel")); regular(sentinel.get(), 37);
    auto rejected_child = parent->open_directory_child(name(ascii("link")));
    require(!rejected_child.value(), "child directory unexpectedly followed link");
    // Remove only the link; the target sentinel must survive.
    held.reset(); followed.reset(); sentinel.reset();
    require(remove_exact(link,
#ifdef _WIN32
        true
#else
        false
#endif
    ), "unlink fixture link");
    f.created.erase(std::remove_if(f.created.begin(), f.created.end(), [&](const auto& v) { return v.first == link; }), f.created.end());
    check_directory(engine, fs, target, ascii("sentinel"), 37);
}
}

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) { std::cerr << "usage: platform_qualification NEW_ABSOLUTE_FIXTURE_ROOT [UNC_ALIAS_OF_ROOT]\n"; return 1; }
    int failed = 0, gaps = 0, passed = 0;
    try {
#ifdef _WIN32
        Path root = wide(argv[1]);
        require(root.starts_with(L"V:\\tmp\\"), "Windows fixtures must use V:\\tmp");
#else
        Path root = argv[1]; require(root.starts_with("/"), "absolute fixture root required");
#ifdef __APPLE__
        require(root.starts_with("/Volumes/S8T/tmp/") || root.starts_with("/Volumes/PRO-BLADE/tmp/"), "Mac temporary volume required");
#endif
#endif
        Fixtures fixtures(root);
        ckfe_engine* raw = nullptr; require(ckfe_engine_create(&raw) == CKFE_API_OK, "engine create");
        Engine engine(raw, ckfe_engine_destroy); NativeFileSystem fs;
        auto test = [&](const char* label, const std::function<void()>& run) {
            try { run(); ++passed; std::cout << "PASS " << label << '\n'; }
            catch (const Gap& e) { ++gaps; std::cout << "GAP " << label << " " << e.what() << '\n'; }
            catch (const std::exception& e) { ++failed; std::cout << "FAIL " << label << " " << e.what() << '\n'; }
        };
        fixtures.file(root + sep + ascii("ordinary"), 11);
        test("ordinary-public-and-native", [&] { check_directory(raw, fs, root, ascii("ordinary"), 11); });
        test("invalid-components-and-error-ownership", [&] { rejection(raw, root); });
        test("retained-parent-and-entry-after-replacement", [&] { retained(raw, fs, fixtures); });
        test("real-reparse-no-follow-and-target-survival", [&] { reparse(raw, fs, fixtures); });
        test("native-no-clobber-and-wrong-identity-mutation-guards", [&] { mutation_guards(raw, fs, fixtures); });
        test("native-exclusive-create-write-flush", [&] { native_create(raw, fs, fixtures); });
#ifdef _WIN32
        test("sharing-denial-and-retry-through-public-and-native", [&] { sharing_denied(raw, fs, fixtures); });
        test("native-directory-FlushFileBuffers-API", [&] { raw_directory_flush(fixtures); });
        test("library-create-directory-parent-flush-gate", [&] { native_directory_flush(fs, fixtures); });
        test("library-rename-source-destination-flush-gates", [&] { native_rename_flush(raw, fs, fixtures); });
#endif
        Path longdir = root;
        for (int i = 0; longdir.size() < 380; ++i) {
            longdir += sep + ascii(("segment_" + std::to_string(i) + std::string(45, 'x')).c_str()); fixtures.dir(longdir);
        }
        fixtures.file(longdir + sep + ascii("longfile"), 17);
        test("long-path-over-260-public-and-native", [&] { check_directory(raw, fs, longdir, ascii("longfile"), 17); });
#ifdef _WIN32
        test("long-DOS-UTF8-entry-point", [&] {
            std::string text(longdir.begin(), longdir.end()); Error error; ckfe_directory* out = nullptr;
            error.ok(ckfe_directory_open_utf8(raw, text.c_str(), 0, &out, &error.value));
            Directory d(out, ckfe_directory_destroy); auto e = entry(d.get(), L"longfile"); regular(e.get(), 17);
        });
        Path exact = L"exact_"; exact.push_back(wchar_t(0xd800)); exact += L". ";
#else
        Path exact = "exact_"; exact.push_back(char(0xff)); exact += ". ";
#endif
        fixtures.file(root + sep + exact, 23);
        test("exact-native-unpaired-surrogate-or-nonUTF8-name", [&] { check_directory(raw, fs, root, exact, 23); cursor_checks(fs, root, exact); });
        auto exact_directory = root + sep + exact + ascii("_directory");
        fixtures.dir(exact_directory); fixtures.file(exact_directory + sep + ascii("inner"), 53);
        test("exact-native-directory-address", [&] { check_directory(raw, fs, exact_directory, ascii("inner"), 53); });
#ifdef _WIN32
        fixtures.file(root + sep + L"CON", 31);
        test("reserved-basename-through-held-parent", [&] { check_directory(raw, fs, root, L"CON", 31); });
        test("UNC-long-public-and-native-same-object", [&] {
            if (argc != 3) throw Gap("no reachable UNC alias supplied; namespace parsing alone is insufficient");
            auto alias = wide(argv[2]); auto suffix = longdir.substr(root.size());
            if (GetFileAttributesW(extended(alias).c_str()) == INVALID_FILE_ATTRIBUTES)
                throw Gap("actual UNC fixture alias unavailable Win32=" + std::to_string(GetLastError()));
            check_directory(raw, fs, alias + suffix, L"longfile", 17);
            check_directory(raw, fs, extended(alias + suffix), L"longfile", 17);
            check_directory(raw, fs, alias, exact, 23);
            check_directory(raw, fs, alias + exact_directory.substr(root.size()), L"inner", 53);
            auto local = take(fs.inspect_basic(std::filesystem::path(longdir + L"\\longfile")));
            auto remote = take(fs.inspect_basic(std::filesystem::path(alias + suffix + L"\\longfile")));
            require(compare_identity(take(local.identity), take(remote.identity)) == IdentityComparison::Same, "UNC alias identity mismatch");
        });
#endif
        if (!fixtures.cleanup()) ++failed;
    } catch (const std::exception& e) { ++failed; std::cout << "FAIL setup " << e.what() << '\n'; }
    std::cout << "SUMMARY passed=" << passed << " failed=" << failed << " gaps=" << gaps << '\n';
    return failed ? 1 : gaps ? 2 : 0;
}
