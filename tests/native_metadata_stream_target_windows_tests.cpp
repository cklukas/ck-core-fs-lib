// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_filesystem.hpp"
#include "platform/native_metadata_stream_target.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "windows_name.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <algorithm>
#include <array>
#include <bit>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

using namespace ck::files;
namespace {
#define CHECK(x) do { if (!(x)) throw std::runtime_error(std::string("line ") + std::to_string(__LINE__) + " " + #x); } while (false)

void wincheck(bool ok, const char* call) {
    if (!ok) throw std::runtime_error(std::string(call) + " Win32=" + std::to_string(GetLastError()));
}
template<class T> T take(Observation<T> result) {
    if (!result.value()) {
        const auto& e = *result.unavailable_detail();
        throw std::runtime_error(e.error.operation + " state=" + std::to_string(unsigned(e.state)) +
                                 " code=" + std::to_string(e.error.code));
    }
    return std::move(result).take_value();
}
thread_local unsigned suppressed_time_calls=0;
thread_local bool opening_independent_reader=false,reader_rights_ok=false;
BOOL WINAPI watched_set_times(HANDLE handle,const FILETIME* creation,const FILETIME* access,const FILETIME* write) {
    using Set=BOOL(WINAPI*)(HANDLE,const FILETIME*,const FILETIME*,const FILETIME*);
    static const auto real=std::bit_cast<Set>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"SetFileTime"));
    const BOOL result=real(handle,creation,access,write);const DWORD error=GetLastError();
    if(result&&!creation&&access&&write&&access->dwLowDateTime==MAXDWORD&&access->dwHighDateTime==MAXDWORD&&
       write->dwLowDateTime==MAXDWORD&&write->dwHighDateTime==MAXDWORD) {
        ++suppressed_time_calls;
        if(opening_independent_reader) {
            using Query=NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
            static const auto query=std::bit_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationFile"));
            struct Access {ACCESS_MASK rights;} granted{};IO_STATUS_BLOCK io{};
            const auto status=query(handle,&io,&granted,sizeof(granted),8); // FileAccessInformation.
            reader_rights_ok=status==0&&io.Status==0&&io.Information==sizeof(granted)&&
                (granted.rights&FILE_WRITE_ATTRIBUTES)&&
                !(granted.rights&(FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_EA|DELETE|WRITE_DAC|WRITE_OWNER));
        }
    }
    SetLastError(error);return result;
}
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE h) : value(h) { wincheck(h && h != INVALID_HANDLE_VALUE, "open handle"); }
    Handle(const Handle&) = delete;
    void close() { wincheck(CloseHandle(std::exchange(value, INVALID_HANDLE_VALUE)), "CloseHandle"); }
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
Handle open(const std::wstring& p, DWORD access, DWORD disposition = OPEN_EXISTING, bool directory = false) {
    return Handle(CreateFileW(p.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, disposition, FILE_FLAG_OPEN_REPARSE_POINT |
                              (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr));
}
FILE_ID_INFO id(HANDLE h) {
    FILE_ID_INFO result{};
    wincheck(GetFileInformationByHandleEx(h, FileIdInfo, &result, sizeof(result)), "FileIdInfo");
    return result;
}
bool same_id(const FILE_ID_INFO& a, const FILE_ID_INFO& b) {
    return a.VolumeSerialNumber == b.VolumeSerialNumber &&
        !std::memcmp(a.FileId.Identifier, b.FileId.Identifier, sizeof(a.FileId.Identifier));
}
std::wstring guid_path(HANDLE h) {
    constexpr DWORD flags = FILE_NAME_OPENED | VOLUME_NAME_GUID;
    DWORD size = GetFinalPathNameByHandleW(h, nullptr, 0, flags);
    wincheck(size != 0, "final path size");
    std::wstring result(size, L'\0');
    DWORD count = GetFinalPathNameByHandleW(h, result.data(), size, flags);
    wincheck(count && count < size, "final path");
    result.resize(count);
    return result;
}
std::wstring fs_name(HANDLE directory) {
    wchar_t fs[32]{};
    wincheck(GetVolumeInformationByHandleW(directory, nullptr, 0, nullptr, nullptr, nullptr, fs, 32),
             "GetVolumeInformationByHandleW");
    return fs;
}
// Windows environment strings are read through the bounded wide API. A racing
// environment update cannot trigger an unbounded allocation or a truncated path.
std::optional<std::wstring> environment(const wchar_t* variable) {
    constexpr DWORD max_units = 32767;
    for (unsigned retry = 0; retry != 3; ++retry) {
        SetLastError(ERROR_SUCCESS);
        const DWORD size = GetEnvironmentVariableW(variable, nullptr, 0);
        if (!size) {
            const DWORD error = GetLastError();
            CHECK(error == ERROR_ENVVAR_NOT_FOUND || error == ERROR_SUCCESS);
            return std::nullopt;
        }
        CHECK(size <= max_units);
        std::wstring value(size, L'\0');
        const DWORD count = GetEnvironmentVariableW(variable, value.data(), size);
        if (!count) {
            const DWORD error = GetLastError();
            CHECK(error == ERROR_ENVVAR_NOT_FOUND || error == ERROR_SUCCESS);
            return std::nullopt;
        }
        if (count >= size) continue;
        value.resize(count);
        return value;
    }
    throw std::runtime_error("environment changed repeatedly");
}
std::size_t namespace_root(std::wstring_view path) {
    CHECK(path.starts_with(L"\\\\?\\"));
    if (path.starts_with(L"\\\\?\\UNC\\")) {
        const auto server = path.find(L'\\', 8);
        CHECK(server != path.npos && server > 8);
        const auto share = path.find(L'\\', server + 1);
        CHECK(share != path.npos && share > server + 1);
        for (auto component : {path.substr(8, server - 8), path.substr(server + 1, share - server - 1)})
            CHECK(component != L"." && component != L".." && component.find(L':') == component.npos);
        return share + 1;
    }
    if (path.starts_with(L"\\\\?\\Volume{")) {
        const auto end = path.find(L"}\\", 11);
        CHECK(end == 47); // Exact counted volume GUID namespace, not a device path.
        return end + 2;
    }
    CHECK(path.size() >= 7 && path[5] == L':' && path[6] == L'\\');
    CHECK((path[4] >= L'A' && path[4] <= L'Z') || (path[4] >= L'a' && path[4] <= L'z'));
    return 7;
}
bool ordinal_equal(std::wstring_view a, std::wstring_view b) {
    CHECK(a.size() <= 32767 && b.size() <= 32767);
    return CompareStringOrdinal(a.data(), int(a.size()), b.data(), int(b.size()), TRUE) == CSTR_EQUAL;
}
std::wstring task_path(std::wstring_view input, bool require_v) {
    auto extended = windows_extended_path(input);
    CHECK(extended);
    const auto root = namespace_root(*extended);
    while (extended->size() > root && extended->ends_with(L'\\')) extended->pop_back();
    CHECK(extended->size() > root); // TEMP must name a directory below its namespace root.
    for (size_t begin = root; begin < extended->size();) {
        const auto end = extended->find(L'\\', begin);
        const auto part = std::wstring_view(*extended).substr(begin, end == extended->npos ? end : end - begin);
        CHECK(!part.empty() && part != L"." && part != L".." && part.find(L':') == part.npos);
        if (end == extended->npos) break;
        begin = end + 1;
    }
    if (require_v) {
        constexpr std::wstring_view prefix = L"\\\\?\\V:\\tmp\\";
        CHECK(extended->size() > prefix.size() && ordinal_equal(std::wstring_view(*extended).substr(0, prefix.size()), prefix));
    }
    return *extended;
}
void plain_directory(HANDLE handle) {
    FILE_ATTRIBUTE_TAG_INFO tag{};
    wincheck(GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)), "directory tag");
    CHECK((tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT));
}
// Inspect every original ancestor without following its final reparse point.
// Permit only a real volume mount, map it to its native volume GUID, and compare
// native identities on both spellings. No arbitrary junction/symlink is admitted.
// Subsequent local fixture I/O uses the checked GUID spelling; an actual UNC
// share retains its extended UNC namespace. This is test setup, never replay authority.
std::wstring checked_directory(const std::wstring& path) {
    const auto root = namespace_root(path);
    auto source_root = open(path.substr(0, root), FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
    plain_directory(source_root.value);
    auto mapped = path.starts_with(L"\\\\?\\UNC\\") ? path.substr(0, root) : guid_path(source_root.value);
    CHECK(namespace_root(mapped) == mapped.size());
    bool crossed_mount = false;
    for (size_t begin = root; begin < path.size();) {
        auto end = path.find(L'\\', begin);
        if (end == path.npos) end = path.size();
        const auto original = path.substr(0, end);
        auto h = open(original, FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
        FILE_ATTRIBUTE_TAG_INFO tag{};
        wincheck(GetFileInformationByHandleEx(h.value, FileAttributeTagInfo, &tag, sizeof(tag)), "ancestor tag");
        CHECK(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY);
        if (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            CHECK(!crossed_mount && tag.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT);
            wchar_t volume[64]{};
            wincheck(GetVolumeNameForVolumeMountPointW((original + L"\\").c_str(), volume, 64), "real volume mount");
            mapped = volume;
            CHECK(mapped.starts_with(L"\\\\?\\Volume{") && namespace_root(mapped) == mapped.size());
            auto actual = Handle(CreateFileW(original.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            auto volume_root = open(mapped, FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
            plain_directory(volume_root.value);
            CHECK(same_id(id(actual.value), id(volume_root.value)));
            crossed_mount = true;
        } else {
            if (!mapped.ends_with(L'\\')) mapped += L'\\';
            mapped += path.substr(begin, end - begin);
            auto actual = open(mapped, FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
            plain_directory(actual.value);
            CHECK(same_id(id(h.value), id(actual.value)));
        }
        begin = end + 1;
    }
    auto final = open(mapped, FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
    plain_directory(final.value);
    return mapped;
}
struct FixtureOptions { std::wstring expected_fs; std::optional<std::wstring> root; };
FixtureOptions options(int argc, wchar_t** argv) {
    FixtureOptions result;
    for (int i = 1; i < argc; ++i) {
        const std::wstring_view key(argv[i]);
        CHECK(i + 1 < argc);
        if (key == L"--expect-filesystem") {
            CHECK(result.expected_fs.empty()); result.expected_fs = argv[++i];
            CHECK(result.expected_fs == L"NTFS" || result.expected_fs == L"ReFS");
        } else if (key == L"--fixture-root") {
            CHECK(!result.root); result.root = argv[++i];
        } else throw std::runtime_error("unknown fixture option");
    }
    CHECK(!result.expected_fs.empty());
    return result;
}
std::wstring test_base(const FixtureOptions& configuration) {
    const auto dev_policy = environment(L"CK_FS_REQUIRE_V_DEV_DRIVE");
    CHECK(!dev_policy || *dev_policy == L"0" || *dev_policy == L"1");
    const bool require_v = dev_policy && *dev_policy == L"1";
    const auto raw_temp = environment(L"TEMP");
    CHECK(raw_temp && !raw_temp->empty());
    const auto temp = task_path(*raw_temp, require_v);
    const auto mapped_temp = checked_directory(temp);
    auto held = open(mapped_temp, FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
    if (require_v) {
        auto drive = open(L"\\\\?\\V:\\", FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
        CHECK(fs_name(drive.value) == L"NTFS" || fs_name(drive.value) == L"ReFS");
        for (const auto* variable : {L"TMP", L"TMPDIR"}) {
            const auto value = environment(variable); CHECK(value && !value->empty());
            auto h = open(checked_directory(task_path(*value, true)), FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
            CHECK(same_id(id(held.value), id(h.value)));
        }
    }
    auto base = mapped_temp;
    if (configuration.root) {
        const auto supplied = task_path(*configuration.root, require_v);
        CHECK(supplied.size() >= temp.size() && ordinal_equal(std::wstring_view(supplied).substr(0, temp.size()), temp));
        CHECK(supplied.size() == temp.size() || supplied[temp.size()] == L'\\');
        base = checked_directory(supplied);
    }
    auto directory = open(base, FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
    const auto actual_fs = fs_name(directory.value);
    CHECK(actual_fs == configuration.expected_fs);
    std::wcout << L"actual native metadata stream target filesystem=" << actual_fs
               << L" expected=" << configuration.expected_fs << L" workstation-V=" << require_v << L'\n';
    return base;
}

HANDLE effective_token(DWORD rights) {
    HANDLE h{};
    if (!OpenThreadToken(GetCurrentThread(), rights, TRUE, &h)) {
        if (GetLastError() != ERROR_NO_TOKEN || !OpenProcessToken(GetCurrentProcess(), rights, &h))
            return nullptr;
    }
    return h;
}

void mkdir_private(const std::wstring& path) {
    Handle token(effective_token(TOKEN_QUERY));
    DWORD bytes = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &bytes);
    CHECK(bytes);
    std::vector<std::byte> user(bytes);
    wincheck(GetTokenInformation(token.value, TokenUser, user.data(), bytes, &bytes), "TokenUser");
    wchar_t* sid = nullptr;
    wincheck(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &sid), "user SID");
    const std::wstring sddl = L"O:" + std::wstring(sid) + L"D:P(A;OICI;FA;;;" + sid + L")(A;OICI;FA;;;SY)";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR sd{};
    wincheck(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr),
             "private SDDL");
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
    BOOL created = CreateDirectoryW(path.c_str(), &sa);
    DWORD err = GetLastError();
    LocalFree(sd);
    SetLastError(err);
    wincheck(created, "create private directory");
}
struct Find {
    HANDLE h;
    ~Find() { if (h != INVALID_HANDLE_VALUE) FindClose(h); }
};
std::map<std::wstring, DWORD> entries(const std::wstring& dir) {
    WIN32_FIND_DATAW entry{};
    Find search{FindFirstFileW((dir + L"\\*").c_str(), &entry)};
    std::map<std::wstring, DWORD> result;
    if (search.h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) return result;
    wincheck(search.h != INVALID_HANDLE_VALUE, "FindFirstFileW");
    do {
        std::wstring name(entry.cFileName);
        if (name != L"." && name != L"..") result.emplace(std::move(name), entry.dwFileAttributes);
    } while (FindNextFileW(search.h, &entry));
    wincheck(GetLastError() == ERROR_NO_MORE_FILES, "FindNextFileW");
    return result;
}
void remove_tree(const std::wstring& dir) {
    for (const auto& [name, attr] : entries(dir)) {
        auto child = dir + L"\\" + name;
        if (attr & FILE_ATTRIBUTE_DIRECTORY) {
            if (attr & FILE_ATTRIBUTE_REPARSE_POINT) wincheck(RemoveDirectoryW(child.c_str()), "remove reparse directory");
            else remove_tree(child);
        } else wincheck(DeleteFileW(child.c_str()), "delete fixture file");
    }
    wincheck(RemoveDirectoryW(dir.c_str()), "remove fixture directory");
}
// Only set after successful exclusive creation. Also cleans up partial fixture setup.
struct OwnedTree {
    std::wstring path;
    explicit OwnedTree(std::wstring p) : path(std::move(p)) { mkdir_private(path); }
    ~OwnedTree() {
        try { remove_tree(path); }
        catch (const std::exception& e) { std::wcerr << L"cleanup failed in " << path << L'\n'; std::cerr << e.what() << '\n'; cleanup_failed = true; }
    }
    static inline bool cleanup_failed = false;
};

NativeName name(std::u16string units) { return NativeName::from_windows(std::move(units)).value(); }
constexpr char stream_data[] = "first\0second\xff" "third";
const auto bytes = std::as_bytes(std::span(stream_data, sizeof(stream_data) - 1));
const std::u16string stream_name = u":exact_" + std::u16string(1, char16_t(0xd800)) + u". :$DATA";

void seed(const std::wstring& path, std::span<const std::byte> data, bool directory_stream = false) {
    auto h = open(path, GENERIC_WRITE, CREATE_NEW, directory_stream);
    DWORD count = 0;
    wincheck(WriteFile(h.value, data.data(), static_cast<DWORD>(data.size()), &count, nullptr), "seed data");
    CHECK(count == data.size());
    wincheck(FlushFileBuffers(h.value), "flush seed");
    h.close();
}

struct RootLatch final : MetadataCaptureFailureLatch {
    explicit RootLatch(PreparedJournalRoot::Pointer owner) : root(std::move(owner)) {}
    PreparedJournalRoot::Pointer root;
    mutable bool accepted = true;
    void record_first(MetadataCaptureCleanupError e) const noexcept override {
        if (!detail::record_prepared_journal_consumer_failure(*root, e.state, e.domain, e.code, e.operation))
            accepted = false;
    }
};

struct Fixture {
    static inline unsigned serial = 0;
    OwnedTree tree;
    std::wstring path;
    NativeFileSystem fs;
    std::shared_ptr<const DirectoryCursor> parent;
    PreparedJournalRoot::Pointer root;
    std::shared_ptr<RootLatch> latch;
    explicit Fixture(const std::wstring& base)
        : tree(base + L"\\stream-target-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
               std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(++serial)), path(tree.path) {
        for (auto c : {L'a', L'b'}) {
            path += L"\\" + std::wstring(110, c);
            mkdir_private(path);
        }
        CHECK((path + L"\\source").size() > 260);
        parent = std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(path)));
        PreparedJournalRootRequest request;
        request.parent = parent;
        request.child = name(u"journal");
        request.disposition = JournalRootDisposition::ProvisionChild;
        JournalRootPreparationProgress progress;
        root = take(prepare_native_journal_root(std::move(request), progress));
        CHECK(progress.phase == JournalRootPreparationPhase::Ready);
        latch = std::make_shared<RootLatch>(root);
    }
    void clean_root() {
        CHECK(latch->accepted);
        latch.reset();
        CHECK(take(root->finish_io()));
    }
};

MetadataReplayPolicy policy(bool full) {
    MetadataReplayPolicy p;
    p.scope = full ? RegularMetadataScope::CompleteMetadataV1 : RegularMetadataScope::OrdinaryCallerVisibleV1;
    p.ownership = full ? MetadataOwnership::Original : MetadataOwnership::CurrentCaller;
    p.allow_privilege_metadata = full;
    return p;
}

// Only capture acquisition/advancement can report an unavailable Complete policy.
// Preserve the actual domain/code so unrelated provider or I/O errors fail the case.
struct CaptureFailure { UnavailableObservation detail; };
template<class T> T capture_value(Observation<T> result) {
    if (!result.value()) throw CaptureFailure{*result.unavailable_detail()};
    return std::move(result).take_value();
}
struct Capture {
    std::unique_ptr<MetadataCaptureJob> job;
    std::shared_ptr<const NativeMetadataProof> proof;
    Capture(Fixture& f, bool directory, bool full, bool with_stream=true) {
        const auto source = f.path + L"\\source";
        if (directory) mkdir_private(source);
        else seed(source, bytes.first(5));
        if(with_stream)seed(source + std::wstring(stream_name.begin(), stream_name.end()), bytes, directory);
        MetadataCaptureLimits limits;
        limits.read.max_bytes = 3;
        if (directory) {
            std::shared_ptr<const DirectoryCursor> cursor(take(f.parent->open_directory_child(name(u"source"))));
            job = capture_value(MetadataCaptureJob::begin_directory(cursor, policy(full), limits, {}, f.latch));
        } else {
            const auto access = EntryAccess::ContentRead | EntryAccess::MetadataAndAttributes | EntryAccess::MetadataAndSecurity;
            // begin() must itself acquire the Complete security view from this held source.
            std::shared_ptr<const OpenedEntry> entry(capture_value(f.parent->open_child(name(u"source"), access)));
            job = capture_value(MetadataCaptureJob::begin(entry, policy(full), limits, {}, f.latch));
        }
        for (unsigned i = 0; i < 512 && job->progress().phase != MetadataCapturePhase::Complete; ++i) {
            auto step = job->advance();
            if (!step.value()) {
                auto e = *step.unavailable_detail();
                CHECK(take(job->finish_io()));
                throw CaptureFailure{std::move(e)};
            }
            CHECK(step.value()->content_reads <= 1 && step.value()->content_bytes <= 3);
        }
        proof = take(job->result());
        CHECK(!proof->io_finished() && proof->main_digest().has_value() == !directory);
        const auto& s = proof->snapshot();
        CHECK(s.policy.ownership == policy(full).ownership && s.policy.scope == policy(full).scope);
        CHECK(s.channel_coverage == DataChannelCoverage::WindowsFileStreamInfo && s.channel_evidence);
        if(with_stream)CHECK(s.channels.size() == 1 && s.channels.front().identifier.windows_units() &&
              *s.channels.front().identifier.windows_units() == stream_name && s.channels.front().logical_size == bytes.size());
        else CHECK(s.channels.empty());
        if (full) CHECK(s.security_coverage && s.security_coverage->family() == MetadataSecurityCoverage::WindowsPersistentSecurityV1);
    }
    void finish() {
        CHECK(take(proof->finish_io()) && take(job->finish_io()));
        job.reset();
        proof.reset();
    }
};

struct Target {
    std::unique_ptr<OpenedEntry> stage;
    std::unique_ptr<NativeCreatedDirectory> dir;
    Target(Fixture& f, bool directory, bool full) {
        if (directory) dir = take(create_native_directory(f.parent, name(u"target"), policy(full)));
        else {
            auto created = take(f.parent->create_staging_file(name(u"target")));
            CHECK(created.staging_namespace == StagingNamespace::Named && created.name == name(u"target"));
            stage = std::move(created.entry);
            CHECK(take(stage->write_content(0, bytes.first(5))) == 5);
        }
    }
    OpenedEntry& entry() { return dir ? dir->metadata_writer() : *stage; }
    Observation<bool> finish() { return dir ? dir->finish_io() : stage->finish_content_writes(); }
};

using detail::open_native_metadata_stream_reader;
using detail::open_native_metadata_stream_writer;

void check_stream(const MetadataReplayChannelSource& reader) {
    for (size_t offset = 0; offset < bytes.size();) {
        const auto data = take(reader.read_content({2}, offset));
        const auto expected = bytes.subspan(offset, std::min<size_t>(2, bytes.size() - offset));
        CHECK(std::ranges::equal(data.bytes, expected));
        offset += expected.size();
        CHECK(data.complete == (offset == bytes.size()));
    }
    const auto eof = take(reader.read_content({2}, bytes.size()));
    CHECK(eof.complete && eof.bytes.empty());
}

void round_trip(Fixture& f, Capture& capture, bool directory, bool full) {
    Target target(f, directory, full);
    auto& entry = target.entry();
    const auto& s = capture.proof->snapshot();
    const auto& channel = s.channels.front();
    const auto basic = take(entry.inspect_basic());
    CHECK(basic.identity.value());
    const auto before_writer_setup=suppressed_time_calls;
    auto writer = take(open_native_metadata_stream_writer(entry, capture.proof, channel.identifier, f.latch));
    CHECK(suppressed_time_calls==before_writer_setup+1);
    const auto initial = take(writer->inspect());
    CHECK(initial.identifier == channel.identifier && initial.logical_size == 0 &&
          compare_identity(initial.owner, *basic.identity.value()) == IdentityComparison::Same);
    constexpr LONGLONG access_ticks = 125911584000000017LL, write_ticks = 125911584000123459LL;
    auto desired = s.basic;
    desired.accessed = Observation<FileTimestamp>::available(FileTimestamp::from_windows_ticks(access_ticks));
    desired.modified = Observation<FileTimestamp>::available(FileTimestamp::from_windows_ticks(write_ticks));
    CHECK(take(entry.apply_replay_basic(desired, s.policy)));
    for (size_t offset = 0; offset < bytes.size();) {
        auto part = take(channel.source->read_content({3}, offset));
        CHECK(std::ranges::equal(part.bytes, bytes.subspan(offset, std::min<size_t>(3, bytes.size() - offset))));
        CHECK(take(writer->write(offset, part.bytes)) == part.bytes.size());
        offset += part.bytes.size();
    }
    CHECK(take(writer->finish_io()) && take(writer->finish_io()));
    CHECK(!writer->write(0, bytes.first(1)).value());
    writer.reset();
    auto duplicate = open_native_metadata_stream_writer(entry, capture.proof, channel.identifier, f.latch);
    CHECK(!duplicate.value() && duplicate.state() == ObservationState::Changed &&
          duplicate.unavailable_detail()->error.domain == ErrorDomain::NtStatus);
    const auto before_reader_setup=suppressed_time_calls;reader_rights_ok=false;opening_independent_reader=true;
    auto reader = take(open_native_metadata_stream_reader(entry, capture.proof, channel.identifier, f.latch));
    opening_independent_reader=false;
    CHECK(suppressed_time_calls==before_reader_setup+1&&reader_rights_ok);
    const auto verified = take(reader->inspect());
    CHECK(verified.identifier == channel.identifier && verified.logical_size == bytes.size() &&
          compare_identity(verified.owner, initial.owner) == IdentityComparison::Same);
    check_stream(*reader);
    CHECK(take(reader->finish_io()) && take(reader->finish_io()));
    CHECK(!reader->read_content({1}, 0).value());
    reader.reset();
    CHECK(take(target.finish()));
    // Release even the directory's independent verifier/cursor before observing the final times.
    target.dir.reset();
    target.stage.reset();
    auto final = open(f.path + L"\\target", FILE_READ_ATTRIBUTES, OPEN_EXISTING, directory);
    FILE_BASIC_INFO info{};
    wincheck(GetFileInformationByHandleEx(final.value, FileBasicInfo, &info, sizeof(info)), "final base times");
    if (info.LastAccessTime.QuadPart != access_ticks || info.LastWriteTime.QuadPart != write_ticks)
        throw std::runtime_error("final FILETIME atime=" + std::to_string(info.LastAccessTime.QuadPart) +
            " expected=" + std::to_string(access_ticks) + " mtime=" + std::to_string(info.LastWriteTime.QuadPart) +
            " expected=" + std::to_string(write_ticks));
    final.close();
    capture.finish();
    f.clean_root();
}

class InjectedEntry final : public OpenedEntry {
public:
    mutable unsigned virtual_calls=0;
private:
    Observation<bool> qualify_metadata_replay(const MetadataReplayPolicy&) const override {++virtual_calls;return Observation<bool>::available(true);}
    Observation<BasicMetadata> inspect_basic() const override {
        ++virtual_calls;return Observation<BasicMetadata>::unavailable(ObservationState::Unsupported, {ErrorDomain::Adapter, 0, "injected"});
    }
};
void denied_factories(OpenedEntry& entry, const std::shared_ptr<const NativeMetadataProof>& proof,
                      const NativeFeatureIdentifier& identifier, const std::shared_ptr<RootLatch>& latch,
                      std::string_view writer_op, std::string_view reader_op) {
    auto check = [](const auto& result, std::string_view op) {
        CHECK(!result.value() && result.state() == ObservationState::Unsupported);
        const auto& error = result.unavailable_detail()->error;
        CHECK(error.domain == ErrorDomain::Adapter && error.code == static_cast<int64_t>(AdapterError::ProviderReviewRequired));
        CHECK(error.operation == op);
    };
    check(open_native_metadata_stream_writer(entry, proof, identifier, latch), writer_op);
    check(open_native_metadata_stream_reader(entry, proof, identifier, latch), reader_op);
}
void refusals(const std::wstring& base) {
    Fixture f(base);
    Capture capture(f, false, false);
    Target target(f, false, false);
    const auto& id = capture.proof->snapshot().channels.front().identifier;
    constexpr auto writer_inputs = "metadata_stream.native_writer_inputs", reader_inputs = "metadata_stream.native_reader_inputs";
    constexpr auto private_target = "metadata_stream.private_open_target_required";
    constexpr auto listed = "metadata_stream.open_native_channel_proof_required";
    denied_factories(target.entry(), {}, id, f.latch, writer_inputs, reader_inputs);
    denied_factories(target.entry(), capture.proof, id, {}, writer_inputs, reader_inputs);
    InjectedEntry injected;
    denied_factories(injected, capture.proof, id, f.latch, writer_inputs, reader_inputs);
    auto ordinary = take(f.parent->open_child(name(u"source"), EntryAccess::ContentRead));
    denied_factories(*ordinary, capture.proof, id, f.latch, private_target, private_target);
    const auto wrong = NativeFeatureIdentifier::from_windows(u":unlisted:$DATA").value();
    denied_factories(target.entry(), capture.proof, wrong, f.latch, listed, listed);

    const auto catalog = take(target.entry().inspect_data_channels());
    CHECK(catalog.channels.size() == 1 && catalog.channels.front().kind == DataChannelKind::MainData);

    // A valid manifest name on the actual stage, created outside the bridge.
    // Even matching names must never authorize truncating somebody else's ADS.
    const auto stream = f.path + L"\\target" + std::wstring(stream_name.begin(), stream_name.end());
    seed(stream, bytes.last(4));
    auto collision = open_native_metadata_stream_writer(target.entry(), capture.proof, id, f.latch);
    CHECK(!collision.value() && collision.state() == ObservationState::Unsupported &&
          collision.unavailable_detail()->error.operation == "metadata_stream.unowned_target_channel");
    CHECK(take(capture.proof->finish_io()) && capture.proof->io_finished());
    denied_factories(target.entry(), capture.proof, id, f.latch, private_target, private_target);
    CHECK(take(target.finish()));
    auto h = open(stream, GENERIC_READ);
    std::array<std::byte, 5> saved{};
    DWORD count = 0;
    wincheck(ReadFile(h.value, saved.data(), static_cast<DWORD>(saved.size()), &count, nullptr), "existing stream read");
    CHECK(count == 4 && std::ranges::equal(std::span(saved).first(count), bytes.last(4)));
    h.close();
    capture.finish();
    f.clean_root();
}

enum class Fault { FlushAndClose, WriterClose, ReaderClose };
struct Watch {
    FILE_ID_INFO id;
    PreparedJournalRoot& root;
    Fault fault;
    unsigned flush_calls = 0, close_calls = 0, injected_flush = 0, injected_close = 0;
    HANDLE consumed = nullptr;
    bool retried = false, fail_allocation = false, threw = false;
    detail::PreparedJournalConsumerFailure at_allocation{};
};
thread_local Watch* watching = nullptr;
bool selected(HANDLE h, const Watch& w) {
    FILE_ID_INFO actual{};
    return GetFileInformationByHandleEx(h, FileIdInfo, &actual, sizeof(actual)) && same_id(actual, w.id);
}
BOOL WINAPI watched_flush(HANDLE h) {
    using Fn = BOOL(WINAPI*)(HANDLE);
    static const auto real = std::bit_cast<Fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FlushFileBuffers"));
    auto* w = watching;
    const bool match = w && selected(h, *w);
    if (w && h == w->consumed) w->retried = true;
    const BOOL ok = real(h);
    const DWORD error = GetLastError();
    if (match) {
        ++w->flush_calls;
        if (ok && w->fault == Fault::FlushAndClose && !w->injected_flush) {
            ++w->injected_flush;
            SetLastError(ERROR_WRITE_FAULT);
            return FALSE;
        }
    }
    SetLastError(error);
    return ok;
}
BOOL WINAPI watched_close(HANDLE h) {
    using Fn = BOOL(WINAPI*)(HANDLE);
    static const auto real = std::bit_cast<Fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CloseHandle"));
    auto* w = watching;
    if (w && h == w->consumed) w->retried = true;
    const bool match = w && selected(h, *w);
    const BOOL ok = real(h);
    const DWORD error = GetLastError();
    if (match) {
        ++w->close_calls;
        if (ok && !w->injected_close) {
            ++w->injected_close;
            w->consumed = h;
            w->fail_allocation = true;
            SetLastError(ERROR_READ_FAULT);
            return FALSE;
        }
    }
    SetLastError(error);
    return ok;
}
struct WatchScope {
    explicit WatchScope(Watch& w) { watching = &w; }
    ~WatchScope() { watching = nullptr; }
};
} // namespace

// Fail exactly one actual allocation after the selected native handle is consumed.
// Snapshot Root at that allocation, before any recovery/cached finish can repair it.
void* operator new(std::size_t n) {
    if (watching && std::exchange(watching->fail_allocation, false)) {
        watching->threw = true;
        detail::read_prepared_journal_consumer_failure(watching->root, watching->at_allocation);
        throw std::bad_alloc();
    }
    if (void* p = std::malloc(n ? n : 1)) return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
extern "C" {
decltype(&CloseHandle) __imp_CloseHandle = &watched_close;
decltype(&FlushFileBuffers) __imp_FlushFileBuffers = &watched_flush;
decltype(&SetFileTime) __imp_SetFileTime = &watched_set_times;
}

namespace {
void first_error(const Observation<bool>& result, DWORD code, std::string_view operation) {
    CHECK(!result.value() && result.state() == ObservationState::Failed);
    const auto& error = result.unavailable_detail()->error;
    CHECK(error.domain == ErrorDomain::Win32 && error.code == code && error.operation == operation);
}
void cleanup_fault(const std::wstring& base, Fault fault) {
    const bool reader_fault = fault == Fault::ReaderClose;
    const bool flush_fault = fault == Fault::FlushAndClose;
    const DWORD code = flush_fault ? ERROR_WRITE_FAULT : ERROR_READ_FAULT;
    const char* operation = reader_fault ? "metadata_capture.channel_CloseHandle" :
        flush_fault ? "metadata_channels.finish_FlushFileBuffers" : "metadata_channels.finish_CloseHandle";
    Fixture f(base);
    Capture capture(f, false, false);
    Target target(f, false, false);
    auto& entry = target.entry();
    const auto& identifier = capture.proof->snapshot().channels.front().identifier;
    auto writer = take(open_native_metadata_stream_writer(entry, capture.proof, identifier, f.latch));
    CHECK(take(writer->write(0, bytes)) == bytes.size());
    std::unique_ptr<detail::NativeMetadataStreamReader> reader;
    if (reader_fault) {
        CHECK(take(writer->finish_io()));
        writer.reset();
        reader = take(open_native_metadata_stream_reader(entry, capture.proof, identifier, f.latch));
        check_stream(*reader);
    }
    auto held = open(f.path + L"\\target", FILE_READ_ATTRIBUTES);
    Watch watch{id(held.value), *f.root, fault};
    held.close();
    auto finish = [&] { return reader_fault ? reader->finish_io() : writer->finish_io(); };
    {
        WatchScope observe(watch);
        std::optional<Observation<bool>> first;
        try { first.emplace(finish()); }
        catch (const std::bad_alloc&) { CHECK(watch.threw); }
        if (first) first_error(*first, code, operation);
        CHECK(watch.threw && watch.injected_close == 1 && watch.injected_flush == unsigned(flush_fault));
        const auto& seen = watch.at_allocation;
        CHECK(!seen.pending && seen.state == ObservationState::Failed && seen.domain == ErrorDomain::Win32 &&
              seen.code == code && std::string_view(seen.operation.data()) == operation);
        first_error(finish(), code, operation);
        first_error(finish(), code, operation);
        reader.reset();
        writer.reset();
        CHECK(watch.close_calls == 1 && watch.flush_calls == unsigned(!reader_fault) && !watch.retried);
        auto base_close = target.finish();
        if (reader_fault) CHECK(take(std::move(base_close)));
        else first_error(base_close, code, operation);
        CHECK(!watch.retried);
    }
    CHECK(f.latch->accepted);
    f.latch->record_first({ObservationState::Denied, ErrorDomain::Win32, ERROR_ACCESS_DENIED, "test.later_failure"});
    first_error(f.root->revalidate(), code, operation);
    capture.finish();
    f.latch.reset();
    first_error(f.root->finish_io(), code, operation);
    first_error(f.root->finish_io(), code, operation);
}

// Scope strictly to explicit Complete cases. Adjust only an assigned, disabled
// privilege and restore the exact previous state, including on a test failure.
struct CompletePrivilege {
    std::optional<Handle> adjustment;
    TOKEN_PRIVILEGES previous{};
    bool enabled = false;
    static inline bool restore_failed = false;
    CompletePrivilege() {
        Handle token(effective_token(TOKEN_QUERY));
        LUID security{};
        wincheck(LookupPrivilegeValueW(nullptr, L"SeSecurityPrivilege", &security), "lookup security privilege");
        DWORD size = 0;
        GetTokenInformation(token.value, TokenPrivileges, nullptr, 0, &size);
        CHECK(size && GetLastError() == ERROR_INSUFFICIENT_BUFFER);
        std::vector<std::byte> buffer(size);
        wincheck(GetTokenInformation(token.value, TokenPrivileges, buffer.data(), size, &size), "query privileges");
        const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(buffer.data());
        for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
            const auto& item = privileges->Privileges[i];
            if (item.Luid.HighPart != security.HighPart || item.Luid.LowPart != security.LowPart) continue;
            if (!(item.Attributes & SE_PRIVILEGE_ENABLED)) {
                HANDLE adjustable = effective_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES);
                if (!adjustable && GetLastError() == ERROR_ACCESS_DENIED) return;
                adjustment.emplace(adjustable);
                TOKEN_PRIVILEGES request{};
                request.PrivilegeCount = 1;
                request.Privileges[0] = {security, SE_PRIVILEGE_ENABLED};
                SetLastError(ERROR_SUCCESS);
                wincheck(AdjustTokenPrivileges(adjustment->value, FALSE, &request, sizeof(previous), &previous, &size),
                         "enable assigned SeSecurityPrivilege");
                const auto error = GetLastError();
                if (error == ERROR_NOT_ALL_ASSIGNED) return;
                CHECK(error == ERROR_SUCCESS);
            }
            enabled = true;
            break;
        }
    }
    ~CompletePrivilege() {
        if (previous.PrivilegeCount) {
            SetLastError(ERROR_SUCCESS);
            if (!AdjustTokenPrivileges(adjustment->value, FALSE, &previous, 0, nullptr, nullptr) ||
                GetLastError() != ERROR_SUCCESS) restore_failed = true;
        }
    }
};

void exercise(const std::wstring& base, bool directory, bool full, bool privilege) {
    Fixture f(base);
    const char* kind = directory ? "directory" : "file";
    try {
        Capture capture(f, directory, full);
        CHECK(!full || privilege);
        round_trip(f, capture, directory, full);
        std::cout << "PASS " << (full ? "Complete " : "CurrentCaller ") << kind << " ADS and final timestamps\n";
    } catch (const CaptureFailure& failure) {
        const auto& e = failure.detail;
        if (!full || privilege || e.state != ObservationState::Denied ||
            e.error.domain != ErrorDomain::Win32 ||
            (e.error.code != ERROR_PRIVILEGE_NOT_HELD && e.error.code != ERROR_ACCESS_DENIED))
            throw;
        f.clean_root();
        std::cout << "PASS Complete " << kind << " privilege denial (positive replay unavailable) "
                  << e.error.operation << " Win32=" << e.error.code << '\n';
    }
}
void zero_ads_qualifier(const std::wstring& base,bool directory,bool full,bool privilege) {
    Fixture f(base);
    try {
        Capture capture(f,directory,full,false);Target target(f,directory,full);
        auto& entry=target.entry();const auto before=take(entry.inspect_basic());
        CHECK(take(detail::qualify_native_metadata_target(entry,*capture.proof)));
        const auto after=take(entry.inspect_basic());
        CHECK(before.identity.value()&&after.identity.value()&&compare_identity(*before.identity.value(),*after.identity.value())==IdentityComparison::Same);
        CHECK(before.modified.value()&&after.modified.value()&&*before.modified.value()==*after.modified.value());
        CHECK(capture.proof->snapshot().channels.empty());
        const auto catalog=take(entry.inspect_data_channels());
        CHECK(catalog.channels.size()==(directory?0:1));
        InjectedEntry fake;
        const auto nonnative=detail::qualify_native_metadata_target(fake,*capture.proof);
        CHECK(!nonnative.value()&&nonnative.state()==ObservationState::Unsupported&&fake.virtual_calls==0);
        CHECK(nonnative.unavailable_detail()->error.operation=="metadata_stream.native_target_required");
        auto readonly=take(f.parent->open_child(name(u"source"),EntryAccess::MetadataOnly));
        const auto denied=detail::qualify_native_metadata_target(*readonly,*capture.proof);
        CHECK(!denied.value()&&denied.state()==ObservationState::Unsupported);
        CHECK(denied.unavailable_detail()->error.operation=="metadata_stream.private_open_target_required");
        if(!directory) {
            auto wrong=take(f.parent->create_staging_file(name(u"wrong-size")));
            const auto shape=detail::qualify_native_metadata_target(*wrong.entry,*capture.proof);
            CHECK(!shape.value()&&shape.state()==ObservationState::Unsupported&&shape.unavailable_detail()->error.operation=="metadata_stream.target_shape");
            CHECK(take(wrong.entry->finish_content_writes()));
        }
        CHECK(take(capture.proof->finish_io()));
        const auto closed=detail::qualify_native_metadata_target(entry,*capture.proof);
        CHECK(!closed.value()&&closed.state()==ObservationState::Unsupported);
        CHECK(take(target.finish()));capture.finish();f.clean_root();
        std::cout<<"PASS "<<(full?"Complete ":"CurrentCaller ")<<(directory?"directory":"regular")<<" ZERO-ADS private qualifier and nonnative/readonly/closed/shape denial\n";
    }catch(const CaptureFailure& failure) {
        const auto& e=failure.detail;
        if(!full||privilege||e.state!=ObservationState::Denied||e.error.domain!=ErrorDomain::Win32||
           (e.error.code!=ERROR_PRIVILEGE_NOT_HELD&&e.error.code!=ERROR_ACCESS_DENIED))throw;
        f.clean_root();
        std::cout<<"PASS Complete ZERO-ADS privilege denial (positive qualifier unavailable) "<<e.error.operation<<" Win32="<<e.error.code<<'\n';
    }
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        const auto base = test_base(options(argc, argv));
        for (bool directory : {false, true}) exercise(base, directory, false, false);
        refusals(base);
        std::cout << "PASS factory denials and foreign ADS preservation\n";
        for (auto fault : {Fault::FlushAndClose, Fault::WriterClose, Fault::ReaderClose}) {
            cleanup_fault(base, fault);
            std::cout << "PASS " << (fault == Fault::FlushAndClose ? "writer flush then close" :
                fault == Fault::WriterClose ? "writer close" : "reader close") << " OOM, sticky Root, cached finish\n";
        }
        for(bool directory:{false,true})zero_ads_qualifier(base,directory,false,false);
        {
            CompletePrivilege privilege;
            for (bool directory : {false, true}) exercise(base, directory, true, privilege.enabled);
            for(bool directory:{false,true})zero_ads_qualifier(base,directory,true,privilege.enabled);
        }
        CHECK(!CompletePrivilege::restore_failed && !OwnedTree::cleanup_failed);
        return 0;
    } catch (const CaptureFailure& failure) {
        const auto& e = failure.detail;
        std::cerr << "FAIL capture " << e.error.operation << " state=" << unsigned(e.state)
                  << " domain=" << unsigned(e.error.domain) << " code=" << e.error.code << '\n';
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
    }
    if (CompletePrivilege::restore_failed) std::cerr << "SeSecurityPrivilege restoration failed\n";
    return 1;
}
