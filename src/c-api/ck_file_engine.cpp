// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_file_engine.h"

#include "native_filesystem.hpp"
#include "native_operation_copy_job.hpp"
#include "native_operation_move_job.hpp"
#include "name_mapping.hpp"
#include "operation_journal_file.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <new>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <variant>

using namespace ck::files;

struct ckfe_engine { NativeFileSystem filesystem; };
struct ckfe_directory { std::shared_ptr<const DirectoryCursor> cursor; };
struct ckfe_entry { HeldChild::Pointer child; };

using CopyJob = OperationBatchJob::Pointer;
using MoveJob = NativeOperationMoveBatchJob::Pointer;

struct ckfe_job {
    std::variant<CopyJob, MoveJob> operation;
    std::mutex mutex;
    std::jthread worker;
    std::stop_source stop;
    ckfe_job_snapshot snapshot{CKFE_JOB_READY, 0, 1, 1, 0, 0, 0};
    std::optional<UnavailableObservation> failure;
};

namespace {

void clear_error(ckfe_error *error) noexcept {
    if (!error) return;
    std::free(error->operation);
    std::memset(error, 0, sizeof(*error));
}

char *copy_text(const std::string &text) noexcept {
    auto *result = static_cast<char *>(std::malloc(text.size() + 1));
    if (!result) return nullptr;
    std::memcpy(result, text.data(), text.size());
    result[text.size()] = '\0';
    return result;
}

void set_error(ckfe_error *out, const UnavailableObservation &detail) noexcept {
    if (!out) return;
    clear_error(out);
    out->state = static_cast<int32_t>(detail.state);
    out->domain = static_cast<int32_t>(detail.error.domain);
    out->code = detail.error.code;
    out->operation = copy_text(detail.error.operation);
}

void set_exception(ckfe_error *out, const char *operation) noexcept {
    if (!out) return;
    clear_error(out);
    out->state = static_cast<int32_t>(ObservationState::Failed);
    out->domain = static_cast<int32_t>(ErrorDomain::Adapter);
    out->code = static_cast<int64_t>(AdapterError::InvalidNativeResult);
    out->operation = copy_text(operation);
}

template <class T>
ckfe_api_status reject(Observation<T> &result, ckfe_error *error) {
    if (result.unavailable_detail()) set_error(error, *result.unavailable_detail());
    return CKFE_API_INVALID_ARGUMENT;
}

std::optional<std::filesystem::path> host_path(const char *text) {
    if (!text || !*text) return std::nullopt;
    // This conversion is lexical validation only. NativeFileSystem performs
    // the final open through its platform boundary; no filesystem operation
    // is performed through std::filesystem here.
    auto path = std::filesystem::u8path(std::string(text));
    auto address = NativeAbsolutePath::from_host(path);
    if (!address.value() || !path.is_absolute()) return std::nullopt;
    return path;
}

Observation<NativeName> native_name_utf8(const char *text, NameEncoding encoding) {
    if (!text) return Observation<NativeName>::unavailable(ObservationState::Failed,
        {ErrorDomain::Adapter, static_cast<int64_t>(AdapterError::InvalidIdentifier), "c_api.name.null"});
    auto source = NativeName::from_posix(std::string(text));
    if (!source) return Observation<NativeName>::unavailable(ObservationState::Failed,
        {ErrorDomain::Adapter, static_cast<int64_t>(AdapterError::InvalidIdentifier), "c_api.name.invalid"});
    return map_native_name(*source, encoding);
}

Observation<NativeName> native_name_utf16(const uint16_t *text, size_t units) {
    if (!text || units == 0) return Observation<NativeName>::unavailable(ObservationState::Failed,
        {ErrorDomain::Adapter, static_cast<int64_t>(AdapterError::InvalidIdentifier), "c_api.name.null"});
    std::u16string value;
    value.reserve(units);
    for (size_t index = 0; index != units; ++index) value.push_back(static_cast<char16_t>(text[index]));
    auto name = NativeName::from_windows(std::move(value));
#if defined(_WIN32)
    if (name) return Observation<NativeName>::available(std::move(*name));
#endif
    return name ? map_native_name(*name, NameEncoding::PosixBytes)
                : Observation<NativeName>::unavailable(ObservationState::Failed,
                    {ErrorDomain::Adapter, static_cast<int64_t>(AdapterError::InvalidIdentifier), "c_api.name.invalid"});
}

Observation<NativeAbsolutePath> journal_path(const char *text) {
    const auto path = host_path(text);
    if (!path) return Observation<NativeAbsolutePath>::unavailable(ObservationState::Failed,
        {ErrorDomain::Adapter, static_cast<int64_t>(AdapterError::InvalidPath), "c_api.journal_path"});
    return NativeAbsolutePath::from_host(*path);
}

OperationJournalId next_id() noexcept {
    static std::atomic<uint64_t> counter{1};
    OperationJournalId id;
    const auto time = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto serial = counter.fetch_add(1, std::memory_order_relaxed);
    for (unsigned index = 0; index != 8; ++index) {
        id.bytes[index] = std::byte{static_cast<unsigned char>(time >> (index * 8U))};
        id.bytes[8 + index] = std::byte{static_cast<unsigned char>(serial >> (index * 8U))};
    }
    return id;
}

ckfe_job_state batch_state(OperationBatchState state) noexcept {
    switch (state) {
    case OperationBatchState::Ready: return CKFE_JOB_READY;
    case OperationBatchState::Running: return CKFE_JOB_RUNNING;
    case OperationBatchState::Complete: return CKFE_JOB_COMPLETED;
    case OperationBatchState::Cancelled: return CKFE_JOB_CANCELLED;
    case OperationBatchState::RetainedSource: return CKFE_JOB_CHANGED;
    case OperationBatchState::NeedsReconciliation: return CKFE_JOB_RECOVERY_REQUIRED;
    case OperationBatchState::Failed: return CKFE_JOB_FAILED;
    }
    return CKFE_JOB_FAILED;
}

ckfe_job_state move_state(OperationBatchState state) noexcept { return batch_state(state); }

void snapshot_failure(ckfe_job &job) {
    if (std::holds_alternative<CopyJob>(job.operation)) {
        const auto &result = std::get<CopyJob>(job.operation)->result();
        if (!result.items.empty() && result.items.back().failure) job.failure = result.items.back().failure;
    } else {
        const auto &result = std::get<MoveJob>(job.operation)->result();
        if (!result.items.empty() && result.items.back().failure) job.failure = result.items.back().failure;
    }
}

void run_job(ckfe_job &job) noexcept {
    try {
        for (;;) {
            ckfe_job_state state;
            {
                std::lock_guard lock(job.mutex);
                state = job.snapshot.state;
            }
            if (state == CKFE_JOB_COMPLETED || state == CKFE_JOB_CANCELLED ||
                state == CKFE_JOB_FAILED || state == CKFE_JOB_CHANGED || state == CKFE_JOB_RECOVERY_REQUIRED)
                break;
            if (std::holds_alternative<CopyJob>(job.operation)) {
                auto &operation = std::get<CopyJob>(job.operation);
                operation->advance(job.stop.get_token());
                std::lock_guard lock(job.mutex);
                job.snapshot.state = batch_state(operation->state());
                job.snapshot.processed_items = operation->result().items.empty() ? 0 :
                    operation->result().items.size() - (operation->state() == OperationBatchState::Running ? 1 : 0);
                snapshot_failure(job);
            } else {
                auto &operation = std::get<MoveJob>(job.operation);
                operation->advance(job.stop.get_token());
                std::lock_guard lock(job.mutex);
                job.snapshot.state = move_state(operation->state());
                job.snapshot.processed_items = operation->result().items.empty() ? 0 :
                    operation->result().items.size() - (operation->state() == OperationBatchState::Running ? 1 : 0);
                snapshot_failure(job);
            }
        }
    } catch (...) {
        std::lock_guard lock(job.mutex);
        job.snapshot.state = CKFE_JOB_FAILED;
    }
}

template <class Start>
ckfe_api_status start_job(Start &&start, ckfe_job **out, ckfe_error *error) {
    if (!out) return CKFE_API_INVALID_ARGUMENT;
    *out = nullptr;
    try {
        auto operation = start();
        if (!operation.value()) { set_error(error, *operation.unavailable_detail()); return CKFE_API_OK; }
        auto *job = new ckfe_job{std::move(operation).take_value()};
        job->snapshot.state = CKFE_JOB_RUNNING;
        job->worker = std::jthread([job](std::stop_token) { run_job(*job); });
        *out = job;
        return CKFE_API_OK;
    } catch (const std::bad_alloc &) { return CKFE_API_OUT_OF_MEMORY; }
      catch (...) { set_exception(error, "c_api.job_start"); return CKFE_API_EXCEPTION; }
}
} // namespace

extern "C" {

const char *ckfe_version(void) { return "0.1.0"; }

const char *ckfe_api_status_name(ckfe_api_status status) {
    switch (status) {
    case CKFE_API_OK: return "ok";
    case CKFE_API_INVALID_ARGUMENT: return "invalid_argument";
    case CKFE_API_OUT_OF_MEMORY: return "out_of_memory";
    case CKFE_API_EXCEPTION: return "exception";
    }
    return "unknown";
}

const char *ckfe_job_state_name(ckfe_job_state state) {
    switch (state) {
    case CKFE_JOB_READY: return "ready";
    case CKFE_JOB_RUNNING: return "running";
    case CKFE_JOB_COMPLETED: return "completed";
    case CKFE_JOB_CANCELLED: return "cancelled";
    case CKFE_JOB_FAILED: return "failed";
    case CKFE_JOB_CHANGED: return "changed";
    case CKFE_JOB_UNSUPPORTED: return "unsupported";
    case CKFE_JOB_DENIED: return "denied";
    case CKFE_JOB_RECOVERY_REQUIRED: return "recovery_required";
    }
    return "unknown";
}

void ckfe_error_free(ckfe_error *error) { clear_error(error); }

void ckfe_error_init(ckfe_error *error) {
    if (!error) return;
    std::memset(error, 0, sizeof(*error));
}

ckfe_api_status ckfe_engine_create(ckfe_engine **out_engine) {
    if (!out_engine) return CKFE_API_INVALID_ARGUMENT;
    *out_engine = nullptr;
    try { *out_engine = new ckfe_engine; return CKFE_API_OK; }
    catch (const std::bad_alloc &) { return CKFE_API_OUT_OF_MEMORY; }
    catch (...) { return CKFE_API_EXCEPTION; }
}

void ckfe_engine_destroy(ckfe_engine *engine) { delete engine; }

ckfe_api_status ckfe_directory_open_utf8(ckfe_engine *engine, const char *path, int follow,
                                         ckfe_directory **out, ckfe_error *error) {
    if (!engine || !out) return CKFE_API_INVALID_ARGUMENT;
    *out = nullptr;
    try {
        const auto host = host_path(path);
        if (!host) { set_exception(error, "c_api.directory_path"); return CKFE_API_INVALID_ARGUMENT; }
        auto opened = engine->filesystem.open_directory(*host,
            follow ? DirectoryLinkPolicy::FollowFinalLink : DirectoryLinkPolicy::RejectFinalLink);
        if (!opened.value()) { set_error(error, *opened.unavailable_detail()); return CKFE_API_OK; }
        *out = new ckfe_directory{std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value())};
        return CKFE_API_OK;
    } catch (const std::bad_alloc &) { return CKFE_API_OUT_OF_MEMORY; }
    catch (...) { set_exception(error, "c_api.directory_open"); return CKFE_API_EXCEPTION; }
}

ckfe_api_status ckfe_directory_open_utf16(ckfe_engine *engine, const uint16_t *path, size_t units,
                                          int follow, ckfe_directory **out, ckfe_error *error) {
    if (!engine || !out || !path || units == 0) return CKFE_API_INVALID_ARGUMENT;
    try {
        std::u16string value;
        value.reserve(units);
        for (size_t index = 0; index != units; ++index) value.push_back(static_cast<char16_t>(path[index]));
        auto address = NativeAbsolutePath::from_windows(value);
        if (!address.value()) { set_error(error, *address.unavailable_detail()); return CKFE_API_OK; }
        auto host = address.value()->host_path();
        if (!host.value()) { set_error(error, *host.unavailable_detail()); return CKFE_API_OK; }
        auto opened = engine->filesystem.open_directory(*host.value(),
            follow ? DirectoryLinkPolicy::FollowFinalLink : DirectoryLinkPolicy::RejectFinalLink);
        if (!opened.value()) { set_error(error, *opened.unavailable_detail()); return CKFE_API_OK; }
        *out = new ckfe_directory{std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value())};
        return CKFE_API_OK;
    } catch (const std::bad_alloc &) { return CKFE_API_OUT_OF_MEMORY; }
    catch (...) { set_exception(error, "c_api.directory_open_utf16"); return CKFE_API_EXCEPTION; }
}

void ckfe_directory_destroy(ckfe_directory *directory) { delete directory; }

ckfe_api_status ckfe_entry_open_utf8(ckfe_directory *directory, const char *name,
                                     ckfe_entry **out, ckfe_error *error) {
    if (!directory || !out) return CKFE_API_INVALID_ARGUMENT;
    *out = nullptr;
    try {
#if defined(_WIN32)
        const auto encoding = NameEncoding::WindowsUtf16;
#else
        const auto encoding = NameEncoding::PosixBytes;
#endif
        auto native = native_name_utf8(name, encoding);
        if (!native.value()) { set_error(error, *native.unavailable_detail()); return CKFE_API_OK; }
        auto child = HeldChild::observe_with_access(directory->cursor, std::move(native).take_value(), EntryAccess::ContentRead);
        if (!child.value()) { set_error(error, *child.unavailable_detail()); return CKFE_API_OK; }
        *out = new ckfe_entry{std::move(child).take_value()};
        return CKFE_API_OK;
    } catch (const std::bad_alloc &) { return CKFE_API_OUT_OF_MEMORY; }
    catch (...) { set_exception(error, "c_api.entry_open"); return CKFE_API_EXCEPTION; }
}

ckfe_api_status ckfe_entry_open_utf16(ckfe_directory *directory, const uint16_t *name, size_t units,
                                      ckfe_entry **out, ckfe_error *error) {
    if (!directory || !out) return CKFE_API_INVALID_ARGUMENT;
    *out = nullptr;
    try {
        auto native = native_name_utf16(name, units);
        if (!native.value()) { set_error(error, *native.unavailable_detail()); return CKFE_API_OK; }
        auto child = HeldChild::observe_with_access(directory->cursor, std::move(native).take_value(), EntryAccess::ContentRead);
        if (!child.value()) { set_error(error, *child.unavailable_detail()); return CKFE_API_OK; }
        *out = new ckfe_entry{std::move(child).take_value()};
        return CKFE_API_OK;
    } catch (const std::bad_alloc &) { return CKFE_API_OUT_OF_MEMORY; }
    catch (...) { set_exception(error, "c_api.entry_open_utf16"); return CKFE_API_EXCEPTION; }
}

void ckfe_entry_destroy(ckfe_entry *entry) { delete entry; }

ckfe_api_status ckfe_entry_metadata(const ckfe_entry *entry, ckfe_metadata *metadata, ckfe_error *error) {
    if (!entry || !metadata) return CKFE_API_INVALID_ARGUMENT;
    std::memset(metadata, 0, sizeof(*metadata));
    try {
        auto value = entry->child->inspect_basic();
        if (!value.value()) { set_error(error, *value.unavailable_detail()); return CKFE_API_OK; }
        const auto &source = *value.value();
        if (source.kind.value()) {
            metadata->available_fields |= 1ULL << 0;
            switch (*source.kind.value()) {
            case ObjectKind::RegularFile: metadata->kind = CKFE_OBJECT_REGULAR_FILE; break;
            case ObjectKind::Directory: metadata->kind = CKFE_OBJECT_DIRECTORY; break;
            case ObjectKind::SymbolicLink: metadata->kind = CKFE_OBJECT_SYMBOLIC_LINK; break;
            case ObjectKind::Junction: metadata->kind = CKFE_OBJECT_JUNCTION; break;
            case ObjectKind::ReparsePoint: metadata->kind = CKFE_OBJECT_REPARSE_POINT; break;
            default: metadata->kind = CKFE_OBJECT_OTHER; break;
            }
        }
        if (source.logical_size.value()) { metadata->available_fields |= 1ULL << 1; metadata->logical_size = *source.logical_size.value(); }
        if (source.allocated_size.value()) { metadata->available_fields |= 1ULL << 2; metadata->allocated_size = *source.allocated_size.value(); }
        if (source.link_count.value()) { metadata->available_fields |= 1ULL << 3; metadata->link_count = *source.link_count.value(); }
        if (source.identity.value()) {
            metadata->available_fields |= 1ULL << 4;
            metadata->identity_scheme = static_cast<uint8_t>(source.identity.value()->scheme);
            std::memcpy(metadata->identity_volume, source.identity.value()->volume.bytes.data(), 16);
            std::memcpy(metadata->identity_object, source.identity.value()->object.bytes.data(), 16);
            if (source.identity.value()->generation) { metadata->has_generation = 1; metadata->generation = *source.identity.value()->generation; }
        }
        return CKFE_API_OK;
    } catch (...) { set_exception(error, "c_api.entry_metadata"); return CKFE_API_EXCEPTION; }
}

ckfe_api_status ckfe_job_start_copy_regular(ckfe_entry *source, ckfe_directory *destination,
                                            const char *destination_name, const char *journal_root,
                                            int allow_metadata_loss, ckfe_job **out, ckfe_error *error) {
    if (!source || !destination || !out) return CKFE_API_INVALID_ARGUMENT;
    try {
#if defined(_WIN32)
        const auto encoding = NameEncoding::WindowsUtf16;
#else
        const auto encoding = NameEncoding::PosixBytes;
#endif
        auto name = native_name_utf8(destination_name, encoding);
        auto root = journal_path(journal_root);
        if (!name.value()) { set_error(error, *name.unavailable_detail()); return CKFE_API_OK; }
        if (!root.value()) { set_error(error, *root.unavailable_detail()); return CKFE_API_OK; }
        auto prepared = prepare_native_operation_journal_root(*root.value());
        if (!prepared.value()) { set_error(error, *prepared.unavailable_detail()); return CKFE_API_OK; }
        NativeOperationCopyBatchRequest request;
        request.sources = {source->child}; request.destination = destination->cursor;
        request.destination_names = {std::move(name).take_value()}; request.journal_root = std::move(root).take_value();
        request.journal_id = next_id(); request.policy.journal_limits = {1, 32, 4096};
        request.policy.copy_limits.chunk_bytes = 1024 * 1024; request.policy.copy_limits.max_bytes = UINT64_MAX;
        request.policy.allow_unhandled_metadata_loss = allow_metadata_loss != 0;
        request.open_journal = [](const NativeAbsolutePath &path, const NativeName &basename, bool create_new) {
            return open_native_operation_journal_file(path, basename, create_new);
        };
        return start_job([request = std::move(request)]() mutable { return create_native_operation_copy_batch(std::move(request)); }, out, error);
    } catch (...) { set_exception(error, "c_api.job_start_copy"); return CKFE_API_EXCEPTION; }
}

ckfe_api_status ckfe_job_start_move_regular(ckfe_entry *source, ckfe_directory *destination,
                                            const char *destination_name, const char *journal_root,
                                            int allow_metadata_loss, ckfe_job **out, ckfe_error *error) {
    if (!source || !destination || !out) return CKFE_API_INVALID_ARGUMENT;
    try {
#if defined(_WIN32)
        const auto encoding = NameEncoding::WindowsUtf16;
#else
        const auto encoding = NameEncoding::PosixBytes;
#endif
        auto name = native_name_utf8(destination_name, encoding);
        auto root = journal_path(journal_root);
        if (!name.value()) { set_error(error, *name.unavailable_detail()); return CKFE_API_OK; }
        if (!root.value()) { set_error(error, *root.unavailable_detail()); return CKFE_API_OK; }
        auto prepared = prepare_native_operation_journal_root(*root.value());
        if (!prepared.value()) { set_error(error, *prepared.unavailable_detail()); return CKFE_API_OK; }
        NativeOperationMoveBatchRequest request;
        request.sources = {source->child}; request.destination = destination->cursor;
        request.destination_names = {std::move(name).take_value()}; request.journal_root = std::move(root).take_value();
        request.journal_id = next_id(); request.journal_limits = {1, 32, 4096};
        request.copy_limits.chunk_bytes = 1024 * 1024; request.copy_limits.max_bytes = UINT64_MAX;
        request.allow_unhandled_metadata_loss = allow_metadata_loss != 0;
        request.open_journal = [](const NativeAbsolutePath &path, const NativeName &basename, bool create_new) {
            return open_native_operation_journal_file(path, basename, create_new);
        };
        return start_job([request = std::move(request)]() mutable { return create_native_operation_move_batch(std::move(request)); }, out, error);
    } catch (...) { set_exception(error, "c_api.job_start_move"); return CKFE_API_EXCEPTION; }
}

void ckfe_job_cancel(ckfe_job *job) { if (job) job->stop.request_stop(); }

ckfe_api_status ckfe_job_poll(ckfe_job *job, ckfe_job_snapshot *snapshot, ckfe_error *error) {
    if (!job || !snapshot) return CKFE_API_INVALID_ARGUMENT;
    std::lock_guard lock(job->mutex);
    *snapshot = job->snapshot;
    if (job->failure) set_error(error, *job->failure); else clear_error(error);
    return CKFE_API_OK;
}

void ckfe_job_destroy(ckfe_job *job) { if (!job) return; job->stop.request_stop(); job->worker.request_stop(); if (job->worker.joinable()) job->worker.join(); delete job; }

} // extern "C"
