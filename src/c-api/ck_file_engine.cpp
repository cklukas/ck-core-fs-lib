// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_file_engine.h"

#include "native_filesystem.hpp"
#include "native_operation_copy_job.hpp"
#include "native_operation_move_job.hpp"
#include "name_mapping.hpp"
#include "operation_journal_file.hpp"
#include "operation_recovery.hpp"

#include <atomic>
#include <array>
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
#include <string_view>
#include <thread>
#include <variant>

using namespace ck::files;

struct ckfe_engine { NativeFileSystem filesystem; };
struct ckfe_directory { std::shared_ptr<const DirectoryCursor> cursor; };
struct ckfe_entry { HeldChild::Pointer child; };
struct ckfe_recovery { NativeOperationRecoveryInspection inspection; };

using CopyJob = OperationBatchJob::Pointer;
using MoveJob = NativeOperationMoveBatchJob::Pointer;

struct ckfe_job {
    std::variant<CopyJob, MoveJob> operation;
    std::mutex mutex;
    std::jthread worker;
    std::stop_source stop;
    ckfe_job_snapshot snapshot{CKFE_JOB_READY, 0, 1, 1, 0, 0, 0};
    std::optional<UnavailableObservation> failure;
    std::array<ckfe_job_event, 64> events{};
    size_t event_begin = 0, event_count = 0;
    uint64_t event_sequence = 0, coalesced_events = 0;
    std::optional<ckfe_job_preservation_report_v1> preservation;
    // True only for a policy path that requires native inventory, staging
    // qualification, ownership application and prepublication revalidation.
    bool preservation_scope_checks_required = false;
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
    out->state = static_cast<ckfe_observation_state>(detail.state);
    out->domain = static_cast<ckfe_error_domain>(detail.error.domain);
    out->code = detail.error.code;
    out->operation = copy_text(detail.error.operation);
}

void set_exception(ckfe_error *out, const char *operation) noexcept {
    if (!out) return;
    clear_error(out);
    out->state = CKFE_OBSERVATION_FAILED;
    out->domain = CKFE_ERROR_ADAPTER;
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
    const std::string_view input(text);
    std::u8string utf8(input.size(), u8'\0');
    std::memcpy(utf8.data(), input.data(), input.size());
    auto path = std::filesystem::path(utf8);
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

ckfe_job_state unavailable_state(ObservationState state) noexcept {
    switch (state) {
    case ObservationState::Unsupported: return CKFE_JOB_UNSUPPORTED;
    case ObservationState::Denied: return CKFE_JOB_DENIED;
    case ObservationState::Gone:
    case ObservationState::Changed: return CKFE_JOB_CHANGED;
    case ObservationState::Unknown: return CKFE_JOB_RECOVERY_REQUIRED;
    default: return CKFE_JOB_FAILED;
    }
}

void snapshot_failure(ckfe_job &job) {
    if (std::holds_alternative<CopyJob>(job.operation)) {
        const auto &result = std::get<CopyJob>(job.operation)->result();
        for (const auto &item : result.items) if (item.failure) job.failure = item.failure;
    } else {
        const auto &result = std::get<MoveJob>(job.operation)->result();
        for (const auto &item : result.items) if (item.failure) job.failure = item.failure;
    }
    if (job.failure && job.snapshot.state == CKFE_JOB_FAILED)
        job.snapshot.state = unavailable_state(job.failure->state);
}

void snapshot_progress(ckfe_job &job, const OperationProgress &progress) {
    job.snapshot.processed_bytes = progress.observed_bytes;
    job.snapshot.total_bytes_known = progress.total_bytes.has_value() ? 1 : 0;
    job.snapshot.total_bytes = progress.total_bytes.value_or(0);
}

void publish_event(ckfe_job &job) noexcept {
    if (job.event_count == job.events.size()) {
        job.event_begin = (job.event_begin + 1) % job.events.size();
        --job.event_count;
        ++job.coalesced_events;
    }
    job.events[(job.event_begin + job.event_count++) % job.events.size()] =
        {++job.event_sequence, job.snapshot};
}

void snapshot_items(ckfe_job &job, const OperationBatchResult &result) noexcept {
    job.snapshot.total_items = result.items.size();
    job.snapshot.total_items_known = 1;
    job.snapshot.processed_items = 0;
    for (const auto &item : result.items)
        if (item.outcome != OperationItemOutcome::Pending) ++job.snapshot.processed_items;
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
                state == CKFE_JOB_FAILED || state == CKFE_JOB_CHANGED || state == CKFE_JOB_RECOVERY_REQUIRED ||
                state == CKFE_JOB_UNSUPPORTED || state == CKFE_JOB_DENIED)
                break;
            if (std::holds_alternative<CopyJob>(job.operation)) {
                auto &operation = std::get<CopyJob>(job.operation);
                operation->advance(job.stop.get_token());
                std::lock_guard lock(job.mutex);
                job.snapshot.state = batch_state(operation->state());
                snapshot_items(job, operation->result());
                snapshot_progress(job, operation->progress());
                snapshot_failure(job);
                publish_event(job);
            } else {
                auto &operation = std::get<MoveJob>(job.operation);
                operation->advance(job.stop.get_token());
                std::lock_guard lock(job.mutex);
                job.snapshot.state = move_state(operation->state());
                snapshot_items(job, operation->result());
                snapshot_progress(job, operation->progress());
                snapshot_failure(job);
                publish_event(job);
            }
        }
    } catch (...) {
        std::lock_guard lock(job.mutex);
        // An unexpected adapter exception may have crossed a mutation boundary.
        job.snapshot.state = CKFE_JOB_RECOVERY_REQUIRED;
        publish_event(job);
    }
}

template <class Start>
ckfe_api_status start_job(Start &&start, ckfe_job **out, ckfe_error *error,
    std::optional<ckfe_job_preservation_report_v1> preservation = {},
    bool preservation_scope_checks_required = false) {
    clear_error(error);
    if (!out) return CKFE_API_INVALID_ARGUMENT;
    *out = nullptr;
    try {
        auto job = std::make_unique<ckfe_job>();
        job->preservation = preservation;
        job->preservation_scope_checks_required = preservation_scope_checks_required;
        job->snapshot.state = CKFE_JOB_RUNNING;
        job->worker = std::jthread([raw = job.get(), begin = std::forward<Start>(start)](std::stop_token) mutable {
            try {
                auto operation = begin();
                if (!operation.value()) {
                    std::lock_guard lock(raw->mutex);
                    raw->failure = *operation.unavailable_detail();
                    raw->snapshot.state = unavailable_state(raw->failure->state);
                    publish_event(*raw);
                    return;
                }
                raw->operation = std::move(operation).take_value();
                run_job(*raw);
            } catch (...) {
                std::lock_guard lock(raw->mutex);
                raw->snapshot.state = CKFE_JOB_RECOVERY_REQUIRED;
                publish_event(*raw);
            }
        });
        *out = job.release();
        return CKFE_API_OK;
    } catch (const std::bad_alloc &) { return CKFE_API_OUT_OF_MEMORY; }
      catch (...) { set_exception(error, "c_api.job_start"); return CKFE_API_EXCEPTION; }
}
} // namespace

extern "C" {

const char *ckfe_version(void) { return "0.2.0"; }

uint32_t ckfe_abi_version_major(void) { return 0; }

uint32_t ckfe_abi_version_minor(void) { return 2; }

const char *ckfe_api_status_name(ckfe_api_status status) {
    switch (status) {
    case CKFE_API_OK: return "ok";
    case CKFE_API_INVALID_ARGUMENT: return "invalid_argument";
    case CKFE_API_OUT_OF_MEMORY: return "out_of_memory";
    case CKFE_API_EXCEPTION: return "exception";
    case CKFE_API_OPERATION_UNAVAILABLE: return "operation_unavailable";
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
    clear_error(error);
    if (out) *out = nullptr;
    if (!engine || !out) return CKFE_API_INVALID_ARGUMENT;
    try {
        const auto host = host_path(path);
        if (!host) { set_exception(error, "c_api.directory_path"); return CKFE_API_INVALID_ARGUMENT; }
        auto opened = engine->filesystem.open_directory(*host,
            follow ? DirectoryLinkPolicy::FollowFinalLink : DirectoryLinkPolicy::RejectFinalLink);
        if (!opened.value()) { set_error(error, *opened.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        *out = new ckfe_directory{std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value())};
        return CKFE_API_OK;
    } catch (const std::bad_alloc &) { return CKFE_API_OUT_OF_MEMORY; }
    catch (...) { set_exception(error, "c_api.directory_open"); return CKFE_API_EXCEPTION; }
}

ckfe_api_status ckfe_directory_open_utf16(ckfe_engine *engine, const uint16_t *path, size_t units,
                                          int follow, ckfe_directory **out, ckfe_error *error) {
    clear_error(error);
    if (out) *out = nullptr;
    if (!engine || !out || !path || units == 0) return CKFE_API_INVALID_ARGUMENT;
    try {
        std::u16string value;
        value.reserve(units);
        for (size_t index = 0; index != units; ++index) value.push_back(static_cast<char16_t>(path[index]));
        auto address = NativeAbsolutePath::from_windows(value);
        if (!address.value()) { set_error(error, *address.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        auto host = address.value()->host_path();
        if (!host.value()) { set_error(error, *host.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        auto opened = engine->filesystem.open_directory(*host.value(),
            follow ? DirectoryLinkPolicy::FollowFinalLink : DirectoryLinkPolicy::RejectFinalLink);
        if (!opened.value()) { set_error(error, *opened.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        *out = new ckfe_directory{std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value())};
        return CKFE_API_OK;
    } catch (const std::bad_alloc &) { return CKFE_API_OUT_OF_MEMORY; }
    catch (...) { set_exception(error, "c_api.directory_open_utf16"); return CKFE_API_EXCEPTION; }
}

void ckfe_directory_destroy(ckfe_directory *directory) { delete directory; }

ckfe_api_status ckfe_entry_open_utf8(ckfe_directory *directory, const char *name,
                                     ckfe_entry **out, ckfe_error *error) {
    clear_error(error);
    if (out) *out = nullptr;
    if (!directory || !out) return CKFE_API_INVALID_ARGUMENT;
    try {
#if defined(_WIN32)
        const auto encoding = NameEncoding::WindowsUtf16;
#else
        const auto encoding = NameEncoding::PosixBytes;
#endif
        auto native = native_name_utf8(name, encoding);
        if (!native.value()) { set_error(error, *native.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        auto child = HeldChild::observe_with_access(directory->cursor, std::move(native).take_value(), EntryAccess::ContentRead);
        if (!child.value()) { set_error(error, *child.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        *out = new ckfe_entry{std::move(child).take_value()};
        return CKFE_API_OK;
    } catch (const std::bad_alloc &) { return CKFE_API_OUT_OF_MEMORY; }
    catch (...) { set_exception(error, "c_api.entry_open"); return CKFE_API_EXCEPTION; }
}

ckfe_api_status ckfe_entry_open_utf16(ckfe_directory *directory, const uint16_t *name, size_t units,
                                      ckfe_entry **out, ckfe_error *error) {
    clear_error(error);
    if (out) *out = nullptr;
    if (!directory || !out) return CKFE_API_INVALID_ARGUMENT;
    try {
        auto native = native_name_utf16(name, units);
        if (!native.value()) { set_error(error, *native.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        auto child = HeldChild::observe_with_access(directory->cursor, std::move(native).take_value(), EntryAccess::ContentRead);
        if (!child.value()) { set_error(error, *child.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        *out = new ckfe_entry{std::move(child).take_value()};
        return CKFE_API_OK;
    } catch (const std::bad_alloc &) { return CKFE_API_OUT_OF_MEMORY; }
    catch (...) { set_exception(error, "c_api.entry_open_utf16"); return CKFE_API_EXCEPTION; }
}

void ckfe_entry_destroy(ckfe_entry *entry) { delete entry; }

ckfe_api_status ckfe_entry_metadata(const ckfe_entry *entry, ckfe_metadata *metadata, ckfe_error *error) {
    clear_error(error);
    if (metadata) std::memset(metadata, 0, sizeof(*metadata));
    if (!entry || !metadata) return CKFE_API_INVALID_ARGUMENT;
    try {
        auto value = entry->child->inspect_basic();
        if (!value.value()) { set_error(error, *value.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        const auto &source = *value.value();
        if (source.kind.value()) {
            metadata->available_fields |= CKFE_METADATA_KIND;
            switch (*source.kind.value()) {
            case ObjectKind::RegularFile: metadata->kind = CKFE_OBJECT_REGULAR_FILE; break;
            case ObjectKind::Directory: metadata->kind = CKFE_OBJECT_DIRECTORY; break;
            case ObjectKind::SymbolicLink: metadata->kind = CKFE_OBJECT_SYMBOLIC_LINK; break;
            case ObjectKind::Junction: metadata->kind = CKFE_OBJECT_JUNCTION; break;
            case ObjectKind::ReparsePoint: metadata->kind = CKFE_OBJECT_REPARSE_POINT; break;
            default: metadata->kind = CKFE_OBJECT_OTHER; break;
            }
        }
        if (source.logical_size.value()) { metadata->available_fields |= CKFE_METADATA_LOGICAL_SIZE; metadata->logical_size = *source.logical_size.value(); }
        if (source.allocated_size.value()) { metadata->available_fields |= CKFE_METADATA_ALLOCATED_SIZE; metadata->allocated_size = *source.allocated_size.value(); }
        if (source.link_count.value()) { metadata->available_fields |= CKFE_METADATA_LINK_COUNT; metadata->link_count = *source.link_count.value(); }
        if (source.identity.value()) {
            metadata->available_fields |= CKFE_METADATA_IDENTITY;
            metadata->identity_scheme = static_cast<uint8_t>(source.identity.value()->scheme);
            std::memcpy(metadata->identity_volume, source.identity.value()->volume.bytes.data(), 16);
            std::memcpy(metadata->identity_object, source.identity.value()->object.bytes.data(), 16);
            if (source.identity.value()->generation) { metadata->has_generation = 1; metadata->generation = *source.identity.value()->generation; }
        }
        return CKFE_API_OK;
    } catch (...) { set_exception(error, "c_api.entry_metadata"); return CKFE_API_EXCEPTION; }
}

static ckfe_api_status start_copy_regular(ckfe_entry *source, ckfe_directory *destination,
                                            const char *destination_name, const char *journal_root,
                                            int allow_metadata_loss, RegularMetadataScope scope,
                                            ckfe_job **out, ckfe_error *error) {
    clear_error(error);
    if (out) *out = nullptr;
    if (!source || !destination || !out) return CKFE_API_INVALID_ARGUMENT;
    try {
#if defined(_WIN32)
        const auto encoding = NameEncoding::WindowsUtf16;
#else
        const auto encoding = NameEncoding::PosixBytes;
#endif
        auto name = native_name_utf8(destination_name, encoding);
        auto root = journal_path(journal_root);
        if (!name.value()) { set_error(error, *name.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        if (!root.value()) { set_error(error, *root.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        NativeOperationCopyBatchRequest request;
        request.sources = {source->child}; request.destination = destination->cursor;
        request.destination_names = {std::move(name).take_value()}; request.journal_root = std::move(root).take_value();
        request.journal_id = next_id(); request.policy.journal_limits = {1, 32, 4096};
        request.policy.copy_limits.chunk_bytes = 1024 * 1024;
        request.policy.copy_limits.max_bytes = StreamCopyLimits::hard_max_bytes;
        request.policy.allow_unhandled_metadata_loss = allow_metadata_loss != 0;
        request.policy.metadata_scope = scope;
        request.open_journal = [](const NativeAbsolutePath &path, const NativeName &basename, bool create_new) {
            return open_native_operation_journal_file(path, basename, create_new);
        };
        ckfe_job_preservation_report_v1 report{};
        report.version = 1;
        report.struct_size = sizeof(report);
        report.requested_scope = static_cast<uint32_t>(scope);
        report.provider_qualification = CKFE_OBSERVATION_UNKNOWN;
        report.unknown_fields = CKFE_PRESERVED_ACL | CKFE_PRESERVED_XATTRS |
            CKFE_PRESERVED_LABELS_CAPABILITIES | CKFE_PRESERVED_STORAGE_REPRESENTATION;
        if (scope == RegularMetadataScope::OrdinaryCallerVisibleV1 || allow_metadata_loss)
            report.explicitly_excluded_fields = CKFE_PRESERVED_SOURCE_OWNER | CKFE_PRESERVED_PRIVILEGE_BITS |
                CKFE_PRESERVED_BIRTH_CHANGE_TIMES | CKFE_PRESERVED_STORAGE_REPRESENTATION;
        return start_job([request = std::move(request)]() mutable {
            auto prepared = prepare_native_operation_journal_root(*request.journal_root);
            if (!prepared.value()) return Observation<CopyJob>::unavailable(prepared.state(), prepared.unavailable_detail()->error);
            return create_native_operation_copy_batch(std::move(request));
        }, out, error, report, !allow_metadata_loss && scope == RegularMetadataScope::OrdinaryCallerVisibleV1);
    } catch (...) { set_exception(error, "c_api.job_start_copy"); return CKFE_API_EXCEPTION; }
}

ckfe_api_status ckfe_job_start_copy_regular(ckfe_entry *source, ckfe_directory *destination,
    const char *name, const char *root, int loss, ckfe_job **out, ckfe_error *error) {
    return start_copy_regular(source, destination, name, root, loss,
        RegularMetadataScope::CompleteMetadataV1, out, error);
}

ckfe_api_status ckfe_job_start_copy_regular_v1(ckfe_entry *source, ckfe_directory *destination,
    const char *name, const char *root, const ckfe_copy_options_v1 *options,
    ckfe_job **out, ckfe_error *error) {
    clear_error(error);
    if (out) *out = nullptr;
    if (!options || options->version != CKFE_COPY_OPTIONS_VERSION ||
        options->struct_size != sizeof(*options) || options->metadata_scope > CKFE_METADATA_ORDINARY_CALLER_VISIBLE_V1 ||
        options->allow_metadata_loss > 1) return CKFE_API_INVALID_ARGUMENT;
    for (auto reserved : options->reserved) if (reserved) return CKFE_API_INVALID_ARGUMENT;
    return start_copy_regular(source, destination, name, root, options->allow_metadata_loss,
        static_cast<RegularMetadataScope>(options->metadata_scope), out, error);
}

ckfe_api_status ckfe_job_start_move_regular(ckfe_entry *source, ckfe_directory *destination,
                                            const char *destination_name, const char *journal_root,
                                            int allow_metadata_loss, ckfe_job **out, ckfe_error *error) {
    clear_error(error);
    if (out) *out = nullptr;
    if (!source || !destination || !out) return CKFE_API_INVALID_ARGUMENT;
    try {
#if defined(_WIN32)
        const auto encoding = NameEncoding::WindowsUtf16;
#else
        const auto encoding = NameEncoding::PosixBytes;
#endif
        auto name = native_name_utf8(destination_name, encoding);
        auto root = journal_path(journal_root);
        if (!name.value()) { set_error(error, *name.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        if (!root.value()) { set_error(error, *root.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        NativeOperationMoveBatchRequest request;
        request.sources = {source->child}; request.destination = destination->cursor;
        request.destination_names = {std::move(name).take_value()}; request.journal_root = std::move(root).take_value();
        request.journal_id = next_id(); request.journal_limits = {1, 32, 4096};
        request.copy_limits.chunk_bytes = 1024 * 1024;
        request.copy_limits.max_bytes = StreamCopyLimits::hard_max_bytes;
        request.allow_unhandled_metadata_loss = allow_metadata_loss != 0;
        request.open_journal = [](const NativeAbsolutePath &path, const NativeName &basename, bool create_new) {
            return open_native_operation_journal_file(path, basename, create_new);
        };
        return start_job([request = std::move(request)]() mutable {
            auto prepared = prepare_native_operation_journal_root(*request.journal_root);
            if (!prepared.value()) return Observation<MoveJob>::unavailable(prepared.state(), prepared.unavailable_detail()->error);
            return create_native_operation_move_batch(std::move(request));
        }, out, error);
    } catch (...) { set_exception(error, "c_api.job_start_move"); return CKFE_API_EXCEPTION; }
}

void ckfe_job_cancel(ckfe_job *job) { if (job) job->stop.request_stop(); }

ckfe_api_status ckfe_job_poll(ckfe_job *job, ckfe_job_snapshot *snapshot, ckfe_error *error) {
    clear_error(error);
    if (snapshot) *snapshot = {};
    if (!job || !snapshot) return CKFE_API_INVALID_ARGUMENT;
    try {
    std::lock_guard lock(job->mutex);
    *snapshot = job->snapshot;
    if (job->failure) set_error(error, *job->failure); else clear_error(error);
    return CKFE_API_OK;
    } catch (...) { set_exception(error, "c_api.job_poll"); return CKFE_API_EXCEPTION; }
}

ckfe_api_status ckfe_job_drain_events(ckfe_job *job, ckfe_job_event *events,
    size_t capacity, size_t *count, uint64_t *coalesced, ckfe_error *error) {
    clear_error(error);
    if (count) *count = 0;
    if (coalesced) *coalesced = 0;
    if (!job || !count || !coalesced || (!events && capacity)) return CKFE_API_INVALID_ARGUMENT;
    try {
        std::lock_guard lock(job->mutex);
        const auto n = std::min(capacity, job->event_count);
        for (size_t i = 0; i < n; ++i)
            events[i] = job->events[(job->event_begin + i) % job->events.size()];
        job->event_begin = (job->event_begin + n) % job->events.size();
        job->event_count -= n;
        *count = n;
        *coalesced = job->coalesced_events;
        job->coalesced_events = 0;
        return CKFE_API_OK;
    } catch (...) { set_exception(error, "c_api.job_drain_events"); return CKFE_API_EXCEPTION; }
}

ckfe_api_status ckfe_job_get_preservation_report_v1(ckfe_job *job,
    ckfe_job_preservation_report_v1 *report, size_t bytes, ckfe_error *error) {
    clear_error(error);
    if (!report || bytes != sizeof(*report)) return CKFE_API_INVALID_ARGUMENT;
    *report = {};
    if (!job) return CKFE_API_INVALID_ARGUMENT;
    try {
        std::lock_guard lock(job->mutex);
        if (!job->preservation) return CKFE_API_OPERATION_UNAVAILABLE;
        *report = *job->preservation;
        if (job->snapshot.state == CKFE_JOB_COMPLETED) {
            report->source_preserved_fields = CKFE_PRESERVED_ORDINARY_MODE |
                CKFE_PRESERVED_ACCESS_TIME | CKFE_PRESERVED_MODIFIED_TIME;
#ifndef _WIN32
            report->current_effective_uid_gid_applied =
                job->preservation_scope_checks_required;
#else
            report->source_preserved_fields &= ~static_cast<uint64_t>(CKFE_PRESERVED_ORDINARY_MODE);
#endif
            // Basic fields are individually applied/verified even with loss
            // consent. That is not evidence that the requested provider scope
            // was inventoried or qualified: loss-consenting paths bypass it.
            if (job->preservation_scope_checks_required)
                report->provider_qualification = CKFE_OBSERVATION_AVAILABLE;
        } else if (job->failure) report->provider_qualification = static_cast<ckfe_observation_state>(job->failure->state);
        return CKFE_API_OK;
    } catch (...) { set_exception(error, "c_api.job_preservation_report"); return CKFE_API_EXCEPTION; }
}

void ckfe_job_destroy(ckfe_job *job) { if (!job) return; job->stop.request_stop(); job->worker.request_stop(); if (job->worker.joinable()) job->worker.join(); delete job; }

ckfe_api_status ckfe_recovery_open_utf8(const char *private_root, const char *journal_name,
    ckfe_recovery **out, ckfe_error *error) {
    clear_error(error);
    if (out) *out = nullptr;
    if (!out || !private_root || !journal_name) return CKFE_API_INVALID_ARGUMENT;
    try {
        auto root = journal_path(private_root);
#ifdef _WIN32
        constexpr auto encoding = NameEncoding::WindowsUtf16;
#else
        constexpr auto encoding = NameEncoding::PosixBytes;
#endif
        auto name = native_name_utf8(journal_name, encoding);
        if (!root.value()) { set_error(error, *root.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        if (!name.value()) { set_error(error, *name.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        auto file = open_native_operation_journal_file(*root.value(), *name.value(), false);
        if (!file.value()) { set_error(error, *file.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        auto report = inspect_native_operation_recovery_evidence(**file.value());
        if (!report.value()) { set_error(error, *report.unavailable_detail()); return CKFE_API_OPERATION_UNAVAILABLE; }
        *out = new ckfe_recovery{std::move(report).take_value()};
        return CKFE_API_OK;
    } catch (const std::bad_alloc &) { return CKFE_API_OUT_OF_MEMORY; }
      catch (...) { set_exception(error, "c_api.recovery_open"); return CKFE_API_EXCEPTION; }
}

ckfe_api_status ckfe_recovery_get_summary(const ckfe_recovery *recovery,
    ckfe_recovery_summary *summary, ckfe_error *error) {
    clear_error(error);
    if (summary) *summary = {};
    if (!recovery || !summary) return CKFE_API_INVALID_ARGUMENT;
    const auto &value = recovery->inspection;
    *summary = {value.report.items.size(), static_cast<uint8_t>(value.report.requires_reconciliation),
        static_cast<uint8_t>(value.report.has_untrusted_tail), static_cast<uint8_t>(value.has_untrusted_evidence)};
    return CKFE_API_OK;
}

ckfe_api_status ckfe_recovery_read_page(const ckfe_recovery *recovery, uint64_t first,
    ckfe_recovery_item *items, size_t capacity, size_t *count, ckfe_error *error) {
    clear_error(error);
    if (count) *count = 0;
    if (!recovery || !count || capacity > 256 || (!items && capacity) ||
        first > recovery->inspection.report.items.size()) return CKFE_API_INVALID_ARGUMENT;
    const auto &rows = recovery->inspection.report.items;
    const size_t n = std::min(capacity, rows.size() - static_cast<size_t>(first));
    for (size_t index = 0; index < n; ++index) {
        const auto &row = rows[static_cast<size_t>(first) + index];
        items[index] = {row.item, static_cast<uint32_t>(row.state),
            static_cast<ckfe_recovery_action>(row.action), static_cast<uint8_t>(row.requires_reconciliation)};
    }
    *count = n;
    return CKFE_API_OK;
}

void ckfe_recovery_destroy(ckfe_recovery *recovery) { delete recovery; }

} // extern "C"
