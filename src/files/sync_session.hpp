// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "native_path.hpp"
#include "sync_baseline.hpp"
#include <functional>
#include <memory>
#include <optional>
#include <string_view>

namespace ck::files {

// Internal C++ contract. The C facade owns the session and translates exceptions.
// Calls on one session/backend must be serialized. Native roots/locks remain
// held until destruction; callers revalidate before using borrowed root handles.
struct SyncSessionIdentity final {
    SyncDigest left_root{}, right_root{}, policy{}, pair{};
};
enum class SyncSessionState { FirstRun, Ready, Recovered, ReviewRequired, HistoryChanged };
struct SyncSessionSnapshot final {
    SyncSessionState state = SyncSessionState::ReviewRequired;
    std::uint64_t generation = 0;
    std::optional<SyncBaseline> baseline;
    // Inspection only, never implicitly promoted after corruption/lost intent.
    std::optional<SyncBaseline> previous;
};
enum class SyncSessionIo { Write, FileFlush, Publish, ParentFlush, Remove };
// Test hook: return false to fail BEFORE the named operation. Write is called
// for every native write, including retries. max_write_bytes forces short writes.
struct SyncSessionFaults final {
    std::function<bool(SyncSessionIo)> before;
    std::size_t max_write_bytes = 1024 * 1024;
};

// Adapter boundary for native storage and deterministic crash tests. A backend
// is authority only if it has proved identities, exact ancestry and overlap
// locks for BOTH roots. Native factory never accepts caller-asserted proof.
// Names are engine-generated ASCII single components. Missing reads are nullopt;
// denial, unsupported, corruption and I/O failure must never become missing.
class SyncSessionBackend {
public:
    virtual ~SyncSessionBackend() = default;
    virtual const SyncDigest& left_identity() const noexcept = 0;
    virtual const SyncDigest& right_identity() const noexcept = 0;
    virtual Observation<bool> revalidate() = 0;
    virtual std::intptr_t root_handle(bool right) const noexcept = 0;
    virtual Observation<std::optional<std::vector<std::byte>>> read(std::string_view name,
        std::size_t limit) = 0;
    // Create/replace a disposable stage, complete short writes, then flush file.
    virtual Observation<bool> stage(std::string_view name, std::span<const std::byte>) = 0;
    virtual Observation<bool> publish(std::string_view from, std::string_view to) = 0;
    virtual Observation<bool> remove(std::string_view name) = 0;
    virtual Observation<bool> flush_directory() = 0;
};

// Existing private coordinator directory (POSIX: owner, exactly 0700). Durable
// generation storage lives here. Overlap locks are on actual ancestor directory
// objects, NOT pair IDs or coordinator filenames; different coordinator roots
// cannot bypass them. Shared locks on ancestors, exclusive locks on both roots.
// Linked/reparse components, unknown/nonlocal identities or ancestry, nested
// source/target, or coordinator inside either root fail closed. Acquisition is
// nonblocking (Changed on contention). Locks coordinate cooperating sessions;
// they are not a filesystem transaction against unrelated writers.
Observation<std::unique_ptr<SyncSessionBackend>> open_native_sync_session_backend(
    const NativeAbsolutePath& coordinator, const NativeAbsolutePath& left,
    const NativeAbsolutePath& right, SyncSessionFaults faults = {});

class SyncSession final {
public:
    static Observation<std::unique_ptr<SyncSession>> open(std::unique_ptr<SyncSessionBackend>,
        const SyncDigest& policy, SyncBaselineLimits limits = {});
    const SyncSessionIdentity& identity() const noexcept { return identity_; }
    const SyncSessionSnapshot& snapshot() const noexcept { return snapshot_; }
    std::intptr_t root_handle(bool right) const noexcept { return backend_->root_handle(right); }
    Observation<bool> revalidate() { return backend_->revalidate(); }
    // Refresh also completes a valid durable intent, under the held root locks.
    // A failed/uncertain commit requires refresh before further commits.
    Observation<bool> refresh();
    // Cancellation is checked before durable intent publication. After that point
    // commit/recovery completes the intended generation, even if cancelled.
    // CAS against the loaded AND stored generation. Explicit first-run approval
    // is required. ReviewRequired cannot commit; the caller must review/reset
    // storage separately. Only ConfirmedEqual advances rows; omitted/skipped
    // entries retain their old evidence via advance_sync_baseline.
    Observation<SyncBaselineAdvance> commit(std::uint64_t expected_generation,
        std::span<const SyncBaselineUpdate>, bool approve_first_run = false,
        std::function<bool()> cancelled = {});
private:
    SyncSession(std::unique_ptr<SyncSessionBackend>, SyncSessionIdentity, SyncBaselineLimits);
    std::unique_ptr<SyncSessionBackend> backend_;
    SyncSessionIdentity identity_;
    SyncBaselineLimits limits_;
    SyncSessionSnapshot snapshot_;
    std::string prefix_;
    SyncDigest loaded_digest_{};
    bool uncertain_ = false;
};
} // namespace ck::files
