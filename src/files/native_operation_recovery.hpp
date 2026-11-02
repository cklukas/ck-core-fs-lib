// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once

#include "directory_cursor.hpp"
#include "operation_recovery.hpp"

#include <cstdint>
#include <memory>

namespace ck::files {

class NativeOperationCopyJob;
class VerifiedCopyRetryJob;
struct NativeOperationRecoveryCleanupRequest;
// Worker-owned, process-local authority. Only a trusted stage creator can mint
// this object from the original created handle and live journal. Serialized
// IDs, timestamps and a freshly reopened entry cannot manufacture continuity.
class NativeStagingOwnershipReceipt final {
public:
    using Pointer = std::shared_ptr<const NativeStagingOwnershipReceipt>;
    ~NativeStagingOwnershipReceipt();
    NativeStagingOwnershipReceipt(const NativeStagingOwnershipReceipt&) = delete;
    NativeStagingOwnershipReceipt& operator=(const NativeStagingOwnershipReceipt&) = delete;
private:
    struct State;
    explicit NativeStagingOwnershipReceipt(std::shared_ptr<State>) noexcept;
    static Observation<Pointer> bind_created(OperationJournal::Pointer journal, std::size_t item,
        std::shared_ptr<const DirectoryCursor> destination, std::shared_ptr<OpenedEntry> created,
        std::optional<NativeName> named_component, StagingNamespace staging_namespace);
    std::shared_ptr<State> state_;
    friend class NativeOperationCopyJob;
    friend class VerifiedCopyRetryJob;
    friend Observation<bool> cleanup_native_unpublished_staging(const NativeOperationRecoveryCleanupRequest&);
};

struct NativeOperationRecoveryCleanupRequest final {
    NativeOperationRecoveryArtifact artifact;
    std::shared_ptr<const DirectoryCursor> destination;
    ObjectIdentity destination_identity;
    NativeStagingOwnershipReceipt::Pointer ownership;
};

// Mutating cleanup requires live creator ownership and a pre-publication live
// journal. A fresh-process inspection is review-only, even with matching native
// IDs. Anonymous staging names are hints and are never passed to path I/O.
// Caller serializes this worker-only operation with its originating copy job.
Observation<bool> cleanup_native_unpublished_staging(
    const NativeOperationRecoveryCleanupRequest& request);

struct NativeOperationRecoveryVerificationRequest final {
    NativeOperationRecoveryArtifact artifact;
    std::shared_ptr<const DirectoryCursor> destination;
    ObjectIdentity destination_identity;
    std::uint64_t max_bytes = 4ULL * 1024 * 1024 * 1024;
};

// Read-only post-publication verification. It binds the held destination
// directory, exact native destination name, published object identity, size,
// and durable content digest. A false result is a verified mismatch; an
// unavailable result is an inability to establish the receipt. No mutation or
// pathname-based fallback is performed.
Observation<bool> verify_native_published_destination(
    const NativeOperationRecoveryVerificationRequest& request);

} // namespace ck::files
