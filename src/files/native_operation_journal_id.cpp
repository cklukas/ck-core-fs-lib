// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_operation_journal_id.hpp"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#else
#include <cerrno>
#include <unistd.h>
#endif

namespace ck::files {

Observation<OperationJournalId> new_native_operation_journal_id() {
    using Result = Observation<OperationJournalId>;
    OperationJournalId id;
#if defined(_WIN32)
    const auto status = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(id.bytes.data()),
        static_cast<ULONG>(id.bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0)
        return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::NtStatus, static_cast<std::int64_t>(status), "operation_journal_id.BCryptGenRandom"});
#else
    if (getentropy(id.bytes.data(), id.bytes.size()) != 0) {
        const auto code = errno;
        return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Posix, code, "operation_journal_id.getentropy"});
    }
#endif
    if (id == OperationJournalId{})
        return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult),
             "operation_journal_id.zero_entropy"});
    return Result::available(id);
}

} // namespace ck::files
