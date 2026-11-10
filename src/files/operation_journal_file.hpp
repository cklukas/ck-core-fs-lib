// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once

#include "operation_journal.hpp"
#include "native_path.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace ck::files {

class PreparedJournalRoot;
class DirectoryCursor;

// A worker-owned byte file (writer or explicitly read-only inspection view). The native adapter is responsible for
// opening an exclusively addressed, private regular file and for retaining
// the handle until the worker finishes. It must never reopen a path between
// size/read/write/flush calls.
class OperationJournalFile {
public:
    virtual ~OperationJournalFile() = default;
    virtual Observation<std::uint64_t> size() = 0;
    virtual Observation<std::size_t> read_at(std::uint64_t offset, std::span<std::byte> bytes) = 0;
    virtual Observation<std::size_t> write_at(std::uint64_t offset, std::span<const std::byte> bytes) = 0;
    virtual Observation<bool> flush() = 0;
    // Explicit worker-bound completion, including delayed close errors. Native
    // adapters must release every owned native handle and cache the outcome so a
    // second call cannot close a reused descriptor. Memory-only adapters have
    // no native close and use the flush default. Never retry close after EINTR.
    virtual Observation<bool> finish_io() { return flush(); }
};

// Reads the bounded durable prefix and reports a corrupt/truncated tail while
// preserving every earlier verified record. A short read is never treated as
// an empty file or as successful recovery.
Observation<OperationJournalDecode> load_operation_journal(
    OperationJournalFile& file, OperationJournalLimits journal_limits = {},
    OperationJournalCodecLimits codec_limits = {});

// Appends one frame at the current durable end. The journal is changed only
// after all writes and flush succeed; callers must reconcile after failure.
Observation<bool> append_operation_journal_file(
    OperationJournalFile& file, OperationJournal& journal, OperationJournalRecord record,
    OperationJournalCodecLimits limits = {});

// Opens or creates one named durable journal below a caller-owned private
// directory. The basename is exact native data and is never presentation text.
// create_new=true refuses an existing file; false opens an existing file only.
Observation<std::unique_ptr<OperationJournalFile>> open_native_operation_journal_file(
    const NativeAbsolutePath& private_root, const NativeName& basename, bool create_new);

// Initial observation-only scan acquisition. Windows requests READ_CONTROL
// in addition to list/attribute access; ordinary browsing rights are unchanged.
// Requires an already-private, native-qualified directory, never prepares it.
// Read-only describes factory I/O and the trusted caller's scan protocol, NOT
// a restricted DirectoryCursor authority type. Its generic provider mutators
// remain available: callers MUST use only observation/enumeration/held-journal
// inspection and terminal completion here, never mutators or access upgrades.
// This does not reduce the caller's existing native authority or issue a
// PreparedJournalRoot/mutation capability.
Observation<std::unique_ptr<DirectoryCursor>> open_native_operation_journal_directory(
    const NativeAbsolutePath& private_root);

// Terminal worker completion for a cursor issued by the scan factory above.
// Consumes its root close once and caches native failure, without flushing.
// After completion only repeated finish and destruction are permitted.
Observation<bool> finish_operation_journal_directory(DirectoryCursor& directory);

// Observation only: existing regular single-link private journal, opened
// relative to the genuine held cursor without a navigation/by-ID reopen.
// write_at/flush refuse without I/O. finish_io checks and closes without flush;
// success does not certify durable publication or content immutability.
// Windows excludes live data writers by native sharing. POSIX version/identity
// bookends are observations, not a mandatory writer-exclusion lease.
Observation<std::unique_ptr<OperationJournalFile>> open_held_operation_journal_file(
    const DirectoryCursor& directory, const NativeName& basename);

// Additive retained-capability entry point. Never resolves private_root's
// former navigation address. Keep the shared PreparedJournalRoot owner alive
// until this journal has completed finish_io(). Worker-only.
Observation<std::unique_ptr<OperationJournalFile>> open_prepared_operation_journal_file(
    PreparedJournalRoot& private_root, const NativeName& basename, bool create_new);

// Establish and verify the platform-private journal-root contract before
// workers open individual journals. This may tighten an app-owned directory's
// permissions/security descriptor, but never weakens the contract.
Observation<bool> prepare_native_operation_journal_root(const NativeAbsolutePath& private_root);

} // namespace ck::files
