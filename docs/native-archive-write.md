# Native archive image writer

`NativeArchiveWriteJob` is a worker-owned C++ primitive in the unreleased
Native layer (`ck_core_fs_native`). It materializes a bounded byte recipe into
one newly created regular file, verifies that image, journals its protocol and
attempts no-replace publication below a held destination. Use the matching
Native/Platform implementation and headers; this adds no stable C API export.

The ckUtilities archive adapter supplies an encoded header, manifest and data
extents. Source inventory, loss review and live/snapshot acquisition belong to
that adapter and its source provider. This writer neither acquires a volume
snapshot nor reads a raw device, filesystem image or source directory tree.
An archive consistency label is not proof that a snapshot was acquired.

## Held creation and ownership

A request supplies a genuine retained `DirectoryCursor`, a Ready
`PreparedJournalRoot`, exact native destination/staging/journal components,
and an operation journal ID. `begin()` obtains the namespace-child private
scope guard; each protocol step rechecks it. The destination must pass the
Root's native private-state boundary checks. A displayed directory address,
caller-created identity value or journal record cannot replace these owners.

The job itself calls `create_staging_file()`. Preparation accepts only the
concrete native opened-entry brand with a still-live creator publication
context, write access and the expected fresh regular-file shape. It retains
the original writer and its publication parent through write, readback and
publication. The API accepts no arbitrary writer or raw descriptor/handle.

The staging namespace is explicit: `Unknown` before creation, `Anonymous`
without a name, or `Named` with its exact created component. A Linux anonymous
staging hint is never opened, renamed or removed. A failed named stage and its
journal remain evidence; this primitive does not delete them by pathname.
Closing an anonymous owner releases that unnamed object through native lifetime.

## Recipe, bounds and verification

| Request field | Default or contract |
| --- | --- |
| `logical_size` | Full image length; default zero; bounded by `max_logical_size` (default 1 TiB) and the native size type |
| `extents` | Owned byte vectors, ordered by offset, nonempty, nonoverlapping and wholly inside the logical image |
| `max_extents` / `max_recipe_bytes` | Default 65,536 extents and 256 MiB of supplied extent bytes; these are explicit request limits |
| `step_bytes` | Default 64 KiB; must be 1 byte through 1 MiB |
| `sparse` | Default true; requires supported native layout inspection after preparation |
| `minimum_unallocated_bytes` | Default zero; an optional minimum proved by current native unallocated ranges; valid only with `sparse` |
| `application_evidence` | Opaque descriptive bytes, at most 1 MiB; journal/codec limits also apply |
| Names and journal ID | Valid exact native components in the Root's encoding; destination and staging hint must differ; journal limits remain enforced |

Gaps denote logical zero bytes, never source addresses. The native creator is
extended to the exact size and only supplied extents are written. Verification
reads the entire logical image, reconstructs each expected extent/zero-gap
window, compares every returned byte and computes SHA-256 over the full image,
including gaps. The digest is valid only when `image_verified` is true.
Verification is proportional to logical size, even for a very sparse recipe.

Size and native metadata bookends surround readback and are checked again
before publication. With sparse mode enabled, the layout must have a known
family, the exact owner identity and size, and valid ordered in-bounds ranges.
`unallocated_bytes` reports that native layout observation; sparse enabling
alone does not prove holes or a physical storage saving. No metadata replay,
Full-security preservation or source-snapshot consistency is inferred from
successful content verification.

Each `advance()` performs at most one content read **or** write of at most
`step_bytes`. Root validation, journal work, layout queries, flush and close
are also worker I/O; a step is not a wall-clock latency guarantee. Short native
reads/writes advance only their actual count. `written_bytes` counts supplied
extent bytes written; `verified_bytes` counts full logical bytes read back.
`content_calls` counts attempted content reads and writes.

## Journal and publication

The journal progresses through `Planned`, `Prepared`, `Copied`, `Verified`,
`CommitIntended`, `DestinationCommitted` and `Complete`, with the required
journal durability barriers. The stage is flushed before verification and
publication. The native publisher checks the final binding and required
file/parent barriers; the writer is consumed before the final Complete record.
Image publication and the separate journal are not a cross-file atomic commit
or a physical power-loss qualification.

Archive records carry the **ARW2** descriptive envelope: the bytes `ARW` and
numeric version 2, exact destination component, staging namespace, optional
actual staging component, logical length, verification flag, 32-byte digest
and length-prefixed application evidence. Component encodings preserve POSIX
bytes or Windows UTF-16 units. Early records may have no created stage or valid
digest. Anonymous records never turn the hint into a staging name. This
internal envelope is not the archive payload format or a stable C wire API.

Decoding a record grants no open, cleanup, retry, publication or restart
ownership. Even a recorded named component and digest cannot mint a live
creator handle. Legacy records do not upgrade into that authority.

Publication uses the original held stage with native **no-replace** semantics.
An occupied final name is not overwritten. `publication_attempted` is set
before invoking the publisher; `publication_uncertain` remains set unless the
call proves success or a known pre-publication `Changed` refusal. Do not infer
absence of effects from a generic failure category. Inspect the phase,
`published`, uncertainty and fixed failure tuple together.

| Worker outcome | Meaning |
| --- | --- |
| `Complete` | Image verified, publication proved, required journal protocol completed and this job's native owners drained |
| `Cancelled` | Clean cancellation/early finish before publication, after this job's drainage; no pathname cleanup is authorized |
| `NeedsReconciliation` | Native/protocol/finalization failure, uncertain publication, or interruption of an already published protocol; retain evidence |
| `Drain`, `drained == false` | Do not expose a terminal outcome yet; a reserved Root first-error writer can still be publishing its tuple |

A stop request before publication drains rather than publishes. After proven
publication, `advance(stop)` continues the completion protocol; it may still
reach Complete. A later close or journal failure requires reconciliation.
Explicit `finish_io()` or destruction only drains and appends no new commit
records: interrupting an incomplete published/uncertain protocol cannot be
reported as clean cancellation. Repeated terminal calls perform no native I/O.

## Root drainage and lifetime

Native failure and cleanup paths preserve the Root's first-writer failure
state before diagnostic allocation. The fixed `NativeArchiveFailure` retains
state, domain, code and a bounded operation name even when formatting fails.
All remaining owned closes are attempted once; an ambiguous close does not
reopen or retry the consumed native handle. A close failure can turn a planned
cancellation into NeedsReconciliation.

The job closes its writer, retained publication parent and journal under its
Root cleanup observer, then releases its scope/destination consumers. A pending
Root first writer revokes completion immediately. After native drainage,
further Drain advances resolve that state by memory-only reads; finalizers and
destructors never wait for the writer. The outer worker must retain Root and
resolve its final outcome before publishing a final application result.

`begin`, `advance`, `finish_io`, destruction, and release of related native
owners belong on the worker. The job is advanced serially; it is not a
thread-safe polling object. Publish copied progress to other threads.
`progress()` itself is a memory-only view for that serial owner.

The job does **not** finish the shared Root. Drain/destroy all job and request
consumers first, then finish Root from its owning worker and inspect the final
Root result. A later Root failure can still prevent an application-level
success. See [owned journal-root lifecycle](native-contracts.md#owned-journal-root-lifecycle).

## Minimal C++ consumer

This helper takes an already bounded request with genuine held owners. For
example, `logical_size = 4096` and one byte extent at offset 16 request that
byte surrounded by logical zeros. Component construction and Root preparation
happen on the same worker before calling the helper; the caller retains Root
independently until all consumers are gone.

```cpp
#include "native_archive_write_job.hpp"
#include <chrono>
#include <thread>
#include <utility>

ck::files::Observation<ck::files::NativeArchiveProgress> write_on_worker(
    ck::files::NativeArchiveWriteRequest request, std::stop_token stop) {
    using namespace ck::files;
    using Result = Observation<NativeArchiveProgress>;
    auto began = NativeArchiveWriteJob::begin(std::move(request));
    if (!began.value())
        return Result::unavailable(began.state(), began.unavailable_detail()->error);
    auto job = std::move(began).take_value();
    for (;;) {
        const auto progress = job->advance(stop);
        if (progress.phase == NativeArchivePhase::Complete ||
            progress.phase == NativeArchivePhase::Cancelled ||
            progress.phase == NativeArchivePhase::NeedsReconciliation) {
            job.reset(); // Native owner release stays on this worker.
            return Result::available(progress);
        }
        if (progress.phase == NativeArchivePhase::Drain && !progress.drained)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}
```

An Available helper result contains an outcome, not an unconditional success:
inspect its phase and failure tuple. `begin()` may allocate and throw; retain
the outer worker's exception and Root-drain handling. Do not abandon a pending
first-error publication by treating a single `finish_io()` result as drained.

## Native capabilities and integration scope

| Provider | Current implementation and qualification boundary |
| --- | --- |
| Linux | Held `O_TMPFILE` staging, exact-size `ftruncate`, native data-layout evidence, and held-object no-replace linking with identity and durability checks. The audited held `/proc/thread-self/fd` adapter may support unprivileged publication; no former/display pathname fallback. Focused normal Linux core/adapter receipts exist for their frozen cohorts; final combined and sanitizer gates remain separate. |
| Windows | Qualified native local NTFS/ReFS admission precedes named staging. `NtCreateFile` retains the original DELETE-bearing writer with write/delete sharing denied; sparse enable/size use handle APIs, and publication uses exact UTF-16 handle-relative no-replace rename with identity/parent durability checks. Normal archive cases passed on the recorded local NTFS/ReFS providers with ordinary, long-path and exact UTF-16 names; the matching installed-consumer receipts preserve their source and provider limits. Combined qualification remains open. UNC has a no-creation provider-refusal control, not positive UNC qualification. Broader security/fault matrices remain separate gates. |
| Darwin | Staging creation returns typed Unsupported (`create_staging_file.fd_publication_unqualified`). No archive publication success is claimed; a job may already have created its journal before this refusal. |
| Other/unknown providers | Native creator, Root, identity, sparse/layout and publication requirements must all qualify; an API declaration or filesystem label alone grants no capability. |

The frontend `write_volume_archive()` passes its encoded header/manifest/data
recipe to this job and requires real destination/Root owners. Legacy journal
callbacks cannot authorize native publication. A Complete native job maps to
`Durable`. Interrupted or failed outcomes with proved publication, and outcomes
with publication uncertainty, map to `PublishedDurabilityUnknown`. The service
resolves the outer Root's fixed error after consumer drainage; a Root failure
can also downgrade the result to `PublishedDurabilityUnknown` and Indeterminate.
A returned output address is presentation evidence, not a reopen or removal address.

This primitive creates one new image. Whole-volume snapshot/image acquisition,
restoration, stable C archive jobs, durable replacement/old-version retention,
Tree receipt execution, and restart cleanup authority are separate work. It
provides no arbitrary-writer exclusion across providers, automatic expiry,
pathname cleanup, existing-target replacement or cross-object atomicity. See
[retained replacement](native-contracts.md#retained-replacement) and the
[development roadmap](roadmap.md#current-development-gates) for those boundaries.

## Windows archive qualification targets

Before invoking development tools, select an explicit task directory on the
development drive and set `TEMP`, `TMP` and `TMPDIR` there. Configure with an
absolute `CK_CORE_FS_NATIVE_TEST_ROOT` and select its actual filesystem with
`CK_CORE_FS_ARCHIVE_TEST_FS=NTFS` or `ReFS`; an empty or invalid selection is a
configuration error. This is independent of other suites' provider options.

Build `ck_fs_native_archive_write_windows_tests`, then run CTest with
`-R "^native_archive_windows_" --parallel 1 --output-on-failure`. Three tests
cover ordinary, long and exact UTF-16 names. Each uses a unique fixture through
the shared native runner and verifies publication, sparse layout, complete
readback, cancellation, interrupted completion, occupied-target preservation,
retained staging evidence and handle balance. The runner keeps extended paths
through cleanup; provider mismatches fail rather than skip.

`tests/installed_native_archive_windows` uses the same registration function
against an installed SDK. Select its matching compiler/configuration and
`CMAKE_PREFIX_PATH`, and set `ARCHIVE_TEST_SOURCE_ROOT` to the matching source
checkout. An explicit `CK_CORE_FS_ARCHIVE_UNC_TEST_ROOT` adds a reachable UNC
prerequisite-refusal test. Unreachable UNC is a failure; this test proves no
archive publication capability on that provider.
