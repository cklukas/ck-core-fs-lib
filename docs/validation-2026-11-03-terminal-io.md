# Terminal copy I/O qualification — 2026-11-03

Native copy execution now finalizes its data writer and journal before every
terminal outcome, including failure, cancellation and an exception in the
protocol. A stopped child is drained through synchronous parent transitions.
Finalizers run once; a consumed handle is never retried. A close failure keeps
the first error and requires reconciliation. Finalization grants no publication,
source retirement or staging-name cleanup authority.

The native finalizer attempts the journal close even after a writer failure.
It records error scalars without allocation until both closes were attempted.
Low-memory diagnostics may omit the operation tag while preserving native
error state, domain and code.

| Qualification | Result |
| --- | --- |
| macOS normal build, 15 failure/cancellation/exception combinations | PASS |
| macOS fully instrumented ASan/UBSan implementation and finalizer tests | PASS |
| macOS fully instrumented TSan implementation and finalizer tests | PASS |
| Linux ext4 actual anonymous writer `EIO`, legacy and externally owned journal roots | PASS |
| Linux clean/error controls: source bytes unchanged, no publication, cached terminal results, external Root drain | PASS |
| Windows 2025 full native suite, install and installed C consumer | PASS |
| Linux browser ON/OFF, full native suite, install and installed C consumer | PASS |
| Linux fully instrumented ASan/UBSan/LeakSanitizer and TSan CI | PASS |

These CI results apply to committed implementation `5ff252180154ede3f2c5d5848e8b8c70a52f0ed3`:
[workflow run 41569977680](https://github.com/cklukas/ck-core-fs-lib/actions/runs/41569977680).
The hosted Mac job was not scheduled because the required mounted temporary
volumes are unavailable there; the separate local Mac results above apply.

The Linux native test checks 47 assertions; independent clean/error controls
check 98. The final protocol-exception change additionally passed the 15-case
normal and sanitizer tests. Explicitly linked fresh execution objects precede
the verified archives; link maps confirm that the older execution object was
not loaded. No sanitizer suppressions or kernel/security changes were used.
macOS LeakSanitizer is unsupported by the installed runtime and is not claimed.

This checkpoint does not qualify a new publication provider, complete metadata
preservation, or the unreleased journal-root/session/retry interfaces. The five
known positive macOS publication gates remain unresolved and failing.
