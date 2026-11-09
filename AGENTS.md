# ck-core-fs-lib agent instructions

## Mandatory branch policy

Continue all development and commits on `master` only. Do not create new
development branches or continue work on `codex/...` branches.

GitHub must contain only the `master` branch. Merge outstanding changes into
`master` before removing other GitHub branches, and verify that each deleted
branch tip is reachable from the published `master`. Do not discard changes
or rewrite history to perform this cleanup. Branches on rpi4 may remain.

Preserve immutable source snapshots and active qualification inputs. Existing
frozen validation checkouts may retain their original commit, but new work and
publication must use `master`.

This repository is the headless filesystem backend shared by ckUtilities,
CDE, and other frontends. Keep the public boundary independent of ckVision,
Turbo Vision, Motif, STL types, and UI-thread callbacks.

Windows filesystem code must use modern wide-character/native handle APIs and
must not rely on legacy `MAX_PATH`-limited path handling. Convert validated
absolute DOS and UNC addresses to extended-length form (`\\?\\` /
`\\?\\UNC\\`) at the Win32 boundary, or use a handle-relative native API.
Do not add narrow Win32 final I/O, `std::fstream`, or `std::filesystem` final
I/O for long or adversarial paths. Preserve identity, reparse, sharing,
access, cancellation, and error-state checks. Every replacement needs tests
for ordinary and long paths, UNC namespaces, exact UTF-16 names, and relevant
reparse/security behavior.

The C ABI is exception-free. Ownership and callback/job lifetimes must be
explicit in `include/ck_file_engine.h`; never expose C++ or UI types there.

## Development workspaces and qualification

On the Mac, verify `/Volumes/S8T` is mounted and place temporary builds,
checkouts, caches, generated intermediates and test data in a unique directory
beneath `/Volumes/S8T/tmp`. `/Volumes/PRO-BLADE/tmp` is the allowed fallback.
Explicitly set `TMPDIR` before tools that may create temporary files. Never use
`/tmp` or `/private/tmp`; stop if neither approved volume is mounted. Permanent
sources do not belong on S8T.

On the Windows workstation, verify `V:` before development tools. Keep permanent
sources on V: and all temporary work in a unique `V:\tmp` directory. Set `TEMP`,
`TMP` and applicable `TMPDIR` there. Do not fall back to C: or D:. Other remote
machines use sensible machine-local temporary directories; Mac volumes are not
remote prerequisites.

Before builds, identify exact existing output paths and running project PIDs.
Preserve active work and source/assets; remove owned obsolete outputs after
retaining concise evidence. Record source/header/asset fingerprints, build
start/end and elapsed time, target/configuration, toolchain/runtime and exact
output path. Compare elapsed time with a real comparable baseline; investigate
unexpected timing rather than assuming freshness. Rebuild all translation units
affected by C++ class/layout or instrumentation changes; never combine current
private headers with an older SDK binary. Keep one verified app instance by
default, launch only its absolute current path, and inspect its actual window
before claiming a visual fix.

A declaration, skipped fixture, model test, typed Unsupported result or normal
build does not qualify native success, another filesystem, the final combined
revision or a sanitizer build. Preserve failures and state each receipt's exact
source cohort, provider, scope and remaining gates.
