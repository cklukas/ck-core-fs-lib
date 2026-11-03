# Darwin ThreadSanitizer qualification

The stock Darwin arm64 runtime reports a race for detached workers that write
only their own native `errno`. LLVM's generic TLS discovery returns an empty
range for that storage. The qualification correction records and retires its
exact four-byte lifetime, preserving unrelated shadow history and race checks.

The [reproduction toolkit](https://github.com/cklukas/ck-core-fs-lib/tree/master/tools/qualification/darwin-tsan)
contains the production patch, separate tests, LLVM license, source provenance,
build scripts and reference records. Its source pin is LLVM 23.1.4 commit
`7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`. This is a local qualification
patch, without a claim of upstream acceptance.

## Recorded results

The original qualified arm64 runtime SHA-256 is
`124e6acd2266a0526f9184c852ca6f3270997378bdbcedc22c72765b4d155890`.
The complete Root11 SDK built with the matching compiler/runtime passed its
race checks; five mandatory macOS publication tests still fail as documented
in the [Root checkpoint](validation-2026-11-03-journal-roots.md).

The permanent toolkit was subsequently executed from the project checkout:

| Check | Result |
| --- | --- |
| Clean pinned runtime and unit-object build | PASS; one compiler process |
| Detached/joined native errno and GCD reuse | PASS |
| Foreign errno, ordinary TLS and finished-thread races | Expected race reports and exit 66 |
| Signal-errno diagnostic | Expected report and exit 66 |
| Dynamic TLS and detach controls | PASS |
| Exact shadow tests | 4/4 PASS |
| Enabled upstream unit tests | 45/45 PASS; eight existing disabled tests excluded |
| Actual runtime image and unchanged runtime hash | PASS |

The reproduced runtime SHA-256 is
`ba79ff2e55b670221abbcd28d5becef30eae9b56b9f77d9a6a9673f4e356eae2`.
Its distinct build directory and Mach-O artifact identity are recorded
separately; it does not replace the original artifact's qualification record.
Runtime construction, including preparation and unit objects, took 167 seconds;
the control runner took 56 seconds and the unit runner 4.39 seconds.

All product translation units still require matching instrumentation and
headers. These results do not establish a stock Apple/LLVM runtime pass or a
full backend pass for a newly built SDK. No product serialization, ignorelist,
sanitizer suppression or `no_sanitize` workaround is used.

## Reproduce

Use a clean source checkout at the exact pin. Temporary source, staging,
builds, caches and test outputs must be under mounted `/Volumes/S8T/tmp` or
`/Volumes/PRO-BLADE/tmp`; the toolkit itself may stay in the permanent project.
Every output directory must be fresh. CMake build paths cannot contain
semicolons; the runner rejects them before creating output. Source paths and
JSON configuration preserve spaces and shell metacharacters.

```sh
toolkit=/absolute/path/to/ck-core-fs-lib/tools/qualification/darwin-tsan
source=/Volumes/S8T/tmp/llvm-clean
work=/Volumes/S8T/tmp/ckfs-tsan-qualified
bash "$toolkit/scripts/configure-build.sh" --source "$source" --work "$work"
bash "$toolkit/scripts/run-controls.sh" --work "$work"
python3 "$toolkit/scripts/run-unit-mach-o.py" --work "$work"
```

Use `--prepare-only` on the first command to validate the source, patches,
toolchain and path handling without compiling. It records `PREPARED`, which
is not a runtime qualification pass. Patches and executable inputs are hashed;
the scripts record explicit outputs, timing, runtime identity and results.
