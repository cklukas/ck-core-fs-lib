# Darwin arm64 TSan native errno qualification

This toolkit preserves a local LLVM compiler-rt correction and reproducible
qualification for LLVM 23.1.4, commit
`7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`.

The production patch tracks the exact native errno TLS lifetime. The separate
test patch exercises exact byte masks, detached and joined workers, GCD reuse,
and intentional races. LLVM's license and the original qualification records
are included. No upstream acceptance or stock-runtime pass is claimed.

Run the scripts from this permanent directory with a clean pinned LLVM source
and fresh temporary work beneath a mounted S8T/tmp or PRO-BLADE/tmp:

```sh
bash scripts/configure-build.sh --source "$source" --work "$work"
bash scripts/run-controls.sh --work "$work"
python3 scripts/run-unit-mach-o.py --work "$work"
```

The build command supports `--prepare-only`; PREPARED is not a runtime pass.
CMake build paths containing semicolons are rejected before output creation.
Source staging copies present tracked files and preserves symlinks, excluding
ignored caches. No Git fetch or checkout modification occurs.

The permanent toolkit has been run end to end: build, runtime-image checks,
positive/intentional-race controls, four focused tests and all 45 enabled unit
tests passed. Eight pre-existing disabled tests are excluded. See
`records/reproduced-*.json` and `docs/qualification.md`.

Original runtime SHA-256:
`124e6acd2266a0526f9184c852ca6f3270997378bdbcedc22c72765b4d155890`.
Reproduced runtime SHA-256:
`ba79ff2e55b670221abbcd28d5becef30eae9b56b9f77d9a6a9673f4e356eae2`.
These are distinct recorded artifacts built from the same pinned correction.
