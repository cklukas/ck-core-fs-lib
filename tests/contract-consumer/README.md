# Installed C-consumer qualification

This project uses only an installed package and its public C header/shared
library. It must configure with `LANGUAGES C`; implementation headers and C++
compiler settings do not belong to the consumer contract.

The fourteen cases cover deterministic outputs on rejected calls, error reuse,
metadata availability, rejected job ownership, byte-native POSIX names and
addresses, held parents, substituted entries, explicit final-link policy,
complete-scope preserving copy, and cancellation/completion races. Separate
versioned ordinary-scope copy and cancellation cases keep the complete-scope
gates intact. Ordinary completion must report required mode/times as preserved,
no overlap with excluded/unknown fields, and verified effective caller ownership.
Two loss-consenting copies exist solely to verify that successful copying cannot
falsely qualify a bypassed provider scope or claim bypassed ownership setup.
They do not relax or replace either preservation-success gate.

The preservation-success cases prohibit opting into metadata loss. Unsupported preservation is
a failed qualification gate, not a passing copy. A cancellation racing with
completion may settle in either state; each terminal result must accurately
describe the resulting data. These small-copy tests do not independently prove
cancellation latency during a blocked transfer, recovery after a crash, or
cross-filesystem move safety. Those need controlled operation/fault tests.

The filesystem fixtures currently run on POSIX. The portable rejected-output
cases also run on Windows; POSIX-only cases return an explicit skip there.
Windows native-name/reparse/UNC mutation qualification remains separate.
Raw-byte fixtures skip only when native fixture creation rejects the name with
EILSEQ; other setup errors fail, and Linux raw-byte qualification remains required.

Pass an explicit temporary build directory to CMake. Each test fixture is a
unique child of that build directory, with no implicit system-temp fallback.
Two CPU slots are reserved for tests that run a worker-owned job.

```sh
cmake -S tests/contract-consumer -B /absolute/task/consumer-build \
  -DCMAKE_PREFIX_PATH=/absolute/installed-prefix
cmake --build /absolute/task/consumer-build --parallel 6
ctest --test-dir /absolute/task/consumer-build --output-on-failure -j 6
```
