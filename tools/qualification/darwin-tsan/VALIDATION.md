# Toolkit validation

The source pin is LLVM 23.1.4 commit
`7a941dfb2877a0b8cf30323fefa85ad019e0b0f5`. Production and test patches remain
separate; their byte hashes and upstream license are preserved.

The permanent scripts were executed, including fresh source staging and a
complete one-process runtime/unit build. Runtime construction and preparation
took 167 seconds. All positive and intentional-race control expectations passed
in 56 seconds, with actual runtime paths and unchanged hashes checked. The
normal Mach-O unit runner passed four focused tests and all 45 enabled unit
tests in 4.39 seconds; eight existing disabled tests are not counted.

The unit module embeds the matching official runtime/unit objects in one
image. A normal LC_LOAD_DYLIB dependency loads it before main and survives gtest
re-exec. No DYLD_INSERT_LIBRARIES or sanitizer suppression is used.

Preparation was also executed with spaces and shell metacharacters. Unsupported
CMake semicolon build paths, reused outputs and symlink escapes are rejected.
Both mounted permitted temporary volumes are accepted. Read-only toolkit files
may live in the permanent project checkout.

Failed intermediate runner attempts remain in the task evidence: CMake path
parsing, missing upstream test include, SIP environment-variable stripping by
a system launcher, and reporting/command-selection errors. They were corrected
before the complete passing run. No failed attempt is counted as a pass.

The original and reproduced artifact records are separate. A new product SDK
still needs a complete matching build and its own native/sanitizer tests.
