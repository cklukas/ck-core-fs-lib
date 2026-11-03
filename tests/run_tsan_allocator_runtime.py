"""Require allocator/OOM support and detection of a deliberate heap race."""
import os
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: run_tsan_allocator_runtime.py BINARY EXACT_RUNTIME")
environment = dict(os.environ, TSAN_OPTIONS="halt_on_error=1:abort_on_error=0:exitcode=66")
for mode, expected in [("clean", 0), ("race", 66)]:
    result = subprocess.run([sys.argv[1], mode, sys.argv[2]], env=environment,
                            capture_output=True, text=True, timeout=30)
    output = result.stdout + result.stderr
    print(output, end="", flush=True)
    if result.returncode != expected or "TSAN_ALLOCATOR_CONTROL_PASS" not in output:
        raise SystemExit(f"allocator/runtime control failed: {mode}, exit={result.returncode}")
    finding = "WARNING: ThreadSanitizer: data race" in output
    if finding != (mode == "race"):
        raise SystemExit(f"intentional race detection control failed: {mode}")
print("PASS matching shared TSan runtime: allocator/OOM intact; intentional heap race detected")
