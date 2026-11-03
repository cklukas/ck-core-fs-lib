"""Qualify private-Root mount aliases inside an unprivileged Linux namespace.

Exit 77 means UNQUALIFIED, never PASS. CTest must not turn that into success;
required qualification runners need working unprivileged namespaces/OverlayFS.
No sysctl, privilege escalation, or host mount changes are attempted.
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile


def unqualified(reason):
    print(f"UNQUALIFIED private_scope_mounts: {reason}", flush=True)
    return 77


def namespace_id(name):
    identity = os.stat(f"/proc/self/ns/{name}")
    return f"{identity.st_dev}:{identity.st_ino}"


def main():
    if len(sys.argv) != 3:
        print("usage: run_private_scope_mounts.py BINARY ABSOLUTE_SCRATCH_ROOT", file=sys.stderr)
        return 1
    if sys.platform != "linux":
        return unqualified("Linux user/mount namespaces are required")
    if os.geteuid() == 0:
        return unqualified("run as an ordinary host user; host root is not unprivileged qualification")
    executable = Path(sys.argv[1]).absolute()
    parent = Path(sys.argv[2])
    if not parent.is_absolute() or not executable.is_file() or not os.access(executable, os.X_OK):
        print("FAIL private_scope_mounts: executable and absolute scratch root are required", file=sys.stderr)
        return 1
    unshare = shutil.which("unshare")
    if not unshare or not Path("/bin/true").is_file():
        return unqualified("unshare or /bin/true is unavailable")
    try:
        original_user, original_mount = namespace_id("user"), namespace_id("mnt")
    except OSError as error:
        return unqualified(f"namespace identity unavailable: {error}")
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="private-scope-mounts-", dir=parent) as scratch:
        # These names are OverlayFS mount-option data, not shell text. Refuse
        # ambiguous separators rather than silently mounting a different tree.
        if any(char in scratch for char in ",:\\\n"):
            return unqualified("scratch pathname contains an OverlayFS option separator")
        environment = dict(os.environ, TMPDIR=scratch, TEMP=scratch, TMP=scratch,
                           PYTHONDONTWRITEBYTECODE="1")
        isolate = [unshare, "--user", "--map-root-user", "--mount", "--propagation", "private"]
        try:
            probe = subprocess.run(isolate + ["/bin/true"], env=environment,
                                   capture_output=True, text=True, timeout=15)
            if probe.returncode:
                return unqualified(f"isolated namespace creation refused: {probe.stderr.strip()}")
            result = subprocess.run(isolate + [str(executable), "--isolated", scratch,
                                              original_user, original_mount], env=environment,
                                    capture_output=True, text=True, timeout=150)
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f"FAIL private_scope_mounts: {error}", file=sys.stderr)
            return 1
        print(result.stdout, end="", flush=True)
        print(result.stderr, end="", file=sys.stderr, flush=True)
        if result.returncode == 77:
            return unqualified("native namespace/mount/filesystem qualification unavailable (see diagnostic)")
        if result.returncode or "PRIVATE_SCOPE_MOUNTS_PASS\n" not in result.stdout:
            print(f"FAIL private_scope_mounts: native qualification exit={result.returncode}", file=sys.stderr)
            return 1
        print("PASS private_scope_mounts: all required aliases refused before effects; unrelated input accepted", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
