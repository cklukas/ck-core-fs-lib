# Copyright (c) 2026 C. Klukas. All rights reserved.
# SPDX-License-Identifier: LGPL-2.0-or-later
"""Ordinary native UNIX held-journal regression; unsupported is a failure."""
from pathlib import Path
import ctypes
import json
import os
import plistlib
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 3:
        raise RuntimeError("binary and explicit absolute native fixture root required")
    binary, scratch = sys.argv[1:]
    if not Path(binary).is_absolute() or not Path(scratch).is_absolute() or not Path(scratch).is_dir():
        raise RuntimeError("existing binary and explicit native fixture root required")
    if os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise RuntimeError("ordinary unprivileged caller required, not host root/set-id")
    proof = {"uid": os.getuid(), "gid": os.getgid()}
    if sys.platform == "linux":
        fields = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
        if int(fields["CapPrm"].strip(), 16) or int(fields["CapEff"].strip(), 16):
            raise RuntimeError("zero permitted/effective native capabilities required")
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
        libc.prctl.restype = ctypes.c_int
        if libc.prctl(38, 1, 0, 0, 0):
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        status = Path("/proc/self/status").read_text()
        if not any(line.startswith("NoNewPrivs:") and line.split()[1] == "1" for line in status.splitlines()):
            raise RuntimeError("process-local no-new-privileges was not established")
        proof.update(CapPrm=fields["CapPrm"].strip(), CapEff=fields["CapEff"].strip(), NoNewPrivs=1)
        # No namespace/mount operation is required by this read-only fixture.
    elif sys.platform == "darwin":
        mount = Path(scratch).resolve(strict=True)
        while mount.parent != mount and not os.path.ismount(mount):
            mount = mount.parent
        info = plistlib.loads(subprocess.check_output(
            ["/usr/sbin/diskutil", "info", "-plist", str(mount)], timeout=10))
        if info.get("GlobalPermissionsEnabled") is not True or info.get("FilesystemType") not in ("apfs", "hfs"):
            raise RuntimeError("ownership-enabled native APFS/HFS fixture root required; NoOwners is unqualified")
        proof.update(filesystem=info["FilesystemType"], ownership=True, mount=info.get("MountPoint"))
    else:
        raise RuntimeError("native fixture preflight is qualified only on Linux/Darwin")
    print("HELD_JOURNAL_UNIX_CALLER " + json.dumps(proof, sort_keys=True), flush=True)
    # run() kills and waits for its exact native child on TimeoutExpired.
    # Keep that 45s deadline below CTest60, allowing Darwin preflight10 and
    # fixture cleanup; never delegate to the older 150s native wrapper.
    with tempfile.TemporaryDirectory(prefix="held-journal-reader-", dir=scratch) as work:
        environment = dict(os.environ, TMPDIR=work, TEMP=work, TMP=work,
                           PYTHONDONTWRITEBYTECODE="1")
        print("HELD_JOURNAL_UNIX_FIXTURE " + work, flush=True)
        subprocess.run([binary, work], check=True, timeout=45, env=environment)



if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"UNQUALIFIED held-journal UNIX fixture: {error}", file=sys.stderr, flush=True)
        sys.exit(1)
