"""Native C tree contract: exact reviewed plan, stale proof, ownership/cancel."""
from pathlib import Path
import os
import stat
import subprocess
import sys
import tempfile

binary, scratch, mode = sys.argv[1:]
scratch = Path(scratch).resolve()
scratch.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="tree-c-", dir=scratch) as work:
    root = Path(work)
    source, target, journal = (root / x for x in ("source", "target", "journals"))
    source.mkdir()
    target.mkdir()
    journal.mkdir(mode=0o755 if mode == "compare" else 0o700)
    journal_mode = stat.S_IMODE(journal.stat().st_mode)
    (source / "alpha").write_bytes(b"complete file data\0\xff" * 256)
    (source / "nested").mkdir()
    (source / "nested" / "beta").write_bytes(b"nested exact bytes\x80" * 128)
    if mode in ("keepboth", "compare"):
        (target / "alpha").write_bytes(b"original target remains")
    env = dict(os.environ, TMPDIR=str(root), TEMP=str(root), TMP=str(root))
    command = [binary, str(root), str(journal), mode]
    if mode == "stale":
        proc = subprocess.Popen(command, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        assert proc.stdout.readline().strip() == "REVIEWED"
        (source / "alpha").write_bytes(b"changed after review")
        proc.communicate("x", timeout=45)
        assert proc.returncode == 0
        assert list(target.iterdir()) == [], "stale plan mutated destination"
    else:
        subprocess.run(command, env=env, check=True, timeout=45)
        if mode == "compare":
            assert (target / "alpha").read_bytes() == b"original target remains"
            assert list(target.iterdir()) == [target / "alpha"]
            assert list(journal.iterdir()) == [], "Compare created mutation journals"
            assert stat.S_IMODE(journal.stat().st_mode) == journal_mode, "Compare changed journal-root permissions"
        elif mode in ("copy", "keepboth"):
            if mode == "keepboth":
                assert (target / "alpha").read_bytes() == b"original target remains"
                assert (target / "alpha-incoming").read_bytes() == (source / "alpha").read_bytes()
            else:
                assert (target / "alpha").read_bytes() == (source / "alpha").read_bytes()
            assert (target / "nested" / "beta").read_bytes() == (source / "nested" / "beta").read_bytes()
        else:
            assert list(target.iterdir()) == []
