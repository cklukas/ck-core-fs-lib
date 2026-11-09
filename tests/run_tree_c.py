"""Native C tree contract: exact reviewed plan, stale proof, ownership/cancel."""
from pathlib import Path
import os
import stat
import subprocess
import sys
import tempfile

binary, scratch, mode = sys.argv[1:]
scratch = Path(scratch)
if not scratch.is_absolute():
    raise ValueError("tree fixture scratch must be absolute")
if os.name == "nt":
    spelling = os.fspath(scratch).replace("/", "\\")
    if not spelling.startswith("\\\\?\\"):
        spelling = "\\\\?\\UNC\\" + spelling[2:] if spelling.startswith("\\\\") else "\\\\?\\" + spelling
    scratch = Path(spelling)
else:
    scratch = scratch.resolve()
scratch.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="tree-c-", dir=scratch) as work:
    root = Path(work)
    source, target, journal = (root / x for x in ("source", "target", "journals"))
    source.mkdir()
    target.mkdir()
    # The C fixture provisions mutating Windows journals through the real Root
    # worker, then finishes/drains it before legacy pathname adoption. Python
    # must not precreate an inherited-DACL directory in those cases.
    if mode != "prepared_stale" and (os.name != "nt" or mode == "compare"):
        journal.mkdir(mode=0o755 if mode == "compare" else 0o700)
    journal_mode = stat.S_IMODE(journal.stat().st_mode) if journal.exists() else None
    (source / "alpha").write_bytes(b"complete file data\0\xff" * 256)
    (source / "nested").mkdir()
    (source / "nested" / "beta").write_bytes(b"nested exact bytes\x80" * 128)
    if sys.platform.startswith("linux") and mode != "compare":
        # Linux qualifies replay into existing directories; its strong native
        # new-directory creator remains unavailable. Keep both source rows.
        (target / "nested").mkdir()
    target_before = {p.relative_to(target): (p.is_dir(), p.stat().st_mtime_ns,
                                           p.stat().st_ctime_ns)
                     for p in target.rglob("*")}
    if mode in ("keepboth", "compare"):
        (target / "alpha").write_bytes(b"original target remains")
    env = dict(os.environ, TMPDIR=str(root), TEMP=str(root), TMP=str(root))
    command = [binary, str(root), str(journal), mode]
    if mode in ("stale", "prepared_stale"):
        proc = subprocess.Popen(command, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        assert proc.stdout.readline().strip() == "REVIEWED"
        (source / "alpha").write_bytes(b"changed after review")
        proc.communicate("x", timeout=45)
        assert proc.returncode == 0
        target_after = {p.relative_to(target): (p.is_dir(), p.stat().st_mtime_ns,
                                              p.stat().st_ctime_ns)
                        for p in target.rglob("*")}
        assert target_after == target_before, "stale plan mutated destination"
        if mode == "prepared_stale":
            assert list(journal.iterdir()) == [], "stale plan wrote a mutation journal"
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
            assert {p.relative_to(target) for p in target.rglob("*")} == set(target_before)
