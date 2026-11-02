"""Run a native contract suite in a unique, explicitly located workspace."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

binary, scratch = sys.argv[1:]
parent = Path(scratch).resolve()
parent.mkdir(parents=True, exist_ok=True)
# Keep the extended namespace through Python's final cleanup too. Otherwise
# Win32 trims a native trailing dot/space and rmtree leaves exact-name fixtures
# behind even though the C adapter moved and restored them correctly.
native_parent = os.fspath(parent)
if os.name == "nt":
    native_parent = native_parent.replace("/", "\\")
    if not native_parent.startswith("\\\\?\\"):
        native_parent = ("\\\\?\\UNC\\" + native_parent[2:]
                         if native_parent.startswith("\\\\")
                         else "\\\\?\\" + native_parent)
with tempfile.TemporaryDirectory(prefix="native-contract-", dir=native_parent) as work:
    env = dict(os.environ, TMPDIR=work, TEMP=work, TMP=work)
    subprocess.run([binary, work], check=True, env=env, timeout=150)
