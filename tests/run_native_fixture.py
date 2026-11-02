"""Run a native contract suite in a unique, explicitly located workspace."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

binary, scratch = sys.argv[1:]
parent = Path(scratch).resolve()
parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="native-contract-", dir=parent) as work:
    env = dict(os.environ, TMPDIR=work, TEMP=work, TMP=work)
    subprocess.run([binary, work], check=True, env=env, timeout=150)
