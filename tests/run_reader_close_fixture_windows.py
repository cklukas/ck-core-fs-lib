# SPDX-License-Identifier: LGPL-2.0-or-later
"""Thin reader-close launcher; private native workspace owns cleanup."""
import os
import sys
sys.dont_write_bytecode = True
from native_fixture_workspace_windows import run_fixture


def main():
    if os.name != "nt" or len(sys.argv) < 4:
        raise RuntimeError("Windows only: binary explicit-parent NTFS|ReFS [args]")
    binary, parent, provider, *args = sys.argv[1:]
    return run_fixture(binary, parent, provider, args, seed=False)


if __name__ == "__main__":
    main()
