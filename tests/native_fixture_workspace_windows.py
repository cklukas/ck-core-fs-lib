# SPDX-License-Identifier: LGPL-2.0-or-later
"""Private shared held-native Windows fixture workspace.

Derivative of the qualified V3 reader wrapper: first failure survives every
independent drain. Native provider/ACL checks and 45/285 +3 +5 bounds remain.
SOURCE ONLY until the paired native controls and original twelve requalify it.
"""
import ctypes as c
from ctypes import wintypes as w
import json
import ntpath
import os
import subprocess
import sys
import time
import uuid


class _StopFixture(Exception):
    """Private unwinding marker; native diagnostic formatting follows all drains."""


class _FirstFailure:
    def __init__(self):
        self.kind = None
        self.code = 0
        self.operation = None
        self.exception = None

    def native(self, code, operation, *, ntstatus=False):
        if self.kind is None:
            self.kind = "ntstatus" if ntstatus else "win32"
            self.code = code
            self.operation = operation

    def caught(self, error):
        if self.kind is None:
            self.kind = "exception"
            self.exception = error

    def raise_after_drain(self):
        if self.kind == "exception":
            raise self.exception
        if self.kind == "ntstatus":
            raise RuntimeError("%s status=%08x" % (self.operation, self.code & 0xffffffff))
        if self.kind == "win32":
            raise c.WinError(self.code)


class _NativeReleases:
    """Same native release path used by wrapper and private real-kernel controls."""
    def __init__(self, kernel, first, stop, observe):
        self.kernel = kernel
        self.first = first
        self.stop = stop
        self.observe = observe

    def close(self, handle, role):
        ok = self.kernel.CloseHandle(handle)  # Genuine native call always precedes observer.
        error = 0 if ok else c.get_last_error()
        if not ok:
            self.first.native(error, "CloseHandle")
        self.observe("close-" + role, handle, ok, error)
        if not ok:
            raise self.stop
    def free(self, address, role):
        remaining = self.kernel.LocalFree(address)
        error = c.get_last_error() if remaining else 0
        if remaining:
            self.first.native(error, "LocalFree")
        self.observe("free-" + role, address, not remaining, error)
        if remaining:
            raise self.stop

def run_fixture(binary, parent, provider, args, *, seed=False, _native_observer=None,
                _admit_action_scope=None, _hosted_scope_lease=None):
    if os.name != "nt":
        raise RuntimeError("Windows only: binary explicit-parent NTFS|ReFS [args]")
    if provider not in ("NTFS", "ReFS"):
        raise ValueError("explicit native provider required")
    if _admit_action_scope is not None and (seed or provider != "NTFS" or args):
        raise ValueError("action scope requires its own NTFS workspace")
    if _hosted_scope_lease is not None and _admit_action_scope is None:
        raise ValueError("a hosted lease requires native action admission")
    if not parent.startswith("\\\\?\\"):
        parent = parent.replace("/", "\\")
        if parent.startswith("\\\\"):
            parent = "\\\\?\\UNC\\" + parent[2:]
        elif len(parent) >= 3 and parent[0].isascii() and parent[0].isalpha() and parent[1:3] == ":\\":
            parent = "\\\\?\\" + parent
        else:
            raise ValueError("absolute DOS/UNC parent required")
    elif "/" in parent:
        raise ValueError("extended namespace must already use exact native separators")
    drive, tail = ntpath.splitdrive(parent)
    if not drive or not tail.startswith("\\") or "\0" in parent:
        raise ValueError("absolute native parent required")
    if any(part in (".", "..") or ":" in part for part in tail.split("\\")):
        raise ValueError("relative/stream components forbidden")
    if os.environ.get("CK_FS_REQUIRE_V_DEV_DRIVE") == "1" and not parent.upper().startswith("\\\\?\\V:\\TMP\\"):
        raise ValueError("fixture must be beneath explicit V:\\tmp")

    # Private Python-controller argument only; neither CLI nor environment can
    # enable it. Observations follow genuine native calls. Return values are
    # ignored; observer exceptions can only add failure, never native success.
    first = _FirstFailure()
    stop = _StopFixture()

    def observe(event, owner, ok=True, error=0):
        if _native_observer is not None:
            _native_observer(event, owner, bool(ok), error)

    k = c.WinDLL("kernel32", use_last_error=True)
    n = c.WinDLL("ntdll")
    a = c.WinDLL("advapi32", use_last_error=True)
    H, U, P = w.HANDLE, w.ULONG, c.c_void_p
    class Name(c.Structure):
        _fields_ = [("length", w.USHORT), ("capacity", w.USHORT), ("buffer", P)]
    class Attributes(c.Structure):
        _fields_ = [("length", U), ("root", H), ("name", c.POINTER(Name)),
                    ("flags", U), ("security", P), ("qos", P)]
    class Io(c.Structure):
        _fields_ = [("status", P), ("information", c.c_size_t)]
    class FileDispositionInfo(c.Structure):
        # Exact SDK winbase.h FILE_DISPOSITION_INFO, not Win32 BOOL.
        _fields_ = [("DeleteFile", w.BOOLEAN)]
    # x64 SDK10.0.26100 layouts; fail before any native I/O if Python ABI differs.
    if (c.sizeof(P), c.sizeof(U), c.sizeof(w.BOOL), c.sizeof(w.BOOLEAN)) != (8, 4, 4, 1):
        raise RuntimeError("Windows x64 scalar ABI required")
    if (c.sizeof(Name), Name.buffer.offset, c.sizeof(Attributes),
            Attributes.root.offset, Attributes.name.offset, Attributes.flags.offset,
            Attributes.security.offset, Attributes.qos.offset,
            c.sizeof(Io), Io.information.offset) != (16, 8, 48, 8, 16, 24, 32, 40, 16, 8):
        raise RuntimeError("Windows SDK native structure layout mismatch")
    if c.sizeof(FileDispositionInfo) != 1 or FileDispositionInfo.DeleteFile.offset != 0:
        raise RuntimeError("SDK FILE_DISPOSITION_INFO BOOLEAN layout mismatch")
    k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, P, w.DWORD, w.DWORD, H]
    k.CreateFileW.restype = H
    k.CloseHandle.argtypes = [H]; k.CloseHandle.restype = w.BOOL
    k.GetVolumeInformationByHandleW.argtypes = [H, w.LPWSTR, w.DWORD, P, P, P, w.LPWSTR, w.DWORD]
    k.GetVolumeInformationByHandleW.restype = w.BOOL
    k.SetFileInformationByHandle.argtypes = [H, c.c_int, P, w.DWORD]
    k.SetFileInformationByHandle.restype = w.BOOL
    k.GetFileInformationByHandleEx.argtypes = [H, c.c_int, P, w.DWORD]
    k.GetFileInformationByHandleEx.restype = w.BOOL
    k.GetCurrentProcess.argtypes = []; k.GetCurrentProcess.restype = H
    k.LocalFree.argtypes = [P]; k.LocalFree.restype = P
    a.OpenProcessToken.argtypes = [H, w.DWORD, c.POINTER(H)]; a.OpenProcessToken.restype = w.BOOL
    a.GetTokenInformation.argtypes = [H, c.c_int, P, w.DWORD, c.POINTER(w.DWORD)]
    a.GetTokenInformation.restype = w.BOOL
    a.ConvertSidToStringSidW.argtypes = [P, c.POINTER(w.LPWSTR)]
    a.ConvertSidToStringSidW.restype = w.BOOL
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, c.POINTER(P), P]
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
    n.NtCreateFile.argtypes = [c.POINTER(H), U, c.POINTER(Attributes), c.POINTER(Io),
                              P, U, U, U, U, P, U]
    n.NtCreateFile.restype = c.c_int32
    n.NtQueryDirectoryFile.argtypes = [H, H, P, P, c.POINTER(Io), P, U, U, w.BOOLEAN, P, w.BOOLEAN]
    n.NtQueryDirectoryFile.restype = c.c_int32

    def require(ok):
        if not ok:
            first.native(c.get_last_error(), "native fixture operation")
            raise stop
    releases = _NativeReleases(k, first, stop, observe)
    close, free = releases.close, releases.free
    def relative(owner, text, create=False, security=None):
        raw = text.encode("utf-16-le", "surrogatepass")
        storage = c.create_string_buffer(raw + b"\0\0")
        name = Name(len(raw), len(raw) + 2, c.cast(storage, P))
        attr = Attributes(c.sizeof(Attributes), owner, c.pointer(name), 0, security, None)
        result, io = H(), Io()
        # DELETE|READ_ATTRIBUTES|SYNCHRONIZE|LIST_DIRECTORY; no access upgrade.
        access = 0x10000 | 0x80 | 0x100000 | 1 | (4 if create else 0)
        # Deny DELETE sharing: retain the exact namespace edge until disposal.
        status = n.NtCreateFile(c.byref(result), access, c.byref(attr), c.byref(io),
            None, 0, 3, 2 if create else 1,
            0x20 | 0x200000 | 0x4000 | (1 if create else 0), None, 0)
        if status:
            first.native(status, "NtCreateFile", ntstatus=True)
            raise stop
        if create and io.information != 2:  # FILE_CREATED, never adopt an existing root.
            first.caught(RuntimeError("exclusive root creation not proven"))
            consumed, result = result, None
            close(consumed, "unexpected-root")
            raise stop
        return result

    # Allocate owner cells before acquiring the first native owner. Release
    # detachment uses None, not a new ctypes object, including exceptional paths.
    parent_handle = None
    root = None
    work = None
    child = None
    token = H()
    sd = P()
    sid = w.LPWSTR()
    exited = True
    preserved = False
    invalid_handle = H(-1).value
    try:
        parent_handle = k.CreateFileW(parent, 0x80 | 4 | 0x100000, 3, None, 3, 0x02200000, None)
        if parent_handle == invalid_handle:
            parent_handle = None
            require(False)
        observe("open-parent", parent_handle)
        actual = c.create_unicode_buffer(32)
        require(k.GetVolumeInformationByHandleW(parent_handle, None, 0, None, None, None, actual, 32))
        parent_tag = (w.DWORD * 2)()
        require(k.GetFileInformationByHandleEx(parent_handle, 9, c.byref(parent_tag), c.sizeof(parent_tag)))
        if not parent_tag[0] & 0x10 or parent_tag[0] & 0x400:
            raise RuntimeError("native parent must be an actual directory, not a final reparse object")
        if actual.value != provider:
            raise RuntimeError("actual native provider does not match explicit selection")
        scope_guid = None
        if _admit_action_scope is not None:
            # Admission reads the already-held parent before any creation.
            scope_guid = _admit_action_scope(parent_handle)
            if not scope_guid:
                raise RuntimeError("missing admitted action scope volume identity")
        require(a.OpenProcessToken(k.GetCurrentProcess(), 8, c.byref(token)))
        observe("open-token", token)
        needed = w.DWORD()
        a.GetTokenInformation(token, 1, None, 0, c.byref(needed))
        if not 0 < needed.value <= 65536:
            raise RuntimeError("invalid TokenUser extent")
        user = c.create_string_buffer(needed.value)
        require(a.GetTokenInformation(token, 1, user, needed, c.byref(needed)))
        require(a.ConvertSidToStringSidW(c.cast(user, c.POINTER(P))[0], c.byref(sid)))
        observe("open-sid", c.cast(sid, P))
        sddl = "O:%sD:P(A;;FA;;;%s)(A;;FA;;;SY)" % (sid.value, sid.value)
        consumed, sid = sid, None
        free(consumed, "sid")
        require(a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, c.byref(sd), None))
        observe("open-sd", sd)
        prefix = "action-scope-" if scope_guid else ("seed-close-" if seed else "reader-close-")
        name = prefix + uuid.uuid4().hex
        root = relative(parent_handle, name, create=True, security=sd)
        work = parent.rstrip("\\") + "\\" + name
        observe("open-root", root)
        # Before launch: close non-owning setup resources, retain native root+parent.
        consumed, sd = sd, None
        free(consumed, "sd")
        consumed, token = token, None
        close(consumed, "token")
        env = dict(os.environ, TEMP=work, TMP=work, TMPDIR=work)
        # Provider is checked natively above; seed wmain takes ROOT only.
        if scope_guid:
            env["CKFEA_ISOLATED_SCOPE_VOLUME"] = "1"
            command = [binary, work, scope_guid]
            child_timeout = 150
        else:
            command = [binary, work, *args] if seed else [binary, work, provider, *args]
            child_timeout = 285 if seed else 45
        startup = None
        if _hosted_scope_lease is not None:
            # The child retains a reference to the same exclusive file object.
            # CTest killing this wrapper cannot make detach safe while the child lives.
            command.append("--hosted")
            startup = subprocess.STARTUPINFO(lpAttributeList={"handle_list": [_hosted_scope_lease]})
            os.set_handle_inheritable(_hosted_scope_lease, True)
        try:
            child = subprocess.Popen(command, executable=binary if scope_guid else None,
                                     env=env, startupinfo=startup, close_fds=True, shell=False)
        finally:
            if _hosted_scope_lease is not None:
                os.set_handle_inheritable(_hosted_scope_lease, False)
        observe("child-started", child.pid)
        try:
            result = child.wait(timeout=child_timeout)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)  # Reap before any cleanup, never leave run()'s150s orphan.
            result = 124
        if result:
            raise subprocess.CalledProcessError(result, command)
    except BaseException as error:
        first.caught(error)
    finally:
        # No allocation/formatting of a native diagnostic precedes these drains.
        # Child termination must be positively established before disposal.
        exited = child is None
        if child is not None:
            try:
                exited = child.poll() is not None
            except BaseException as error:
                first.caught(error)
        if not exited:
            try:
                child.kill(); child.wait(timeout=3); exited = True
            except BaseException as error:
                first.caught(error)
        # Each variable is detached BEFORE its one native release attempt.
        # Failure of one drain cannot bypass any following owner.
        consumed, sid = sid, None
        if consumed:
            try: free(consumed, "sid")
            except BaseException as error: first.caught(error)
        consumed, sd = sd, None
        if consumed:
            try: free(consumed, "sd")
            except BaseException as error: first.caught(error)
        consumed, token = token, None
        if consumed:
            try: close(consumed, "token")
            except BaseException as error: first.caught(error)
        try:
            if root is not None and exited:
                deadline = time.monotonic() + 5
                remaining = [16384]
                def dispose(handle, depth=0):
                    if depth > 128 or time.monotonic() > deadline:
                        raise RuntimeError("native cleanup bound; root preserved")
                    tag = (w.DWORD * 2)()
                    require(k.GetFileInformationByHandleEx(handle, 9, c.byref(tag), c.sizeof(tag)))
                    # Observation follows the genuine tag query and precedes
                    # all disposition calls in this subtree. A failed witness
                    # adds cleanup failure; it never fabricates native success.
                    observe("dispose-ready", handle)
                    if tag[0] & 0x10 and not tag[0] & 0x400:
                        while True:
                            buffer, io = c.create_string_buffer(65536), Io()
                            restart = True
                            found = None
                            while found is None:
                                status = n.NtQueryDirectoryFile(handle, None, None, None, c.byref(io), buffer,
                                    len(buffer), 12, False, None, restart)
                                restart = False
                                if status & 0xffffffff == 0x80000006:
                                    break
                                if status != 0 or not 12 <= io.information <= len(buffer):
                                    raise RuntimeError("native cleanup enumeration failed")
                                data, offset = buffer.raw[:io.information], 0
                                while True:
                                    nxt = int.from_bytes(data[offset:offset+4], "little")
                                    count = int.from_bytes(data[offset+8:offset+12], "little")
                                    if count % 2 or offset + 12 + count > len(data):
                                        raise RuntimeError("invalid native name extent")
                                    entry = data[offset+12:offset+12+count].decode("utf-16-le", "surrogatepass")
                                    if entry not in (".", ".."):
                                        if not entry or any(x in entry for x in ("\\", "/", "\0", ":")):
                                            raise RuntimeError("invalid native cleanup name")
                                        found = entry; break
                                    if not nxt: break
                                    if nxt < 12 or offset + nxt + 12 > len(data):
                                        raise RuntimeError("invalid native entry offset")
                                    offset += nxt
                            if found is None: break
                            remaining[0] -= 1
                            if remaining[0] < 0 or time.monotonic() > deadline:
                                raise RuntimeError("native cleanup bound; root preserved")
                            owned = relative(handle, found)
                            try:
                                observe("open-owned", owned)
                                dispose(owned, depth + 1)
                            except BaseException as error:
                                first.caught(error)
                                raise
                            finally:
                                consumed, owned = owned, None
                                close(consumed, "owned")
                    delete = FileDispositionInfo(True)
                    require(k.SetFileInformationByHandle(handle, 4, c.byref(delete), c.sizeof(FileDispositionInfo)))
                    observe("dispose", handle)
                dispose(root)
        except BaseException as error:
            preserved = True
            first.caught(error)
        finally:
            consumed, root = root, None
            if consumed is not None:
                try: close(consumed, "root")
                except BaseException as error: first.caught(error)
            consumed, parent_handle = parent_handle, None
            if consumed is not None:
                try: close(consumed, "parent")
                except BaseException as error: first.caught(error)
        if not exited or preserved:
            try:
                if not exited:
                    print("PRESERVED live child/root", child.pid, ascii(work), file=sys.stderr)
                else:
                    print("PRESERVED native fixture root", json.dumps(work, ensure_ascii=True), file=sys.stderr)
            except BaseException:
                pass  # A diagnostic must never replace the first failure.
    first.raise_after_drain()
