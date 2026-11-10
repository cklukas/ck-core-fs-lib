# SPDX-License-Identifier: LGPL-2.0-or-later
"""Admit the exclusive action-scope NTFS VHD by held volume identity."""
import base64
from contextlib import ExitStack, contextmanager
import ctypes as c
from ctypes import wintypes as w
import ntpath
import os
import re
import subprocess
import sys

sys.dont_write_bytecode = True
from native_fixture_workspace_windows import run_fixture


def workstation_path(raw):
    path = raw.replace("/", "\\")
    if path.startswith("\\\\?\\"):
        path = path[4:]
    if not path.startswith("V:\\tmp\\"):
        raise ValueError("action scope needs explicit workstation paths below V:\\tmp")
    if any(part in ("", ".", "..") or any(ch in part for ch in ":\0\r\n;")
           for part in path[3:].split("\\")):
        raise ValueError("ambiguous action-scope address")
    return path


def require(ok):
    if not ok:
        raise c.WinError(c.get_last_error())


VOLUME_GUID = re.compile(
    r"\\\\\?\\Volume\{([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})\}\\"
)
LABEL = "CKFEA05SCOPE"


def hosted_temp():
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("RUNNER_OS") != "Windows"
            or os.environ.get("CK_FS_REQUIRE_V_DEV_DRIVE") == "1"):
        raise ValueError("hosted action scope requires the GitHub-hosted Windows job")
    return dos_path(os.environ.get("RUNNER_TEMP", ""), "D")


def dos_path(raw, drive):
    if raw.startswith("\\\\?\\") and "/" in raw:
        raise ValueError("extended paths must use native separators")
    path = raw.replace("/", "\\")
    if path.startswith("\\\\?\\"):
        path = path[4:]
    if not path.upper().startswith(drive + ":\\"):
        raise ValueError(f"explicit {drive}: path required")
    if any(part in ("", ".", "..") or part.endswith((" ", "."))
           or any(ch in part for ch in ':\0\r\n;*?"<>|')
           for part in path[3:].split("\\")):
        raise ValueError("ambiguous action-scope address")
    return drive + path[1:]


def below(path, parent):
    return path.lower().startswith(parent.lower() + "\\")


def extended(path):
    return path if path.startswith("\\\\?\\") else "\\\\?\\" + path


class FileId(c.Structure):
    _fields_ = [("serial", c.c_uint64), ("file", c.c_ubyte * 16)]


class ScopeWindows:
    def __init__(self):
        k = self.kernel = c.WinDLL("kernel32", use_last_error=True)
        k.GetSystemDirectoryW.argtypes = [w.LPWSTR, w.UINT]
        k.GetSystemDirectoryW.restype = w.UINT
        system = c.create_unicode_buffer(32768)
        count = k.GetSystemDirectoryW(system, len(system))
        require(0 < count < len(system))
        self.system = system.value
        self.powershell = ntpath.join(self.system, "WindowsPowerShell", "v1.0", "powershell.exe")
        k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
        k.CreateFileW.restype = w.HANDLE
        k.CloseHandle.argtypes = [w.HANDLE]
        k.CloseHandle.restype = w.BOOL
        k.GetFileInformationByHandleEx.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]
        k.GetFileInformationByHandleEx.restype = w.BOOL
        k.GetVolumeInformationByHandleW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD, c.c_void_p, c.c_void_p,
                                                   c.c_void_p, w.LPWSTR, w.DWORD]
        k.GetVolumeInformationByHandleW.restype = w.BOOL
        k.GetFinalPathNameByHandleW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD]
        k.GetFinalPathNameByHandleW.restype = w.DWORD
        k.SetFileInformationByHandle.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]
        k.SetFileInformationByHandle.restype = w.BOOL

    @contextmanager
    def open(self, path, *, follow_mount=False, directory=True, access=0x80, share=3, creation=3):
        flags = 0x02000000 | (0 if follow_mount else 0x00200000)
        handle = self.kernel.CreateFileW(extended(path), access, share, None, creation, flags, None)
        require(handle != w.HANDLE(-1).value)
        try:
            tag = (w.DWORD * 2)()
            require(self.kernel.GetFileInformationByHandleEx(handle, 9, c.byref(tag), c.sizeof(tag)))
            if tag[0] & 0x400 or bool(tag[0] & 0x10) != directory:
                raise RuntimeError("action scope requires an ordinary native file or directory")
            yield handle
        finally:
            require(self.kernel.CloseHandle(handle))

    def path(self, handle):
        path = c.create_unicode_buffer(32768)
        count = self.kernel.GetFinalPathNameByHandleW(handle, path, len(path), 1)
        require(0 < count < len(path))
        match = VOLUME_GUID.match(path.value)
        if not match:
            raise RuntimeError("native volume GUID required")
        return match.group(), path.value

    def identity(self, handle):
        file_id = FileId()
        require(self.kernel.GetFileInformationByHandleEx(handle, 18, c.byref(file_id), c.sizeof(file_id)))
        return bytes(file_id).hex()

    def volume(self, handle):
        label, filesystem = c.create_unicode_buffer(128), c.create_unicode_buffer(32)
        require(self.kernel.GetVolumeInformationByHandleW(handle, label, len(label), None, None,
                                                            None, filesystem, len(filesystem)))
        return filesystem.value, label.value

    def remove(self, handle):
        # SDK FILE_DISPOSITION_INFO.DeleteFile is BOOLEAN, not BOOL.
        delete_file = w.BOOLEAN(True)
        require(self.kernel.SetFileInformationByHandle(handle, 4, c.byref(delete_file), c.sizeof(delete_file)))

    def storage(self, script, env, timeout):
        prelude = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
if (-not [Environment]::Is64BitProcess) { throw 'x64 Windows PowerShell required' }
Import-Module -Name $env:CKFS_SCOPE_STORAGE_MODULE -ErrorAction Stop
"""
        storage_module = ntpath.join(self.system, "WindowsPowerShell", "v1.0", "Modules", "Storage", "Storage.psd1")
        command = [self.powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                   base64.b64encode((prelude + script).encode("utf-16-le")).decode("ascii")]
        return checked_process(command, timeout, dict(env, CKFS_SCOPE_STORAGE_MODULE=storage_module,
                                                      PSModulePath=ntpath.dirname(ntpath.dirname(storage_module))))


class NativeCommandIndeterminate(RuntimeError):
    """The native provider may still have work queued after its client stops."""


def checked_process(command, timeout, env=None, *, inherit=()):
    startup = subprocess.STARTUPINFO(lpAttributeList={"handle_list": list(inherit)}) if inherit else None
    try:
        for handle in inherit:
            os.set_handle_inheritable(handle, True)
        child = subprocess.Popen(command, executable=command[0], env=env, stdout=subprocess.PIPE,
                                 startupinfo=startup, close_fds=True)
    finally:
        for handle in inherit:
            os.set_handle_inheritable(handle, False)
    try:
        stdout, _ = child.communicate(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt, OSError) as failure:
        try:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=3)
        except (subprocess.TimeoutExpired, KeyboardInterrupt, OSError) as drain:
            raise NativeCommandIndeterminate(f"Could not reap native command PID {child.pid}") from drain
        raise NativeCommandIndeterminate(f"Interrupted native command {command[0]}, reaped PID {child.pid}") from failure
    if child.returncode:
        if stdout:
            print(stdout.decode("utf-8", errors="backslashreplace"), file=sys.stderr, flush=True)
        raise subprocess.CalledProcessError(child.returncode, command[0], output=stdout)
    return stdout.decode("utf-8", errors="strict").strip()


def main():
    if os.name != "nt" or len(sys.argv) < 5 or not sys.argv[2] or not sys.argv[3]:
        raise ValueError("action_native_scope requires an owned NTFS VHD and a separate workspace")
    if "CKFEA_ISOLATED_SCOPE_VOLUME" in os.environ:
        raise ValueError("action scope isolation must be admitted by this launcher")
    raw_binary, raw_root, raw_image, *raw_data = sys.argv[1:]
    hosted = raw_root.startswith("hosted-guid:")
    if hosted:
        temp = hosted_temp()
        binary = dos_path(raw_binary, "D")
        image = dos_path(raw_image, "D")
        root = "\\\\?\\Volume{" + raw_root.removeprefix("hosted-guid:") + "}\\"
        data_roots = [dos_path(path, "D") for path in raw_data]
        if (not VOLUME_GUID.fullmatch(root) or ntpath.basename(image) != "scope.vhd"
                or not all(below(path, temp) for path in [binary, image, *data_roots])
                or not ntpath.basename(ntpath.dirname(image)).startswith("ckfs-action-vhd-")):
            raise ValueError("hosted action scope must use its exact GUID and D: runner-owned image")
        for key in ("TEMP", "TMP", "TMPDIR"):
            if not below(dos_path(os.environ.get(key, ""), "D"), temp):
                raise ValueError("hosted temporary storage must stay below RUNNER_TEMP")
        drive_name = "D:\\"
    else:
        binary = workstation_path(raw_binary)
        root, image = map(workstation_path, (raw_root, raw_image))
        data_roots = [workstation_path(path) for path in raw_data]
        for key in ("TEMP", "TMP", "TMPDIR"):
            workstation_path(os.environ.get(key, ""))
        owner = ntpath.dirname(image)
        if owner == "V:\\tmp" or not root.startswith(owner + "\\") or not image.lower().endswith((".vhd", ".vhdx")):
            raise ValueError("workspace and VHD must belong to the same explicit V: task")
        drive_name = "V:\\"
    owner = ntpath.dirname(image)
    native = ScopeWindows()

    # The caller provisions and leases the image. Bind the live partition to
    # that exact attached file, without creating, mounting or formatting disks.
    storage_probe = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$imagePath = $env:CKFS_SCOPE_IMAGE
$image = Storage\Get-DiskImage -ImagePath $imagePath
$disks = @($image | Storage\Get-Disk)
if (-not $image.Attached -or $image.ImagePath -ine $imagePath -or $disks.Count -ne 1) { throw 'owned VHD attachment not established' }
$disk = $disks[0]
$partitions = @($disk | Storage\Get-Partition | Where-Object { $_.AccessPaths -contains $env:CKFS_SCOPE_GUID })
if ($partitions.Count -ne 1) { throw 'held volume does not identify one partition on the VHD' }
$partition = $partitions[0]
if ($disk.IsBoot -or $disk.IsSystem -or $disk.IsReadOnly -or
    $disk.BusType -ne 'File Backed Virtual' -or $disk.Location -ine $imagePath -or
    $image.DevicePath -ine ('\\.\PhysicalDrive' + $disk.Number)) { throw 'held scope volume does not belong to the writable owned image' }
$ordinal = [StringComparison]::OrdinalIgnoreCase
if ($env:CKFS_SCOPE_HOSTED -ceq '1') {
    if ($partition.AccessPaths.Count -ne 1 -or
        $env:CKFS_SCOPE_NATIVE_ROOT -ine $env:CKFS_SCOPE_GUID -or
        $env:CKFS_SCOPE_ROOT -ine $env:CKFS_SCOPE_GUID) { throw 'hosted scope needs an unaliased VHD volume root' }
    $mount = $null
} else {
    $mounts = @($partition.AccessPaths | Where-Object {
        $_.StartsWith($env:CKFS_SCOPE_OWNER + '\', $ordinal) -and
        $env:CKFS_SCOPE_ROOT.StartsWith($_.TrimEnd('\') + '\', $ordinal)
    })
    if ($partition.AccessPaths.Count -ne 2 -or $mounts.Count -ne 1) { throw 'dedicated mount under the V: task is required' }
    $relative = $env:CKFS_SCOPE_ROOT.Substring($mounts[0].TrimEnd('\').Length + 1)
    if (-not [string]::Equals($env:CKFS_SCOPE_NATIVE_ROOT, $env:CKFS_SCOPE_GUID + $relative, $ordinal)) { throw 'scope address redirects within the volume' }
    $mount = $mounts[0]
}
[ordered]@{image=$image.ImagePath; disk=$disk.Number; partition=$partition.PartitionNumber;
    mount=$mount; volume=$env:CKFS_SCOPE_GUID; root=$env:CKFS_SCOPE_ROOT} | ConvertTo-Json -Compress
"""
    with ExitStack() as handles:
        drive = handles.enter_context(native.open(drive_name, follow_mount=True))
        image_handle = handles.enter_context(native.open(image, directory=False))
        if native.path(image_handle)[1] != native.path(drive)[0] + image[3:]:
            raise RuntimeError("VHD address redirects away from the exact backing file")
        lease = None
        if hosted:
            lease = handles.enter_context(native.open(ntpath.join(owner, "scope.lease"), directory=False,
                                                      access=0x80000000, share=0))
            if native.path(lease)[1] != native.path(drive)[0] + ntpath.join(owner, "scope.lease")[3:]:
                raise RuntimeError("action scope lease redirects away from its native owner")
        data_guids = {
            native.path(handles.enter_context(native.open(path, follow_mount=True)))[0].lower()
            for path in data_roots
        }

        def admit(parent_handle):
            guid, opened_root = native.path(parent_handle)
            if native.volume(parent_handle) != ("NTFS", LABEL) or guid.lower() in data_guids:
                raise RuntimeError("action scope requires its own CKFEA05SCOPE NTFS volume")
            env = dict(os.environ, CKFS_SCOPE_IMAGE=image, CKFS_SCOPE_GUID=guid,
                       CKFS_SCOPE_OWNER=owner, CKFS_SCOPE_ROOT=root, CKFS_SCOPE_NATIVE_ROOT=opened_root,
                       CKFS_SCOPE_HOSTED="1" if hosted else "0")
            print(native.storage(storage_probe, env, 12), flush=True)
            return guid

        run_fixture(extended(binary), root, "NTFS", [], _admit_action_scope=admit,
                    _hosted_scope_lease=lease)


if __name__ == "__main__":
    main()
