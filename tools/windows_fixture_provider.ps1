# Requires PowerShell 7 on the controlled Windows native qualification host.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$FixtureRoot,
      [Parameter(Mandatory)][string]$Report,
      [switch]$ValidatePathsOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or $PSVersionTable.PSVersion.Major -lt 7) { throw 'Windows PowerShell 7 is required' }
if (-not [IO.Path]::IsPathFullyQualified($FixtureRoot) -or -not [IO.Path]::IsPathFullyQualified($Report)) { throw 'Explicit absolute scratch/report paths required' }
# Policy comparison only. Preserve the original native spelling for all I/O.
# Accept DOS and extended DOS spellings; never reinterpret UNC/device namespaces.
function Assert-WorkstationTempPath([string]$Path, [string]$Label) {
  $comparison = $Path.Replace('/', '\')
  if ($comparison.StartsWith('\\?\', [StringComparison]::Ordinal)) { $comparison = $comparison.Substring(4) }
  if ($comparison -cnotmatch '^[A-Za-z]:\\') { throw "$Label must be an absolute DOS address beneath V:\tmp" }
  $parts = $comparison.Substring(3).Split([char]'\', [StringSplitOptions]::RemoveEmptyEntries)
  foreach ($part in $parts) {
    if ($part -ceq '.' -or $part -ceq '..' -or $part.Contains(':')) { throw "$Label has ambiguous workstation path components" }
  }
  $comparison = $comparison.Substring(0,3) + [string]::Join('\', $parts)
  if (-not $comparison.StartsWith('V:\tmp\', [StringComparison]::OrdinalIgnoreCase)) { throw "$Label must be beneath V:\tmp" }
}
# Both paths are checked before report creation or any other output write.
if ($env:CK_FS_REQUIRE_V_DEV_DRIVE -ceq '1') {
  Assert-WorkstationTempPath $FixtureRoot 'FixtureRoot'
  Assert-WorkstationTempPath $Report 'Report'
}
$root = [IO.Path]::GetFullPath($FixtureRoot)
$reportPath = [IO.Path]::GetFullPath($Report)
$reportParent = [IO.Path]::GetDirectoryName($reportPath)
# This is local scratch discovery, not UNC/provider execution authority.
function Assert-NoReparseAncestors([string]$Path, [bool]$AllowMissing = $false) {
  $current = [IO.DirectoryInfo]::new($Path)
  $foundExisting = $false
  while ($null -ne $current) {
    try { $attributes = [IO.File]::GetAttributes($current.FullName) }
    catch [IO.FileNotFoundException] {
      if (-not $AllowMissing) { throw }
      $current = $current.Parent
      continue
    }
    catch [IO.DirectoryNotFoundException] {
      if (-not $AllowMissing) { throw }
      $current = $current.Parent
      continue
    }
    $foundExisting = $true
    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw 'Qualification path traverses a reparse/mounted directory'
    }
    if (($attributes -band [IO.FileAttributes]::Directory) -eq 0) { throw 'Scratch ancestor is not a directory' }
    $current = $current.Parent
  }
  if (-not $foundExisting) { throw 'Qualification path has no available directory ancestor' }
}
# CMake writes only its output here: refuse redirected output ancestry.
# The explicit native fixture is an initial address, not provider/ownership
# authority. It may name a mounted volume; each native fixture must acquire and
# independently qualify its actual provider before writes. Automatic provider
# discovery below still refuses reparse/mounted ancestry.
if ($ValidatePathsOnly) {
  Assert-NoReparseAncestors $reportPath $true
  return
}
if (-not [IO.Directory]::Exists($root)) { throw 'Fixture scratch must already exist' }
Assert-NoReparseAncestors $root
if (-not [IO.Directory]::Exists($reportParent)) { throw 'Report parent must already exist' }
Assert-NoReparseAncestors $reportParent
$driveRoot = [IO.Path]::GetPathRoot($root)
# DriveInfo queries a fixed drive root and rejects extended DOS spelling.
# All fixture/report I/O keeps the original complete native address.
if ($driveRoot.StartsWith('\\?\', [StringComparison]::Ordinal)) {
  $dosRoot = $driveRoot.Substring(4)
  if ($dosRoot -cnotmatch '^[A-Za-z]:\\$') { throw 'Local DOS drive root required for automatic provider discovery' }
  $driveRoot = $dosRoot
}
$drive = [IO.DriveInfo]::new($driveRoot)
if (-not $drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'Ready local fixed scratch drive required' }
$filesystem = $drive.DriveFormat
if ($filesystem -cnotin @('NTFS', 'ReFS')) { throw "Unsupported controlled scratch provider: $filesystem" }
Assert-NoReparseAncestors $root
if ([IO.DriveInfo]::new($driveRoot).DriveFormat -cne $filesystem) { throw 'Scratch drive provider changed during discovery' }
$record = [ordered]@{schema=1; fixture_root=$root; drive_root=$driveRoot; filesystem=$filesystem;
  require_v_dev_drive=($env:CK_FS_REQUIRE_V_DEV_DRIVE -ceq '1'); powershell=$PSVersionTable.PSVersion.ToString(); dotnet=[Runtime.InteropServices.RuntimeInformation]::FrameworkDescription;
  api='System.IO.DriveInfo.DriveFormat (UTF-16 GetVolumeInformationW); no-reparse ancestry before/after';
  meaning='Caller expected-provider observation only; native fixtures independently qualify actual held provider'}
$json = $record | ConvertTo-Json -Depth 4
Assert-NoReparseAncestors $reportParent
$stream = [IO.File]::Open($reportPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes($json + "`n"); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
$filesystem
