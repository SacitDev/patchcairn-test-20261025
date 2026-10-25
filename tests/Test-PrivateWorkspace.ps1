[CmdletBinding()]
param()
# Independent .NET ACL verification (System.Security.AccessControl) of the private folders and files the Python code
# creates through private_workspace and the Windows file backend: the owner is the current user, the DACL is protected
# and holds exactly the user, SYSTEM and Administrators with full control (inherited by children of a folder). Prints
# one PASS or FAIL line per check and exits 1 if any check fails. Runs a small driver with `-I -S -B` under the Python
# named by PATCHCAIRN_TEST_PYTHON (a full drive path such as C:\..., as CI sets it; a set value that is not an existing
# full drive path fails the run), and when it is unset under `py -3.14` (the Python launcher);
# fixtures live under work/test-fixtures/ and are removed. No account names or SIDs are printed.
$env:TZ='UTC'
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$work=Join-Path $repo ('work\test-fixtures\private-acl-'+[Guid]::NewGuid().ToString('N'))
$script:failed=0
function Check([string]$Name,[scriptblock]$Test) {
 try { $passed=[bool](& $Test) } catch { $passed=$false }
 if ($passed) { Write-Output ('PASS '+$Name) } else { $script:failed++; Write-Output ('FAIL '+$Name) }
}
$user=[Security.Principal.WindowsIdentity]::GetCurrent().User
$principals=@(@($user.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique | Sort-Object)
function Get-Privacy([string]$Path,[bool]$Directory) {
 # 'private' or the first property that differs.
 $acl=Get-Acl -LiteralPath $Path
 if (-not $acl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($user)) { return 'owner' }
 if (-not $acl.AreAccessRulesProtected) { return 'not protected' }
 $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 $sids=@($rules | ForEach-Object { $_.IdentityReference.Value } | Sort-Object)
 if ($rules.Count -ne $principals.Count -or @(Compare-Object $sids $principals).Count) { return 'principals' }
 $inheritance=if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
 foreach ($rule in $rules) {
  if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.IsInherited -or
      $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
      $rule.InheritanceFlags -ne $inheritance -or $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { return 'rule' }
 }
 return 'private'
}
$driver=@'
import sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
import private_workspace
import windows_scoped

base = Path(sys.argv[2])
private_workspace.ensure_private_directory(base / "workspace", create=True)
private_workspace.write_private_new(base / "workspace" / "record.json", b"{}")
(base / "selected").mkdir()
with windows_scoped.WindowsRoot(str(base / "selected")) as root:
    root.mkdir("backup")
    for name, data in (("backup.zip", b"PK\x05\x06" + bytes(18)), ("manifest.json", b"{}"), ("README.txt", b"fictional")):
        root.create_file("backup/" + name, data=data)
    with root.open_new("restored.txt", private=False, original_mode=0o100644) as out:
        out.write(b"restored into an existing folder")
        out.commit()
print("created")
'@
[IO.Directory]::CreateDirectory($work) | Out-Null
try {
 $script=Join-Path $work 'driver.py'
 [IO.File]::WriteAllText($script,$driver,(New-Object Text.UTF8Encoding($false)))
 $python=$env:PATCHCAIRN_TEST_PYTHON;$version=@()
 if ($python -and -not ($python -match '^[A-Za-z]:\\' -and (Test-Path -LiteralPath $python -PathType Leaf))) { $python=$null }
 elseif (-not $python) {
  $launcher=Get-Command py -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($launcher) { $python=$launcher.Source;$version=@('-3.14') }
 }
 Check 'python interpreter available' { $null -ne $python }
 Check 'python driver created the fixtures' { $out=& $python @version -I -S -B $script (Join-Path $repo 'scripts') $work;$LASTEXITCODE -eq 0 -and "$out".Trim() -ceq 'created' }
 Check 'private workspace folder: owner, protected DACL, exactly three ACEs' { (Get-Privacy (Join-Path $work 'workspace') $true) -ceq 'private' }
 Check 'private workspace file: owner, protected DACL, exactly three ACEs' { (Get-Privacy (Join-Path $work 'workspace\record.json') $false) -ceq 'private' }
 Check 'backup folder: owner, protected DACL, exactly three ACEs' { (Get-Privacy (Join-Path $work 'selected\backup') $true) -ceq 'private' }
 foreach ($file in @('backup.zip','manifest.json','README.txt')) {
  Check ('backup file '+$file+': owner, protected DACL, exactly three ACEs') { (Get-Privacy (Join-Path $work ('selected\backup\'+$file)) $false) -ceq 'private' }
 }
 # A non-private object gets the token's default owner: Administrators for a process with a full administrator token
 # (any elevated process; GitHub's Windows runners disable UAC), otherwise the user. So the restored file's check
 # ignores the owner, and the ordinary folder's check expects the answer Get-Privacy must give for the owner it has.
 Check 'restored file in an existing folder inherits that folder''s permissions' {
  $acl=Get-Acl -LiteralPath (Join-Path $work 'selected\restored.txt')
  $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  -not $acl.AreAccessRulesProtected -and $rules.Count -ge 1 -and @($rules | Where-Object { -not $_.IsInherited }).Count -eq 0
 }
 Check 'ordinary folder is recognised as not private' {
  $folder=Join-Path $work 'selected'
  $acl=Get-Acl -LiteralPath $folder
  $expected=if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($user)) { 'not protected' } else { 'owner' }
  (Get-Privacy $folder $true) -ceq $expected -and -not $acl.AreAccessRulesProtected
 }
} finally {
 Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
if ($script:failed) { Write-Output ('FAILED '+$script:failed+' check(s)');exit 1 }
