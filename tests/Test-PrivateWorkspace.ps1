#requires -Version 5.1
[CmdletBinding()]
param([string]$OutputDirectory)
$env:TZ='UTC'
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$sourceRoot=Split-Path -Parent $PSScriptRoot
$sourceFiles=@('scripts/Toolkit.Core.psm1','scripts/Private.Workspace.ps1','scripts/Windows.Native.cs','templates/ledger-contract.json','tests/Test-PrivateWorkspace.ps1')
$sourceHashes=@(foreach($relative in $sourceFiles){[pscustomobject]@{relative_path=$relative;sha256=(Get-FileHash -LiteralPath (Join-Path $sourceRoot $relative) -Algorithm SHA256).Hash.ToLowerInvariant()}})
$work=[IO.Path]::GetFullPath((Join-Path $sourceRoot 'work'))
if(-not $OutputDirectory){$OutputDirectory=Join-Path $work '_tests/private-workspace'}
$out=[IO.Path]::GetFullPath($OutputDirectory)
if(-not $out.StartsWith($work+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Private workspace fixture output must remain inside toolkit work.'}
$null=[IO.Directory]::CreateDirectory($out)
$suite=Join-Path $out ('private-workspace-'+[Guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($suite)
$utf8=New-Object Text.UTF8Encoding($false)
. (Join-Path $sourceRoot 'scripts/Private.Workspace.ps1')
Import-Module (Join-Path $sourceRoot 'scripts/Toolkit.Core.psm1') -Force -DisableNameChecking
$results=New-Object 'Collections.Generic.List[object]';$status='failed'
function Check([bool]$Value,[string]$Name){if(-not $Value){throw ('CHECK FAILED: '+$Name)};$results.Add([pscustomobject]@{name=$Name;status='passed'})}
function Refuses([scriptblock]$Operation,[string]$Name){$held=$false;try{& $Operation|Out-Null}catch{$held=$true};Check $held $Name}
function Hash([byte[]]$Bytes){$sha=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
function SecurityHash([string]$Path,[bool]$Directory=$true){return Hash ((Get-ToolkitPrivateSecurity $Path $Directory).GetSecurityDescriptorBinaryForm())}
function FictionalToolkit {
    $root=Join-Path $suite ('toolkit-'+[Guid]::NewGuid().ToString('N'))
    foreach($relative in @('scripts','templates')){$null=[IO.Directory]::CreateDirectory((Join-Path $root $relative))}
    foreach($relative in @('scripts/Toolkit.Core.psm1','scripts/Private.Workspace.ps1','templates/ledger-contract.json')){[IO.File]::WriteAllBytes((Join-Path $root $relative),[IO.File]::ReadAllBytes((Join-Path $sourceRoot $relative)))}
    $marker=[ordered]@{schema_version='1.0';toolkit_id=[Guid]::NewGuid().ToString();name='Fictional private workspace test';version='1.0.0'}
    [IO.File]::WriteAllText((Join-Path $root 'toolkit.json'),(ConvertTo-Json -InputObject $marker -Compress),$utf8)
    return $root
}
function CreateFictionalSecurity([string]$Path,[ValidateSet('broad','missing-control','deny','unprotected')][string]$Case) {
    if(Test-Path -LiteralPath $Path){throw 'Fictional ACL fixture may create only a fresh absent object.'}
    if($Case -ceq 'unprotected'){$null=[IO.Directory]::CreateDirectory($Path);return}
    $principals=Get-ToolkitPrivatePrincipals
    $security=New-Object Security.AccessControl.DirectorySecurity
    $security.SetOwner($principals.User)
    $security.SetAccessRuleProtection(($Case -cne 'unprotected'),$false)
    $inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach($principal in $principals.Allowed.Values){$rights=if($Case -ceq 'missing-control' -and $principal.Value -ceq $principals.User.Value){[Security.AccessControl.FileSystemRights]::ReadAndExecute}else{[Security.AccessControl.FileSystemRights]::FullControl};$rule=New-Object Security.AccessControl.FileSystemAccessRule $principal,$rights,$inherit,([Security.AccessControl.PropagationFlags]::None),([Security.AccessControl.AccessControlType]::Allow);$security.AddAccessRule($rule)}
    if($Case -in @('broad','deny')){$world=New-Object Security.Principal.SecurityIdentifier ([Security.Principal.WellKnownSidType]::WorldSid),$null;$access=if($Case -ceq 'deny'){[Security.AccessControl.AccessControlType]::Deny}else{[Security.AccessControl.AccessControlType]::Allow};$rule=New-Object Security.AccessControl.FileSystemAccessRule $world,([Security.AccessControl.FileSystemRights]::ReadAndExecute),$inherit,([Security.AccessControl.PropagationFlags]::None),$access;$security.AddAccessRule($rule)}
    if($null -ne [IO.Directory].GetMethod('CreateDirectory',[type[]]@([string],[Security.AccessControl.DirectorySecurity]))){$null=[IO.Directory]::CreateDirectory($Path,$security)}else{$extension=Get-ToolkitPrivateAclExtension;$extension::Create((New-Object IO.DirectoryInfo $Path),$security)}
}
try {
    $tk=FictionalToolkit
    $run=New-ToolkitRun -Mode fixture -Platform windows -Purpose 'Fictional privacy fixture; no host inventory' -ToolkitRoot $tk
    $private=Join-Path $tk 'work'
    $principals=Get-ToolkitPrivatePrincipals
    $security=Get-ToolkitPrivateSecurity $private $true
    $raw=New-Object Security.AccessControl.RawSecurityDescriptor ($security.GetSecurityDescriptorBinaryForm()),0
    Check ($raw.Owner.Value -ceq $principals.User.Value) 'New namespace owner is the current token user'
    Check (($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0) 'New namespace DACL is protected at creation'
    Check (@($raw.DiscretionaryAcl|Where-Object {-not $principals.Allowed.ContainsKey($_.SecurityIdentifier.Value)}).Count -eq 0) 'New namespace grants no broad or unknown principal access'
    Check ($raw.DiscretionaryAcl.Count -eq $principals.Allowed.Count) 'New namespace retains only current user, SYSTEM and Administrators full control'
    Assert-ToolkitPrivateWorkspace $private
    Check $true 'Actual namespace, run, control-file and child ACLs pass readback admission'
    $aclBefore=SecurityHash $private
    New-ToolkitPrivateDirectory $private
    Check ((SecurityHash $private) -ceq $aclBefore) 'Already private namespace admission preserves its ACL bytes'
    $fileProbe=Join-Path $private 'explicit-owner-file.fixture'
    $fileStream=New-ToolkitPrivateFileStream -Path $fileProbe
    try {
        $fileSecurity=Get-ToolkitPrivateSecurity $fileProbe $false
        $fileRaw=[Security.AccessControl.RawSecurityDescriptor]::new($fileSecurity.GetSecurityDescriptorBinaryForm(),0)
        Check ($fileRaw.Owner.Value -ceq $principals.User.Value) 'Atomic file creator sets actual TokenUser ownership before any bytes'
        Check ($fileStream.Length -eq 0 -and ($fileRaw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0) 'New empty file already has a protected DACL before its first write'
        Assert-ToolkitPrivateObject $fileProbe $false $principals
        Check $true 'New file readback grants only current user, SYSTEM and Administrators control'
        $fictionalBytes=$utf8.GetBytes('Fictional explicit file owner fixture');$fileStream.Write($fictionalBytes,0,$fictionalBytes.Length);$fileStream.Flush($true)
    } finally {$fileStream.Dispose()}
    $fileAclBefore=SecurityHash $fileProbe $false;$fileBytesBefore=Hash ([IO.File]::ReadAllBytes($fileProbe))
    Refuses {$unexpectedStream=New-ToolkitPrivateFileStream -Path $fileProbe;$unexpectedStream.Dispose()} 'Private file creator preserves create-new collision refusal'
    Check ((SecurityHash $fileProbe $false) -ceq $fileAclBefore -and (Hash ([IO.File]::ReadAllBytes($fileProbe))) -ceq $fileBytesBefore) 'Existing file collision preserves exact ACL and contents without repair'
    $lockProbe=Join-Path $private 'explicit-owner-lock.fixture'
    $lockStream=New-ToolkitPrivateFileStream -Path $lockProbe -Access ReadWrite -Options DeleteOnClose
    try {Assert-ToolkitPrivateWorkspace $private;Check $true 'Read/write delete-on-close stream has actual TokenUser ownership during exclusive lock admission'}finally{$lockStream.Dispose()}
    Check (-not (Test-Path -LiteralPath $lockProbe)) 'Explicit-owner lock preserves delete-on-close behavior'
    Write-ToolkitArtifact -RunId $run.run_id -RelativePath 'evidence/nested/fictional.txt' -Content 'Fictional selected metadata and owner quotation only' -ToolkitRoot $tk
    Assert-ToolkitPrivateWorkspace $private
    Check ((Get-ToolkitLedger -RunId $run.run_id -ToolkitRoot $tk).run.id -ceq $run.run_id) 'Private artifact ACL permits owner bookkeeping inside the private namespace'
    $updatedLedger=Get-ToolkitLedger -RunId $run.run_id -ToolkitRoot $tk;$updatedLedger.run.purpose='Fictional owner-controlled atomic replacement';Set-ToolkitLedger -RunId $run.run_id -Ledger $updatedLedger -ToolkitRoot $tk
    $replacementSecurity=Get-ToolkitPrivateSecurity (Join-Path $run.path 'ledger.json') $false
    $replacementRaw=[Security.AccessControl.RawSecurityDescriptor]::new($replacementSecurity.GetSecurityDescriptorBinaryForm(),0)
    Check ($replacementRaw.Owner.Value -ceq $principals.User.Value) 'Atomic control replacement retains explicit TokenUser ownership'
    [IO.File]::WriteAllBytes((Join-Path $tk 'scripts/Windows.Native.cs'),[IO.File]::ReadAllBytes((Join-Path $sourceRoot 'scripts/Windows.Native.cs')))
    [IO.File]::WriteAllText((Join-Path $tk 'README.md'),'# Fictional public export smoke fixture',$utf8)
    $exportList=[ordered]@{files=@('README.md','toolkit.json','scripts/Toolkit.Core.psm1','scripts/Private.Workspace.ps1','scripts/Windows.Native.cs','templates/ledger-contract.json','templates/export-allowlist.json')}
    [IO.File]::WriteAllText((Join-Path $tk 'templates/export-allowlist.json'),(ConvertTo-Json -InputObject $exportList -Compress),$utf8)
    $export=Export-Toolkit -ToolkitRoot $tk
    $archiveSecurity=Get-ToolkitPrivateSecurity $export.archive $false;$archiveRaw=[Security.AccessControl.RawSecurityDescriptor]::new($archiveSecurity.GetSecurityDescriptorBinaryForm(),0)
    $archiveStream=[IO.File]::OpenRead($export.archive)
    try {$archive=[IO.Compression.ZipArchive]::new($archiveStream,[IO.Compression.ZipArchiveMode]::Read,$true);try{Check ($archiveRaw.Owner.Value -ceq $principals.User.Value -and $archive.Entries.Count -eq 7 -and $export.files -eq 7) 'Export ZIP remains readable and has explicit TokenUser ownership'}finally{$archive.Dispose()}}finally{$archiveStream.Dispose()}
    $plan=New-ToolkitCleanupPlan -RunId $run.run_id -Scope Temporary -ToolkitRoot $tk
    $planSecurity=Get-ToolkitPrivateSecurity $plan.plan_path $false;$planRaw=[Security.AccessControl.RawSecurityDescriptor]::new($planSecurity.GetSecurityDescriptorBinaryForm(),0)
    Check ($planRaw.Owner.Value -ceq $principals.User.Value -and -not $plan.deletion_performed) 'Cleanup preview creates an explicit TokenUser-owned control without maintenance'
    Assert-ToolkitPrivateWorkspace $private
    Check $true 'Compiler, nested artifact, plan and export directories retain strict TokenUser owner admission'
    foreach($case in @('broad','missing-control','deny','unprotected')) {
        $unsafeToolkit=FictionalToolkit;$unsafe=Join-Path $unsafeToolkit 'work'
        CreateFictionalSecurity $unsafe $case
        $before=SecurityHash $unsafe
        Refuses {New-ToolkitRun -Mode fixture -Platform windows -ToolkitRoot $unsafeToolkit} ('Existing unsafe namespace refused before run or lock writes: '+$case)
        Check ((SecurityHash $unsafe) -ceq $before) ('Unsafe namespace ACL is unchanged: '+$case)
        Check (-not (Test-Path -LiteralPath (Join-Path $unsafe '_locks'))) ('Unsafe namespace receives no generated lock area: '+$case)
        Refuses {New-ToolkitPrivateDirectory $unsafe} ('Private directory helper refuses existing unsafe namespace without adoption: '+$case)
        Check ((SecurityHash $unsafe) -ceq $before) ('Helper preserves unsafe namespace ACL bytes: '+$case)
    }
    $nestedToolkit=FictionalToolkit
    $nestedRun=New-ToolkitRun -Mode fixture -Platform windows -Purpose 'Fictional shared-child hold' -ToolkitRoot $nestedToolkit
    $ledger=Join-Path $nestedRun.path 'ledger.json';$audit=Join-Path $nestedRun.path 'actions.jsonl';$owned=Join-Path $nestedRun.path 'owned-files.json'
    $ledgerBefore=Hash ([IO.File]::ReadAllBytes($ledger));$auditBefore=Hash ([IO.File]::ReadAllBytes($audit));$ownedBefore=Hash ([IO.File]::ReadAllBytes($owned))
    $sharedChild=Join-Path $nestedRun.path 'fictional-shared-child';CreateFictionalSecurity $sharedChild 'broad';$childAcl=SecurityHash $sharedChild
    Refuses {Get-ToolkitLedger -RunId $nestedRun.run_id -ToolkitRoot $nestedToolkit} 'Private root with a separately shared descendant is refused before private control reads'
    Refuses {Write-ToolkitArtifact -RunId $nestedRun.run_id -RelativePath 'evidence/held.txt' -Content 'Fictional held bytes' -ToolkitRoot $nestedToolkit} 'Shared descendant holds artifact writes before a file is created'
    Check ((SecurityHash $sharedChild) -ceq $childAcl -and -not (Test-Path -LiteralPath (Join-Path $nestedRun.path 'evidence/held.txt')) -and (Hash ([IO.File]::ReadAllBytes($ledger))) -ceq $ledgerBefore -and (Hash ([IO.File]::ReadAllBytes($audit))) -ceq $auditBefore -and (Hash ([IO.File]::ReadAllBytes($owned))) -ceq $ownedBefore) 'Descendant refusal preserves ACL, ledger, ownership and audit bytes'
    $fileToolkit=FictionalToolkit;$fileWork=Join-Path $fileToolkit 'work';[IO.File]::WriteAllText($fileWork,'Fictional ordinary file',$utf8);$fileBefore=Hash ([IO.File]::ReadAllBytes($fileWork))
    Refuses {New-ToolkitRun -Mode fixture -Platform windows -ToolkitRoot $fileToolkit} 'Ordinary file at the namespace path is refused'
    Check ((Hash ([IO.File]::ReadAllBytes($fileWork))) -ceq $fileBefore) 'Wrong-type namespace bytes are unchanged'
    $copiedToolkit=FictionalToolkit
    Import-Module (Join-Path $copiedToolkit 'scripts/Toolkit.Core.psm1') -Force -DisableNameChecking
    $copiedRun=New-ToolkitRun -Mode fixture -Platform windows -Purpose 'Fictional copied module helper' -ToolkitRoot $copiedToolkit
    Assert-ToolkitPrivateWorkspace (Join-Path $copiedToolkit 'work')
    Check ((Get-ToolkitLedger -RunId $copiedRun.run_id -ToolkitRoot $copiedToolkit).run.id -ceq $copiedRun.run_id) 'Copied module resolves the copied private-workspace helper'
    $status='passed'
} catch {$results.Add([pscustomobject]@{name='Suite stopped';status='failed';reason=$_.Exception.GetType().Name+': '+$_.Exception.Message})}
$sourceUnchanged=$true
foreach($entry in $sourceHashes){if((Get-FileHash -LiteralPath (Join-Path $sourceRoot $entry.relative_path) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256){$sourceUnchanged=$false}}
if(-not $sourceUnchanged){$status='failed';$results.Add([pscustomobject]@{name='Source hashes changed during fixture execution';status='failed'})}
$result=[ordered]@{status=$status;fixture_only=$true;live_inventory_executed=$false;real_maintenance_executed=$false;permissions_changed_on_existing_objects=$false;raw_acl_or_account_identifiers_reported=$false;completed_utc=[DateTime]::UtcNow.ToString('o');powershell_version=$PSVersionTable.PSVersion.ToString();powershell_edition=$PSVersionTable.PSEdition;source_hashes=$sourceHashes;source_hashes_unchanged=$sourceUnchanged;checks=$results.ToArray();passed=@($results|Where-Object status -ceq 'passed').Count;skipped=0}
$resultPath=Join-Path $suite 'result.json';[IO.File]::WriteAllText($resultPath,(ConvertTo-Json -InputObject $result -Depth 20 -Compress),$utf8)
[pscustomobject]@{status=$status;passed=$result.passed;skipped=0;result=$resultPath}
if($status -cne 'passed'){throw 'Private workspace fictional fixture suite failed; inspect its owned result.json.'}
