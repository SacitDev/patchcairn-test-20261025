#requires -Version 5.1
[CmdletBinding()]
param([string]$OutputDirectory)
$env:TZ='UTC'
$ErrorActionPreference='Stop'
$sourceRoot=Split-Path -Parent $PSScriptRoot
$sourceFiles=@('scripts/Toolkit.Core.psm1','scripts/Private.Workspace.ps1','scripts/Windows.Native.cs','scripts/Invoke-Toolkit.ps1','scripts/Collect-WindowsBaseline.ps1','templates/report.html','templates/ledger-contract.json','templates/export-allowlist.json','tests/fictional-ledger.json','tests/Invoke-FixtureTests.ps1')
$sourceHashes=@(foreach($relative in $sourceFiles){[pscustomobject]@{relative_path=$relative;sha256=(Get-FileHash -LiteralPath (Join-Path $sourceRoot $relative) -Algorithm SHA256).Hash.ToLowerInvariant()}})
$work=[IO.Path]::GetFullPath((Join-Path $sourceRoot 'work'))
if(-not $OutputDirectory){$OutputDirectory=Join-Path $work '_tests'}
$out=[IO.Path]::GetFullPath($OutputDirectory)
if(-not $out.StartsWith($work+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture output must remain inside toolkit work.'}
$null=[IO.Directory]::CreateDirectory($out);$suite=Join-Path $out ('fixture-suite-'+[Guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($suite)
$tk=Join-Path $suite 'toolkit';foreach($d in @('scripts','templates','tests')){$null=[IO.Directory]::CreateDirectory((Join-Path $tk $d))}
$utf8=New-Object Text.UTF8Encoding($false)
function Json($v){ConvertTo-Json -InputObject $v -Depth 60 -Compress}
function Parse([string]$t){if((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')){return ConvertFrom-Json -InputObject $t -DateKind String};return ConvertFrom-Json -InputObject $t}
function Hash([byte[]]$b){$s=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($s.ComputeHash($b))).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
function Save([string]$p,[string]$t){[IO.File]::WriteAllText($p,$t,$utf8)}
foreach($p in @('scripts/Toolkit.Core.psm1','scripts/Private.Workspace.ps1','scripts/Windows.Native.cs','scripts/Invoke-Toolkit.ps1','scripts/Collect-WindowsBaseline.ps1','templates/report.html','templates/ledger-contract.json','tests/fictional-ledger.json')){[IO.File]::WriteAllBytes((Join-Path $tk $p),[IO.File]::ReadAllBytes((Join-Path $sourceRoot $p)))}
$tkid=[Guid]::NewGuid().ToString();Save (Join-Path $tk 'toolkit.json') (Json ([ordered]@{schema_version='1.0';toolkit_id=$tkid;name='PatchCairn fictional fixture';version='1.0.0';purpose='Fictional tests only'}));Save (Join-Path $tk 'README.md') '# Fictional public fixture source';$attributesBytes=$utf8.GetBytes("* -text`n");[IO.File]::WriteAllBytes((Join-Path $tk '.gitattributes'),$attributesBytes);Save (Join-Path $tk 'templates/export-allowlist.json') (Json @{files=@('.gitattributes','README.md','toolkit.json','scripts/Toolkit.Core.psm1','scripts/Private.Workspace.ps1','scripts/Windows.Native.cs','templates/report.html','templates/ledger-contract.json','templates/export-allowlist.json')})
Import-Module (Join-Path $sourceRoot 'scripts/Toolkit.Core.psm1') -Force -DisableNameChecking
$results=New-Object Collections.Generic.List[object];$status='failed';$demo=$null
function Check([bool]$ok,[string]$name){if(-not $ok){$results.Add([pscustomobject]@{name=$name;status='failed'});throw ('CHECK FAILED: '+$name)};$results.Add([pscustomobject]@{name=$name;status='passed'})}
function Refuses([scriptblock]$operation,[string]$name){$refused=$false;try{& $operation|Out-Null}catch{$refused=$true};Check $refused $name}
# Fixed fictional labels and exact allowlisted failure tokens only; no arbitrary exception text.
$diagnosticSteps=New-Object Collections.Generic.List[object]
function Get-FixtureFailureClassification([Management.Automation.ErrorRecord]$record){
 $failure=[ordered]@{category='unclassified';exception_type='other';native_refusal='none';compiler_error_id='none';guard_label='none';script_basename='none';script_line=0;script_column=0}
 $compilerIds=@('SOURCE_CODE_ERROR,Microsoft.PowerShell.Commands.AddTypeCommand','COMPILER_ERRORS,Microsoft.PowerShell.Commands.AddTypeCommand')
 if($record.FullyQualifiedErrorId -cin $compilerIds){$failure.category='add-type-compiler';$failure.compiler_error_id=$record.FullyQualifiedErrorId}
 $knownTypes=@('System.Exception','System.InvalidOperationException','System.IO.IOException','System.IO.FileNotFoundException','System.IO.FileLoadException','System.UnauthorizedAccessException','System.TypeLoadException','System.ComponentModel.Win32Exception','System.Management.Automation.MethodInvocationException','System.Management.Automation.RuntimeException','System.Management.Automation.PSInvalidOperationException','System.Management.Automation.PSArgumentException')
 $nativeTokens=@('metadata','canonical-path','exact-path-mismatch','access-or-sharing','reparse','type','hardlink','seek','hash-read','run-boundary','allowlist','relative-path','duplicate-path','missing-root','unowned-target','missing-owned-entry','stale-membership','stale-content-or-identity','node-limit','unknown-entry','changed-after-pin','membership-drift','public-relative-path','public-boundary','public-size','public-read','public-drift','owned-relative-path','owned-boundary','owned-file-drift')
 # Exact public source literals only. Unknown messages are never emitted.
 $guardMessages=@{
  'Private workspace security cannot be verified; hold without changing permissions.'='private-security-read'
  'Private workspace reparse point or wrong object type refused.'='private-object-type'
  'Private workspace owner differs from the current token user; no adoption or permission repair.'='private-owner'
  'Private workspace requires a present protected namespace DACL; no permission repair.'='private-namespace-dacl'
  'Private workspace contains an unsupported access rule; hold without changing permissions.'='private-access-rule'
  'Private workspace access is not restricted to the current user and trusted Windows administrators; no permission repair.'='private-access-scope'
  'Private workspace lacks required owner or trusted administrator control; hold.'='private-required-control'
  'Private workspace reparse point refused.'='private-child-reparse'
  'Exact plan/hash/approval identifiers are required.'='cleanup-identifiers'
  'Plan hash changed.'='cleanup-plan-hash'
  'Wrong or expired cleanup plan.'='cleanup-plan-validity'
  'Cleanup acknowledgment must be boolean.'='cleanup-acknowledgment-type'
  'Exact owner-recorded approval missing or stale.'='cleanup-approval'
  'Full purge requires explicit records/backups deletion acknowledgment.'='cleanup-full-acknowledgment'
  'This cleanup plan is consumed. Preserve receipt; no automatic retry.'='cleanup-consumed'
  'Ledger/checkpoint/ownership changed after preview.'='cleanup-ledger-binding'
  'Selected scope/ownership changed after preview.'='cleanup-membership'
  'Invalid plan identifier before any operation write.'='cleanup-early-identifier'
  'Foreign or missing cleanup backend; no operation write.'='cleanup-early-backend'
 }
 $invocation=$record.InvocationInfo
 if($null -ne $invocation -and $invocation.ScriptLineNumber -ge 1 -and $invocation.ScriptLineNumber -le 65535 -and $invocation.OffsetInLine -ge 1 -and $invocation.OffsetInLine -le 1000000){
  foreach($relative in @('scripts/Toolkit.Core.psm1','scripts/Private.Workspace.ps1','tests/Invoke-FixtureTests.ps1')){
   $knownPath=[IO.Path]::GetFullPath((Join-Path $sourceRoot $relative))
   if([string]::Equals($invocation.ScriptName,$knownPath,[StringComparison]::OrdinalIgnoreCase)){$failure.script_basename=[IO.Path]::GetFileName($relative);$failure.script_line=$invocation.ScriptLineNumber;$failure.script_column=$invocation.OffsetInLine;break}
  }
 }
 $exception=$record.Exception
 for($depth=0;$null -ne $exception -and $depth -lt 8;$depth++){
  $type=$exception.GetType().FullName;$failure.exception_type=if($type -cin $knownTypes){$type}else{'other'}
  $message=$exception.Message
  if($message.Length -le 512){foreach($guard in $guardMessages.GetEnumerator()){if($message -ceq $guard.Key){$failure.category='toolkit-guard';$failure.guard_label=$guard.Value;break}}}
  if($message.Length -le 100 -and $message.StartsWith('Owned cleanup refused: ',[StringComparison]::Ordinal)){
   $token=$message.Substring(23)
   if($token -cin $nativeTokens){$failure.category='native-refusal';$failure.native_refusal=$token}
   elseif($token -cmatch '\Aunlink-failed-([0-9]{1,10})\z'){
    $code=[uint32]0
    if([uint32]::TryParse($Matches[1],[Globalization.NumberStyles]::None,[Globalization.CultureInfo]::InvariantCulture,[ref]$code)){$failure.category='native-refusal';$failure.native_refusal='unlink-failed-'+$code.ToString([Globalization.CultureInfo]::InvariantCulture)}
   }
  }
  $exception=$exception.InnerException
 }
 return [pscustomobject]$failure
}
function FixtureStep([string]$name,[scriptblock]$operation){
 try{$value=& $operation}catch{$diagnosticSteps.Add([pscustomobject]@{name=$name;status='failed';failure=(Get-FixtureFailureClassification $_)});throw}
 $diagnosticSteps.Add([pscustomobject]@{name=$name;status='passed'})
 return $value
}
function Write-FixtureDiagnostics($checks,$steps){
 foreach($check in @($checks)+@($steps)){
  $line='Fictional fixture check: '+$check.name+'; status='+$check.status
  if($check.PSObject.Properties['failure']){$f=$check.failure;$line+='; category='+$f.category+'; exception_type='+$f.exception_type+'; native_refusal='+$f.native_refusal+'; compiler_error_id='+$f.compiler_error_id+'; guard_label='+$f.guard_label+'; script_basename='+$f.script_basename+'; script_line='+$f.script_line+'; script_column='+$f.script_column}
  Write-Host $line
 }
}
function PrivateFixtureDirectory([string]$Path){$privateModule=Get-Module Toolkit.Core;& $privateModule {param($FixturePath) New-ToolkitPrivateDirectory $FixturePath} $Path}
function PrivateFixtureNew([string]$Path,[string]$Content){$privateModule=Get-Module Toolkit.Core;& $privateModule {param($FixturePath,[byte[]]$FixtureBytes) Write-ToolkitNew $FixturePath $FixtureBytes} $Path ($utf8.GetBytes($Content))}
function PrivateFixtureLock([string]$Path){$privateModule=Get-Module Toolkit.Core;& $privateModule {param($FixturePath) New-ToolkitPrivateFileStream -Path $FixturePath -Access ReadWrite -Options DeleteOnClose} $Path}
function Fresh(){New-ToolkitRun -Mode Fixture -Platform Windows -Purpose 'Fictional test; no real audit or update' -ToolkitRoot $tk}
function VerifiedRecoveryFixture(){
 $value=Fresh
 Write-ToolkitArtifact -RunId $value.run_id -RelativePath 'backups/needed.txt' -Role backup -Content 'fictional retained bytes' -RollbackNeeded -ToolkitRoot $tk
 Write-ToolkitArtifact -RunId $value.run_id -RelativePath 'evidence/verified.json' -Role evidence -Content '{"fictional":true}' -ToolkitRoot $tk
 $ledger=Get-ToolkitLedger -RunId $value.run_id -ToolkitRoot $tk
 $ledger.evidence=@([pscustomobject]@{id='proof';relative_path='evidence/verified.json';sha256=(Hash ($utf8.GetBytes('{"fictional":true}')));kind='fictional';observed_utc='2025-01-01T00:00:00Z';scope='fictional';limits='Synthetic only'})
 $ledger.actions=@([pscustomobject]@{id='verified-recovery';kind='verify';state='completed';component_ids=@();evidence_ids=@('proof');approval_id=$null;started_utc='2025-01-01T00:00:00Z';finished_utc='2025-01-01T00:00:01Z';outcome='Fictional verification';automatic_retry=$false})
 $ledger.run.status='completed';$ledger.run.phase='closed';Set-ToolkitLedger -RunId $value.run_id -Ledger $ledger -ToolkitRoot $tk
 return $value
}
function WithFictionalReleaseFailure([string]$Stage,[scriptblock]$Operation){
 $module=Get-Module Toolkit.Core
 & $module {param($stage)
  $script:FixtureReleaseFailureStage=$stage
  $script:FixtureOriginalAudit=${function:Add-ToolkitAudit}
  $script:FixtureOriginalControl=${function:Write-ToolkitControl}
  function script:Add-ToolkitAudit($Run,[string]$Operation,[string]$Status,$Details){
   if($script:FixtureReleaseFailureStage -ceq 'completion-audit' -and $Operation -ceq 'ReleaseRecovery' -and $Status -ceq 'completed'){
    $held=New-Object IO.FileStream((Join-Path $Run.Path 'actions.jsonl'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try{& $script:FixtureOriginalAudit $Run $Operation $Status $Details}finally{$held.Dispose()}
   }else{& $script:FixtureOriginalAudit $Run $Operation $Status $Details}
  }
  function script:Write-ToolkitControl([string]$Path,$Value){
   if($script:FixtureReleaseFailureStage -ceq 'final-control' -and [IO.Path]::GetFileName($Path) -ceq 'owned-files.json' -and @($Value.files|Where-Object {$_.PSObject.Properties['recovery_release'] -and $_.recovery_release.status -ceq 'completed'}).Count){throw 'Injected fictional final control interruption before replacement.'}
   & $script:FixtureOriginalControl $Path $Value
  }
 } $Stage
 try{& $Operation}finally{& $module {Set-Item -LiteralPath Function:script:Add-ToolkitAudit -Value $script:FixtureOriginalAudit;Set-Item -LiteralPath Function:script:Write-ToolkitControl -Value $script:FixtureOriginalControl;Remove-Variable -Scope Script -Name FixtureReleaseFailureStage,FixtureOriginalAudit,FixtureOriginalControl}}
}
function FictionalApproval($plan,[bool]$FullAck){$l=Get-ToolkitLedger -RunId $plan.run_id -ToolkitRoot $tk;if($l.run.mode -cne 'fixture'){throw 'Test cannot approve a real run.'};$p=Parse ([IO.File]::ReadAllText($plan.plan_path));$id='approval-'+[Guid]::NewGuid().ToString('N');$dir=Join-Path $tk 'work/_approvals';PrivateFixtureDirectory $dir;$a=[ordered]@{schema_version='1.0';backend='windows-powershell-v2';toolkit_id=$tkid;run_id=$p.run_id;plan_id=$p.plan_id;plan_sha256=$plan.plan_sha256;action_ids=@($p.action_id);scope=$p.scope;actor='owner';decision='approved';approved=$true;recorded_utc=[DateTime]::UtcNow.ToString('o');authorization_quote='Fictional fixture consent only; not authorization for any real maintenance.';acknowledge_records_and_backups_deletion=$FullAck};PrivateFixtureNew (Join-Path $dir ($id+'.json')) (Json $a);return $id}
try{
 # Proposed evidence must pass the same ownership/content checks before replacement as on read.
 foreach($invalidEvidence in @('unregistered','ownership-hash-mismatch','bytes-mismatch')){
  $candidate=Fresh;$candidatePath=Join-Path $candidate.path 'ledger.json'
  Write-ToolkitArtifact -RunId $candidate.run_id -RelativePath 'evidence/known.json' -Role evidence -Content '{"fictional":true}' -ToolkitRoot $tk
  $priorLedger=Hash ([IO.File]::ReadAllBytes($candidatePath));$priorOwned=Hash ([IO.File]::ReadAllBytes((Join-Path $candidate.path 'owned-files.json')));$priorAudit=Hash ([IO.File]::ReadAllBytes((Join-Path $candidate.path 'actions.jsonl')))
  $candidateLedger=Get-ToolkitLedger -RunId $candidate.run_id -ToolkitRoot $tk
  $knownHash=Hash ($utf8.GetBytes('{"fictional":true}'))
  $candidateLedger.evidence=@([pscustomobject]@{id='proof';relative_path=$(if($invalidEvidence -ceq 'unregistered'){'evidence/missing.json'}else{'evidence/known.json'});sha256=$(if($invalidEvidence -ceq 'ownership-hash-mismatch'){'0'*64}else{$knownHash});kind='fictional';observed_utc='2025-01-01T00:00:00Z';scope='fictional';limits='No host facts'})
  if($invalidEvidence -ceq 'bytes-mismatch'){Save (Join-Path $candidate.path 'evidence/known.json') '{"fictional":"changed bytes"}'}
  Refuses {Set-ToolkitLedger -RunId $candidate.run_id -Ledger $candidateLedger -ToolkitRoot $tk} ('Candidate evidence refused before replacement: '+$invalidEvidence)
  $current=Get-ToolkitLedger -RunId $candidate.run_id -ToolkitRoot $tk
  Check ((Hash ([IO.File]::ReadAllBytes($candidatePath))) -ceq $priorLedger -and (Hash ([IO.File]::ReadAllBytes((Join-Path $candidate.path 'owned-files.json')))) -ceq $priorOwned -and (Hash ([IO.File]::ReadAllBytes((Join-Path $candidate.path 'actions.jsonl')))) -ceq $priorAudit -and $current.evidence.Count -eq 0) ('Rejected evidence preserves readable canonical ledger and controls: '+$invalidEvidence)
 }
 # Disappeared registered files/directories must not be implicitly restored or duplicated.
 foreach($lostCase in @('registered-file','case-alias','registered-parent-new-child')){
  $lost=Fresh;$registered='temporary/nested/lost.txt';$writePath=$registered
  Write-ToolkitArtifact -RunId $lost.run_id -RelativePath $registered -Role temporary -Content 'fictional registered bytes' -ToolkitRoot $tk
  $moved=Join-Path $suite ('disappeared-'+[Guid]::NewGuid().ToString('N'))
  if($lostCase -ceq 'registered-parent-new-child'){
   [IO.Directory]::Move((Join-Path $lost.path 'temporary/nested'),$moved);$writePath='temporary/nested/new/deeper.txt'
  }else{
   [IO.File]::Move((Join-Path $lost.path $registered),$moved)
   if($lostCase -ceq 'case-alias'){$writePath='temporary/nested/LOST.txt'}
  }
  $lostLedgerPath=Join-Path $lost.path 'ledger.json';$lostOwnedPath=Join-Path $lost.path 'owned-files.json';$lostAuditPath=Join-Path $lost.path 'actions.jsonl'
  $lostLedgerHash=Hash ([IO.File]::ReadAllBytes($lostLedgerPath));$lostOwnedHash=Hash ([IO.File]::ReadAllBytes($lostOwnedPath));$lostAuditHash=Hash ([IO.File]::ReadAllBytes($lostAuditPath))
  Refuses {Write-ToolkitArtifact -RunId $lost.run_id -RelativePath $writePath -Role temporary -Content 'fictional registered bytes' -ToolkitRoot $tk} ('Missing registered artifact state refuses before creation: '+$lostCase)
  $readable=Get-ToolkitLedger -RunId $lost.run_id -ToolkitRoot $tk;$lostOwned=Parse ([IO.File]::ReadAllText($lostOwnedPath))
  Check (-not (Test-Path -LiteralPath (Join-Path $lost.path $writePath)) -and (Hash ([IO.File]::ReadAllBytes($lostLedgerPath))) -ceq $lostLedgerHash -and (Hash ([IO.File]::ReadAllBytes($lostOwnedPath))) -ceq $lostOwnedHash -and (Hash ([IO.File]::ReadAllBytes($lostAuditPath))) -ceq $lostAuditHash -and @($lostOwned.files|Where-Object relative_path -ceq $registered).Count -eq 1 -and $readable.run.id -ceq $lost.run_id) ('Missing-state refusal preserves readable ledger, ownership and audit bytes: '+$lostCase)
  if($lostCase -ceq 'registered-parent-new-child'){Check (-not (Test-Path -LiteralPath (Join-Path $lost.path 'temporary/nested'))) 'Missing registered parent is not recreated before refusing a new child'}
  Write-ToolkitArtifact -RunId $lost.run_id -RelativePath 'evidence/continuation.json' -Role evidence -Content '{"fictional":"separate valid artifact"}' -ToolkitRoot $tk
  Check ((Test-Path -LiteralPath (Join-Path $lost.path 'evidence/continuation.json')) -and (Get-ToolkitLedger -RunId $lost.run_id -ToolkitRoot $tk).run.id -ceq $lost.run_id) ('Separate valid bookkeeping remains usable after missing-state refusal: '+$lostCase)
  Refuses {New-ToolkitCleanupPlan -RunId $lost.run_id -ToolkitRoot $tk} ('Missing registered artifact still holds cleanup for explicit reconciliation: '+$lostCase)
 }
 $lostReport=Fresh;$built=Build-ToolkitReport -RunId $lostReport.run_id -ToolkitRoot $tk
 $reportRelative=$built.report.Substring($lostReport.path.Length+1).Replace('\','/')
 [IO.File]::Move($built.report,(Join-Path $suite ('missing-report-'+[Guid]::NewGuid().ToString('N')+'.fixture')))
 $reportLedgerHash=Hash ([IO.File]::ReadAllBytes((Join-Path $lostReport.path 'ledger.json')));$reportOwnedHash=Hash ([IO.File]::ReadAllBytes((Join-Path $lostReport.path 'owned-files.json')));$reportAuditHash=Hash ([IO.File]::ReadAllBytes((Join-Path $lostReport.path 'actions.jsonl')))
 Refuses {Build-ToolkitReport -RunId $lostReport.run_id -ToolkitRoot $tk} 'Rebuilding a missing registered report refuses without implicit restoration'
 $reportOwned=Parse ([IO.File]::ReadAllText((Join-Path $lostReport.path 'owned-files.json')))
 Check (-not (Test-Path -LiteralPath $built.report) -and (Hash ([IO.File]::ReadAllBytes((Join-Path $lostReport.path 'ledger.json')))) -ceq $reportLedgerHash -and (Hash ([IO.File]::ReadAllBytes((Join-Path $lostReport.path 'owned-files.json')))) -ceq $reportOwnedHash -and (Hash ([IO.File]::ReadAllBytes((Join-Path $lostReport.path 'actions.jsonl')))) -ceq $reportAuditHash -and @($reportOwned.files|Where-Object relative_path -ceq $reportRelative).Count -eq 1 -and (Get-ToolkitLedger -RunId $lostReport.run_id -ToolkitRoot $tk).run.id -ceq $lostReport.run_id) 'Missing report refusal preserves exact controls and single ownership row'
 $r=Fresh;$body='{"fictional":true,"observed":"no host facts"}';Write-ToolkitArtifact -RunId $r.run_id -RelativePath 'evidence/observation.json' -Role evidence -Content $body -ToolkitRoot $tk
 $fixture=[IO.File]::ReadAllText((Join-Path $sourceRoot 'tests/fictional-ledger.json')).Replace('TOOLKIT_ID',$tkid).Replace('RUN_ID',$r.run_id).Replace('EVIDENCE_SHA256',(Hash ($utf8.GetBytes($body))));$ledger=Parse $fixture;Set-ToolkitLedger -RunId $r.run_id -Ledger $ledger -ToolkitRoot $tk
 $validation=Test-ToolkitLedger -RunId $r.run_id -ToolkitRoot $tk;Check ($validation.status -ceq 'passed') 'Fictional canonical ledger validates'
 $demo=Build-ToolkitReport -RunId $r.run_id -ToolkitRoot $tk;$summary=Parse ([IO.File]::ReadAllText($demo.summary));$snapshot=Parse ([IO.File]::ReadAllText((Join-Path (Split-Path -Parent $demo.report) 'ledger.snapshot.json')));$html=[IO.File]::ReadAllText($demo.report);$embedded=Parse ([regex]::Match($html,'(?s)<script id="toolkit-data" type="application/json">(.*?)</script>').Groups[1].Value);$csv=@(Import-Csv -LiteralPath $demo.csv)
 Check ((Json $embedded.ledger) -ceq (Json $snapshot) -and $summary.ledger_sha256 -ceq $demo.ledger_sha256 -and $csv.Count -eq @($snapshot.components).Count) 'HTML/CSV/summary use exact same immutable snapshot'
 Check ($html.Contains('\u003c/script\u003e') -and -not $html.Contains('</script><script>globalThis.fixtureInjection')) 'Malicious HTML remains encoded data'
 Check ($embedded.ledger.run.purpose.Contains('@@DATA@@') -and $embedded.ledger.run.purpose.Contains('@@LEDGER_SHA@@')) 'Literal template tokens remain untouched inside ledger text'
 Check ($html.Contains('FICTIONAL DEMONSTRATION') -and $html.Contains('no real audit or update performed')) 'Large explicit fictional banner'
 Check ($summary.update_states.verified -eq 1 -and $summary.security_states.not_assessed -eq 3 -and $summary.counts_are_not_security_clearance) 'Verified version does not imply security cleared'
 Check (([IO.File]::ReadAllText($demo.summary_markdown)).Contains('FICTIONAL DEMONSTRATION')) 'Human summary Markdown is generated from snapshot'
 $formula=@($csv|Where-Object id -ceq 'hostile-display')[0].installed_version;Check ($formula -ceq "'=1+1") 'Spreadsheet formula prefix neutralized'
 Refuses {New-ToolkitCleanupPlan -RunId $r.run_id -Scope Temporary -ToolkitRoot $tk} 'Unapproved future action prevents temporary cleanup'
 Refuses {Get-ToolkitWindowsBaseline -RunId $r.run_id -ToolkitRoot $tk} 'Fixture mode refuses actual baseline collection'
 $immutable=Fresh;$l=Get-ToolkitLedger -RunId $immutable.run_id -ToolkitRoot $tk;$l.run.mode='real';Refuses {Set-ToolkitLedger -RunId $immutable.run_id -Ledger $l -ToolkitRoot $tk} 'Fixture to real promotion rejected by SetLedger';$l=Get-ToolkitLedger -RunId $immutable.run_id -ToolkitRoot $tk;$l.run.platform='linux';Refuses {Set-ToolkitLedger -RunId $immutable.run_id -Ledger $l -ToolkitRoot $tk} 'Creation platform change rejected by SetLedger'
 $tamper=Fresh;$l=Get-ToolkitLedger -RunId $tamper.run_id -ToolkitRoot $tk;$l.run.mode='real';Save (Join-Path $tamper.path 'ledger.json') (Json $l);Refuses {Get-ToolkitLedger -RunId $tamper.run_id -ToolkitRoot $tk} 'Direct ledger mode tampering rejected on read without collecting'
 $legacy=Fresh;$marker=Parse ([IO.File]::ReadAllText((Join-Path $legacy.path 'run-marker.json')));$marker.PSObject.Properties.Remove('creation_mode');Save (Join-Path $legacy.path 'run-marker.json') (Json $marker);Refuses {Get-ToolkitLedger -RunId $legacy.run_id -ToolkitRoot $tk} 'Missing immutable creation metadata refused without migration'
 $bad=Parse $fixture;$bad.components[0].name=[pscustomobject]@{unexpected='object'};Refuses {Set-ToolkitLedger -RunId $r.run_id -Ledger $bad -ToolkitRoot $tk} 'Object-valued component name rejected'
 $bad=Parse $fixture;$bad.run.status='completed';$bad.run.phase='closed';Refuses {Set-ToolkitLedger -RunId $r.run_id -Ledger $bad -ToolkitRoot $tk} 'Completed run with unfinished action rejected'
 foreach($authority in @('official_vendor','official_os','package_registry','secondary')){$bad=Parse $fixture;$bad.sources[0].authority=$authority;$bad.sources[0].url=$null;$bad.sources[0].provenance_verified=$true;Refuses {Set-ToolkitLedger -RunId $r.run_id -Ledger $bad -ToolkitRoot $tk} ('Null URL refused for web source '+$authority)}
 $bad=Parse $fixture;$bad.sources[0].url='javascript:alert(1)';Refuses {Set-ToolkitLedger -RunId $r.run_id -Ledger $bad -ToolkitRoot $tk} 'Unsafe source URL rejected'
 $bad=Parse $fixture;$bad.actions[1].state='completed';$bad.actions[1].finished_utc='2025-01-01T00:00:02Z';Refuses {Set-ToolkitLedger -RunId $r.run_id -Ledger $bad -ToolkitRoot $tk} 'Mutation outcome without exact approval binding rejected'
 $r2=FixtureStep 'Temporary cleanup fixture run creation' {Fresh}
 FixtureStep 'Temporary cleanup fixture temporary artifact write' {Write-ToolkitArtifact -RunId $r2.run_id -RelativePath 'temporary/helper.txt' -Role temporary -Content 'synthetic temporary helper' -ToolkitRoot $tk}
 FixtureStep 'Temporary cleanup fixture evidence artifact write' {Write-ToolkitArtifact -RunId $r2.run_id -RelativePath 'evidence/keep.txt' -Role evidence -Content 'synthetic evidence' -ToolkitRoot $tk}
 FixtureStep 'Temporary cleanup fixture backup artifact write' {Write-ToolkitArtifact -RunId $r2.run_id -RelativePath 'backups/keep.txt' -Role backup -Content 'synthetic recovery' -ToolkitRoot $tk}
 $empty=FixtureStep 'Temporary cleanup fixture report build' {Build-ToolkitReport -RunId $r2.run_id -ToolkitRoot $tk}
 $plan=FixtureStep 'Temporary cleanup fixture native plan capture' {New-ToolkitCleanupPlan -RunId $r2.run_id -Scope Temporary -ToolkitRoot $tk}
 $approval=FixtureStep 'Temporary cleanup fixture approval record' {FictionalApproval $plan $false}
 $deleted=FixtureStep 'Temporary cleanup fixture native apply' {Invoke-ToolkitCleanup -PlanId $plan.plan_id -ExpectedPlanSHA256 $plan.plan_sha256 -ApprovalId $approval -ToolkitRoot $tk}
 Check ($deleted.status -ceq 'completed' -and -not (Test-Path -LiteralPath (Join-Path $r2.path 'temporary/helper.txt'))) 'Exact approved temporary artifact removed'
 Check ((Test-Path -LiteralPath (Join-Path $r2.path 'evidence/keep.txt')) -and (Test-Path -LiteralPath (Join-Path $r2.path 'backups/keep.txt')) -and (Test-Path -LiteralPath $empty.report) -and (Test-Path -LiteralPath (Join-Path $r2.path 'ledger.json'))) 'Temporary cleanup preserves evidence/backups/report/ledger'
 Refuses {Invoke-ToolkitCleanup -PlanId $plan.plan_id -ExpectedPlanSHA256 $plan.plan_sha256 -ApprovalId $approval -ToolkitRoot $tk} 'Consumed native cleanup plan cannot be retried'
 $stale=Fresh;Write-ToolkitArtifact -RunId $stale.run_id -RelativePath 'temporary/change.txt' -Role temporary -Content 'before' -ToolkitRoot $tk;$p=New-ToolkitCleanupPlan -RunId $stale.run_id -ToolkitRoot $tk;$a=FictionalApproval $p $false;Save (Join-Path $stale.path 'temporary/change.txt') 'changed after preview';Refuses {Invoke-ToolkitCleanup -PlanId $p.plan_id -ExpectedPlanSHA256 $p.plan_sha256 -ApprovalId $a -ToolkitRoot $tk} 'Changed content after preview refuses before deletion';Check (Test-Path -LiteralPath (Join-Path $stale.path 'temporary/change.txt')) 'Stale artifact retained'
 $checkpoint=Fresh;Write-ToolkitArtifact -RunId $checkpoint.run_id -RelativePath 'temporary/resume.txt' -Role temporary -Content 'checkpoint fixture' -ToolkitRoot $tk;$p=New-ToolkitCleanupPlan -RunId $checkpoint.run_id -ToolkitRoot $tk;$a=FictionalApproval $p $false;$l=Get-ToolkitLedger -RunId $checkpoint.run_id -ToolkitRoot $tk;$l.run|Add-Member -NotePropertyName checkpoint_id -NotePropertyValue 'fictional-post-restart-checkpoint';Set-ToolkitLedger -RunId $checkpoint.run_id -Ledger $l -ToolkitRoot $tk;Refuses {Invoke-ToolkitCleanup -PlanId $p.plan_id -ExpectedPlanSHA256 $p.plan_sha256 -ApprovalId $a -ToolkitRoot $tk} 'Changed checkpoint/ledger invalidates prior cleanup preview'
 $unknown=Fresh;PrivateFixtureNew (Join-Path $unknown.path 'unregistered.txt') 'fictional unknown artifact';Refuses {New-ToolkitCleanupPlan -RunId $unknown.run_id -ToolkitRoot $tk} 'Unknown run file refused'
 $missing=Fresh;[IO.File]::Move((Join-Path $missing.path 'run-marker.json'),(Join-Path $missing.path 'missing-marker.fixture'));Refuses {New-ToolkitCleanupPlan -RunId $missing.run_id -ToolkitRoot $tk} 'Missing positive ownership marker refused'
 $active=Fresh;$lockDir=Join-Path $tk 'work/_locks';PrivateFixtureDirectory $lockDir;$lock=PrivateFixtureLock (Join-Path $lockDir ($active.run_id+'.lock'));try{Refuses {New-ToolkitCleanupPlan -RunId $active.run_id -ToolkitRoot $tk} 'Active operation lock refused'}finally{$lock.Dispose()}
 $rollback=Fresh;Write-ToolkitArtifact -RunId $rollback.run_id -RelativePath 'backups/recovery.txt' -Role backup -Content 'needed recovery' -RollbackNeeded -ToolkitRoot $tk;Refuses {New-ToolkitCleanupPlan -RunId $rollback.run_id -ToolkitRoot $tk} 'Future-needed rollback artifact refused'
 $restart=Fresh;$l=Get-ToolkitLedger -RunId $restart.run_id -ToolkitRoot $tk;$l.run.pending_restart=$true;Set-ToolkitLedger -RunId $restart.run_id -Ledger $l -ToolkitRoot $tk;Refuses {New-ToolkitCleanupPlan -RunId $restart.run_id -ToolkitRoot $tk} 'Pending restart workflow state refused'
 $full=Fresh;Write-ToolkitArtifact -RunId $full.run_id -RelativePath 'backups/synthetic.txt' -Role backup -Content 'fixture backup' -ToolkitRoot $tk;$l=Get-ToolkitLedger -RunId $full.run_id -ToolkitRoot $tk;$l.run.status='completed';$l.run.phase='closed';Set-ToolkitLedger -RunId $full.run_id -Ledger $l -ToolkitRoot $tk;$p=New-ToolkitCleanupPlan -RunId $full.run_id -Scope CompletedRun -ToolkitRoot $tk;$a=FictionalApproval $p $false;Refuses {Invoke-ToolkitCleanup -PlanId $p.plan_id -ExpectedPlanSHA256 $p.plan_sha256 -ApprovalId $a -ToolkitRoot $tk} 'Full purge requires explicit records/backups acknowledgment';$p=New-ToolkitCleanupPlan -RunId $full.run_id -Scope CompletedRun -ToolkitRoot $tk;$a=FictionalApproval $p $true;$res=Invoke-ToolkitCleanup -PlanId $p.plan_id -ExpectedPlanSHA256 $p.plan_sha256 -ApprovalId $a -ToolkitRoot $tk;Check ($res.status -ceq 'completed' -and -not (Test-Path -LiteralPath $full.path) -and (Test-Path -LiteralPath $tk)) 'Approved full purge removes only completed run including backup'
 $outsidePrivate=Join-Path $suite 'private-outside-sentinel';PrivateFixtureDirectory $outsidePrivate;$outside=Join-Path $outsidePrivate 'outside-sentinel.txt';PrivateFixtureNew $outside 'fictional outside sentinel';$outsideHash=Hash ([IO.File]::ReadAllBytes($outside));$hard=Fresh;try{$null=New-Item -ItemType HardLink -Path (Join-Path $hard.path 'temporary/alias.txt') -Target $outside -ErrorAction Stop;[IO.File]::SetAttributes($outside,[IO.FileAttributes]::ReadOnly);$attrs=[IO.File]::GetAttributes($outside);$owned=Parse ([IO.File]::ReadAllText((Join-Path $hard.path 'owned-files.json')));$owned.files+=@([pscustomobject]@{relative_path='temporary/alias.txt';role='temporary';sha256=$outsideHash;bytes=[IO.File]::ReadAllBytes($outside).Length;rollback_needed=$false});Save (Join-Path $hard.path 'owned-files.json') (Json $owned);Refuses {New-ToolkitCleanupPlan -RunId $hard.run_id -ToolkitRoot $tk} 'Read-only hardlinked alias refused';Check ((Hash ([IO.File]::ReadAllBytes($outside))) -ceq $outsideHash -and [IO.File]::GetAttributes($outside) -eq $attrs) 'Outside hardlink bytes/readonly attributes unchanged'}catch{if($_.Exception.Message -like 'CHECK FAILED:*'){throw};$results.Add([pscustomobject]@{name='Hardlink fixture setup';status='skipped';reason='Host did not provide unprivileged fixture creation.'})}
 $junction=Fresh;$outsideDir=Join-Path $suite 'outside-junction-target';$null=[IO.Directory]::CreateDirectory($outsideDir);Save (Join-Path $outsideDir 'sentinel.txt') 'fictional junction target';$savedDir=Join-Path $suite ('empty-saved-'+[Guid]::NewGuid().ToString('N'));[IO.Directory]::Move((Join-Path $junction.path 'temporary'),$savedDir);try{$null=New-Item -ItemType Junction -Path (Join-Path $junction.path 'temporary') -Target $outsideDir -ErrorAction Stop;Refuses {New-ToolkitCleanupPlan -RunId $junction.run_id -ToolkitRoot $tk} 'Junction is refused before following target';Check ([IO.File]::ReadAllText((Join-Path $outsideDir 'sentinel.txt')) -ceq 'fictional junction target') 'Junction target unchanged'}catch{if($_.Exception.Message -like 'CHECK FAILED:*'){throw};$results.Add([pscustomobject]@{name='Junction fixture setup';status='skipped';reason='Host did not provide unprivileged fixture creation.'})}finally{$junctionPath=Join-Path $junction.path 'temporary';if(Test-Path -LiteralPath $junctionPath){$junctionItem=Get-Item -LiteralPath $junctionPath -Force;if(-not ($junctionItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Fictional junction teardown refused an ordinary directory.'};[IO.Directory]::Delete($junctionPath)};[IO.Directory]::Move($savedDir,$junctionPath)}
 PrivateFixtureNew (Join-Path $tk 'work/export-canary.txt') 'NEVER EXPORT THIS FICTIONAL WORK CANARY';$export=Export-Toolkit -ToolkitRoot $tk;Add-Type -AssemblyName System.IO.Compression.FileSystem;$zip=[IO.Compression.ZipFile]::OpenRead($export.archive);try{$entries=@($zip.Entries.FullName);$attributesEntries=@($zip.Entries|Where-Object {$_.FullName -ceq '.gitattributes'});$stream=$zip.GetEntry('.gitattributes').Open();$memory=New-Object IO.MemoryStream;try{$stream.CopyTo($memory);Check (@($entries|Where-Object {$_ -match '(^|/)(work|\.git)/'}).Count -eq 0 -and $entries.Count -eq 9 -and $attributesEntries.Count -eq 1 -and $memory.Length -eq 8 -and (Hash $memory.ToArray()) -ceq (Hash $attributesBytes)) 'Exact allowlisted export includes exact attributes bytes and excludes work/Git sentinel'}finally{$stream.Dispose();$memory.Dispose()}}finally{$zip.Dispose()}
 Refuses {New-ToolkitCleanupPlan -RunId '../sibling' -ToolkitRoot $tk} 'Traversal run identifier refused'
 $grammar=Join-Path $suite 'grammar-toolkit';$null=[IO.Directory]::CreateDirectory((Join-Path $grammar 'work'));Save (Join-Path $grammar 'toolkit.json') (Json @{schema_version='1.0';toolkit_id=[Guid]::NewGuid().ToString();name='Fictional grammar fixture';version='1.0.0'});Refuses {New-ToolkitCleanupPlan -RunId ('run-'+('a'*32)+"`n") -ToolkitRoot $grammar} 'Final-LF run identifier rejected';Check (-not (Test-Path -LiteralPath (Join-Path $grammar 'work/_locks'))) 'Invalid identifier rejected before lock-area creation'
 # Process environment spoofing cannot change the native host classification.
 $savedOS=$env:OS
 try {$env:OS='Fictional_NonWindows';$actual=[Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT;$module=Get-Module Toolkit.Core;$classification=& $module {Test-ToolkitWindowsHost};$spoof=Fresh;Check ($classification -eq $actual -and (Get-ToolkitLedger -RunId $spoof.run_id -ToolkitRoot $tk).run.mode -ceq 'fixture') 'Mutable OS environment does not change actual host classification or fixture semantics'}finally{$env:OS=$savedOS}
 # V2 raw input, backend ownership and shared-contract invariants.
 $v2=Fresh;$original=[IO.File]::ReadAllText((Join-Path $v2.path 'ledger.json'));$l=Parse $original
 Check ((Parse ([IO.File]::ReadAllText((Join-Path $v2.path 'run-marker.json')))).backend -ceq 'windows-powershell-v2') 'Immutable Windows V2 backend recorded at creation'
 $rawCases=@(
  $original.Replace('"schema_version":"1.0"','"schema_version":"1.0","schema_version":"1.0"'),
  $original.Replace('"schema_version":"1.0"','"Schema_Version":"1.0","schema_version":"1.0"'),
  $original.Replace('"pending_restart":false','"pending_restart":1e9999'),
  (([string][char]0xFEFF)+$original)
 )
 $n=0;foreach($raw in $rawCases){$n++;Save (Join-Path $v2.path 'ledger.json') $raw;Refuses {Get-ToolkitLedger -RunId $v2.run_id -ToolkitRoot $tk} ('Strict raw JSON refusal '+$n)};Save (Join-Path $v2.path 'ledger.json') $original
 foreach($stamp in @('2025-02-30T00:00:00Z','2025-01-01T00:00:00+00:00',"2025-01-01T00:00:00Z`n",'2025-01-01T00:00:00.12345678Z')){$bad=Parse $original;$bad.run.created_utc=$stamp;Refuses {Set-ToolkitLedger -RunId $v2.run_id -Ledger $bad -ToolkitRoot $tk} ('Strict UTC refusal '+$stamp)}
 $bad=Parse $fixture;$bad.sources[0].url='https://vendor.example/releases?token=fiction';Refuses {Set-ToolkitLedger -RunId $r.run_id -Ledger $bad -ToolkitRoot $tk} 'Public source queries refused by canonical policy'
 $bad=Parse $fixture;$bad.sources[0].retrieved_utc=$null;Set-ToolkitLedger -RunId $r.run_id -Ledger $bad -ToolkitRoot $tk;Check ((Get-ToolkitLedger -RunId $r.run_id -ToolkitRoot $tk).sources[0].retrieved_utc -eq $null) 'Nullable source retrieval time preserved as unknown';Set-ToolkitLedger -RunId $r.run_id -Ledger (Parse $fixture) -ToolkitRoot $tk
 $bad=Parse $fixture;$bad.components[0].update_state=@('held');Refuses {Set-ToolkitLedger -RunId $r.run_id -Ledger $bad -ToolkitRoot $tk} 'One-element array cannot masquerade as enum string'
 $bad=Parse $fixture;$bad.components[0].id='bad id';Refuses {Set-ToolkitLedger -RunId $r.run_id -Ledger $bad -ToolkitRoot $tk} 'Record IDs follow shared bounded grammar'
 $bad=Parse $fixture;$bad.components[0].evidence_ids=@('Evidence-fiction');Refuses {Set-ToolkitLedger -RunId $r.run_id -Ledger $bad -ToolkitRoot $tk} 'Reference matching is ordinal case sensitive'
 $bad=Parse $fixture;$bad.diagnosis.hypotheses+=@($bad.diagnosis.hypotheses[0]);Refuses {Set-ToolkitLedger -RunId $r.run_id -Ledger $bad -ToolkitRoot $tk} 'Duplicate nested hypothesis IDs refused'
 $bad=Parse $fixture;$bad.actions[0]|Add-Member -NotePropertyName group_id -NotePropertyValue ' ';Refuses {Set-ToolkitLedger -RunId $r.run_id -Ledger $bad -ToolkitRoot $tk} 'Whitespace-only execution group refused'
 $foreign=Fresh;$markerPath=Join-Path $foreign.path 'run-marker.json';$marker=Parse ([IO.File]::ReadAllText($markerPath));$marker.backend='posix-python-v2';Save $markerPath (Json $marker)
 $beforeAudit=Hash ([IO.File]::ReadAllBytes((Join-Path $foreign.path 'actions.jsonl')));$beforeOwned=Hash ([IO.File]::ReadAllBytes((Join-Path $foreign.path 'owned-files.json')));$lockTime=[IO.Directory]::GetLastWriteTimeUtc((Join-Path $tk 'work/_locks'))
 Refuses {Set-ToolkitLedger -RunId $foreign.run_id -Ledger (Parse $original) -ToolkitRoot $tk} 'Foreign backend refuses before mutation'
 Check ((Hash ([IO.File]::ReadAllBytes((Join-Path $foreign.path 'actions.jsonl')))) -ceq $beforeAudit -and (Hash ([IO.File]::ReadAllBytes((Join-Path $foreign.path 'owned-files.json')))) -ceq $beforeOwned -and [IO.Directory]::GetLastWriteTimeUtc((Join-Path $tk 'work/_locks')) -eq $lockTime) 'Foreign backend refusal creates no operation lock or run write'
 $marker.PSObject.Properties.Remove('backend');Save $markerPath (Json $marker);Refuses {Build-ToolkitReport -RunId $foreign.run_id -ToolkitRoot $tk} 'Old missing-backend development run held without migration'
 $metadata=Fresh;Write-ToolkitArtifact -RunId $metadata.run_id -RelativePath 'backups/recovery.txt' -Role backup -Content 'fictional recovery' -ToolkitRoot $tk
 Refuses {Write-ToolkitArtifact -RunId $metadata.run_id -RelativePath 'backups/recovery.txt' -Role backup -Content 'fictional recovery' -RollbackNeeded -ToolkitRoot $tk} 'Identical bytes cannot silently change rollback protection'
 $recover=Fresh;Write-ToolkitArtifact -RunId $recover.run_id -RelativePath 'evidence/recovery.json' -Role evidence -Content '{"fictional":"verification"}' -ToolkitRoot $tk
 $l=Get-ToolkitLedger -RunId $recover.run_id -ToolkitRoot $tk;$l.evidence=@([pscustomobject]@{id='proof';relative_path='evidence/recovery.json';sha256=(Hash ($utf8.GetBytes('{"fictional":"verification"}')));kind='fictional';observed_utc='2025-01-01T00:00:00Z';scope='fictional';limits='No host facts'})
 $failed=[pscustomobject]@{id='failed-attempt';kind='diagnose';state='failed';component_ids=@();evidence_ids=@('proof');approval_id=$null;started_utc='2025-01-01T00:00:00Z';finished_utc='2025-01-01T00:00:01Z';outcome='Fictional interruption';automatic_retry=$false};$l.actions=@($failed);Set-ToolkitLedger -RunId $recover.run_id -Ledger $l -ToolkitRoot $tk
 $bad=Parse (Json $l);$bad.actions[0].outcome='changed history';Refuses {Set-ToolkitLedger -RunId $recover.run_id -Ledger $bad -ToolkitRoot $tk} 'Failed action record is immutable'
 $l.run.status='completed';$l.run.phase='closed';Refuses {Set-ToolkitLedger -RunId $recover.run_id -Ledger $l -ToolkitRoot $tk} 'Unresolved failed history prevents closure'
 $l.actions+=@([pscustomobject]@{id='recovery-check';kind='verify';state='completed';component_ids=@();evidence_ids=@('proof');approval_id=$null;started_utc='2025-01-01T00:00:02Z';finished_utc='2025-01-01T00:00:03Z';outcome='Fictional evidence-backed recovery';automatic_retry=$false;resolves_action_ids=@('failed-attempt')});Set-ToolkitLedger -RunId $recover.run_id -Ledger $l -ToolkitRoot $tk
 $rp=New-ToolkitCleanupPlan -RunId $recover.run_id -Scope CompletedRun -ToolkitRoot $tk;Check ($rp.scope -ceq 'CompletedRun') 'Evidence-backed recovery permits completed-run preview without rewriting failed history'
 $md=Fresh;$l=Get-ToolkitLedger -RunId $md.run_id -ToolkitRoot $tk;$l.diagnosis.uncertainty='![fictional image](https://remote.example/image.png)';Set-ToolkitLedger -RunId $md.run_id -Ledger $l -ToolkitRoot $tk;$mr=Build-ToolkitReport -RunId $md.run_id -ToolkitRoot $tk
 Check (([IO.File]::ReadAllText($mr.summary_markdown)).Contains('\!\[fictional image\]\(https://remote\.example/image\.png\)')) 'Markdown summary text cannot become a remote image'
 # Static binary source asset support is exact, bounded and asset-bound.
 $assets=Join-Path $tk 'assets';$null=[IO.Directory]::CreateDirectory($assets);$png=[Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aL1sAAAAASUVORK5CYII=');[IO.File]::WriteAllBytes((Join-Path $assets 'fictional.png'),$png)
 $allow=Parse ([IO.File]::ReadAllText((Join-Path $tk 'templates/export-allowlist.json')));$allow.files+=@('assets/fictional.png');Save (Join-Path $tk 'templates/export-allowlist.json') (Json $allow)
 $tm=Parse ([IO.File]::ReadAllText((Join-Path $tk 'toolkit.json')));$tm|Add-Member -NotePropertyName branding -NotePropertyValue ([pscustomobject]@{report_logo='assets/fictional.png'});Save (Join-Path $tk 'toolkit.json') (Json $tm)
 $branded=Build-ToolkitReport -RunId $md.run_id -ToolkitRoot $tk;Check (([IO.File]::ReadAllText($branded.report)).Contains('data:image/png;base64,'+[Convert]::ToBase64String($png)) -and $branded.report -cne $mr.report) 'Allowlisted PNG embeds locally and changes effective-template identity'
 $ex=Export-Toolkit -ToolkitRoot $tk;$z=[IO.Compression.ZipFile]::OpenRead($ex.archive);try{Check (@($z.Entries.FullName|Where-Object {$_ -ceq 'assets/fictional.png'}).Count -eq 1) 'Valid exact PNG source asset included once'}finally{$z.Dispose()}
 $licensePath=Join-Path $tk 'LICENSE';$licenseBytes=$utf8.GetBytes("Fictional source license fixture only.`nNo legal grant or publication is made by this test.`n");[IO.File]::WriteAllBytes($licensePath,$licenseBytes)
 $allow.files+=@('LICENSE');$licenseAllow=@($allow.files);Save (Join-Path $tk 'templates/export-allowlist.json') (Json $allow)
 $licenseExport=Export-Toolkit -ToolkitRoot $tk;$z=[IO.Compression.ZipFile]::OpenRead($licenseExport.archive)
 try {
  $licenseEntries=@($z.Entries|Where-Object {$_.FullName -ceq 'LICENSE'});Check ($licenseEntries.Count -eq 1 -and $z.Entries.Count -eq $licenseAllow.Count) 'Exact root LICENSE is included once with allowlist parity'
  $stream=$licenseEntries[0].Open();$memory=New-Object IO.MemoryStream;try{$stream.CopyTo($memory);Check ((Hash $memory.ToArray()) -ceq (Hash $licenseBytes) -and $memory.Length -eq $licenseBytes.Length) 'LICENSE UTF-8 bytes are copied exactly without rewriting'}finally{$stream.Dispose();$memory.Dispose()}
  Check (@($z.Entries.FullName|Where-Object {$_ -match '(^|/)(work|\.git)/'}).Count -eq 0) 'LICENSE exception does not include work or Git records'
 } finally {$z.Dispose()}
 $licenseManifest=Parse ([IO.File]::ReadAllText($licenseExport.manifest));$licenseRows=@($licenseManifest.files|Where-Object {$_.relative_path -ceq 'LICENSE'});Check ($licenseRows.Count -eq 1 -and $licenseRows[0].sha256 -ceq (Hash $licenseBytes)) 'LICENSE manifest binds the exact original source hash'
 $null=[IO.Directory]::CreateDirectory((Join-Path $tk 'docs'));Save (Join-Path $tk 'NOTICE') 'Fictional unapproved extensionless source';Save (Join-Path $tk 'docs/LICENSE') 'Fictional nested license';[IO.File]::WriteAllBytes((Join-Path $tk 'docs/.gitattributes'),$attributesBytes)
 foreach($badLicenseName in @('NOTICE','docs/LICENSE','license','.GITATTRIBUTES','docs/.gitattributes')) {
  Save (Join-Path $tk 'templates/export-allowlist.json') (Json @{files=@($licenseAllow|Where-Object {$_ -cne 'LICENSE' -and $_ -cne '.gitattributes'})+@($badLicenseName)})
  Refuses {Export-Toolkit -ToolkitRoot $tk} ('Extensionless exception refuses '+$badLicenseName)
 }
 Save (Join-Path $tk 'templates/export-allowlist.json') (Json @{files=$licenseAllow})
 [IO.File]::WriteAllBytes($licensePath,[byte[]]@(255));Refuses {Export-Toolkit -ToolkitRoot $tk} 'LICENSE invalid UTF-8 bytes refused';[IO.File]::WriteAllBytes($licensePath,$licenseBytes)
 [IO.File]::WriteAllBytes($licensePath,[byte[]]@(65,0,66));Refuses {Export-Toolkit -ToolkitRoot $tk} 'LICENSE NUL-containing payload refused';[IO.File]::WriteAllBytes($licensePath,$licenseBytes)
 $attributesPath=Join-Path $tk '.gitattributes';[IO.File]::WriteAllBytes($attributesPath,[byte[]]@(65,0,66));try{Refuses {Export-Toolkit -ToolkitRoot $tk} '.gitattributes NUL-containing payload refused'}finally{[IO.File]::WriteAllBytes($attributesPath,$attributesBytes)}
 [IO.File]::WriteAllBytes($licensePath,$utf8.GetBytes(('x'*4000001)));Refuses {Export-Toolkit -ToolkitRoot $tk} 'LICENSE existing four-million-byte public read bound preserved';[IO.File]::WriteAllBytes($licensePath,$licenseBytes)
 Save (Join-Path $assets 'fictional.png') 'not a PNG';Refuses {Export-Toolkit -ToolkitRoot $tk} 'Non-PNG bytes under PNG suffix refused';[IO.File]::WriteAllBytes((Join-Path $assets 'fictional.png'),$png)
 $readme=[IO.File]::ReadAllBytes((Join-Path $tk 'README.md'));[IO.File]::WriteAllBytes((Join-Path $tk 'README.md'),[byte[]]@(255));Refuses {Export-Toolkit -ToolkitRoot $tk} 'Invalid UTF-8 public text source refused';[IO.File]::WriteAllBytes((Join-Path $tk 'README.md'),$readme)
 $allow.files+=@('readme.md');Save (Join-Path $tk 'templates/export-allowlist.json') (Json $allow);Refuses {Export-Toolkit -ToolkitRoot $tk} 'Case-colliding export entry refused before duplicate ZIP members'
 # Recovery-release operation is metadata-only, exact and separately authorized.
 $release=Fresh;Write-ToolkitArtifact -RunId $release.run_id -RelativePath 'backups/needed.txt' -Role backup -Content 'fictional retained bytes' -RollbackNeeded -ToolkitRoot $tk
 Refuses {Write-ToolkitArtifact -RunId $release.run_id -RelativePath 'temporary/invalid.txt' -Role temporary -Content 'fictional' -RollbackNeeded -ToolkitRoot $tk} 'Rollback protection is reserved for backup artifacts'
 $backupHash=Hash ($utf8.GetBytes('fictional retained bytes'))
 Refuses {Release-ToolkitRecovery -RunId $release.run_id -RelativePath 'backups/needed.txt' -ExpectedSHA256 $backupHash -EvidenceIds @('proof') -OwnerQuote 'Fictional consent' -Reason 'Fictional verified recovery' -ToolkitRoot $tk} 'Early recovery release refused'
 Write-ToolkitArtifact -RunId $release.run_id -RelativePath 'evidence/verified.json' -Role evidence -Content '{"fictional":true}' -ToolkitRoot $tk
 $l=Get-ToolkitLedger -RunId $release.run_id -ToolkitRoot $tk;$l.evidence=@([pscustomobject]@{id='proof';relative_path='evidence/verified.json';sha256=(Hash ($utf8.GetBytes('{"fictional":true}')));kind='fictional';observed_utc='2025-01-01T00:00:00Z';scope='fictional';limits='Synthetic only'});$l.actions=@([pscustomobject]@{id='verified-recovery';kind='verify';state='completed';component_ids=@();evidence_ids=@('proof');approval_id=$null;started_utc='2025-01-01T00:00:00Z';finished_utc='2025-01-01T00:00:01Z';outcome='Fictional verification';automatic_retry=$false});$l.run.status='completed';$l.run.phase='closed';Set-ToolkitLedger -RunId $release.run_id -Ledger $l -ToolkitRoot $tk
 Refuses {Release-ToolkitRecovery -RunId $release.run_id -RelativePath 'backups/needed.txt' -ExpectedSHA256 $backupHash -EvidenceIds @() -OwnerQuote 'Fictional consent' -Reason 'Fictional verified recovery' -ToolkitRoot $tk} 'Recovery release without verification evidence refused'
 Refuses {Release-ToolkitRecovery -RunId $release.run_id -RelativePath 'backups/needed.txt' -ExpectedSHA256 $backupHash -EvidenceIds @('proof') -OwnerQuote ' ' -Reason 'Fictional verified recovery' -ToolkitRoot $tk} 'Recovery release without actual nonblank consent refused'
 Refuses {Release-ToolkitRecovery -RunId $release.run_id -RelativePath 'backups/needed.txt' -ExpectedSHA256 ('0'*64) -EvidenceIds @('proof') -OwnerQuote 'Fictional consent' -Reason 'Fictional verified recovery' -ToolkitRoot $tk} 'Recovery release wrong hash refused'
 $beforeReleaseOwned=Hash ([IO.File]::ReadAllBytes((Join-Path $release.path 'owned-files.json')));$beforeReleaseAudit=Hash ([IO.File]::ReadAllBytes((Join-Path $release.path 'actions.jsonl')))
 $heldAudit=New-Object IO.FileStream((Join-Path $release.path 'actions.jsonl'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
 try{Refuses {Release-ToolkitRecovery -RunId $release.run_id -RelativePath 'backups/needed.txt' -ExpectedSHA256 $backupHash -EvidenceIds @('proof') -OwnerQuote 'Fictional consent only' -Reason 'Fictional verified recovery retained elsewhere' -ToolkitRoot $tk} 'Locked intent audit refuses before changing recovery protection'}finally{$heldAudit.Dispose()}
 Check ((Hash ([IO.File]::ReadAllBytes((Join-Path $release.path 'owned-files.json')))) -ceq $beforeReleaseOwned -and (Hash ([IO.File]::ReadAllBytes((Join-Path $release.path 'actions.jsonl')))) -ceq $beforeReleaseAudit -and (Hash ([IO.File]::ReadAllBytes((Join-Path $release.path 'backups/needed.txt')))) -ceq $backupHash) 'Failed intent preserves protection, audit and exact backup bytes'
 Refuses {New-ToolkitCleanupPlan -RunId $release.run_id -Scope CompletedRun -ToolkitRoot $tk} 'Failed release intent leaves completed-run cleanup held'
 $rel=Release-ToolkitRecovery -RunId $release.run_id -RelativePath 'backups/needed.txt' -ExpectedSHA256 $backupHash -EvidenceIds @('proof') -OwnerQuote 'Fictional consent only' -Reason 'Fictional verified recovery retained elsewhere' -ToolkitRoot $tk
 Check (-not $rel.rollback_needed -and (Hash ([IO.File]::ReadAllBytes((Join-Path $release.path 'backups/needed.txt')))) -ceq $backupHash) 'Exact recovery release changes protection metadata only and preserves bytes'
 $eligible=New-ToolkitCleanupPlan -RunId $release.run_id -Scope CompletedRun -ToolkitRoot $tk;Check ($eligible.scope -ceq 'CompletedRun') 'Released completed run needs a fresh explicit cleanup plan and approval'
 foreach($failureStage in @('completion-audit','final-control')){
  $interrupted=VerifiedRecoveryFixture
  Write-ToolkitArtifact -RunId $interrupted.run_id -RelativePath 'backups/untouched.txt' -Role backup -Content 'separate fictional backup' -ToolkitRoot $tk
  $interruptedOwnedPath=Join-Path $interrupted.path 'owned-files.json';$interruptedAuditPath=Join-Path $interrupted.path 'actions.jsonl'
  WithFictionalReleaseFailure $failureStage {Refuses {Release-ToolkitRecovery -RunId $interrupted.run_id -RelativePath 'backups/needed.txt' -ExpectedSHA256 $backupHash -EvidenceIds @('proof') -OwnerQuote 'Exact fictional original consent' -Reason 'Exact fictional original reason' -ToolkitRoot $tk} ('Injected release interruption: '+$failureStage)}
  $pendingOwned=Parse ([IO.File]::ReadAllText($interruptedOwnedPath));$pending=@($pendingOwned.files|Where-Object relative_path -ceq 'backups/needed.txt')[0];$untouched=@($pendingOwned.files|Where-Object relative_path -ceq 'backups/untouched.txt')[0]
  $releaseId=$pending.recovery_release.decision.release_id
  Check ($pending.rollback_needed -eq $false -and $pending.recovery_release.status -ceq 'pending' -and $null -eq $pending.recovery_release.completed_utc -and -not $untouched.PSObject.Properties['recovery_release'] -and (Hash ([IO.File]::ReadAllBytes((Join-Path $interrupted.path 'backups/needed.txt')))) -ceq $backupHash) ('Interrupted flag change retains a per-artifact pending hold and backup bytes: '+$failureStage)
  $auditRows=@([IO.File]::ReadAllLines($interruptedAuditPath)|Where-Object {$_}|ForEach-Object {Parse $_})
  $intents=@($auditRows|Where-Object {$_.operation -ceq 'ReleaseRecovery' -and $_.status -ceq 'intent'})
  Check ($intents.Count -eq 1 -and $intents[0].details.release_id -ceq $releaseId -and $intents[0].details.authorization_quote -ceq 'Exact fictional original consent' -and $intents[0].details.reason -ceq 'Exact fictional original reason' -and $intents[0].details.artifact_sha256 -ceq $backupHash -and (Json $intents[0].details.evidence_ids) -ceq (Json @('proof')) -and (Json $intents[0].details) -ceq (Json $pending.recovery_release.decision)) ('Interrupted release retains exact durable original decision: '+$failureStage)
  Refuses {New-ToolkitCleanupPlan -RunId $interrupted.run_id -Scope Temporary -ToolkitRoot $tk} ('Pending recovery-release receipt blocks temporary cleanup: '+$failureStage)
  Refuses {New-ToolkitCleanupPlan -RunId $interrupted.run_id -Scope CompletedRun -ToolkitRoot $tk} ('Pending recovery-release receipt blocks completed-run cleanup: '+$failureStage)
  $pendingHash=Hash ([IO.File]::ReadAllBytes($interruptedOwnedPath));$pendingAuditHash=Hash ([IO.File]::ReadAllBytes($interruptedAuditPath))
  Refuses {Release-ToolkitRecovery -RunId $interrupted.run_id -RelativePath 'backups/needed.txt' -ExpectedSHA256 $backupHash -EvidenceIds @('proof') -OwnerQuote 'A different fictional decision' -Reason 'Exact fictional original reason' -ToolkitRoot $tk} ('Changed quote cannot resume pending release: '+$failureStage)
  Refuses {Release-ToolkitRecovery -RunId $interrupted.run_id -RelativePath 'backups/needed.txt' -ExpectedSHA256 $backupHash -EvidenceIds @('proof') -OwnerQuote 'Exact fictional original consent' -Reason 'A different fictional reason' -ToolkitRoot $tk} ('Changed reason cannot resume pending release: '+$failureStage)
  Check ((Hash ([IO.File]::ReadAllBytes($interruptedOwnedPath))) -ceq $pendingHash -and (Hash ([IO.File]::ReadAllBytes($interruptedAuditPath))) -ceq $pendingAuditHash) ('Mismatched resume leaves original pending decision unchanged: '+$failureStage)
  $savedAuditBytes=[IO.File]::ReadAllBytes($interruptedAuditPath)
  $withoutIntent=@([IO.File]::ReadAllLines($interruptedAuditPath)|Where-Object {$_ -and -not ((Parse $_).operation -ceq 'ReleaseRecovery' -and (Parse $_).status -ceq 'intent')})
  Save $interruptedAuditPath (([string]::Join("`n",$withoutIntent))+"`n")
  try{Refuses {Release-ToolkitRecovery -RunId $interrupted.run_id -RelativePath 'backups/needed.txt' -ExpectedSHA256 $backupHash -EvidenceIds @('proof') -OwnerQuote 'Exact fictional original consent' -Reason 'Exact fictional original reason' -ToolkitRoot $tk} ('Pending receipt without its original durable audit intent cannot resume: '+$failureStage)}finally{[IO.File]::WriteAllBytes($interruptedAuditPath,$savedAuditBytes)}
  $changedLedger=Get-ToolkitLedger -RunId $interrupted.run_id -ToolkitRoot $tk;$originalPurpose=$changedLedger.run.purpose;$changedLedger.run.purpose='A changed fictional checkpoint'
  Set-ToolkitLedger -RunId $interrupted.run_id -Ledger $changedLedger -ToolkitRoot $tk
  try{Refuses {Release-ToolkitRecovery -RunId $interrupted.run_id -RelativePath 'backups/needed.txt' -ExpectedSHA256 $backupHash -EvidenceIds @('proof') -OwnerQuote 'Exact fictional original consent' -Reason 'Exact fictional original reason' -ToolkitRoot $tk} ('Changed ledger snapshot cannot resume pending release: '+$failureStage)}finally{$changedLedger.run.purpose=$originalPurpose;Set-ToolkitLedger -RunId $interrupted.run_id -Ledger $changedLedger -ToolkitRoot $tk}
  $proofPath=Join-Path $interrupted.path 'evidence/verified.json';$savedProof=[IO.File]::ReadAllBytes($proofPath);Save $proofPath '{"fictional":"changed verification bytes"}'
  try{Refuses {Release-ToolkitRecovery -RunId $interrupted.run_id -RelativePath 'backups/needed.txt' -ExpectedSHA256 $backupHash -EvidenceIds @('proof') -OwnerQuote 'Exact fictional original consent' -Reason 'Exact fictional original reason' -ToolkitRoot $tk} ('Changed verification bytes cannot resume pending release: '+$failureStage)}finally{[IO.File]::WriteAllBytes($proofPath,$savedProof)}
  $resumed=Release-ToolkitRecovery -RunId $interrupted.run_id -RelativePath 'backups/needed.txt' -ExpectedSHA256 $backupHash -EvidenceIds @('proof') -OwnerQuote 'Exact fictional original consent' -Reason 'Exact fictional original reason' -ToolkitRoot $tk
  $finishedOwned=Parse ([IO.File]::ReadAllText($interruptedOwnedPath));$finished=@($finishedOwned.files|Where-Object relative_path -ceq 'backups/needed.txt')[0]
  $auditRows=@([IO.File]::ReadAllLines($interruptedAuditPath)|Where-Object {$_}|ForEach-Object {Parse $_});$completions=@($auditRows|Where-Object {$_.operation -ceq 'ReleaseRecovery' -and $_.status -ceq 'completed'})
  Check ($resumed.resumed_pending_release -and $resumed.release_id -ceq $releaseId -and $finished.recovery_release.status -ceq 'completed' -and $completions.Count -eq 1 -and (Json $completions[0].details) -ceq (Json $intents[0].details) -and (Hash ([IO.File]::ReadAllBytes((Join-Path $interrupted.path 'backups/needed.txt')))) -ceq $backupHash) ('Explicit identical resume reuses decision, completes once and preserves bytes: '+$failureStage)
  $freshPlan=New-ToolkitCleanupPlan -RunId $interrupted.run_id -Scope CompletedRun -ToolkitRoot $tk
  Check ($freshPlan.scope -ceq 'CompletedRun' -and (Test-Path -LiteralPath (Join-Path $interrupted.path 'backups/needed.txt'))) ('Only a new preview becomes eligible after exact release reconciliation: '+$failureStage)
  $savedAuditBytes=[IO.File]::ReadAllBytes($interruptedAuditPath)
  $withoutCompletion=@([IO.File]::ReadAllLines($interruptedAuditPath)|Where-Object {$_ -and -not ((Parse $_).operation -ceq 'ReleaseRecovery' -and (Parse $_).status -ceq 'completed')})
  Save $interruptedAuditPath (([string]::Join("`n",$withoutCompletion))+"`n")
  try{Refuses {New-ToolkitCleanupPlan -RunId $interrupted.run_id -Scope CompletedRun -ToolkitRoot $tk} ('Completed receipt without durable completion audit cannot authorize a cleanup preview: '+$failureStage)}finally{[IO.File]::WriteAllBytes($interruptedAuditPath,$savedAuditBytes)}
  Refuses {Release-ToolkitRecovery -RunId $interrupted.run_id -RelativePath 'backups/needed.txt' -ExpectedSHA256 $backupHash -EvidenceIds @('proof') -OwnerQuote 'Exact fictional original consent' -Reason 'Exact fictional original reason' -ToolkitRoot $tk} ('Completed release cannot be repeated: '+$failureStage)
 }
$status='passed'
}catch{$failure=$_.Exception.GetType().Name+': '+$_.Exception.Message;$results.Add([pscustomobject]@{name='Suite stopped';status='failed';reason=$failure;failure=(Get-FixtureFailureClassification $_)})}
$sourceUnchanged=$true;foreach($entry in $sourceHashes){if((Get-FileHash -LiteralPath (Join-Path $sourceRoot $entry.relative_path) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256){$sourceUnchanged=$false}};if(-not $sourceUnchanged){$status='failed';$results.Add([pscustomobject]@{name='Source hashes changed during fixture execution';status='failed'})}
$result=[ordered]@{status=$status;fixture_only=$true;live_inventory_executed=$false;real_maintenance_executed=$false;test_toolkit_root=$tk;demo_report=$(if($demo){$demo.report}else{$null});completed_utc=[DateTime]::UtcNow.ToString('o');powershell_version=$PSVersionTable.PSVersion.ToString();powershell_edition=$PSVersionTable.PSEdition;runtime_version_observed_inside_fixture_process=$true;source_hashes=$sourceHashes;source_hashes_unchanged=$sourceUnchanged;checks=$results.ToArray();passed=@($results|Where-Object status -ceq 'passed').Count;skipped=@($results|Where-Object status -ceq 'skipped').Count}
Save (Join-Path $suite 'result.json') (Json $result)
[pscustomobject]@{status=$status;passed=$result.passed;skipped=$result.skipped;result=(Join-Path $suite 'result.json');demo_report=$result.demo_report}
if($status -cne 'passed'){
 Write-FixtureDiagnostics $result.checks ($diagnosticSteps.ToArray())
 throw 'Fictional fixture suite failed; inspect its owned result.json.'
}
