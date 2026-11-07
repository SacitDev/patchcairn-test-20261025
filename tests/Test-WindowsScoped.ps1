[CmdletBinding()]
param()
# The Windows diagnostic helper scripts/diagnostic_windows.ps1: its update and event recipes in fixture mode (the OS
# version and capacity recipes run in-process in Python and are refused here), its strict request refusals, its
# script-policy holds and its documented start (-File under GetSystemDirectoryW's Windows PowerShell, module path of
# the shell's own modules only). Prints one PASS or FAIL line per check and exits 1 if any check fails. No host recipe
# runs. Selected-file I/O is tested in tests/test_windows_io.py. Fixture files live under work/test-fixtures/ and are
# removed.
$env:TZ='UTC'
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$helper=Join-Path $repo 'scripts\diagnostic_windows.ps1'
$work=Join-Path $repo ('work\test-fixtures\windows-scoped-'+[Guid]::NewGuid().ToString('N'))
$system=[Environment]::SystemDirectory
$script:failed=0
function Check([string]$Name,[scriptblock]$Test) {
 try { $passed=[bool](& $Test) } catch { $passed=$false }
 if ($passed) { Write-Output ('PASS '+$Name) } else { $script:failed++; Write-Output ('FAIL '+$Name) }
}
function Refused([scriptblock]$Action,[string]$Message) {
 try { & $Action | Out-Null } catch { return [string]::Equals($_.Exception.Message,$Message,[StringComparison]::Ordinal) }
 return $false
}
function Request([string]$Recipe,[object[]]$Scope=@()) {
 [ordered]@{schema='patchcairn.diagnostics';schema_version=1;kind='request';request_id=('diag-'+'a'*32);platform='windows';recipe_id=$Recipe;mode='fixture';symptom='Fictional test';scope=$Scope;observed_utc='2026-01-01T00:00:00Z'}
}
# An older-style name, built at run time so no version label sits in the source.
function Versioned([string]$Name,[int]$Number) { return $Name+'.v'+$Number }
function Changed([string]$Key,$Value,[switch]$Remove) {
 $request=Request 'windows.update_context'
 if ($Remove) { $request.Remove($Key) } else { $request[$Key]=$Value }
 return $request
}
$utf8=New-Object Text.UTF8Encoding($false)
$modules=Join-Path $system 'WindowsPowerShell\v1.0\Modules'
function Start-Documented([string]$Script,[string]$Arguments,[string]$ModulePath=$modules,[string]$Policy) {
 # The documented start: Windows PowerShell from the system folder, -NoProfile -NonInteractive -File, an explicit
 # module path and no PSExecutionPolicyPreference (the caller's duties; ModulePath and Policy let a check simulate a
 # caller that passed on inherited ones), no policy override.
 $start=New-Object Diagnostics.ProcessStartInfo
 $start.FileName=Join-Path $system 'WindowsPowerShell\v1.0\powershell.exe'
 $start.Arguments='-NoProfile -NonInteractive -File "'+$Script+'" '+$Arguments
 $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 $start.EnvironmentVariables['PSModulePath']=$ModulePath
 $start.EnvironmentVariables.Remove('PSExecutionPolicyPreference')
 if ($Policy) { $start.EnvironmentVariables['PSExecutionPolicyPreference']=$Policy }
 $process=[Diagnostics.Process]::Start($start)
 $errors=$process.StandardError.ReadToEndAsync()
 $output=$process.StandardOutput.ReadToEnd()
 $process.WaitForExit()
 return [pscustomobject]@{code=$process.ExitCode;output=$output;errors=$errors.Result}
}
function Write-Fixture([string]$Text,[byte[]]$Prefix=@()) {
 $path=Join-Path $work ([Guid]::NewGuid().ToString('N')+'.json')
 [IO.File]::WriteAllBytes($path,[byte[]]($Prefix+$utf8.GetBytes($Text)))
 return $path
}
function Start-Helper([string]$RequestText,[string]$FactsText,[byte[]]$Prefix=@()) {
 Start-Documented $helper ('-RequestPath "'+(Write-Fixture $RequestText $Prefix)+'" -FixturePath "'+(Write-Fixture $FactsText)+'"')
}
[IO.Directory]::CreateDirectory($work) | Out-Null
try {
 . $helper
 # Recipes in fixture mode.
 $update=@{updates=@(@{kb_id='KB1234567';installed_utc=$null})}
 Check 'diagnostic update projection' { $r=Invoke-WindowsDiagnostic -Request (Request 'windows.update_context') -FixtureFacts $update;$r.status -ceq 'observed' -and $r.mode -ceq 'fixture' -and @($r.facts.updates).Count -eq 1 }
 Check 'diagnostic bounded event metadata' { @((Invoke-WindowsDiagnostic -Request (Request 'windows.update_event_metadata' @('window_hours:1','max_events:2')) -FixtureFacts @{events=@(@{event_id=20;provider='Microsoft-Windows-WindowsUpdateClient';level=2;observed_utc='2026-01-01T00:00:00Z'})}).facts.events).Count -eq 1 }
 Check 'diagnostic bounded system event metadata' { @((Invoke-WindowsDiagnostic -Request (Request 'windows.system_event_metadata' @('window_hours:24','max_events:3')) -FixtureFacts @{events=@(@{event_id=41;provider='Microsoft-Windows-Kernel-Power';level=1;observed_utc='2026-01-01T00:00:00Z'})}).facts.events).Count -eq 1 }
 Check 'update events from another provider refused' { Refused { Invoke-WindowsDiagnostic -Request (Request 'windows.update_event_metadata' @('window_hours:1','max_events:2')) -FixtureFacts @{events=@(@{event_id=41;provider='Microsoft-Windows-Kernel-Power';level=1;observed_utc='2026-01-01T00:00:00Z'})} } 'diagnostic:invalid-fixture-facts' }
 Check 'events require selected scope' { Refused { Invoke-WindowsDiagnostic -Request (Request 'windows.update_event_metadata') -FixtureFacts @{events=@()} } 'diagnostic:explicit-event-scope-required' }
 foreach ($recipe in @('windows.os_version','windows.system_capacity','windows.dism_check_health','windows.sfc_verify_only')) {
  Check ('recipe not run by the helper refused: '+$recipe) { Refused { Invoke-WindowsDiagnostic -Request (Request $recipe) -FixtureFacts @{total_bytes=1024L;available_bytes=512L} } 'diagnostic:invalid-request' }
 }
 Check 'diagnostic extra field refused' { Refused { Invoke-WindowsDiagnostic -Request (Request 'windows.update_context') -FixtureFacts @{updates=@();password='fictional forbidden field'} } 'diagnostic:invalid-fixture-facts' }
 Check 'diagnostic extra field named Keys refused' { $facts=ConvertFrom-StrictJson -Text '{"updates":[],"Keys":["updates"]}';Refused { Invoke-WindowsDiagnostic -Request (Request 'windows.update_context') -FixtureFacts $facts } 'diagnostic:invalid-fixture-facts' }
 Check 'command string recipe refused' { Refused { Invoke-WindowsDiagnostic -Request (Request 'powershell; fake-command') -FixtureFacts @{} } 'diagnostic:invalid-request' }
 Check 'event limit escalation refused' { Refused { Invoke-WindowsDiagnostic -Request (Request 'windows.system_event_metadata' @('window_hours:24','max_events:51')) -FixtureFacts @{events=@()} } 'diagnostic:invalid-scope' }
 Check 'unknown provider refused' { Refused { Invoke-WindowsDiagnostic -Request (Request 'windows.system_event_metadata' @('window_hours:24','max_events:1')) -FixtureFacts @{events=@(@{event_id=1;provider='private-provider';level=2;observed_utc='2026-01-01T00:00:00Z'})} } 'diagnostic:invalid-fixture-facts' }
 Check 'request record cannot authorize real collection' { $real=Request 'windows.update_context';$real.mode='real';$held=Invoke-WindowsDiagnostic -Request $real;$held.status -ceq 'held' -and @($held.facts.Keys).Count -eq 0 }
 Check 'fixture facts refused in a real request' { $real=Request 'windows.update_context';$real.mode='real';Refused { Invoke-WindowsDiagnostic -Request $real -FixtureFacts $update -CoordinatorAuthorized } 'diagnostic:fixture-facts-in-real-request' }
 Check 'result carries the unversioned name and integer version' { $r=Invoke-WindowsDiagnostic -Request (Request 'windows.update_context') -FixtureFacts $update;$r.schema -ceq 'patchcairn.diagnostics' -and $r.schema_version -is [int] -and ([long]$r.schema_version).Equals([long]1) }
 # Cultures with another time separator (fi-FI) or calendar (th-TH) must not reach the helper's times. Get-WinEvent
 # reads each window bound as local time whatever its Kind says, as Read-AsGetWinEvent does here; on a host at UTC only
 # the Kind check can tell the two apart. The moment lies far from any daylight-saving change.
 function Under-Culture([string]$Name,[scriptblock]$Test) {
  $thread=[Threading.Thread]::CurrentThread;$previous=$thread.CurrentCulture
  $thread.CurrentCulture=[Globalization.CultureInfo]::new($Name)
  try { & $Test } finally { $thread.CurrentCulture=$previous }
 }
 function Read-AsGetWinEvent([datetime]$Bound) { return [DateTime]::Parse($Bound.ToString()).ToUniversalTime() }
 $moment=[DateTime]::new(2026,6,15,5,6,7,[DateTimeKind]::Utc)
 $stamp='2026-06-15T05:06:07Z'
 foreach ($culture in @('fi-FI','th-TH')) {
  Check ('culture '+$culture+' changes plain date text') { Under-Culture $culture { $moment.ToString('yyyy-MM-ddTHH:mm:ssZ') -cne $stamp } }
  Check ('culture '+$culture+' leaves the result stamp in its fixed form') {
   Under-Culture $culture {
    $at=(Invoke-WindowsDiagnostic -Request (Request 'windows.update_context') -FixtureFacts $update).observed_utc
    [Math]::Abs(([DateTime]::UtcNow-[DateTime]::ParseExact($at,"yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'",[Globalization.CultureInfo]::InvariantCulture)).TotalMinutes) -lt 10
   }
  }
  Check ('culture '+$culture+' leaves update and event stamps in their fixed form') {
   Under-Culture $culture {
    $row=ConvertTo-DiagnosticUpdateRow ([pscustomobject]@{HotFixID='KB1234567';InstalledOn=$moment})
    $entry=ConvertTo-DiagnosticEventRow ([pscustomobject]@{Id=140;ProviderName='Microsoft-Windows-Ntfs';Level=3;TimeCreated=$moment})
    $row.installed_utc -ceq $stamp -and $entry.observed_utc -ceq $stamp -and (Test-WindowsDiagnosticFacts 'windows.update_context' @{updates=@($row)}) -and (Test-WindowsDiagnosticFacts 'windows.system_event_metadata' @{events=@($entry)})
   }
  }
  Check ('culture '+$culture+' leaves the event window in local time') {
   Under-Culture $culture {
    $filter=Get-DiagnosticEventFilter 'windows.system_event_metadata' $moment 6
    $filter.StartTime.Kind -eq [DateTimeKind]::Local -and $filter.EndTime.Kind -eq [DateTimeKind]::Local -and (Read-AsGetWinEvent $filter.StartTime) -eq $moment.AddHours(-6) -and (Read-AsGetWinEvent $filter.EndTime) -eq $moment
   }
  }
 }
 # The script-policy holds: a module loaded from outside the shell's own folder, and an inherited policy override.
 Check 'a module loaded from outside the shell folder is refused' {
  $folder=[IO.Directory]::CreateDirectory((Join-Path $work 'fictional-module')).FullName
  [IO.File]::WriteAllText((Join-Path $folder 'fictional-module.psm1'),"function Get-FictionalValue { 1 }`n",$utf8)
  Assert-SystemModules
  $module=Import-Module (Join-Path $folder 'fictional-module.psm1') -PassThru
  try { Refused { Assert-SystemModules } 'diagnostic:foreign-module' } finally { Remove-Module $module }
 }
 # Strict request refusals.
 foreach ($case in @(@('schema_version text','schema_version','1','record:schema-version'),@('schema_version decimal','schema_version',1.0,'record:schema-version'),
                     @('schema_version boolean','schema_version',$true,'record:schema-version'),@('schema_version 2','schema_version',2,'record:schema-version'),
                     @('schema_version 0','schema_version',0,'record:schema-version'),@('schema wrong','schema','patchcairn.storage','record:schema-name'),
                     @('schema with a version number','schema',(Versioned 'patchcairn.diagnostics' 3),'record:older-format'))) {
  Check ('request refused: '+$case[0]) { Refused { Invoke-WindowsDiagnostic -Request (Changed $case[1] $case[2]) -FixtureFacts @{} } ('diagnostic:invalid-request ('+$case[3]+')') }
 }
 Check 'request refused: schema_version missing' { Refused { Invoke-WindowsDiagnostic -Request (Changed 'schema_version' $null -Remove) -FixtureFacts @{} } 'diagnostic:invalid-request (record:schema-version)' }
 Check 'request refused: schema missing' { Refused { Invoke-WindowsDiagnostic -Request (Changed 'schema' $null -Remove) -FixtureFacts @{} } 'diagnostic:invalid-request (record:schema-name)' }
 Check 'request refused: older versioned request' { $old=Changed 'schema' $null -Remove;$old['schema_version']=Versioned 'patchcairn.diagnostics' 3;Refused { Invoke-WindowsDiagnostic -Request $old -FixtureFacts @{} } 'diagnostic:invalid-request (record:older-format)' }
 Check 'request refused: extra field named Keys' { $keyed=Request 'windows.os_version';$keyed['Keys']=@($keyed.get_Keys());Refused { Invoke-WindowsDiagnostic -Request $keyed -FixtureFacts @{} } 'diagnostic:invalid-request' }
 foreach ($case in @(@('kind',@()),@('request_id',@()),@('platform',@()),@('recipe_id',@('windows.os_version')),@('mode',@('fixture')),
                     @('symptom',@{text='x'}),@('observed_utc',42),@('scope','window_hours:1'))) {
  Check ('request refused: '+$case[0]+' of the wrong type') { Refused { Invoke-WindowsDiagnostic -Request (Changed $case[0] $case[1]) -FixtureFacts @{} } 'diagnostic:invalid-request' }
 }
 # The documented start.
 $requestText=(Request 'windows.update_context' | ConvertTo-Json -Compress)
 $factsText='{"updates":[{"kb_id":"KB1234567","installed_utc":null}]}'
 Check 'helper started with -File observes the fixture' { $run=Start-Helper $requestText $factsText;$result=ConvertFrom-StrictJson -Text $run.output.Trim();$run.code -eq 0 -and $result['status'] -ceq 'observed' -and $result['schema'] -ceq 'patchcairn.diagnostics' -and @($result['facts']['updates']).Count -eq 1 -and $result['facts']['updates'][0]['kb_id'] -ceq 'KB1234567' }
 # Modules named like the real ones, first on an inherited module path (a user's Documents folder, say), must not load.
 $planted=Join-Path $work 'planted-modules'
 foreach ($name in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Diagnostics','CimCmdlets')) {
  $folder=[IO.Directory]::CreateDirectory((Join-Path $planted $name)).FullName
  $body="[Console]::Error.WriteLine('PLANTED-MODULE-LOADED')`n"
  foreach ($command in @('Join-Path','Get-HotFix','ConvertTo-Json','Sort-Object','Select-Object','Compare-Object','Get-CimInstance','Get-WinEvent')) {
   $body+="function $command { [Console]::Error.WriteLine('PLANTED-COMMAND-RAN') }`n"
  }
  [IO.File]::WriteAllText((Join-Path $folder ($name+'.psm1')),$body,$utf8)
 }
 $inherited=$planted+';'+$modules
 Check 'helper started with -File ignores modules planted on an inherited module path' {
  $run=Start-Documented $helper ('-RequestPath "'+(Write-Fixture $requestText)+'" -FixturePath "'+(Write-Fixture $factsText)+'"') $inherited
  $result=ConvertFrom-StrictJson -Text $run.output.Trim()
  $run.code -eq 0 -and $result['status'] -ceq 'observed' -and -not $run.errors.Contains('PLANTED')
 }
 Check 'helper started with -File loads every module from its own folder' {
  $probe=Join-Path $work 'module-probe.ps1'
  [IO.File]::WriteAllText($probe,"param(`$Helper,`$RequestPath,`$FixturePath)`n. `$Helper -RequestPath `$RequestPath -FixturePath `$FixturePath | Out-Null`nforeach (`$m in @(Get-Module)) { `$m.ModuleBase }`n(Get-Command Microsoft.PowerShell.Management\Get-HotFix).Module.ModuleBase`n",$utf8)
  $run=Start-Documented $probe ('-Helper "'+$helper+'" -RequestPath "'+(Write-Fixture $requestText)+'" -FixturePath "'+(Write-Fixture $factsText)+'"') $inherited
  $bases=@($run.output -split "`r?`n" | Where-Object { $_ })
  $own=Join-Path $system 'WindowsPowerShell\v1.0\'
  $run.code -eq 0 -and $bases.Count -ge 2 -and -not $run.errors.Contains('PLANTED') -and
   @($bases | Where-Object { -not ($_.TrimEnd('\')+'\').StartsWith($own,[StringComparison]::OrdinalIgnoreCase) }).Count -eq 0
 }
 # A Process-scope policy set in the parent (Set-ExecutionPolicy -Scope Process) must not reach the helper. The
 # planted value is the strict AllSigned, never a bypass: had the child inherited it, the unsigned probe could not run.
 Check 'documented start does not pass on PSExecutionPolicyPreference set in the parent' {
  $probe=Join-Path $work 'policy-probe.ps1'
  [IO.File]::WriteAllText($probe,"'inherited='+`$env:PSExecutionPolicyPreference`n",$utf8)
  $previous=[Environment]::GetEnvironmentVariable('PSExecutionPolicyPreference')
  [Environment]::SetEnvironmentVariable('PSExecutionPolicyPreference','AllSigned')
  try { $run=Start-Documented $probe '';$helperRun=Start-Helper $requestText $factsText }
  finally { [Environment]::SetEnvironmentVariable('PSExecutionPolicyPreference',$previous) }
  $run.code -eq 0 -and $run.output.Trim() -ceq 'inherited=' -and $helperRun.code -eq 0 -and
   (ConvertFrom-StrictJson -Text $helperRun.output.Trim())['status'] -ceq 'observed'
 }
 # A caller that passed the variable on anyway is refused before the request is read. The planted value is the
 # policy Windows PowerShell already applies here (read by a documented start), so this start changes no policy.
 Check 'helper started with -File refuses an inherited PSExecutionPolicyPreference' {
  $probe=Join-Path $work 'effective-policy.ps1'
  [IO.File]::WriteAllText($probe,"[string](Microsoft.PowerShell.Security\Get-ExecutionPolicy)`n",$utf8)
  $effective=(Start-Documented $probe '').output.Trim()
  $run=Start-Documented $helper ('-RequestPath "'+(Write-Fixture $requestText)+'" -FixturePath "'+(Write-Fixture $factsText)+'"') -Policy $effective
  $effective -and $run.code -ne 0 -and $run.errors.Contains('diagnostic:execution-policy-override') -and -not $run.output.Trim()
 }
 Check 'fixture updates given as one object instead of a list refused' { Refused { Invoke-WindowsDiagnostic -Request (Request 'windows.update_context') -FixtureFacts @{updates=@{kb_id='KB1234567';installed_utc=$null}} } 'diagnostic:invalid-fixture-facts' }
 Check 'helper started with -File refuses a byte order mark' { $run=Start-Helper $requestText $factsText ([byte[]](0xEF,0xBB,0xBF));$run.code -ne 0 -and $run.errors.Contains('record:json-bom') -and -not $run.output.Trim() }
 Check 'helper started with -File refuses a duplicate key' { $run=Start-Helper ($requestText.TrimEnd('}')+',"kind":"request"}') $factsText;$run.code -ne 0 -and $run.errors.Contains('record:json-duplicate-key') }
 Check 'helper started with -File refuses malformed JSON' { $run=Start-Helper ($requestText+',') $factsText;$run.code -ne 0 -and $run.errors.Contains('record:json-invalid') }
 Check 'helper started with -File refuses a text schema_version' { $run=Start-Helper ($requestText.Replace('"schema_version":1','"schema_version":"1"')) $factsText;$run.code -ne 0 -and $run.errors.Contains('record:schema-version') }
} finally {
 Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
if ($script:failed) { Write-Output ('FAILED '+$script:failed+' check(s)');exit 1 }
