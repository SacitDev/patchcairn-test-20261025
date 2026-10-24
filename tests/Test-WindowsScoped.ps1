[CmdletBinding()]
param()
$env:TZ='UTC'
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$owned=Join-Path $repo ('work\upgrade_v3\windows\native-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($owned) | Out-Null
$env:TEMP=$owned;$env:TMP=$owned
Add-Type -Path (Join-Path $repo 'scripts\Windows.Scoped.cs')
. (Join-Path $repo 'scripts\diagnostic_windows.ps1')
$checks=New-Object Collections.Generic.List[string]
function Assert-True([bool]$Value,[string]$Name) { if (-not $Value) { throw ('test failed: '+$Name) };$checks.Add($Name) }
function Assert-Refused([scriptblock]$Action,[string]$Code,[string]$Name) { $refused=$false;try { & $Action | Out-Null } catch { if ($_.Exception.ToString().Contains($Code)) { $refused=$true } else { throw } };Assert-True $refused $Name }
$source=Join-Path $owned 'selected';$quarantine=Join-Path $owned 'quarantine';$outside=Join-Path $owned 'outside'
foreach ($directory in @($source,$quarantine,$outside)) { [IO.Directory]::CreateDirectory($directory) | Out-Null }
[IO.File]::WriteAllText((Join-Path $source 'one.txt'),'fictional selected payload')
$root=[PatchCairn.WindowsScoped]::Inspect($source,'',$false,0,$null)
$dest=[PatchCairn.WindowsScoped]::Inspect($quarantine,'',$false,0,$null)
$file=[PatchCairn.WindowsScoped]::Inspect($source,'one.txt',$true,1024,$root)
Assert-True ($file.kind -eq 'file' -and $file.nlink -eq 1 -and $file.sha256.Length -eq 64) 'native hashed snapshot'
$bytes=[PatchCairn.WindowsScoped]::Read($source,'one.txt',$file,1024,$root)
Assert-True ([Text.Encoding]::UTF8.GetString($bytes) -eq 'fictional selected payload') 'identity bound read'
Assert-Refused { [PatchCairn.WindowsScoped]::Read($source,'one.txt',$file,2,$root) } 'file-byte-bound' 'bounded read refuses before content'
Assert-Refused { [PatchCairn.WindowsScoped]::Inspect($source,'../outside/secret.txt',$false,0,$root) } 'invalid-path-component' 'relative escape refused'
Assert-Refused { [PatchCairn.WindowsScoped]::Inspect($source,'one.txt:stream',$false,0,$root) } 'invalid-path-component' 'alternate stream refused'
Assert-Refused { [PatchCairn.WindowsScoped]::Inspect($source,((@('a')*65)-join '/'),$false,0,$root) } 'invalid-relative-path' 'relative depth bound enforced'
[IO.File]::WriteAllText((Join-Path $source 'one.txt'),'fictional changed payload')
Assert-Refused { [PatchCairn.WindowsScoped]::Remove($source,'one.txt',$file,$root) } 'stale-identity-or-content' 'stale purge refused'
$file=[PatchCairn.WindowsScoped]::Inspect($source,'one.txt',$true,1024,$root)
[IO.File]::WriteAllText((Join-Path $quarantine 'occupied.txt'),'preserve destination')
Assert-Refused { [PatchCairn.WindowsScoped]::Move($source,'one.txt',$quarantine,'occupied.txt',$file,$root,$dest) } 'rename-refused-no-overwrite' 'destination overwrite refused'
Assert-True ([IO.File]::ReadAllText((Join-Path $quarantine 'occupied.txt')) -eq 'preserve destination') 'overwrite refusal preserved bytes'
$moved=[PatchCairn.WindowsScoped]::Move($source,'one.txt',$quarantine,'one.txt',$file,$root,$dest)
Assert-True ($moved.inode -eq $file.inode -and $moved.sha256 -eq $file.sha256 -and -not [IO.File]::Exists((Join-Path $source 'one.txt'))) 'checked samevolume quarantine'
$restored=[PatchCairn.WindowsScoped]::Move($quarantine,'one.txt',$source,'one.txt',$moved,$dest,$root)
Assert-True ($restored.inode -eq $file.inode -and [IO.File]::Exists((Join-Path $source 'one.txt'))) 'checked restore'
[PatchCairn.WindowsScoped]::Remove($source,'one.txt',$restored,$root)
Assert-True (-not [IO.File]::Exists((Join-Path $source 'one.txt'))) 'exact file purge'
$created=[PatchCairn.WindowsScoped]::Create($source,'new.bin',[byte[]]@(1,2,3),100,$root)
Assert-True ($created.size -eq 3 -and $created.sha256.Length -eq 64) 'exclusive checked create'
Assert-Refused { [PatchCairn.WindowsScoped]::Create($source,'new.bin',[byte[]]@(4),100,$root) } 'create-new-refused' 'exclusive create never overwrites'
$dir=[PatchCairn.WindowsScoped]::Mkdir($source,'nested',$root)
Assert-True ($dir.kind -eq 'directory') 'checked mkdir'
Assert-Refused { [PatchCairn.WindowsScoped]::Remove($source,'nested',$created,$root) } 'unexpected-type' 'directory purge unavailable'
[IO.File]::WriteAllText((Join-Path $source 'tamper.txt'),'fictional A')
$tamper=[PatchCairn.WindowsScoped]::Inspect($source,'tamper.txt',$true,1024,$root)
$stamp=[IO.File]::GetLastWriteTimeUtc((Join-Path $source 'tamper.txt'))
[IO.File]::WriteAllText((Join-Path $source 'tamper.txt'),'fictional B')
[IO.File]::SetLastWriteTimeUtc((Join-Path $source 'tamper.txt'),$stamp)
Assert-Refused { [PatchCairn.WindowsScoped]::Remove($source,'tamper.txt',$tamper,$root) } 'stale-identity-or-content' 'same size and timestamp content replacement refused'
[IO.File]::WriteAllText((Join-Path $source 'readonly.txt'),'fictional protected')
[IO.File]::SetAttributes((Join-Path $source 'readonly.txt'),[IO.FileAttributes]::ReadOnly)
$readonly=[PatchCairn.WindowsScoped]::Inspect($source,'readonly.txt',$true,1024,$root)
Assert-Refused { [PatchCairn.WindowsScoped]::Remove($source,'readonly.txt',$readonly,$root) } 'readonly-or-system-file' 'readonly purge refuses without force'
Assert-Refused { [PatchCairn.WindowsScoped]::Inspect($source,'absent.txt',$false,0,$root) } 'missing-entry' 'exact absent leaf categorised'
$locked=New-Object IO.FileStream((Join-Path $source 'tamper.txt'),[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
try { Assert-Refused { [PatchCairn.WindowsScoped]::Inspect($source,'tamper.txt',$true,1024,$root) } 'access-sharing-or-missing' 'existing writer blocks checked read' } finally { $locked.Dispose() }
$hard=Join-Path $source 'hard.bin'
New-Item -ItemType HardLink -Path $hard -Target (Join-Path $source 'new.bin') | Out-Null
Assert-Refused { [PatchCairn.WindowsScoped]::Inspect($source,'new.bin',$false,0,$root) } 'hardlink' 'hardlink metadata refused'
Assert-Refused { [PatchCairn.WindowsScoped]::List($source,'',20000,$root) } 'hardlink' 'hardlink scope listing refused'
$junction=Join-Path $owned 'junction'
New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
Assert-Refused { [PatchCairn.WindowsScoped]::Inspect($junction,'',$false,0,$null) } 'reparse-point' 'reparse ancestor refused'
New-Item -ItemType Junction -Path (Join-Path $source 'escape') -Target $outside | Out-Null
Assert-Refused { [PatchCairn.WindowsScoped]::Inspect($source,'escape/absent.txt',$false,0,$root) } 'reparse-point' 'nested reparse ancestor refused'
$renamed=Join-Path $owned 'renamed'
[IO.Directory]::Move($quarantine,$renamed)
[IO.Directory]::CreateDirectory($quarantine) | Out-Null
Assert-Refused { [PatchCairn.WindowsScoped]::Inspect($quarantine,'',$false,0,$dest) } 'selected-root-changed' 'root replacement refused'
# No host diagnostic recipe runs. Fixtures call only validators and fixed transformations.
function Request([string]$Recipe,[object[]]$Scope=@()) { return @{schema_version='patchcairn.diagnostics.v3';kind='request';request_id=('diag-'+'a'*32);platform='windows';recipe_id=$Recipe;mode='fixture';symptom='Fictional test';scope=$Scope;observed_utc='2026-01-01T00:00:00Z'} }
$os=Invoke-WindowsDiagnostic -Request (Request 'windows.os_version') -FixtureFacts @{version='10.0.99999';build='99999';architecture='x64'}
Assert-True ($os.status -eq 'observed' -and $os.mode -eq 'fixture') 'diagnostic fictional OS context'
$capacity=Invoke-WindowsDiagnostic -Request (Request 'windows.system_capacity') -FixtureFacts @{total_bytes=1024L;available_bytes=512L}
Assert-True ($capacity.facts.available_bytes -eq 512) 'diagnostic capacity projection'
$updates=Invoke-WindowsDiagnostic -Request (Request 'windows.update_context') -FixtureFacts @{updates=@(@{kb_id='KB1234567';installed_utc=$null})}
Assert-True ($updates.facts.updates.Count -eq 1) 'diagnostic update projection'
$events=Invoke-WindowsDiagnostic -Request (Request 'windows.update_event_metadata' @('window_hours:1','max_events:2')) -FixtureFacts @{events=@(@{event_id=20;provider='Microsoft-Windows-WindowsUpdateClient';level=2;observed_utc='2026-01-01T00:00:00Z'})}
Assert-True ($events.facts.events.Count -eq 1) 'diagnostic bounded event metadata'
Assert-Refused { Invoke-WindowsDiagnostic -Request (Request 'windows.update_event_metadata') -FixtureFacts @{events=@()} } 'explicit-event-scope-required' 'events require selected scope'
Assert-Refused { Invoke-WindowsDiagnostic -Request (Request 'windows.os_version') -FixtureFacts @{version='10.0';build='1';architecture='x64';password='fictional forbidden field'} } 'invalid-fixture-facts' 'diagnostic extra field refused'
$injection=Request 'powershell; fake-command'
Assert-Refused { Invoke-WindowsDiagnostic -Request $injection -FixtureFacts @{} } 'invalid-request' 'command string recipe refused'
Assert-Refused { Invoke-WindowsDiagnostic -Request (Request 'windows.system_event_metadata' @('window_hours:24','max_events:51')) -FixtureFacts @{events=@()} } 'invalid-scope' 'event limit escalation refused'
Assert-Refused { Invoke-WindowsDiagnostic -Request (Request 'windows.system_event_metadata' @('window_hours:24','max_events:1')) -FixtureFacts @{events=@(@{event_id=1;provider='private-provider';level=2;observed_utc='2026-01-01T00:00:00Z'})} } 'invalid-fixture-facts' 'unknown provider refused'
$real=Request 'windows.os_version';$real.mode='real'
$held=Invoke-WindowsDiagnostic -Request $real
Assert-True ($held.status -eq 'held' -and @($held.facts.Keys).Count -eq 0) 'request record cannot authorize real collection'
$report=@{suite='Windows selected-file and diagnostic fixtures';powershell=$PSVersionTable.PSVersion.ToString();observed_utc=[DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");passed=$checks.Count;checks=$checks.ToArray();limits=@('Only native files in owned work were changed. No live diagnostic collector, host inventory or maintenance ran.','Crossvolume move, power loss, adversarial same-user mutation, other filesystems and other Windows versions were not certified.')}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $owned 'results.json') -Encoding UTF8
$report | ConvertTo-Json -Depth 6
