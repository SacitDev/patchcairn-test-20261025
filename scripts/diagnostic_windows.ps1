# Fixed read-only Windows diagnostic recipes. Dot-source; no collection occurs on import.
$env:TZ='UTC'

function Get-WindowsDiagnosticRecipes {
 @('windows.os_version','windows.system_capacity','windows.update_context','windows.system_event_metadata','windows.update_event_metadata')
}

function Test-DiagnosticKeys($Value,[string[]]$Keys) {
 if ($null -eq $Value) { return $false }
 $actual=@(if ($Value -is [Collections.IDictionary]) { $Value.Keys } else { $Value.PSObject.Properties.Name })
 return (@(Compare-Object @($actual | Sort-Object) @($Keys | Sort-Object)).Count -eq 0)
}

function Test-DiagnosticInteger($Value,[long]$Minimum,[long]$Maximum) {
 return (($Value -is [int] -or $Value -is [long]) -and $Value -ge $Minimum -and $Value -le $Maximum)
}

function Test-WindowsDiagnosticFacts([string]$Recipe,$Facts) {
 switch -Exact ($Recipe) {
  'windows.os_version' {
   return ((Test-DiagnosticKeys $Facts @('version','build','architecture')) -and $Facts.version -is [string] -and $Facts.version -cmatch '\A[0-9]{1,5}(\.[0-9]{1,6}){1,3}\z' -and $Facts.build -is [string] -and $Facts.build -cmatch '\A[0-9]{1,8}\z' -and $Facts.architecture -cin @('x64','arm64','x86','unknown'))
  }
  'windows.system_capacity' {
   return ((Test-DiagnosticKeys $Facts @('total_bytes','available_bytes')) -and (Test-DiagnosticInteger $Facts.total_bytes 0 ([long]::MaxValue)) -and (Test-DiagnosticInteger $Facts.available_bytes 0 $Facts.total_bytes))
  }
  'windows.update_context' {
   if (-not (Test-DiagnosticKeys $Facts @('updates')) -or @($Facts.updates).Count -gt 50) { return $false }
   foreach ($update in @($Facts.updates)) { if (-not (Test-DiagnosticKeys $update @('kb_id','installed_utc')) -or $update.kb_id -isnot [string] -or $update.kb_id -cnotmatch '\AKB[0-9]{4,10}\z' -or ($null -ne $update.installed_utc -and ($update.installed_utc -isnot [string] -or $update.installed_utc -cnotmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z'))) { return $false } }
   return $true
  }
  { $_ -in @('windows.system_event_metadata','windows.update_event_metadata') } {
   if (-not (Test-DiagnosticKeys $Facts @('events')) -or @($Facts.events).Count -gt 50) { return $false }
   $providers=@('Microsoft-Windows-WindowsUpdateClient','Microsoft-Windows-Kernel-Power','EventLog','Microsoft-Windows-WHEA-Logger','disk','Ntfs','volmgr')
   foreach ($event in @($Facts.events)) { if (-not (Test-DiagnosticKeys $event @('event_id','provider','level','observed_utc')) -or -not (Test-DiagnosticInteger $event.event_id 1 65535) -or $event.provider -cnotin $providers -or -not (Test-DiagnosticInteger $event.level 1 5) -or $event.observed_utc -isnot [string] -or $event.observed_utc -cnotmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z') { return $false } }
   if ($Recipe -eq 'windows.update_event_metadata' -and @($Facts.events | Where-Object { $_.provider -cne 'Microsoft-Windows-WindowsUpdateClient' }).Count -ne 0) { return $false }
   return $true
  }
 }
 return $false
}

function Invoke-WindowsDiagnostic {
 [CmdletBinding()]
 param([Parameter(Mandatory=$true)]$Request,$FixtureFacts=$null,[switch]$CoordinatorAuthorized)
 $ErrorActionPreference='Stop'
 $schema='patchcairn.diagnostics.v3'
 $keys=@('schema_version','kind','request_id','platform','recipe_id','mode','symptom','scope','observed_utc')
 if (-not (Test-DiagnosticKeys $Request $keys) -or $Request.schema_version -cne $schema -or $Request.kind -cne 'request' -or $Request.request_id -cnotmatch '\Adiag-[a-f0-9]{32}\z' -or $Request.platform -cne 'windows' -or $Request.mode -cnotin @('fixture','real') -or $Request.recipe_id -cnotin (Get-WindowsDiagnosticRecipes)) { throw 'diagnostic:invalid-request' }
 $window=24; $maximum=20
 $isEvents=$Request.recipe_id -in @('windows.system_event_metadata','windows.update_event_metadata')
 $seen=@{}
 foreach ($token in @($Request.scope)) {
  if (-not $isEvents -or $token -isnot [string] -or $token -cnotmatch '\A(window_hours|max_events):([0-9]{1,2})\z' -or $seen.ContainsKey($Matches[1])) { throw 'diagnostic:invalid-scope' }
  $key=$Matches[1];$value=[int]$Matches[2];$seen[$key]=$true
  if ($key -eq 'window_hours' -and $value -ge 1 -and $value -le 24) { $window=$value }
  elseif ($key -eq 'max_events' -and $value -ge 1 -and $value -le 50) { $maximum=$value }
  else { throw 'diagnostic:invalid-scope' }
 }
 # Event context always needs explicit selected bounds, even though defaults are bounded.
 if ($isEvents -and ($seen.Count -ne 2)) { throw 'diagnostic:explicit-event-scope-required' }
 $now=[DateTime]::UtcNow
 $result=[ordered]@{schema_version=$schema;kind='adapter_result';request_id=$Request.request_id;platform='windows';recipe_id=$Request.recipe_id;mode=$Request.mode;status='held';observed_utc=$now.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ");facts=@{};limitations=@();provenance=@()}
 $provenance=@{
  'windows.os_version'='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem'
  'windows.system_capacity'='https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem'
  'windows.update_context'='https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix'
  'windows.system_event_metadata'='https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent'
  'windows.update_event_metadata'='https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent'
 }
 $result.provenance=@($provenance[$Request.recipe_id])
 if ($Request.mode -eq 'fixture') {
  if (-not (Test-WindowsDiagnosticFacts $Request.recipe_id $FixtureFacts)) { throw 'diagnostic:invalid-fixture-facts' }
  if ($isEvents -and @($FixtureFacts.events).Count -gt $maximum) { throw 'diagnostic:event-bound' }
  $result.facts=$FixtureFacts;$result.status='observed';$result.limitations=@('Fictional injected evidence; no host collector was run.')
  return [pscustomobject]$result
 }
 if ($null -ne $FixtureFacts) { throw 'diagnostic:fixture-facts-in-real-request' }
 if (-not $CoordinatorAuthorized) { $result.limitations=@('A request record does not prove owner authority. The coordinator must authorize the selected read-only recipe in this process.');return [pscustomobject]$result }
 if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { $result.limitations=@('Windows recipe is unavailable on this platform.');return [pscustomobject]$result }
 try {
  $facts=@{}
  switch -Exact ($Request.recipe_id) {
   'windows.os_version' {
    $os=Get-CimInstance -ClassName Win32_OperatingSystem -Property Version,BuildNumber -ErrorAction Stop
    $architecture='unknown'
    try { $native=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString();if ($native -ceq 'X64') { $architecture='x64' } elseif ($native -ceq 'Arm64') { $architecture='arm64' } elseif ($native -ceq 'X86') { $architecture='x86' } } catch { $architecture='unknown' }
    $facts=@{version=[string]$os.Version;build=[string]$os.BuildNumber;architecture=$architecture}
    $result.limitations=@('Version context does not establish support, update completeness or security remediation.')
   }
   'windows.system_capacity' {
    $os=Get-CimInstance -ClassName Win32_OperatingSystem -Property TotalVisibleMemorySize,FreePhysicalMemory -ErrorAction Stop
    $facts=@{total_bytes=([long]$os.TotalVisibleMemorySize*1024L);available_bytes=([long]$os.FreePhysicalMemory*1024L)}
    $result.limitations=@('Memory availability is a momentary observation; it does not identify the cause of a slowdown.')
   }
   'windows.update_context' {
    $updates=@(Get-HotFix -ErrorAction Stop | Where-Object { $_.HotFixID -cmatch '\AKB[0-9]{4,10}\z' } | Sort-Object -Property HotFixID | Select-Object -First 50 | ForEach-Object { $stamp=$null;if ($_.InstalledOn -is [datetime]) { $stamp=$_.InstalledOn.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") };@{kb_id=[string]$_.HotFixID;installed_utc=$stamp} })
    $facts=@{updates=$updates};$result.limitations=@('Only up to 50 CBS-reported hotfix records are shown. This is not complete update history or evidence that no restart or update is pending.')
   }
   { $_ -in @('windows.system_event_metadata','windows.update_event_metadata') } {
    $filter=@{StartTime=$now.AddHours(-$window);EndTime=$now;Level=@(1,2,3)}
    if ($Request.recipe_id -eq 'windows.update_event_metadata') { $filter.LogName='Microsoft-Windows-WindowsUpdateClient/Operational';$filter.ProviderName='Microsoft-Windows-WindowsUpdateClient' }
    else { $filter.LogName='System';$filter.ProviderName=@('Microsoft-Windows-Kernel-Power','EventLog','Microsoft-Windows-WHEA-Logger','disk','Ntfs','volmgr');$filter.Id=@(7,11,15,17,18,19,20,41,51,55,57,98,129,140,153,157,161,6008) }
    # Do not access Message, Properties, ToXml, UserId or MachineName.
    try { $rows=@(Get-WinEvent -FilterHashtable $filter -MaxEvents $maximum -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $rows=@() } else { throw } }
    $events=@($rows | ForEach-Object { @{event_id=[int]$_.Id;provider=[string]$_.ProviderName;level=[int]$_.Level;observed_utc=$_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")} })
    $facts=@{events=$events};$result.limitations=@('Selected bounded event metadata only. Messages and payloads were not accessed. Missing events do not prove a healthy system or establish a cause.')
   }
  }
  if (-not (Test-WindowsDiagnosticFacts $Request.recipe_id $facts)) { throw 'diagnostic:unexpected-provider-data' }
  $result.facts=$facts;$result.status='observed'
 } catch {
  $result.status='held';$result.facts=@{};$result.limitations=@('The selected read-only recipe could not obtain valid bounded evidence with current permissions and capabilities. No repair was attempted.')
 }
 return [pscustomobject]$result
}
