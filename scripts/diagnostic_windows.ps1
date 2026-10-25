# Fixed read-only Windows diagnostic recipes. Dot-source to define the functions; nothing is collected then.
# The caller starts the helper only as
#   <GetSystemDirectoryW>\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -File diagnostic_windows.ps1
#     -RequestPath <request file> [-FixturePath <fictional facts file>] [-CoordinatorAuthorized]
# with an explicit environment whose PSModulePath is <GetSystemDirectoryW>\WindowsPowerShell\v1.0\Modules only and
# that has no PSExecutionPolicyPreference (the caller removes an inherited one: it would override the machine's
# policy), and never with an execution-policy bypass. The script repeats the module path as its first statement,
# without a cmdlet (a cmdlet would load its module from the inherited path first), refuses a start that still carries
# PSExecutionPolicyPreference or -ExecutionPolicy, checks that every loaded module comes from $PSHOME, uses no command
# that loads a module before that, and names each cmdlet it needs with its module. Under the Restricted or AllSigned
# policy (the default on Windows clients) the start fails: the recipe is reported as held, and neither
# -ExecutionPolicy nor a policy change is ever used. -CoordinatorAuthorized is only the caller's claim; the host's
# command approval and the owner supply the authority. The request is read with the strict record reader below.
[CmdletBinding()]
param([string]$RequestPath,[string]$FixturePath,[switch]$CoordinatorAuthorized)
if ($RequestPath) {
 $env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')
 if ($env:PSExecutionPolicyPreference) { throw 'diagnostic:execution-policy-override' }
}
$env:TZ='UTC'

function Assert-SystemModules {
 # Get-Module is built in and loads nothing. Windows PowerShell reports its own modules' base as $PSHOME itself.
 $own=$PSHOME.TrimEnd('\')+'\'
 foreach ($module in @(Get-Module)) {
  if (-not ($module.ModuleBase.TrimEnd('\')+'\').StartsWith($own,[StringComparison]::OrdinalIgnoreCase)) { throw 'diagnostic:foreign-module' }
 }
}

function Get-WindowsDiagnosticRecipes {
 @('windows.os_version','windows.system_capacity','windows.update_context','windows.system_event_metadata','windows.update_event_metadata')
}

function Test-DiagnosticKeys($Value,[string[]]$Keys) {
 if ($null -eq $Value) { return $false }
 # get_Keys(): a dictionary key named "Keys" would shadow the Keys property.
 $actual=[string[]]@(if ($Value -is [Collections.IDictionary]) { $Value.get_Keys() } else { $Value.PSObject.Properties.Name })
 $set=[Collections.Generic.HashSet[string]]::new($actual,[StringComparer]::Ordinal)
 return ($set.Count -eq $actual.Count -and $set.Count -eq $Keys.Count -and $set.SetEquals($Keys))
}

function ConvertFrom-StrictJson {
 # One JSON value (RFC 8259) without a byte order mark, duplicate or case-variant keys, non-finite numbers, lone
 # surrogates or nesting deeper than MaxDepth. Objects become case-sensitive ordered dictionaries, integers [long],
 # other numbers [double]. The parser keeps its own stack, so deep input cannot exhaust PowerShell's call depth.
 param([Parameter(Mandatory=$true)][AllowEmptyString()][string]$Text,[int]$MaxDepth=64)
 if ($Text.Length -gt 0 -and $Text[0] -eq [char]0xFEFF) { throw 'record:json-bom' }
 $token=[regex]'\G[ \t\n\r]*(?:(?<p>[{}\[\],:])|(?<s>"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*")|(?<n>-?(?:0|[1-9][0-9]*)(?<f>\.[0-9]+)?(?<e>[eE][+-]?[0-9]+)?)|(?<l>true|false|null))'
 $strict=[Text.UTF8Encoding]::new($false,$true)
 $stack=[Collections.ArrayList]::new()
 $at=0;$result=$null;$done=$false;$expect='value'
 while ($true) {
  $m=$token.Match($Text,$at)
  if (-not $m.Success) {
   if ($done -and $Text.Substring($at).Trim(" `t`n`r".ToCharArray()).Length -eq 0) { break }
   throw 'record:json-invalid'
  }
  if ($done) { throw 'record:json-invalid' }
  $at=$m.Index+$m.Length
  $frame=if ($stack.Count) { $stack[$stack.Count-1] } else { $null }
  if ($m.Groups['p'].Success) {
   $p=$m.Groups['p'].Value
   if ($p -eq ',' -and $expect -eq 'comma') { $expect=if ($frame.kind -eq 'object') { 'key' } else { 'value' };continue }
   if ($p -eq ':' -and $expect -eq 'colon') { $expect='value';continue }
   if (($p -eq '}' -and $frame -and $frame.kind -eq 'object' -and ($expect -eq 'comma' -or ($expect -eq 'key' -and $frame.first))) -or
       ($p -eq ']' -and $frame -and $frame.kind -eq 'array' -and ($expect -eq 'comma' -or ($expect -eq 'value' -and $frame.first)))) {
    $stack.RemoveAt($stack.Count-1)
    $value=if ($frame.kind -eq 'array') { ,($frame.items.ToArray()) } else { $frame.items }
   } elseif (($p -eq '{' -or $p -eq '[') -and $expect -eq 'value') {
    if ($stack.Count -ge $MaxDepth) { throw 'record:json-too-deep' }
    if ($p -eq '{') {
     [void]$stack.Add(@{kind='object';items=[Collections.Specialized.OrderedDictionary]::new();seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);key=$null;first=$true})
     $expect='key'
    } else {
     [void]$stack.Add(@{kind='array';items=[Collections.ArrayList]::new();first=$true})
     $expect='value'
    }
    continue
   } else { throw 'record:json-invalid' }
  } elseif ($m.Groups['s'].Success) {
   $value=[regex]::Replace($m.Groups['s'].Value.Substring(1,$m.Groups['s'].Value.Length-2),'\\(?:u([0-9a-fA-F]{4})|(.))',{
    param($e)
    if ($e.Groups[1].Success) { return [string][char][Convert]::ToInt32($e.Groups[1].Value,16) }
    switch -CaseSensitive ($e.Groups[2].Value) { 'b' { "`b" } 'f' { "`f" } 'n' { "`n" } 'r' { "`r" } 't' { "`t" } default { $e.Groups[2].Value } }
   })
   try { [void]$strict.GetBytes($value) } catch { throw 'record:json-encoding' }
   if ($expect -eq 'key') {
    if (-not $frame.seen.Add($value)) { throw 'record:json-duplicate-key' }
    $frame.key=$value;$expect='colon';continue
   }
   if ($expect -ne 'value') { throw 'record:json-invalid' }
  } elseif ($m.Groups['n'].Success) {
   if ($expect -ne 'value') { throw 'record:json-invalid' }
   $n=$m.Groups['n'].Value
   if ($m.Groups['f'].Success -or $m.Groups['e'].Success) {
    # .NET Framework reports an overflow as a failed parse, .NET as infinity; both are refused.
    $value=[double]0
    if (-not [double]::TryParse($n,[Globalization.NumberStyles]::Float,[Globalization.CultureInfo]::InvariantCulture,[ref]$value) -or
        [double]::IsInfinity($value)) { throw 'record:json-nonfinite' }
   } else {
    $number=[long]0
    if ($n.TrimStart('-').Length -gt 19 -or -not [long]::TryParse($n,[Globalization.NumberStyles]::AllowLeadingSign,[Globalization.CultureInfo]::InvariantCulture,[ref]$number)) { throw 'record:json-number' }
    $value=$number
   }
  } else {
   if ($expect -ne 'value') { throw 'record:json-invalid' }
   $value=switch -CaseSensitive ($m.Groups['l'].Value) { 'true' { $true } 'false' { $false } default { $null } }
  }
  # A complete value: store it in its container, or finish.
  if (-not $stack.Count) { $result=$value;$done=$true;continue }
  $frame=$stack[$stack.Count-1];$frame.first=$false
  if ($frame.kind -eq 'object') { $frame.items.Add($frame.key,$value) } else { [void]$frame.items.Add($value) }
  $expect='comma'
 }
 return ,$result
}

function Assert-PatchCairnRecord {
 # A typed record carries exactly the schema name and the integer schema_version 1; a container (no Schema) carries
 # only the integer. Older versioned names are refused with their own code. schema_version is never compared with a
 # coercing operator: the type is checked first and the value with Int64.Equals.
 param([Parameter(Mandatory=$true)][AllowNull()]$Record,[string]$Schema)
 if ($Record -isnot [Collections.IDictionary]) { throw 'record:record-shape' }
 $name=if ($Record.Contains('schema')) { $Record['schema'] } else { $null }
 $version=if ($Record.Contains('schema_version')) { $Record['schema_version'] } else { $null }
 if (($name -is [string] -and $name -cmatch '[._-][vV][0-9]+\z') -or
     ($null -eq $name -and $version -is [string] -and ($version -cmatch '[._-][vV][0-9]+\z' -or $version -cmatch '\A[0-9]+\.[0-9]+\z'))) { throw 'record:older-format' }
 if ($Schema) {
  if ($name -isnot [string] -or -not [string]::Equals($name,$Schema,[StringComparison]::Ordinal)) { throw 'record:schema-name' }
 } elseif ($Record.Contains('schema')) { throw 'record:schema-name' }
 if (-not (($version -is [int] -or $version -is [long]) -and ([long]$version).Equals([long]1))) { throw 'record:schema-version' }
 return ,$Record
}

function Read-StrictJsonFile {
 # UTF-8 bytes from a file: a file over MaxBytes is refused before it is read, a byte order mark and invalid UTF-8
 # before parsing. The path is resolved against the PowerShell location, not the process folder.
 param([Parameter(Mandatory=$true)][string]$Path,[int]$MaxBytes=1048576)
 $stream=[IO.File]::OpenRead($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
 try {
  if ($stream.Length -gt $MaxBytes) { throw 'record:json-too-large' }
  $bytes=[byte[]]::new($stream.Length)
  $read=0
  while ($read -lt $bytes.Length) { $count=$stream.Read($bytes,$read,$bytes.Length-$read);if (-not $count) { break };$read+=$count }
  if ($read -ne $bytes.Length -or $stream.ReadByte() -ne -1) { throw 'record:json-changed' }
 } finally { $stream.Dispose() }
 if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { throw 'record:json-bom' }
 try { $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes) } catch { throw 'record:json-encoding' }
 return ,(ConvertFrom-StrictJson -Text $text)
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
   if (-not (Test-DiagnosticKeys $Facts @('updates')) -or $Facts.updates -isnot [array] -or @($Facts.updates).Count -gt 50) { return $false }
   foreach ($update in @($Facts.updates)) { if (-not (Test-DiagnosticKeys $update @('kb_id','installed_utc')) -or $update.kb_id -isnot [string] -or $update.kb_id -cnotmatch '\AKB[0-9]{4,10}\z' -or ($null -ne $update.installed_utc -and ($update.installed_utc -isnot [string] -or $update.installed_utc -cnotmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z'))) { return $false } }
   return $true
  }
  { $_ -in @('windows.system_event_metadata','windows.update_event_metadata') } {
   if (-not (Test-DiagnosticKeys $Facts @('events')) -or $Facts.events -isnot [array] -or @($Facts.events).Count -gt 50) { return $false }
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
 $keys=@('schema','schema_version','kind','request_id','platform','recipe_id','mode','symptom','scope','observed_utc')
 try { [void](Assert-PatchCairnRecord -Record $Request -Schema 'patchcairn.diagnostics') } catch { throw ('diagnostic:invalid-request ('+$_.Exception.Message+')') }
 # Comparison operators apply to each element of an array, so every scalar field must be a string first.
 if (@('kind','request_id','platform','recipe_id','mode','symptom','observed_utc' | Where-Object { $Request[$_] -isnot [string] }).Count -or $Request['scope'] -isnot [array]) { throw 'diagnostic:invalid-request' }
 if (-not (Test-DiagnosticKeys $Request $keys) -or $Request.kind -cne 'request' -or $Request.request_id -cnotmatch '\Adiag-[a-f0-9]{32}\z' -or $Request.platform -cne 'windows' -or $Request.mode -cnotin @('fixture','real') -or $Request.recipe_id -cnotin (Get-WindowsDiagnosticRecipes)) { throw 'diagnostic:invalid-request' }
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
 $result=[ordered]@{schema='patchcairn.diagnostics';schema_version=1;kind='adapter_result';request_id=$Request.request_id;platform='windows';recipe_id=$Request.recipe_id;mode=$Request.mode;status='held';observed_utc=$now.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ");facts=@{};limitations=@();provenance=@()}
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
    $os=CimCmdlets\Get-CimInstance -ClassName Win32_OperatingSystem -Property Version,BuildNumber -ErrorAction Stop
    $architecture='unknown'
    try { $native=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString();if ($native -ceq 'X64') { $architecture='x64' } elseif ($native -ceq 'Arm64') { $architecture='arm64' } elseif ($native -ceq 'X86') { $architecture='x86' } } catch { $architecture='unknown' }
    $facts=@{version=[string]$os.Version;build=[string]$os.BuildNumber;architecture=$architecture}
    $result.limitations=@('Version context does not establish support, update completeness or security remediation.')
   }
   'windows.system_capacity' {
    $os=CimCmdlets\Get-CimInstance -ClassName Win32_OperatingSystem -Property TotalVisibleMemorySize,FreePhysicalMemory -ErrorAction Stop
    $facts=@{total_bytes=([long]$os.TotalVisibleMemorySize*1024L);available_bytes=([long]$os.FreePhysicalMemory*1024L)}
    $result.limitations=@('Memory availability is a momentary observation; it does not identify the cause of a slowdown.')
   }
   'windows.update_context' {
    $updates=@(Microsoft.PowerShell.Management\Get-HotFix -ErrorAction Stop | Where-Object { $_.HotFixID -cmatch '\AKB[0-9]{4,10}\z' } | Microsoft.PowerShell.Utility\Sort-Object -Property HotFixID | Microsoft.PowerShell.Utility\Select-Object -First 50 | ForEach-Object { $stamp=$null;if ($_.InstalledOn -is [datetime]) { $stamp=$_.InstalledOn.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") };@{kb_id=[string]$_.HotFixID;installed_utc=$stamp} })
    $facts=@{updates=$updates};$result.limitations=@('Only up to 50 CBS-reported hotfix records are shown. This is not complete update history or evidence that no restart or update is pending.')
   }
   { $_ -in @('windows.system_event_metadata','windows.update_event_metadata') } {
    $filter=@{StartTime=$now.AddHours(-$window);EndTime=$now;Level=@(1,2,3)}
    if ($Request.recipe_id -eq 'windows.update_event_metadata') { $filter.LogName='Microsoft-Windows-WindowsUpdateClient/Operational';$filter.ProviderName='Microsoft-Windows-WindowsUpdateClient' }
    else { $filter.LogName='System';$filter.ProviderName=@('Microsoft-Windows-Kernel-Power','EventLog','Microsoft-Windows-WHEA-Logger','disk','Ntfs','volmgr');$filter.Id=@(7,11,15,17,18,19,20,41,51,55,57,98,129,140,153,157,161,6008) }
    # Do not access Message, Properties, ToXml, UserId or MachineName.
    try { $rows=@(Microsoft.PowerShell.Diagnostics\Get-WinEvent -FilterHashtable $filter -MaxEvents $maximum -ErrorAction Stop) }
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

if ($RequestPath) {
 $ErrorActionPreference='Stop'
 Assert-SystemModules
 $request=Assert-PatchCairnRecord -Record (Read-StrictJsonFile -Path $RequestPath) -Schema 'patchcairn.diagnostics'
 $facts=if ($FixturePath) { Read-StrictJsonFile -Path $FixturePath } else { $null }
 $json=Invoke-WindowsDiagnostic -Request $request -FixtureFacts $facts -CoordinatorAuthorized:$CoordinatorAuthorized | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 8 -Compress
 Assert-SystemModules
 $json
}
