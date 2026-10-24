[CmdletBinding(DefaultParameterSetName='OneShot')]
param(
 [Parameter(Mandatory=$true,ParameterSetName='OneShot')][string]$RequestPath,
 [Parameter(Mandatory=$true,ParameterSetName='Serve')][switch]$Serve,
 [Parameter(Mandatory=$true,ParameterSetName='Serve')][string]$RepositoryRoot,
 [Parameter(Mandatory=$true,ParameterSetName='Serve')][string]$RequestRoot,
 [Parameter(Mandatory=$true,ParameterSetName='Serve')][string]$WorkerDirectory,
 [Parameter(Mandatory=$true,ParameterSetName='Serve')][string]$Generation,
 [Parameter(Mandatory=$true,ParameterSetName='Serve')][string]$ExpectedDispatcherSha256,
 [Parameter(Mandatory=$true,ParameterSetName='Serve')][string]$ExpectedNativeSha256
)
$env:TZ='UTC'
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)

# Explicit legacy mode. This branch retains the original one-shot admission,
# Add-Type path, eight operations, JSON response and exit-code behavior.
if ($PSCmdlet.ParameterSetName -eq 'OneShot') {
 $repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
 $work=[IO.Path]::GetFullPath((Join-Path $repo 'work'))
 $request=[IO.Path]::GetFullPath($RequestPath)
 if (-not $request.StartsWith($work+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'scoped:request-outside-work' }
 if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'scoped:windows-required' }
 # CodeDOM on Windows PowerShell uses TEMP. Keep compilation files inside this owned request directory.
 $temp=Split-Path -Parent $request
 if (-not (Test-Path -LiteralPath $temp -PathType Container)) { throw 'scoped:request-parent-missing' }
 $cursor=$temp
 while ($cursor) { if (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'scoped:request-reparse' }; $parent=[IO.Path]::GetDirectoryName($cursor); if ($parent -eq $cursor) { break }; $cursor=$parent }
 $env:TEMP=$temp
 $env:TMP=$temp
 try {
  if ((Get-Item -LiteralPath $request).Length -gt 100000000 -or (([IO.File]::GetAttributes($request) -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'scoped:request-bound' }
  Add-Type -Path (Join-Path $PSScriptRoot 'Windows.Scoped.cs')
  [PatchCairn.WindowsScoped]::CheckCapabilities()
  $q=[IO.File]::ReadAllText($request) | ConvertFrom-Json
  if ($q.schema -ne 'patchcairn.windows-scoped.v3' -or $q.quiet_workspace -ne $true) { throw 'scoped:request-contract' }
  function To-Record($value) {
   if ($null -eq $value) { return $null }
   $r=New-Object PatchCairn.ScopedRecord
   foreach ($name in @('relative_path','kind','inode','sha256','device','mode','size','mtime_ns','ctime_ns','nlink','attributes')) { $r.$name=$value.$name }
   return $r
  }
  $rootRecord=To-Record $q.root_record
  $result=$null
  switch -Exact ($q.operation) {
   'probe' { $result=@{ available=$true; reason=$null; adapter='windows-scoped-handles-v3'; platform='windows'; pinning=$true; pinning_scope='ordinary-ancestors-and-file-per-operation'; filesystem='ntfs-only'; move_noreplace=$true; remove_exact_file=$true; remove_file=$true; mkdir=$true; create_file=$true; read_bytes=$true; stream_to=$true; stream_max_bytes=67108864; max_read_bytes=67108864; quiet_workspace_required=$true } }
   'inspect' { $result=[PatchCairn.WindowsScoped]::Inspect($q.root,$q.relative,[bool]$q.hash_file,[long]$q.max_bytes,$rootRecord) }
   'list' { $result=@([PatchCairn.WindowsScoped]::List($q.root,$q.relative,[int]$q.max_entries,$rootRecord)) }
   'read' { $bytes=[PatchCairn.WindowsScoped]::Read($q.root,$q.relative,(To-Record $q.expected),[long]$q.max_bytes,$rootRecord); $result=@{ data_base64=[Convert]::ToBase64String($bytes) } }
   'move' { $result=[PatchCairn.WindowsScoped]::Move($q.root,$q.relative,$q.destination_root,$q.destination_relative,(To-Record $q.expected),$rootRecord,(To-Record $q.destination_root_record)) }
   'remove' { [PatchCairn.WindowsScoped]::Remove($q.root,$q.relative,(To-Record $q.expected),$rootRecord); $result=@{ removed=$true } }
   'mkdir' { $result=[PatchCairn.WindowsScoped]::Mkdir($q.root,$q.relative,$rootRecord) }
   'create' { $result=[PatchCairn.WindowsScoped]::Create($q.root,$q.relative,[Convert]::FromBase64String($q.data_base64),[long]$q.max_bytes,$rootRecord) }
   default { throw 'scoped:unknown-operation' }
  }
  @{ ok=$true; result=$result } | ConvertTo-Json -Depth 8 -Compress
 } catch {
  $code='native-operation-refused'
  $message=$_.Exception.ToString()
  if ($message -match 'scoped:([a-z0-9-]+)') { $code=$Matches[1] }
  @{ ok=$false; code=$code } | ConvertTo-Json -Compress
  exit 2
 }
 return
}

# Serve mode is a fixed, parent-owned child, not a reconnectable service.
# The parent admits private namespaces and retains deny-write/delete pins on
# the source snapshots, packet and ordinary ancestors through response storage.
# It also owns process/job lifetime and per-request deadlines. Nothing here
# accepts an approval flag, command, source path or native method selector.
$ProgressPreference='SilentlyContinue'
$WarningPreference='SilentlyContinue'
$InformationPreference='SilentlyContinue'
$VerbosePreference='SilentlyContinue'
$DebugPreference='SilentlyContinue'
$script:WorkerProtocol='patchcairn.windows-worker.v1'
$script:WorkerUtf8=New-Object Text.UTF8Encoding($false,$true)
$script:WorkerInput=$null
$script:WorkerOutput=$null
[char[]]$script:WorkerJsonStops=New-Object char[] 34
$script:WorkerJsonStops[0]=[char]34;$script:WorkerJsonStops[1]=[char]92
for ($control=0;$control -lt 32;$control++) { $script:WorkerJsonStops[$control+2]=[char]$control }
$control=$null

function Stop-WorkerProtocol {
 throw 'worker:protocol-refused'
}

function Get-WorkerFullPath([string]$Value) {
 if ([string]::IsNullOrEmpty($Value) -or $Value.Length -gt 240 -or $Value -notmatch '\A[A-Za-z]:[\\/]') { Stop-WorkerProtocol }
 $normalized=$Value.Replace('/','\').TrimEnd('\')
 $full=[IO.Path]::GetFullPath($Value).TrimEnd('\')
 if ($full.Length -lt 4 -or -not [string]::Equals($normalized,$full,[StringComparison]::OrdinalIgnoreCase)) { Stop-WorkerProtocol }
 foreach ($part in $full.Substring(3).Split('\')) {
  if ([string]::IsNullOrEmpty($part) -or $part -eq '.' -or $part -eq '..' -or $part.EndsWith('.') -or $part.EndsWith(' ') -or $part.IndexOfAny([char[]]@(':','*','?','<','>','|','"')) -ge 0) { Stop-WorkerProtocol }
  foreach ($character in $part.ToCharArray()) { if ([int]$character -lt 32) { Stop-WorkerProtocol } }
 }
 return $full
}

function Assert-WorkerOrdinaryAncestry([string]$Path,[bool]$Directory) {
 $cursor=$Path
 $leaf=$true
 while (-not [string]::IsNullOrEmpty($cursor)) {
  $attributes=[IO.File]::GetAttributes($cursor)
  if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Stop-WorkerProtocol }
  $isDirectory=($attributes -band [IO.FileAttributes]::Directory) -ne 0
  $requiredDirectory=if ($leaf) { $Directory } else { $true }
  if ($isDirectory -ne $requiredDirectory) { Stop-WorkerProtocol }
  $parent=[IO.Path]::GetDirectoryName($cursor)
  if ($parent -eq $cursor) { break }
  $cursor=$parent
  $leaf=$false
 }
}

function Read-WorkerFileBytes([string]$Path,[long]$Maximum) {
 Assert-WorkerOrdinaryAncestry $Path $false
 $stream=$null
 try {
  $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  $length=$stream.Length
  if ($length -lt 1 -or $length -gt $Maximum -or $length -gt [int]::MaxValue) { Stop-WorkerProtocol }
  [byte[]]$buffer=New-Object byte[] ([int]$length)
  $offset=0
  while ($offset -lt $buffer.Length) {
   $count=$stream.Read($buffer,$offset,$buffer.Length-$offset)
   if ($count -le 0) { Stop-WorkerProtocol }
   $offset+=$count
  }
  if ($stream.ReadByte() -ne -1 -or $stream.Length -ne $length) { Stop-WorkerProtocol }
  Assert-WorkerOrdinaryAncestry $Path $false
  # A byte array must be one return value, never one pipeline item per byte.
  return ,$buffer
 } finally {
  if ($null -ne $stream) { $stream.Dispose() }
 }
}

function Get-WorkerSha256([byte[]]$Bytes) {
 $sha=[Security.Cryptography.SHA256]::Create()
 try { return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','').ToLowerInvariant() }
 finally { $sha.Dispose() }
}

function Read-WorkerExact([IO.Stream]$Stream,[int]$Length,[bool]$AllowCleanEof) {
 [byte[]]$buffer=New-Object byte[] $Length
 $offset=0
 while ($offset -lt $Length) {
  $count=$Stream.Read($buffer,$offset,$Length-$offset)
  if ($count -eq 0) {
   if ($offset -eq 0 -and $AllowCleanEof) { return $null }
   Stop-WorkerProtocol
  }
  if ($count -lt 0) { Stop-WorkerProtocol }
  $offset+=$count
 }
 return ,$buffer
}

function Read-WorkerFrame {
 [byte[]]$header=Read-WorkerExact $script:WorkerInput 8 $true
 if ($null -eq $header) { return $null }
 if ($header[0] -ne 80 -or $header[1] -ne 67 -or $header[2] -ne 87 -or $header[3] -ne 49) { Stop-WorkerProtocol }
 [uint64]$length=[uint64]$header[4]+([uint64]$header[5]*256)+([uint64]$header[6]*65536)+([uint64]$header[7]*16777216)
 if ($length -lt 1 -or $length -gt 8192) { Stop-WorkerProtocol }
 [byte[]]$body=Read-WorkerExact $script:WorkerInput ([int]$length) $false
 return $script:WorkerUtf8.GetString($body)
}

function Write-WorkerFrame([object]$Value) {
 $json=ConvertTo-Json -InputObject $Value -Depth 12 -Compress
 [byte[]]$body=$script:WorkerUtf8.GetBytes($json)
 if ($body.Length -lt 1 -or $body.Length -gt 100000000) { Stop-WorkerProtocol }
 [byte[]]$header=New-Object byte[] 8
 $header[0]=80;$header[1]=67;$header[2]=87;$header[3]=49
 [uint32]$length=$body.Length
 $header[4]=[byte]($length -band 255)
 $header[5]=[byte](($length -shr 8) -band 255)
 $header[6]=[byte](($length -shr 16) -band 255)
 $header[7]=[byte](($length -shr 24) -band 255)
 $script:WorkerOutput.Write($header,0,$header.Length)
 $script:WorkerOutput.Write($body,0,$body.Length)
 $script:WorkerOutput.Flush()
}

function Skip-WorkerJsonWhitespace([string]$Text,[ref]$Position) {
 while ($Position.Value -lt $Text.Length -and @([char]32,[char]9,[char]10,[char]13) -contains $Text[$Position.Value]) { $Position.Value++ }
}

function Read-WorkerJsonString([string]$Text,[ref]$Position,[bool]$Key) {
 if ($Position.Value -ge $Text.Length -or $Text[$Position.Value] -ne [char]34) { Stop-WorkerProtocol }
 $start=$Position.Value
 $index=$start+1
 $closed=$false
 while ($index -lt $Text.Length) {
  # This lexer sees only the <=8-KiB envelope, never packet Base64. Native
  # IndexOfAny skips an ordinary run; PowerShell visits only special characters.
  $special=$Text.IndexOfAny($script:WorkerJsonStops,$index)
  if ($special -lt 0) { Stop-WorkerProtocol }
  $index=$special
  $character=$Text[$index]
  if ($character -eq [char]34) { $index++;$closed=$true;break }
  if ([int]$character -lt 32 -or $Key) { Stop-WorkerProtocol }
  # The remaining stop character is backslash. Escapes are checked explicitly.
  $index++
  if ($index -ge $Text.Length) { Stop-WorkerProtocol }
  $escape=$Text[$index]
  if ($escape -eq [char]117) {
   if ($index+4 -ge $Text.Length -or $Text.Substring($index+1,4) -notmatch '\A[0-9a-fA-F]{4}\z') { Stop-WorkerProtocol }
   $index+=4
  } elseif (@([char]34,[char]92,[char]47,[char]98,[char]102,[char]110,[char]114,[char]116) -notcontains $escape) { Stop-WorkerProtocol }
  $index++
 }
 if (-not $closed) { Stop-WorkerProtocol }
 if ($Key -and $index-$start -gt 66) { Stop-WorkerProtocol }
 $token=$Text.Substring($start,$index-$start)
 $Position.Value=$index
 $holder=ConvertFrom-Json -InputObject ('{"value":'+$token+'}') -ErrorAction Stop
 if ($holder.value -isnot [string]) { Stop-WorkerProtocol }
 return ,([string]$holder.value)
}

function Read-WorkerEnvelope([string]$Text) {
 $allowed=@('protocol','generation','sequence','request_id','request_path','request_sha256','operation')
 $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
 $values=New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
 $position=0
 Skip-WorkerJsonWhitespace $Text ([ref]$position)
 if ($position -ge $Text.Length -or $Text[$position] -ne [char]123) { Stop-WorkerProtocol }
 $position++
 Skip-WorkerJsonWhitespace $Text ([ref]$position)
 if ($position -lt $Text.Length -and $Text[$position] -eq [char]125) { $position++ }
 else {
  while ($true) {
   $key=Read-WorkerJsonString $Text ([ref]$position) $true
   if ($allowed -cnotcontains $key -or -not $seen.Add($key)) { Stop-WorkerProtocol }
   Skip-WorkerJsonWhitespace $Text ([ref]$position)
   if ($position -ge $Text.Length -or $Text[$position] -ne [char]58) { Stop-WorkerProtocol }
   $position++
   Skip-WorkerJsonWhitespace $Text ([ref]$position)
   if ($key -ceq 'sequence') {
    $start=$position
    while ($position -lt $Text.Length -and [int]$Text[$position] -ge 48 -and [int]$Text[$position] -le 57) { $position++ }
    $number=$Text.Substring($start,$position-$start)
    if ($number -notmatch '\A[1-9][0-9]{0,2}\z') { Stop-WorkerProtocol }
    $value=[int]$number
    if ($value -gt 256) { Stop-WorkerProtocol }
   } else {
    $value=Read-WorkerJsonString $Text ([ref]$position) $false
   }
   $values.Add($key,$value)
   Skip-WorkerJsonWhitespace $Text ([ref]$position)
   if ($position -ge $Text.Length) { Stop-WorkerProtocol }
   if ($Text[$position] -eq [char]125) { $position++;break }
   if ($Text[$position] -ne [char]44) { Stop-WorkerProtocol }
   $position++
   Skip-WorkerJsonWhitespace $Text ([ref]$position)
  }
 }
 Skip-WorkerJsonWhitespace $Text ([ref]$position)
 if ($position -ne $Text.Length -or $values.Count -ne 7) { Stop-WorkerProtocol }
 return ,$values
}


function Skip-WorkerPayloadWhitespace([string]$Text,[ref]$Position,[object]$State) {
 Skip-WorkerJsonWhitespace $Text $Position
}

function Read-WorkerPayloadStringSpan([string]$Text,[ref]$Position,[string]$Member) {
 if ($Position.Value -ge $Text.Length -or $Text[$Position.Value] -ne [char]34) { Stop-WorkerProtocol }
 $start=$Position.Value
 $index=$start+1
 $closed=$false
 $escaped=$false
 $maximum=4096
 if ($Member -ceq 'data_base64') { $maximum=89478490 }
 while ($index -lt $Text.Length) {
  $special=$Text.IndexOfAny($script:WorkerJsonStops,$index)
  if ($special -lt 0 -or $special-$start -ge $maximum) { Stop-WorkerProtocol }
  $index=$special
  $character=$Text[$index]
  if ($character -eq [char]34) { $index++;$closed=$true;break }
  if ([int]$character -lt 32 -or $Member -ceq 'data_base64') { Stop-WorkerProtocol }
  $escaped=$true
  $index++
  if ($index -ge $Text.Length) { Stop-WorkerProtocol }
  $escape=$Text[$index]
  if ($escape -eq [char]117) {
   if ($index+4 -ge $Text.Length -or $Text.Substring($index+1,4) -notmatch '\A[0-9a-fA-F]{4}\z') { Stop-WorkerProtocol }
   $index+=4
  } elseif (@([char]34,[char]92,[char]47,[char]98,[char]102,[char]110,[char]114,[char]116) -notcontains $escape) { Stop-WorkerProtocol }
  $index++
 }
 if (-not $closed -or $index-$start -gt $maximum) { Stop-WorkerProtocol }
 $Position.Value=$index
 # Retain indices and kind, not a second large Base64 string or decoded payload.
 return [pscustomobject]@{ Kind='string'; Start=$start; Length=($index-$start); Escaped=$escaped }
}

function Read-WorkerPayloadValue([string]$Text,[ref]$Position,[int]$Depth,[string]$Member,[object]$State) {
 $State.Values++
 if ($Depth -gt 3 -or $State.Values -gt 64) { Stop-WorkerProtocol }
 Skip-WorkerPayloadWhitespace $Text $Position $State
 if ($Position.Value -ge $Text.Length) { Stop-WorkerProtocol }
 $character=$Text[$Position.Value]
 if ($character -eq [char]123) {
  $Position.Value++
  $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  $members=New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
  Skip-WorkerPayloadWhitespace $Text $Position $State
  if ($Position.Value -lt $Text.Length -and $Text[$Position.Value] -eq [char]125) { $Position.Value++ }
  else {
   while ($true) {
    if ($members.Count -ge 16) { Stop-WorkerProtocol }
    $key=Read-WorkerJsonString $Text $Position $true
    if (-not $seen.Add($key)) { Stop-WorkerProtocol }
    Skip-WorkerPayloadWhitespace $Text $Position $State
    if ($Position.Value -ge $Text.Length -or $Text[$Position.Value] -ne [char]58) { Stop-WorkerProtocol }
    $Position.Value++
    $child=Read-WorkerPayloadValue $Text $Position ($Depth+1) $key $State
    $members.Add($key,$child)
    Skip-WorkerPayloadWhitespace $Text $Position $State
    if ($Position.Value -ge $Text.Length) { Stop-WorkerProtocol }
    if ($Text[$Position.Value] -eq [char]125) { $Position.Value++;break }
    if ($Text[$Position.Value] -ne [char]44) { Stop-WorkerProtocol }
    $Position.Value++
    Skip-WorkerPayloadWhitespace $Text $Position $State
   }
  }
  return [pscustomobject]@{ Kind='object'; Members=$members }
 }
 if ($character -eq [char]34) { return Read-WorkerPayloadStringSpan $Text $Position $Member }
 if ($Text.Length-$Position.Value -ge 4 -and $Text.Substring($Position.Value,4) -ceq 'null') {
  $Position.Value+=4
  return [pscustomobject]@{ Kind='null' }
 }
 if ($Text.Length-$Position.Value -ge 4 -and $Text.Substring($Position.Value,4) -ceq 'true') {
  $Position.Value+=4
  return [pscustomobject]@{ Kind='boolean'; Boolean=$true }
 }
 if ($Text.Length-$Position.Value -ge 5 -and $Text.Substring($Position.Value,5) -ceq 'false') {
  $Position.Value+=5
  return [pscustomobject]@{ Kind='boolean'; Boolean=$false }
 }
 if ($character -eq [char]45 -or ([int]$character -ge 48 -and [int]$character -le 57)) {
  [char[]]$stops=@([char]44,[char]125,[char]93,[char]32,[char]9,[char]10,[char]13)
  $end=$Text.IndexOfAny($stops,$Position.Value)
  if ($end -lt 0) { $end=$Text.Length }
  $length=$end-$Position.Value
  if ($length -lt 1 -or $length -gt 20) { Stop-WorkerProtocol }
  $number=$Text.Substring($Position.Value,$length)
  # No exponent, fraction, sign-plus, nonfinite token, leading zero or -0.
  if ($number -notmatch '\A(?:0|-?[1-9][0-9]*)\z') { Stop-WorkerProtocol }
  $exact=[long]::Parse($number,[Globalization.NumberStyles]::AllowLeadingSign,[Globalization.CultureInfo]::InvariantCulture)
  $Position.Value=$end
  return [pscustomobject]@{ Kind='integer'; Number=$exact }
 }
 # Arrays and all other literals/shapes are outside the fixed v3 packet schema.
 Stop-WorkerProtocol
}

function Assert-WorkerPayloadKeys([object]$Token,[string[]]$Names) {
 if ($Token.Kind -cne 'object' -or $Token.Members.Count -ne $Names.Count) { Stop-WorkerProtocol }
 foreach ($name in $Names) { if (-not $Token.Members.ContainsKey($name)) { Stop-WorkerProtocol } }
}

function Assert-WorkerPayloadString([object]$Token) {
 if ($Token.Kind -cne 'string') { Stop-WorkerProtocol }
}

function Assert-WorkerPayloadInteger([object]$Token,[long]$Minimum,[long]$Maximum) {
 if ($Token.Kind -cne 'integer' -or $Token.Number -lt $Minimum -or $Token.Number -gt $Maximum) { Stop-WorkerProtocol }
}

function Assert-WorkerPayloadRecord([object]$Token,[bool]$AllowNull) {
 if ($Token.Kind -ceq 'null') {
  if (-not $AllowNull) { Stop-WorkerProtocol }
  return
 }
 Assert-WorkerPayloadKeys $Token @('relative_path','kind','inode','sha256','device','mode','size','mtime_ns','ctime_ns','nlink','attributes')
 foreach ($name in @('relative_path','kind','inode')) { Assert-WorkerPayloadString $Token.Members[$name] }
 if ($Token.Members['sha256'].Kind -cne 'string' -and $Token.Members['sha256'].Kind -cne 'null') { Stop-WorkerProtocol }
 foreach ($name in @('device','mode','nlink','attributes')) { Assert-WorkerPayloadInteger $Token.Members[$name] 0 4294967295 }
 Assert-WorkerPayloadInteger $Token.Members['size'] 0 ([long]::MaxValue)
 foreach ($name in @('mtime_ns','ctime_ns')) { Assert-WorkerPayloadInteger $Token.Members[$name] ([long]::MinValue) ([long]::MaxValue) }
}

function Assert-WorkerPayloadShape([string]$Text,[object]$Token,[string]$Operation) {
 $common=@('schema','operation','quiet_workspace','root_record')
 $names=$null
 switch -CaseSensitive -Exact ($Operation) {
  'probe' { $names=$common }
  'inspect' { $names=$common+@('root','relative','hash_file','max_bytes') }
  'list' { $names=$common+@('root','relative','max_entries') }
  'read' { $names=$common+@('root','relative','expected','max_bytes') }
  'move' { $names=$common+@('root','relative','destination_root','destination_relative','expected','destination_root_record') }
  'remove' { $names=$common+@('root','relative','expected') }
  'mkdir' { $names=$common+@('root','relative') }
  'create' { $names=$common+@('root','relative','data_base64','max_bytes') }
  default { Stop-WorkerProtocol }
 }
 Assert-WorkerPayloadKeys $Token $names
 Assert-WorkerPayloadString $Token.Members['schema']
 Assert-WorkerPayloadString $Token.Members['operation']
 if ($Token.Members['quiet_workspace'].Kind -cne 'boolean' -or $Token.Members['quiet_workspace'].Boolean -ne $true) { Stop-WorkerProtocol }
 Assert-WorkerPayloadRecord $Token.Members['root_record'] ($Operation -ceq 'probe' -or $Operation -ceq 'inspect')
 if ($Operation -ceq 'probe') {
  if ($Token.Members['root_record'].Kind -cne 'null') { Stop-WorkerProtocol }
  return
 }
 foreach ($name in @('root','relative')) { Assert-WorkerPayloadString $Token.Members[$name] }
 if ($Operation -ceq 'inspect') {
  if ($Token.Members['hash_file'].Kind -cne 'boolean') { Stop-WorkerProtocol }
  Assert-WorkerPayloadInteger $Token.Members['max_bytes'] 1 68719476736
 }
 if ($Operation -ceq 'list') { Assert-WorkerPayloadInteger $Token.Members['max_entries'] 1 20000 }
 if ($Operation -ceq 'read' -or $Operation -ceq 'create') { Assert-WorkerPayloadInteger $Token.Members['max_bytes'] 1 67108864 }
 if (@('read','move','remove') -ccontains $Operation) { Assert-WorkerPayloadRecord $Token.Members['expected'] $false }
 if ($Operation -ceq 'move') {
  foreach ($name in @('destination_root','destination_relative')) { Assert-WorkerPayloadString $Token.Members[$name] }
  Assert-WorkerPayloadRecord $Token.Members['destination_root_record'] $false
 }
 if ($Operation -ceq 'create') {
  $data=$Token.Members['data_base64']
  Assert-WorkerPayloadString $data
  $maximum=([long][Math]::Ceiling($Token.Members['max_bytes'].Number/3.0))*4+2
  if ($data.Escaped -or $data.Length -gt $maximum) { Stop-WorkerProtocol }
  # Match a bounded span directly; never materialize another 64-MiB Base64 copy.
  $base64=New-Object Text.RegularExpressions.Regex '\G[A-Za-z0-9+/]*={0,2}'
  $match=$base64.Match($Text,($data.Start+1),($data.Length-2))
  if (-not $match.Success -or $match.Length -ne $data.Length-2) { Stop-WorkerProtocol }
  $match=$null;$base64=$null
 }
}

function Read-WorkerPayload([string]$Text,[string]$Operation) {
 $state=[pscustomobject]@{ Values=0 }
 $position=0
 $token=Read-WorkerPayloadValue $Text ([ref]$position) 0 '' $state
 Skip-WorkerPayloadWhitespace $Text ([ref]$position) $state
 if ($position -ne $Text.Length) { Stop-WorkerProtocol }
 Assert-WorkerPayloadShape $Text $token $Operation
 $state=$null
 return $token
}

function Assert-WorkerParsedAgreement([object]$Token,[object]$Parsed) {
 switch -CaseSensitive -Exact ($Token.Kind) {
  'object' {
   if ($Parsed -isnot [pscustomobject] -or @($Parsed.PSObject.Properties).Count -ne $Token.Members.Count) { Stop-WorkerProtocol }
   foreach ($name in $Token.Members.Keys) { Assert-WorkerParsedAgreement $Token.Members[$name] $Parsed.$name }
  }
  'string' { if ($Parsed -isnot [string]) { Stop-WorkerProtocol } }
  'boolean' { if ($Parsed -isnot [bool] -or $Parsed -ne $Token.Boolean) { Stop-WorkerProtocol } }
  'integer' {
   # Validate the lexical Int64 before any C# assignment. Never round/repair a
   # Double/Decimal/bool result from an edition-specific JSON parser.
   if (($Parsed -isnot [int] -and $Parsed -isnot [long]) -or [long]$Parsed -ne $Token.Number) { Stop-WorkerProtocol }
  }
  'null' { if ($null -ne $Parsed) { Stop-WorkerProtocol } }
  default { Stop-WorkerProtocol }
 }
}

function Assert-WorkerParsedRecord([object]$Record,[bool]$Root) {
 if ($null -eq $Record) { return }
 if ($Record.inode -cnotmatch '\A[a-f0-9]{16}\z' -or $Record.relative_path.Length -gt 200) { Stop-WorkerProtocol }
 if ($Root) {
  if ($Record.kind -cne 'directory' -or $Record.relative_path -cne '' -or $Record.size -ne 0 -or $null -ne $Record.sha256) { Stop-WorkerProtocol }
 } else {
  if ($Record.kind -cne 'file' -or $Record.sha256 -isnot [string] -or $Record.sha256 -cnotmatch '\A[a-f0-9]{64}\z' -or $Record.nlink -ne 1) { Stop-WorkerProtocol }
 }
}

function Assert-WorkerParsedPayload([object]$Tree,[object]$q,[string]$Operation) {
 Assert-WorkerParsedAgreement $Tree $q
 if ($q.schema -cne 'patchcairn.windows-scoped.v3' -or $q.operation -cne $Operation -or $q.quiet_workspace -ne $true) { Stop-WorkerProtocol }
 Assert-WorkerParsedRecord $q.root_record $true
 if ($Operation -cne 'probe') {
  if ($q.root.Length -gt 240 -or $q.relative.Length -gt 200) { Stop-WorkerProtocol }
 }
 if (@('read','move','remove') -ccontains $Operation) { Assert-WorkerParsedRecord $q.expected $false }
 if ($Operation -ceq 'move') {
  if ($q.destination_root.Length -gt 240 -or $q.destination_relative.Length -gt 200) { Stop-WorkerProtocol }
  Assert-WorkerParsedRecord $q.destination_root_record $true
 }
}

function Invoke-WorkerNativeRequest([object]$q) {
 # Fresh function scope for every call. These are the same eight operations and
 # native arguments as the explicit one-shot path; no selected handles survive.
 try {
  function To-WorkerRecord($value) {
   if ($null -eq $value) { return $null }
   $r=New-Object PatchCairn.ScopedRecord
   foreach ($name in @('relative_path','kind','inode','sha256','device','mode','size','mtime_ns','ctime_ns','nlink','attributes')) { $r.$name=$value.$name }
   return $r
  }
  $rootRecord=To-WorkerRecord $q.root_record
  $result=$null
  switch -Exact ($q.operation) {
   'probe' { $result=@{ available=$true; reason=$null; adapter='windows-scoped-handles-v3'; platform='windows'; pinning=$true; pinning_scope='ordinary-ancestors-and-file-per-operation'; filesystem='ntfs-only'; move_noreplace=$true; remove_exact_file=$true; remove_file=$true; mkdir=$true; create_file=$true; read_bytes=$true; stream_to=$true; stream_max_bytes=67108864; max_read_bytes=67108864; quiet_workspace_required=$true } }
   'inspect' { $result=[PatchCairn.WindowsScoped]::Inspect($q.root,$q.relative,[bool]$q.hash_file,[long]$q.max_bytes,$rootRecord) }
   'list' { $result=@([PatchCairn.WindowsScoped]::List($q.root,$q.relative,[int]$q.max_entries,$rootRecord)) }
   'read' { $bytes=[PatchCairn.WindowsScoped]::Read($q.root,$q.relative,(To-WorkerRecord $q.expected),[long]$q.max_bytes,$rootRecord); $result=@{ data_base64=[Convert]::ToBase64String($bytes) } }
   'move' { $result=[PatchCairn.WindowsScoped]::Move($q.root,$q.relative,$q.destination_root,$q.destination_relative,(To-WorkerRecord $q.expected),$rootRecord,(To-WorkerRecord $q.destination_root_record)) }
   'remove' { [PatchCairn.WindowsScoped]::Remove($q.root,$q.relative,(To-WorkerRecord $q.expected),$rootRecord); $result=@{ removed=$true } }
   'mkdir' { $result=[PatchCairn.WindowsScoped]::Mkdir($q.root,$q.relative,$rootRecord) }
   'create' { $result=[PatchCairn.WindowsScoped]::Create($q.root,$q.relative,[Convert]::FromBase64String($q.data_base64),[long]$q.max_bytes,$rootRecord) }
   default { throw 'scoped:unknown-operation' }
  }
  return @{ ok=$true; result=$result }
 } catch {
  $code='native-operation-refused'
  $message=$_.Exception.ToString()
  if ($message -match 'scoped:([a-z0-9-]{1,80})') { $code=$Matches[1] }
  return @{ ok=$false; code=$code }
 }
}

try {
 if (-not $Serve.IsPresent -or [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or [IntPtr]::Size -ne 8 -or $ExecutionContext.SessionState.LanguageMode.ToString() -cne 'FullLanguage') { Stop-WorkerProtocol }
 if ($Generation -cnotmatch '\A[a-f0-9]{32}\z' -or $ExpectedDispatcherSha256 -cnotmatch '\A[a-f0-9]{64}\z' -or $ExpectedNativeSha256 -cnotmatch '\A[a-f0-9]{64}\z') { Stop-WorkerProtocol }
 $repo=Get-WorkerFullPath $RepositoryRoot
 $requests=Get-WorkerFullPath $RequestRoot
 $worker=Get-WorkerFullPath $WorkerDirectory
 $work=Join-Path $repo 'work'
 if (-not $requests.StartsWith($work+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { Stop-WorkerProtocol }
 if (-not [string]::Equals($worker,(Join-Path $requests ('worker-'+$Generation)),[StringComparison]::OrdinalIgnoreCase)) { Stop-WorkerProtocol }
 Assert-WorkerOrdinaryAncestry $repo $true
 Assert-WorkerOrdinaryAncestry $requests $true
 Assert-WorkerOrdinaryAncestry $worker $true
 $dispatcher=Get-WorkerFullPath $PSCommandPath
 $native=Join-Path $worker 'Windows.Scoped.cs'
 if (-not [string]::Equals($dispatcher,(Join-Path $worker 'Windows.Scoped.Dispatch.ps1'),[StringComparison]::OrdinalIgnoreCase)) { Stop-WorkerProtocol }
 [byte[]]$dispatcherBytes=Read-WorkerFileBytes $dispatcher 4000000
 [byte[]]$nativeBytes=Read-WorkerFileBytes $native 4000000
 $dispatcherSha=Get-WorkerSha256 $dispatcherBytes
 $nativeSha=Get-WorkerSha256 $nativeBytes
 if ($dispatcherSha -cne $ExpectedDispatcherSha256 -or $nativeSha -cne $ExpectedNativeSha256) { Stop-WorkerProtocol }
 $env:TEMP=$worker
 $env:TMP=$worker
 $nativeText=$script:WorkerUtf8.GetString($nativeBytes)
 if ($nativeText.Length -gt 0 -and $nativeText[0] -eq [char]0xfeff) { $nativeText=$nativeText.Substring(1) }
 Add-Type -TypeDefinition $nativeText -ErrorAction Stop | Out-Null
 [PatchCairn.WindowsScoped]::CheckCapabilities()
 $dispatcherBytes=$null;$nativeBytes=$null;$nativeText=$null
 $script:WorkerInput=[Console]::OpenStandardInput()
 $script:WorkerOutput=[Console]::OpenStandardOutput()
 Write-WorkerFrame @{ protocol=$script:WorkerProtocol; generation=$Generation; sequence=0; request_id=('0'*32); response=@{ ok=$true; result=@{ state='ready'; dispatcher_sha256=$dispatcherSha; native_sha256=$nativeSha; powershell_version=$PSVersionTable.PSVersion.ToString(); powershell_edition=[string]$PSVersionTable.PSEdition; bitness=64; language_mode='FullLanguage'; adapter='windows-scoped-handles-v3' } } }
 $requestIds=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
 $operations=@('probe','inspect','list','read','move','remove','mkdir','create')
 for ($nextSequence=1;$nextSequence -le 256;$nextSequence++) {
  $frame=$null;$envelope=$null;$packetBytes=$null;$packetText=$null;$payloadTree=$null;$q=$null;$body=$null
  try {
   $frame=Read-WorkerFrame
   if ($null -eq $frame) { break }
   $envelope=Read-WorkerEnvelope $frame
   if ($envelope['protocol'] -cne $script:WorkerProtocol -or $envelope['generation'] -cne $Generation -or $envelope['sequence'] -ne $nextSequence -or $envelope['request_id'] -cnotmatch '\A[a-f0-9]{32}\z' -or $envelope['request_id'] -ceq ('0'*32) -or $envelope['request_sha256'] -cnotmatch '\A[a-f0-9]{64}\z' -or $operations -cnotcontains $envelope['operation'] -or -not $requestIds.Add($envelope['request_id'])) { Stop-WorkerProtocol }
   $packet=Get-WorkerFullPath $envelope['request_path']
   $expectedPacket=Join-Path (Join-Path $requests ('request-'+$envelope['request_id'])) 'request.json'
   if (-not [string]::Equals($packet,$expectedPacket,[StringComparison]::OrdinalIgnoreCase)) { Stop-WorkerProtocol }
   [byte[]]$packetBytes=Read-WorkerFileBytes $packet 100000000
   if ((Get-WorkerSha256 $packetBytes) -cne $envelope['request_sha256']) { Stop-WorkerProtocol }
   $packetText=$script:WorkerUtf8.GetString($packetBytes)
   $payloadTree=Read-WorkerPayload $packetText $envelope['operation']
   $q=ConvertFrom-Json -InputObject $packetText -ErrorAction Stop
   Assert-WorkerParsedPayload $payloadTree $q $envelope['operation']
   $body=Invoke-WorkerNativeRequest $q
   Write-WorkerFrame @{ protocol=$script:WorkerProtocol; generation=$Generation; sequence=$nextSequence; request_id=$envelope['request_id']; response=$body }
  } finally {
   $frame=$null;$envelope=$null;$packet=$null;$expectedPacket=$null;$packetBytes=$null;$packetText=$null;$payloadTree=$null;$q=$null;$body=$null
   $Error.Clear()
  }
 }
} catch {
 # A protocol, source, packet-hash, startup or write ambiguity has no trustworthy
 # response correlation. Exit categorically; the parent preserves unknown effects.
 $Error.Clear()
 exit 3
} finally {
 $dispatcherBytes=$null;$nativeBytes=$null;$nativeText=$null
 $Error.Clear()
}
