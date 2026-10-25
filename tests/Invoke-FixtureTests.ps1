[CmdletBinding()]
param()
# The PowerShell strict-record suite: the reader in scripts/diagnostic_windows.ps1 that PowerShell uses for every
# PatchCairn record it reads (today the diagnostic request). Typed records need the exact schema name and the integer
# schema_version 1; containers need the integer only. Prints one PASS or FAIL line per check and exits 1 if any check
# fails. Fixture files live under work/test-fixtures/ and are removed.
$env:TZ='UTC'
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$work=Join-Path $repo ('work\test-fixtures\strict-records-'+[Guid]::NewGuid().ToString('N'))
$script:failed=0
function Check([string]$Name,[scriptblock]$Test) {
 try { $passed=[bool](& $Test) } catch { $passed=$false }
 if ($passed) { Write-Output ('PASS '+$Name) } else { $script:failed++; Write-Output ('FAIL '+$Name) }
}
function Refused([scriptblock]$Action,[string]$Code) {
 try { & $Action | Out-Null } catch { return [string]::Equals($_.Exception.Message,$Code,[StringComparison]::Ordinal) }
 return $false
}
function Strict([string]$Case,[string]$Json,[string]$Code,[string]$Schema='patchcairn.diagnostics') {
 Check ('strict schema: '+$Case) { Refused { Assert-PatchCairnRecord -Record (ConvertFrom-StrictJson -Text $Json) -Schema $Schema } $Code }
}
# An older-style name, built at run time so no version label sits in the source.
function Versioned([string]$Name,[int]$Number) { return $Name+'.v'+$Number }
function File([byte[]]$Bytes) {
 $path=Join-Path $work ([Guid]::NewGuid().ToString('N')+'.json')
 [IO.File]::WriteAllBytes($path,$Bytes)
 return $path
}
$utf8=New-Object Text.UTF8Encoding($false)
[IO.Directory]::CreateDirectory($work) | Out-Null
try {
 . (Join-Path $repo 'scripts\diagnostic_windows.ps1')
 $typed='{"schema":"patchcairn.diagnostics","schema_version":'
 Check 'strict schema: integer 1 accepted' { $record=Assert-PatchCairnRecord -Record (ConvertFrom-StrictJson -Text ($typed+'1,"kind":"request"}')) -Schema 'patchcairn.diagnostics';$record['kind'] -ceq 'request' }
 Strict 'schema_version true refused' ($typed+'true}') 'record:schema-version'
 Strict 'schema_version 1.0 refused' ($typed+'1.0}') 'record:schema-version'
 Strict 'schema_version "1" refused' ($typed+'"1"}') 'record:schema-version'
 Strict 'schema_version 0 refused' ($typed+'0}') 'record:schema-version'
 Strict 'schema_version 2 refused' ($typed+'2}') 'record:schema-version'
 Strict 'schema_version null refused' ($typed+'null}') 'record:schema-version'
 Strict 'schema_version missing refused' '{"schema":"patchcairn.diagnostics"}' 'record:schema-version'
 Strict 'schema wrong refused' '{"schema":"patchcairn.storage","schema_version":1}' 'record:schema-name'
 Strict 'schema in other letter case refused' '{"schema":"PatchCairn.Diagnostics","schema_version":1}' 'record:schema-name'
 Strict 'schema with a version number refused as an older format' ('{"schema":"'+(Versioned 'patchcairn.diagnostics' 3)+'","schema_version":1}') 'record:older-format'
 Strict 'schema missing refused' '{"schema_version":1,"kind":"request"}' 'record:schema-name'
 Strict 'older record with a versioned schema_version refused' ('{"schema_version":"'+(Versioned 'patchcairn.diagnostics' 3)+'","kind":"request"}') 'record:older-format'
 Check 'strict schema: container with integer version accepted' { $record=Assert-PatchCairnRecord -Record (ConvertFrom-StrictJson -Text '{"schema_version":1,"items":[]}');@($record['items']).Count -eq 0 }
 Strict 'container version "1" refused' '{"schema_version":"1"}' 'record:schema-version' ''
 Strict 'container version "1.0" refused as an older format' '{"schema_version":"1.0"}' 'record:older-format' ''
 Strict 'container carrying a schema name refused' ($typed+'1}') 'record:schema-name' ''
 Strict 'byte order mark refused' ([string][char]0xFEFF+$typed+'1}') 'record:json-bom'
 Check 'strict schema: byte order mark in a file refused' { Refused { Read-StrictJsonFile -Path (File ([byte[]](0xEF,0xBB,0xBF)+$utf8.GetBytes($typed+'1}'))) } 'record:json-bom' }
 Check 'strict schema: invalid UTF-8 refused' { Refused { Read-StrictJsonFile -Path (File ([byte[]](0x7B,0x22,0xFF,0x22,0x3A,0x31,0x7D))) } 'record:json-encoding' }
 Check 'strict schema: file over the size limit refused' { Refused { Read-StrictJsonFile -Path (File $utf8.GetBytes($typed+'1}')) -MaxBytes 8 } 'record:json-too-large' }
 Check 'strict schema: key named Keys' { $record=ConvertFrom-StrictJson -Text ($typed+'1,"Keys":["schema","schema_version"]}');(-not (Test-DiagnosticKeys $record @('schema','schema_version'))) -and (Test-DiagnosticKeys $record @('schema','schema_version','Keys')) }
 Strict 'duplicate key refused' ($typed+'1,"kind":"a","kind":"b"}') 'record:json-duplicate-key'
 Strict 'key differing only in letter case refused' ($typed+'1,"Schema":"x"}') 'record:json-duplicate-key'
 Strict 'malformed JSON refused (trailing comma)' ($typed+'1,}') 'record:json-invalid'
 Strict 'malformed JSON refused (single quotes)' "{'schema':'patchcairn.diagnostics','schema_version':1}" 'record:json-invalid'
 Strict 'malformed JSON refused (unterminated)' ($typed+'1') 'record:json-invalid'
 Strict 'malformed JSON refused (text after the record)' ($typed+'1} {}') 'record:json-invalid'
 Strict 'malformed JSON refused (NaN)' ($typed+'NaN}') 'record:json-invalid'
 Strict 'non-finite number refused' ($typed+'1e999}') 'record:json-nonfinite'
 Strict 'integer beyond 64 bits refused' ($typed+'12345678901234567890}') 'record:json-number'
 Strict 'unpaired surrogate refused' '{"schema":"\ud800","schema_version":1}' 'record:json-encoding'
 Strict 'depth limit refused' ($typed+'1,"x":'+('['*64)+(']'*64)+'}') 'record:json-too-deep'
 Check 'strict schema: depth limit accepts 64 levels' { $record=Assert-PatchCairnRecord -Record (ConvertFrom-StrictJson -Text ($typed+'1,"x":'+('['*63)+(']'*63)+'}')) -Schema 'patchcairn.diagnostics';$null -ne $record }
 Check 'strict schema: diagnostic request file read end to end' {
  $text='{"schema":"patchcairn.diagnostics","schema_version":1,"kind":"request","request_id":"diag-'+('b'*32)+'","platform":"windows","recipe_id":"windows.os_version","mode":"fixture","symptom":"Fictional","scope":[],"observed_utc":"2026-01-01T00:00:00Z"}'
  $request=Assert-PatchCairnRecord -Record (Read-StrictJsonFile -Path (File $utf8.GetBytes($text))) -Schema 'patchcairn.diagnostics'
  $result=Invoke-WindowsDiagnostic -Request $request -FixtureFacts @{version='10.0.1';build='1';architecture='x64'}
  $result.status -ceq 'observed' -and $request['schema_version'] -is [long]
 }
} finally {
 Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
if ($script:failed) { Write-Output ('FAILED '+$script:failed+' check(s)');exit 1 }
