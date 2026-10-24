# Requires Windows PowerShell5.1 or PowerShell7. No operation executes commands stored in data.
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'Private.Workspace.ps1')
$script:DefaultRoot=Split-Path -Parent $PSScriptRoot
$script:Utf8=New-Object Text.UTF8Encoding($false,$true)
$script:BackendId='windows-powershell-v2'
function Test-ToolkitWindowsHost {return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT}
function ConvertFrom-ToolkitJson([string]$Text) {
    if($null -eq $Text -or $Text.Length -gt 20000000 -or ($Text.Length -gt 0 -and [int]$Text[0] -eq 0xFEFF)){throw 'JSON must be bounded UTF-8 without BOM.'}
    $bytes=$script:Utf8.GetBytes($Text)
    if($bytes.Length -gt 20000000){throw 'JSON byte limit exceeded.'}
    if(-not ('System.Runtime.Serialization.Json.JsonReaderWriterFactory' -as [type])){Add-Type -AssemblyName System.Runtime.Serialization -ErrorAction Stop};
    $reader=[System.Runtime.Serialization.Json.JsonReaderWriterFactory]::CreateJsonReader($bytes,[Xml.XmlDictionaryReaderQuotas]::Max)
    $frames=New-Object Collections.Stack
    $scalarType=$null
    try {
        while($reader.Read()) {
            if($reader.Depth -gt 60){throw 'JSON nesting exceeds contract limit.'}
            if($reader.NodeType -eq [Xml.XmlNodeType]::Element) {
                if($frames.Count -and $frames.Peek().kind -ceq 'object') {
                    $key=$reader.GetAttribute('item');if($null -eq $key){$key=$reader.LocalName}
                    if([string]::IsNullOrEmpty($key) -or -not $frames.Peek().keys.Add($key)){throw 'Duplicate, empty or case-ambiguous JSON property name.'}
                }
                $kind=$reader.GetAttribute('type');$scalarType=$kind
                if($kind -in @('object','array')) {
                    $keys=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                    $frames.Push([pscustomobject]@{kind=$kind;depth=$reader.Depth;keys=$keys})
                }
            } elseif($reader.NodeType -eq [Xml.XmlNodeType]::EndElement) {
                if($frames.Count -and $frames.Peek().depth -eq $reader.Depth){$null=$frames.Pop()}
            } elseif($reader.NodeType -eq [Xml.XmlNodeType]::Text -and $scalarType -ceq 'number') {
                $number=0.0
                if(-not [double]::TryParse($reader.Value,[Globalization.NumberStyles]::Float,[Globalization.CultureInfo]::InvariantCulture,[ref]$number) -or [double]::IsInfinity($number) -or [double]::IsNaN($number)){throw 'Non-finite or out-of-range JSON number.'}
            }
        }
    } finally {$reader.Dispose()}
    if((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')){return ConvertFrom-Json -InputObject $Text -DateKind String}
    return ConvertFrom-Json -InputObject $Text
}
function ConvertTo-ToolkitJson($Value){return ConvertTo-Json -InputObject $Value -Depth 60 -Compress}
function Get-ToolkitHash([byte[]]$Bytes){$s=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($s.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
function Assert-ToolkitRelative([string]$Path){if([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('\') -or $Path.StartsWith('/') -or $Path.Length -gt 240){throw 'Expected a bounded slash-separated relative path.'};foreach($part in $Path.Split('/')){if($part -in @('.','..','') -or $part -cnotmatch '\A[a-zA-Z0-9_.-]+\z' -or $part.EndsWith('.') -or $part -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)'){throw 'Unsafe relative path.'}};return $Path}
function Assert-ToolkitOrdinary([string]$Path,[bool]$Directory){$i=Get-Item -LiteralPath $Path -Force -ErrorAction Stop;if(($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $i.PSIsContainer -ne $Directory){throw 'Reparse or wrong object type refused.'};return $i}
function Assert-ToolkitAncestors([string]$Path){$p=[IO.Path]::GetFullPath($Path);while($p){$null=Assert-ToolkitOrdinary $p $true;$next=[IO.Directory]::GetParent($p);if($null -eq $next){break};$p=$next.FullName}}
function Get-ToolkitContext([string]$ToolkitRoot=$script:DefaultRoot) {
    $root=[IO.Path]::GetFullPath($ToolkitRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $comparison=if((Test-ToolkitWindowsHost)){[StringComparison]::OrdinalIgnoreCase}else{[StringComparison]::Ordinal}
    $default=[IO.Path]::GetFullPath($script:DefaultRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $testParent=[IO.Path]::Combine($default,'work')+[IO.Path]::DirectorySeparatorChar
    if(-not [string]::Equals($root,$default,$comparison) -and -not $root.StartsWith($testParent,$comparison)){throw 'ToolkitRoot override must remain inside this toolkit work area; import the copied toolkit module for another location.'}
    Assert-ToolkitAncestors $root
    $marker=Read-ToolkitJsonFile (Join-Path $root 'toolkit.json') 65536
    $id=[Guid]::Empty
    if($marker.toolkit_id -isnot [string] -or -not [Guid]::TryParse($marker.toolkit_id,[ref]$id)){throw 'Toolkit marker lacks a valid toolkit_id.'}
    $contract=Get-ToolkitLedgerContract $root
    $work=Join-Path $root 'work'
    if(Test-Path -LiteralPath $work){Assert-ToolkitPrivateWorkspace $work}
    return [pscustomobject]@{Root=$root;Work=$work;Id=$id.ToString();Marker=$marker;Contract=$contract.Value;ContractSHA256=$contract.SHA256;Backend=$script:BackendId}
}
function Initialize-ToolkitWork($Context) {
    Assert-ToolkitAncestors $Context.Root
    New-ToolkitPrivateDirectory $Context.Work
}
function Open-ToolkitRunMarker($Context,[string]$RunId) {
    if($RunId -cnotmatch '\Arun-[a-f0-9]{32}\z'){throw 'Invalid run identifier before any operation write.'}
    $path=Join-Path $Context.Work $RunId
    Assert-ToolkitAncestors $path
    $markerPath=Join-Path $path 'run-marker.json'
    $null=Assert-ToolkitOrdinary $markerPath $false
    $stream=New-Object IO.FileStream($markerPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($stream.Length -gt 65536){throw 'Run marker exceeds limit.'}
        $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
        while($offset -lt $bytes.Length){$count=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($count -eq 0){throw 'Incomplete marker read.'};$offset+=$count}
        $marker=ConvertFrom-ToolkitJson ($script:Utf8.GetString($bytes))
        if($null -eq $marker.PSObject.Properties['backend'] -or $marker.backend -isnot [string] -or $marker.backend -cne $script:BackendId){throw 'Foreign or missing immutable run backend; no writes or migration. Use the creating backend or create a fresh run.'}
        return [pscustomobject]@{Stream=$stream;Marker=$marker;Bytes=$bytes}
    } catch {$stream.Dispose();throw}
}
function Get-ToolkitRun($Context,[string]$RunId) {
    $pin=Open-ToolkitRunMarker $Context $RunId
    try {
        $path=Join-Path $Context.Work $RunId
        foreach($name in @('ledger.json','owned-files.json','actions.jsonl')){$null=Assert-ToolkitOrdinary (Join-Path $path $name) $false}
        $marker=$pin.Marker;$owned=Read-ToolkitJsonFile (Join-Path $path 'owned-files.json')
        if($null -eq $marker.PSObject.Properties['creation_mode'] -or $null -eq $marker.PSObject.Properties['creation_platform'] -or $null -eq $owned.PSObject.Properties['marker_sha256']){throw 'Run lacks immutable creation metadata; create a fresh run. No automatic migration.'}
        if($marker.creation_mode -cnotin @('fixture','real') -or $marker.creation_platform -cnotin @('windows','linux','macos','unknown') -or (Get-ToolkitHash $pin.Bytes) -cne $owned.marker_sha256){throw 'Immutable creation marker changed or is invalid.'}
        if($marker.creation_mode -ceq 'real' -and ((-not (Test-ToolkitWindowsHost)) -or $marker.creation_platform -cne 'windows')){throw 'Windows backend real runs require the actual Windows platform.'}
        if($marker.toolkit_id -cne $Context.Id -or $marker.run_id -cne $RunId -or $marker.created_by -cne 'portable-toolkit' -or $marker.creation_nonce -cne $owned.creation_nonce){throw 'Positive run ownership marker mismatch.'}
        return [pscustomobject]@{Id=$RunId;Path=$path;Marker=$marker;Owned=$owned;Context=$Context}
    } finally {$pin.Stream.Dispose()}
}
function Enter-ToolkitLock($Context,[string]$RunId,[bool]$ForNewRun=$false) {
    if($RunId -cnotmatch '\Arun-[a-f0-9]{32}\z'){throw 'Invalid run identifier before lock creation.'}
    $markerPin=$null;$stream=$null
    try {
        if(-not $ForNewRun){$markerPin=Open-ToolkitRunMarker $Context $RunId}
        $dir=Get-ToolkitWorkArea $Context '_locks'
        $path=Join-Path $dir ($RunId+'.lock')
        try {$stream=New-ToolkitPrivateFileStream -Path $path -Access ReadWrite -Options DeleteOnClose} catch {throw 'Active or unresolved operation lock; stop, do not retry automatically.'}
        $lease=[pscustomobject]@{LockStream=$stream;MarkerPin=$markerPin}
        $lease|Add-Member -MemberType ScriptMethod -Name ReleaseMarkerPin -Value {if($this.MarkerPin){$this.MarkerPin.Stream.Dispose();$this.MarkerPin=$null}}
        $lease|Add-Member -MemberType ScriptMethod -Name Dispose -Value {$this.ReleaseMarkerPin();if($this.LockStream){$this.LockStream.Dispose();$this.LockStream=$null}}
        return $lease
    } catch {if($stream){$stream.Dispose()};if($markerPin){$markerPin.Stream.Dispose()};throw}
}
function Write-ToolkitNew([string]$Path,[byte[]]$Bytes){$f=New-ToolkitPrivateFileStream -Path $Path;try{$f.Write($Bytes,0,$Bytes.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Write-ToolkitControl([string]$Path,$Value){$null=Assert-ToolkitOrdinary $Path $false;$bytes=$script:Utf8.GetBytes((ConvertTo-ToolkitJson $Value));$tmp=Join-Path (Split-Path -Parent $Path) ('control-write-'+[Guid]::NewGuid().ToString('N')+'.tmp');Write-ToolkitNew $tmp $bytes;try{[IO.File]::Replace($tmp,$Path,[NullString]::Value)}catch{throw 'Atomic control replacement failed; preserve the existing control and temporary recovery file. No truncation fallback.'}}
function Add-ToolkitAudit($Run,[string]$Operation,[string]$Status,$Details){$row=[ordered]@{time_utc=[DateTime]::UtcNow.ToString('o');run_id=$Run.Id;operation=$Operation;status=$Status;details=$Details};$b=$script:Utf8.GetBytes((ConvertTo-ToolkitJson $row)+"`n");$f=New-Object IO.FileStream((Join-Path $Run.Path 'actions.jsonl'),[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$f.Write($b,0,$b.Length);$f.Flush($true)}finally{$f.Dispose()}}
function Assert-ToolkitEnum($Value,[string[]]$Allowed,[string]$Label){if($Value -isnot [string] -or $Value -cnotin $Allowed){throw ('Invalid '+$Label)}}
function Assert-ToolkitText($Value,[string]$Label,[bool]$Nullable=$false){if($null -eq $Value -and $Nullable){return};if($Value -isnot [string] -or $Value.Length -gt 16384){throw ('Expected bounded string: '+$Label)}}
function Assert-ToolkitArray($Value,[string]$Label){if($Value -isnot [array]){throw ('Expected JSON array: '+$Label)}}
function Read-ToolkitJsonFile([string]$Path,[long]$MaximumBytes=20000000) {
    $item=Assert-ToolkitOrdinary $Path $false
    if($item.Length -gt $MaximumBytes){throw 'Control JSON exceeds its bounded size.'}
    return ConvertFrom-ToolkitJson ($script:Utf8.GetString([IO.File]::ReadAllBytes($Path)))
}
function Get-ToolkitLedgerContract([string]$Root) {
    $path=Join-Path $Root 'templates/ledger-contract.json'
    Assert-ToolkitAncestors (Split-Path -Parent $path)
    $value=Read-ToolkitJsonFile $path 1000000
    if($value.schema_version -cne '1.0' -or $value.ledger_schema_version -cne '1.0' -or $value.backend_ids.windows -cne $script:BackendId){throw 'Unsupported shared ledger contract.'}
    foreach($section in @('root','run','coverage','component','finding','source','evidence','action','approval','diagnosis','hypothesis','alternative')) {
        if($null -eq $value.required_fields.PSObject.Properties[$section] -or $value.required_fields.$section -isnot [array]){throw 'Incomplete shared required-field contract.'}
    }
    return [pscustomobject]@{Value=$value;SHA256=(Get-ToolkitHash ([IO.File]::ReadAllBytes($path)))}
}
function Get-ToolkitContractEnum($Contract,[string]$Name) {
    $property=$Contract.enums.PSObject.Properties[$Name]
    if($null -eq $property -or $property.Value -isnot [array]){throw 'Missing shared enum contract.'}
    return @($property.Value)
}
function Assert-ToolkitRequired($Value,[string]$Section,$Contract) {
    if($null -eq $Value -or $Value -is [string] -or $Value -is [array]){throw ('Expected JSON object: '+$Section)}
    foreach($field in $Contract.required_fields.$Section) {if($null -eq $Value.PSObject.Properties[$field]){throw ('Missing '+$Section+' field: '+$field)}}
}
function Assert-ToolkitUtc($Value,[string]$Label,[bool]$Nullable,$Contract) {
    if($null -eq $Value -and $Nullable){return}
    Assert-ToolkitText $Value $Label
    $pattern='\A(?:'+$Contract.patterns.utc_timestamp+')\z'
    $parsed=[DateTimeOffset]::MinValue
    if($Value -cnotmatch $pattern -or -not [DateTimeOffset]::TryParse($Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal,[ref]$parsed) -or $parsed.Offset -ne [TimeSpan]::Zero){throw ('Expected a valid full UTC Z timestamp: '+$Label)}
}
function Assert-ToolkitContractRecord($Value,[string]$Section,$Contract) {
    Assert-ToolkitRequired $Value $Section $Contract
    foreach($property in @($Contract.array_fields.PSObject.Properties|Where-Object Name -ceq $Section)) {foreach($field in $property.Value){Assert-ToolkitArray $Value.$field ($Section+'.'+$field)}}
    foreach($property in @($Contract.boolean_fields.PSObject.Properties|Where-Object Name -ceq $Section)) {foreach($field in $property.Value){if($Value.$field -isnot [bool]){throw ('Expected boolean: '+$Section+'.'+$field)}}}
    foreach($property in @($Contract.utc_fields.PSObject.Properties|Where-Object Name -ceq $Section)) {foreach($field in $property.Value){$nullableProperty=$Contract.nullable_fields.PSObject.Properties[$Section];$nullable=($null -ne $nullableProperty -and $field -cin @($nullableProperty.Value));Assert-ToolkitUtc $Value.$field ($Section+'.'+$field) $nullable $Contract}}
    foreach($property in $Contract.enums.PSObject.Properties) {if($property.Name.StartsWith($Section+'.',[StringComparison]::Ordinal)){ $field=$property.Name.Substring($Section.Length+1);Assert-ToolkitEnum $Value.$field @($property.Value) ($Section+'.'+$field)}}
}
function New-ToolkitOrdinalMap {return New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)}
function Assert-ToolkitReference($Ids,[string]$Collection,$Value) {Assert-ToolkitText $Value 'reference';if([string]::IsNullOrWhiteSpace($Value) -or -not $Ids[$Collection].ContainsKey($Value)){throw ('Unknown exact reference in '+$Collection)}}
function ConvertTo-ToolkitMarkdown([string]$Text) {
    $escaped=[Net.WebUtility]::HtmlEncode($Text);$escaped=[regex]::Replace($escaped,'[\r\n\u2028\u2029]',' ')
    return [regex]::Replace($escaped,'[\\`*_{}\[\]()#+.!|>]',[Text.RegularExpressions.MatchEvaluator]{param($m)'\'+$m.Value})
}
function Assert-ToolkitLedger($Ledger,[string]$ToolkitId,[string]$RunId,$Contract) {
    if($null -eq $Contract){$Contract=(Get-ToolkitLedgerContract $script:DefaultRoot).Value}
    Assert-ToolkitContractRecord $Ledger 'root' $Contract
    if($Ledger.schema_version -cne $Contract.ledger_schema_version -or $Ledger.toolkit_id -cne $ToolkitId){throw 'Ledger schema/toolkit identity mismatch.'}
    Assert-ToolkitContractRecord $Ledger.run 'run' $Contract
    if($Ledger.run.id -cne $RunId -or $RunId -cnotmatch ('\A(?:'+$Contract.patterns.run_id+')\z')){throw 'Ledger run identity mismatch.'}
    foreach($field in @('id','purpose')){Assert-ToolkitText $Ledger.run.$field ('run.'+$field);if([string]::IsNullOrWhiteSpace($Ledger.run.$field)){throw 'Run identity/purpose cannot be empty.'}}

    $sets=[ordered]@{coverage='coverage';components='component';findings='finding';sources='source';evidence='evidence';actions='action';approvals='approval'}
    $ids=New-ToolkitOrdinalMap
    foreach($set in $sets.Keys) {
        $map=New-ToolkitOrdinalMap
        foreach($record in @($Ledger.$set)) {
            Assert-ToolkitContractRecord $record $sets[$set] $Contract
            Assert-ToolkitText $record.id ($set+' id')
            if($record.id -cnotmatch ('\A(?:'+$Contract.patterns.record_id+')\z') -or $map.ContainsKey($record.id)){throw ('Missing/duplicate exact '+$set+' id')}
            $map.Add($record.id,$record)
        }
        $ids.Add($set,$map)
    }
    if(@($Ledger.components).Count -gt 10000 -or @($Ledger.actions).Count -gt 10000){throw 'Ledger record cap exceeded.'}
    foreach($component in @($Ledger.components)) {
        foreach($field in @('name','kind','next_step')){Assert-ToolkitText $component.$field ('component.'+$field)}
        foreach($field in @('installed_version','reviewed_target','available_release','agent_id')){Assert-ToolkitText $component.$field ('component.'+$field) $true}
        foreach($field in @('architecture','manager','channel','default_resolution','owner_component_id')){if($component.PSObject.Properties[$field]){Assert-ToolkitText $component.$field ('component.'+$field) $true}}
        foreach($id in $component.evidence_ids){Assert-ToolkitReference $ids 'evidence' $id}
        foreach($id in $component.finding_ids){Assert-ToolkitReference $ids 'findings' $id}
        if($component.PSObject.Properties['owner_component_id'] -and $null -ne $component.owner_component_id){Assert-ToolkitReference $ids 'components' $component.owner_component_id}
    }
    foreach($coverage in @($Ledger.coverage)){Assert-ToolkitText $coverage.scope 'coverage.scope';Assert-ToolkitText $coverage.limits 'coverage.limits'}
    foreach($source in @($Ledger.sources)) {
        Assert-ToolkitText $source.title 'source.title';Assert-ToolkitText $source.url 'source.url' $true
        foreach($check in $source.checks){Assert-ToolkitText $check 'source check'}
        if($null -eq $source.url) {if($source.authority -cnotin @('installed_metadata','owner_report')){throw 'Web authority requires a canonical public HTTPS URL.'}}
        else {
            $uri=$null
            if([string]::IsNullOrWhiteSpace($source.url) -or $source.url -cmatch '[\s\p{C}]' -or -not [Uri]::TryCreate($source.url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment){throw 'Source URL must be credential/query/fragment-free HTTPS.'}
        }
        if($source.provenance_verified -and $source.checks.Count -eq 0){throw 'Provenance claim requires recorded checks, not URL syntax alone.'}
    }
    foreach($evidence in @($Ledger.evidence)) {
        $null=Assert-ToolkitRelative $evidence.relative_path
        if($evidence.sha256 -cnotmatch ('\A(?:'+$Contract.patterns.sha256+')\z')){throw 'Invalid evidence hash.'}
        foreach($field in @('kind','scope','limits')){Assert-ToolkitText $evidence.$field ('evidence.'+$field)}
    }
    foreach($finding in @($Ledger.findings)) {
        foreach($field in @('kind','claim')){Assert-ToolkitText $finding.$field ('finding.'+$field)}
        if($null -ne $finding.component_id){Assert-ToolkitReference $ids 'components' $finding.component_id}
        foreach($value in $finding.conditions){Assert-ToolkitText $value 'finding condition'}
        foreach($id in $finding.evidence_ids){Assert-ToolkitReference $ids 'evidence' $id}
        foreach($id in $finding.source_ids){Assert-ToolkitReference $ids 'sources' $id}
    }
    foreach($action in @($Ledger.actions)) {
        if($action.automatic_retry -ne $false){throw 'Automatic retry is not allowed.'}
        Assert-ToolkitText $action.outcome 'action outcome' $true
        if($action.PSObject.Properties['group_id']){Assert-ToolkitText $action.group_id 'action group_id' $true;if($action.group_id -and ($action.group_id.Trim() -cne $action.group_id -or [string]::IsNullOrWhiteSpace($action.group_id))){throw 'Nonempty group_id cannot contain edge whitespace.'}}
        foreach($id in $action.component_ids){Assert-ToolkitReference $ids 'components' $id};foreach($id in $action.evidence_ids){Assert-ToolkitReference $ids 'evidence' $id}
        if($action.state -ceq 'completed' -and $null -eq $action.finished_utc){throw 'Completed action requires a recorded finish time.'}
        if($action.kind -cin @('update','repair','cleanup','retire') -and $action.state -cin @('approved','running','completed')) {
            Assert-ToolkitReference $ids 'approvals' $action.approval_id;$approval=$ids['approvals'][$action.approval_id]
            if($approval.decision -cne 'approved' -or $action.id -cnotin $approval.action_ids){throw 'Mutating action lacks its exact approved action/plan binding.'};if($action.state -ceq 'completed' -and $action.evidence_ids.Count -eq 0){throw 'Completed mutation requires evidence receipts.'}
        }
    }
    foreach($approval in @($Ledger.approvals)) {
        foreach($field in @('scope','authorization_quote')){Assert-ToolkitText $approval.$field ('approval.'+$field)}
        foreach($id in $approval.action_ids){Assert-ToolkitReference $ids 'actions' $id}
        if($approval.decision -ceq 'approved' -and ($approval.plan_sha256 -cnotmatch ('\A(?:'+$Contract.patterns.sha256+')\z') -or $approval.action_ids.Count -eq 0 -or [string]::IsNullOrWhiteSpace($approval.scope) -or [string]::IsNullOrWhiteSpace($approval.authorization_quote))){throw 'Approved plan requires scope, exact actions/hash and actual authorization quotation.'}
    }
    Assert-ToolkitContractRecord $Ledger.diagnosis 'diagnosis' $Contract
    foreach($field in @('original_cause','least_disruptive_fix')){Assert-ToolkitText $Ledger.diagnosis.$field ('diagnosis.'+$field) $true};Assert-ToolkitText $Ledger.diagnosis.uncertainty 'diagnosis uncertainty'
    $hypothesisIds=New-ToolkitOrdinalMap
    foreach($hypothesis in $Ledger.diagnosis.hypotheses) {
        Assert-ToolkitContractRecord $hypothesis 'hypothesis' $Contract;Assert-ToolkitText $hypothesis.id 'hypothesis id';Assert-ToolkitText $hypothesis.claim 'hypothesis claim';if($hypothesis.id -cnotmatch ('\A(?:'+$Contract.patterns.record_id+')\z') -or $hypothesisIds.ContainsKey($hypothesis.id)){throw 'Invalid or duplicate exact hypothesis id.'};$hypothesisIds.Add($hypothesis.id,$hypothesis)
        foreach($id in $hypothesis.evidence_ids){Assert-ToolkitReference $ids 'evidence' $id}
        foreach($alternative in $hypothesis.alternatives){Assert-ToolkitContractRecord $alternative 'alternative' $Contract;Assert-ToolkitText $alternative.claim 'alternative claim';foreach($id in $alternative.evidence_ids){Assert-ToolkitReference $ids 'evidence' $id}}
    }
    if($Ledger.diagnosis.status -ceq 'cause_supported' -and ([string]::IsNullOrWhiteSpace($Ledger.diagnosis.original_cause) -or @($Ledger.diagnosis.hypotheses|Where-Object {$_.state -ceq 'supported' -and $_.evidence_ids.Count -gt 0}).Count -eq 0)){throw 'Supported cause requires an evidence-linked supported hypothesis.'}
    $unresolved=@(Get-ToolkitUnresolvedActions $Ledger)
    if($Ledger.run.status -ceq 'completed' -and ($Ledger.run.phase -cne 'closed' -or $Ledger.run.pending_restart -or $unresolved.Count)){throw 'Completed run cannot contain unfinished or unresolved actions or pending restart.'}
    return $true
}
function Get-ToolkitUnresolvedActions($Ledger) {
    $resolved=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach($action in @($Ledger.actions)) {
        if($action.PSObject.Properties['resolves_action_ids']) {
            Assert-ToolkitArray $action.resolves_action_ids 'action.resolves_action_ids'
            $unique=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
            foreach($id in $action.resolves_action_ids) {
                Assert-ToolkitText $id 'resolved action id'
                $target=@($Ledger.actions|Where-Object id -ceq $id)
                if($action.kind -cne 'verify' -or ($action.state -ceq 'completed' -and $action.evidence_ids.Count -eq 0) -or -not $unique.Add($id) -or $target.Count -ne 1 -or $target[0].state -cnotin @('failed','partial') -or $id -ceq $action.id){throw 'Resolution requires a new completed evidence-backed verify action naming exact failed/partial history.'}
                if($action.state -ceq 'completed'){$null=$resolved.Add($id)}
            }
        }
    }
    return @($Ledger.actions|Where-Object {$_.state -cnotin @('completed','cancelled') -and -not ($_.state -cin @('failed','partial') -and $resolved.Contains($_.id))})
}
function Assert-ToolkitCreationBinding($Ledger,$Run){if($Ledger.run.mode -cne $Run.Marker.creation_mode -or $Ledger.run.platform -cne $Run.Marker.creation_platform){throw 'Ledger mode/platform differ from immutable creation values. Fixtures cannot become real; create a fresh run.'}}
function Assert-ToolkitActivePlan($Ledger,$Run){$active=@($Ledger.actions|Where-Object {$_.kind -in @('update','repair','cleanup','retire') -and $_.state -in @('approved','running')});if($active.Count -eq 0){return};$p=Join-Path $Run.Path 'PLANS.md';$null=Assert-ToolkitOrdinary $p $false;$sha=Get-ToolkitHash ([IO.File]::ReadAllBytes($p));$row=@($Run.Owned.files|Where-Object relative_path -ceq 'PLANS.md');if($row.Count -ne 1 -or $row[0].sha256 -cne $sha){throw 'Current plan changed without positive ownership record.'};foreach($action in $active){$a=@($Ledger.approvals|Where-Object id -ceq $action.approval_id);if($a.Count -ne 1 -or $a[0].plan_sha256 -cne $sha){throw 'Active approval no longer matches current PLANS.md; hold and record a fresh reviewed decision.'}}}
function Assert-ToolkitEvidenceBindings($Ledger,$Run) {
    foreach($e in @($Ledger.evidence)) {
        $row=@($Run.Owned.files|Where-Object relative_path -ceq $e.relative_path)
        if($row.Count -ne 1 -or $row[0].sha256 -cne $e.sha256){throw 'Evidence lacks matching positive ownership/hash record.'}
        $ep=Join-Path $Run.Path $e.relative_path
        Assert-ToolkitAncestors (Split-Path -Parent $ep);$null=Assert-ToolkitOrdinary $ep $false
        if((Get-ToolkitHash ([IO.File]::ReadAllBytes($ep))) -cne $e.sha256){throw 'Evidence changed since recorded snapshot.'}
    }
}
function Read-ToolkitLedger($Run){$bytes=[IO.File]::ReadAllBytes((Join-Path $Run.Path 'ledger.json'));$l=ConvertFrom-ToolkitJson ($script:Utf8.GetString($bytes));$null=Assert-ToolkitLedger $l $Run.Context.Id $Run.Id $Run.Context.Contract;Assert-ToolkitCreationBinding $l $Run;Assert-ToolkitActivePlan $l $Run;Assert-ToolkitEvidenceBindings $l $Run;return [pscustomobject]@{Ledger=$l;Bytes=$bytes;SHA256=(Get-ToolkitHash $bytes)}}
function New-ToolkitRun {
    param([ValidateSet('fixture','real')][string]$Mode='fixture',[ValidateSet('windows','linux','macos','unknown')][string]$Platform='unknown',[string]$Purpose='Assessment record',[string]$ToolkitRoot=$script:DefaultRoot)
    $Mode=$Mode.ToLowerInvariant();$Platform=$Platform.ToLowerInvariant()
    $context=Get-ToolkitContext $ToolkitRoot
    if($Mode -ceq 'real' -and ((-not (Test-ToolkitWindowsHost)) -or $Platform -cne 'windows')){throw 'Real Windows backend runs require the actual Windows platform.'}
    Assert-ToolkitText $Purpose 'run purpose';if([string]::IsNullOrWhiteSpace($Purpose)){throw 'Run purpose cannot be empty.'}
    $id='run-'+[Guid]::NewGuid().ToString('N');$nonce=[Guid]::NewGuid().ToString('N');$now=[DateTime]::UtcNow.ToString('o')
    $marker=[ordered]@{schema_version='1.0';toolkit_id=$context.Id;run_id=$id;creation_nonce=$nonce;created_by='portable-toolkit';created_utc=$now;creation_mode=$Mode;creation_platform=$Platform;backend=$script:BackendId}
    $ledger=[ordered]@{schema_version='1.0';toolkit_id=$context.Id;run=[ordered]@{id=$id;mode=$Mode;platform=$Platform;phase='assessment';status='draft';created_utc=$now;updated_utc=$now;purpose=$Purpose;pending_restart=$false};coverage=@();components=@();findings=@();sources=@();evidence=@();actions=@();approvals=@();diagnosis=[ordered]@{status='not_started';hypotheses=@();original_cause=$null;uncertainty='Not assessed';least_disruptive_fix=$null;repair_approved=$false}}
    # Validate shared schema before creating a run or an operation lock.
    $null=Assert-ToolkitLedger (ConvertFrom-ToolkitJson (ConvertTo-ToolkitJson $ledger)) $context.Id $id $context.Contract
    Initialize-ToolkitWork $context;$lock=Enter-ToolkitLock $context $id $true
    try {
        $path=Join-Path $context.Work $id;New-ToolkitPrivateDirectory $path
        foreach($directory in @('evidence','temporary','reports','backups')){New-ToolkitPrivateDirectory (Join-Path $path $directory)}
        $markerBytes=$script:Utf8.GetBytes((ConvertTo-ToolkitJson $marker))
        Write-ToolkitNew (Join-Path $path 'run-marker.json') $markerBytes
        Write-ToolkitNew (Join-Path $path 'ledger.json') ($script:Utf8.GetBytes((ConvertTo-ToolkitJson $ledger)))
        Write-ToolkitNew (Join-Path $path 'actions.jsonl') ([byte[]]@())
        $plans="# Plan before approval`n`nNo maintenance is approved by this placeholder. Record hypotheses, evidence, uncertainty, least-disruptive proposal, exact actions, risks and recovery before asking for approval.`n"
        $planBytes=$script:Utf8.GetBytes($plans);Write-ToolkitNew (Join-Path $path 'PLANS.md') $planBytes
        $owned=[ordered]@{schema_version='1.0';creation_nonce=$nonce;marker_sha256=(Get-ToolkitHash $markerBytes);directories=@('evidence','temporary','reports','backups');files=@([ordered]@{relative_path='PLANS.md';role='evidence';sha256=(Get-ToolkitHash $planBytes);bytes=$planBytes.Length;rollback_needed=$false})}
        Write-ToolkitNew (Join-Path $path 'owned-files.json') ($script:Utf8.GetBytes((ConvertTo-ToolkitJson $owned)))
        $run=Get-ToolkitRun $context $id;Add-ToolkitAudit $run 'NewRun' 'completed' @{mode=$Mode;collection_performed=$false;backend=$script:BackendId}
        return [pscustomobject]@{run_id=$id;path=$path;mode=$Mode;platform=$Platform;backend=$script:BackendId;collection_performed=$false}
    } finally {$lock.Dispose()}
}
function Get-ToolkitLedger {param([string]$RunId,[string]$ToolkitRoot=$script:DefaultRoot)$c=Get-ToolkitContext $ToolkitRoot;$lock=Enter-ToolkitLock $c $RunId;try{$r=Get-ToolkitRun $c $RunId;return (Read-ToolkitLedger $r).Ledger}finally{$lock.Dispose()}}
function Set-ToolkitLedger {
    param([string]$RunId,$Ledger,[string]$ToolkitRoot=$script:DefaultRoot)
    $context=Get-ToolkitContext $ToolkitRoot;$lock=Enter-ToolkitLock $context $RunId
    try {
        $run=Get-ToolkitRun $context $RunId
        $old=Read-ToolkitLedger $run
        $Ledger=ConvertFrom-ToolkitJson (ConvertTo-ToolkitJson $Ledger);$null=Assert-ToolkitLedger $Ledger $context.Id $RunId $context.Contract
        Assert-ToolkitCreationBinding $Ledger $run;Assert-ToolkitActivePlan $Ledger $run;Assert-ToolkitEvidenceBindings $Ledger $run
        foreach($action in @($old.Ledger.actions|Where-Object {$_.state -cin @('failed','partial')})) {
            $replacement=@($Ledger.actions|Where-Object id -ceq $action.id)
            if($replacement.Count -ne 1 -or (ConvertTo-ToolkitJson $replacement[0]) -cne (ConvertTo-ToolkitJson $action)){throw 'Failed/partial history is immutable. Record a new reviewed recovery/verification action.'}
        }
        Write-ToolkitControl (Join-Path $run.Path 'ledger.json') $Ledger
        Add-ToolkitAudit $run 'SetLedger' 'completed' @{maintenance_executed=$false}
    } finally {$lock.Dispose()}
}
function Write-ToolkitOwnedBytes($Run,[string]$RelativePath,[string]$Role,[byte[]]$Bytes,[bool]$RollbackNeeded=$false) {
    if($RollbackNeeded -and $Role -cne 'backup'){throw 'Needed recovery artifacts must use the backup role/path.'}
    $null=Assert-ToolkitRelative $RelativePath
    if($Role -notin @('temporary','evidence','report','backup')){throw 'Unknown artifact role.'}
    $prefix=$RelativePath.Split('/')[0];$expectedPrefix=@{temporary='temporary';evidence='evidence';report='reports';backup='backups'}[$Role]
    if($prefix -cne $expectedPrefix){throw 'Artifact role/path mismatch.'}
    $owned=$Run.Owned;$full=Join-Path $Run.Path $RelativePath
    # A missing registered artifact is interrupted state, never an invitation to
    # restore bytes or append another ownership row, including Windows case aliases.
    if(@($owned.files|Where-Object relative_path -ieq $RelativePath).Count -and -not [IO.File]::Exists($full)){throw 'Registered artifact is missing; preserve the ownership record and reconcile explicitly. No recreation.'}
    $newDirectories=New-Object Collections.Generic.List[string]
    $parent=Split-Path -Parent $RelativePath.Replace('/',[IO.Path]::DirectorySeparatorChar)
    if($parent) {
        $cur=''
        foreach($part in $parent.Split([IO.Path]::DirectorySeparatorChar)) {
            $cur=if($cur){$cur+'/'+$part}else{$part};$path=Join-Path $Run.Path $cur
            if([IO.Directory]::Exists($path)) {
                $null=Assert-ToolkitOrdinary $path $true
                if($cur -cnotin @($owned.directories)){throw 'Unowned existing directory refused.'}
            } else {
                if($cur -iin @($owned.directories)){throw 'Registered artifact directory is missing; preserve ownership and reconcile explicitly. No recreation.'}
                $newDirectories.Add($cur)
            }
        }
    }
    $sha=Get-ToolkitHash $Bytes;$existing=@($owned.files|Where-Object relative_path -ceq $RelativePath)
    if([IO.File]::Exists($full)) {
        $null=Assert-ToolkitOrdinary $full $false
        if($existing.Count -ne 1 -or (Get-ToolkitHash ([IO.File]::ReadAllBytes($full))) -cne $sha -or $existing[0].sha256 -cne $sha -or $existing[0].role -cne $Role -or $existing[0].bytes -ne $Bytes.Length -or $existing[0].rollback_needed -isnot [bool] -or $existing[0].rollback_needed -ne $RollbackNeeded){throw 'Existing artifact is unknown or changed; no overwrite.'}
        return
    }
    foreach($directory in $newDirectories){New-ToolkitPrivateDirectory (Join-Path $Run.Path $directory);$owned.directories=@($owned.directories)+@($directory)}
    Write-ToolkitNew $full $Bytes
    $owned.files=@($owned.files)+@([pscustomobject]@{relative_path=$RelativePath;role=$Role;sha256=$sha;bytes=$Bytes.Length;rollback_needed=$RollbackNeeded})
    Write-ToolkitControl (Join-Path $Run.Path 'owned-files.json') $owned
}
function Write-ToolkitArtifact {param([string]$RunId,[string]$RelativePath,[ValidateSet('temporary','evidence','backup')][string]$Role='evidence',[string]$Content,[switch]$RollbackNeeded,[string]$ToolkitRoot=$script:DefaultRoot)$c=Get-ToolkitContext $ToolkitRoot;$lock=Enter-ToolkitLock $c $RunId;try{$r=Get-ToolkitRun $c $RunId;$Role=$Role.ToLowerInvariant();Write-ToolkitOwnedBytes $r $RelativePath $Role ($script:Utf8.GetBytes($Content)) $RollbackNeeded.IsPresent;Add-ToolkitAudit $r 'WriteArtifact' 'completed' @{relative_path=$RelativePath;role=$Role}}finally{$lock.Dispose()}}
function Test-ToolkitLedger {param([string]$RunId,[string]$ToolkitRoot=$script:DefaultRoot)$c=Get-ToolkitContext $ToolkitRoot;$lock=Enter-ToolkitLock $c $RunId;try{$r=Get-ToolkitRun $c $RunId;$s=Read-ToolkitLedger $r;$result=[ordered]@{status='passed';schema_version='1.0';run_id=$RunId;ledger_sha256=$s.SHA256;state_source='ledger.json';commands_executed=$false};Write-ToolkitOwnedBytes $r ('reports/validation-'+$s.SHA256+'.json') 'report' ($script:Utf8.GetBytes((ConvertTo-ToolkitJson $result)));Add-ToolkitAudit $r 'ValidateLedger' 'completed' @{ledger_sha256=$s.SHA256};return [pscustomobject]$result}finally{$lock.Dispose()}}
function Get-ToolkitCounts($Rows,[string]$Field){$o=[ordered]@{};foreach($v in @($Rows|ForEach-Object {$_.$Field}|Sort-Object -Unique)){$o[[string]$v]=@($Rows|Where-Object {$_.$Field -ceq $v}).Count};return $o}
function ConvertTo-ToolkitCsv($Rows,[string[]]$Fields){$lines=New-Object Collections.Generic.List[string];$lines.Add((($Fields|ForEach-Object {'"'+$_.Replace('"','""')+'"'}) -join ','));foreach($r in @($Rows)){$values=foreach($field in $Fields){$v=[string]$r.$field;if($v -match '^[\p{Z}\p{C}\s]*[=+@-]|^[\p{C}\s]'){$v="'"+$v};'"'+$v.Replace('"','""')+'"'};$lines.Add(($values -join ','))};return [string]::Join("`r`n",$lines)}
function Assert-ToolkitPng([byte[]]$Bytes) {
    if($Bytes.Length -lt 33 -or $Bytes.Length -gt 2097152){throw 'PNG source asset size refused.'}
    $signature=[byte[]]@(137,80,78,71,13,10,26,10)
    for($i=0;$i -lt 8;$i++){if($Bytes[$i] -ne $signature[$i]){throw 'PNG signature refused.'}}
    if($Bytes[8] -ne 0 -or $Bytes[9] -ne 0 -or $Bytes[10] -ne 0 -or $Bytes[11] -ne 13 -or [Text.Encoding]::ASCII.GetString($Bytes,12,4) -cne 'IHDR'){throw 'PNG must start with a bounded IHDR.'}
    $width=([long]$Bytes[16]*16777216)+([long]$Bytes[17]*65536)+([long]$Bytes[18]*256)+$Bytes[19]
    $height=([long]$Bytes[20]*16777216)+([long]$Bytes[21]*65536)+([long]$Bytes[22]*256)+$Bytes[23]
    if($width -lt 1 -or $height -lt 1 -or $width -gt 4096 -or $height -gt 4096){throw 'PNG source asset dimensions refused.'}
}
function Get-ToolkitReportTemplate($Context) {
    Import-ToolkitNative $Context
    $template=$script:Utf8.GetString([PortableToolkit.OwnedNative]::ReadPublicFile($Context.Root,'templates/report.html'))
    $markup=''
    if($Context.Marker.PSObject.Properties['branding'] -and $Context.Marker.branding -and $Context.Marker.branding.PSObject.Properties['report_logo']) {
        $relative=$Context.Marker.branding.report_logo
        Assert-ToolkitText $relative 'branding.report_logo'
        $null=Assert-ToolkitRelative $relative
        $list=Read-ToolkitJsonFile (Join-Path $Context.Root 'templates/export-allowlist.json') 1000000
        Assert-ToolkitArray $list.files 'export files'
        if(-not $relative.StartsWith('assets/',[StringComparison]::Ordinal) -or [IO.Path]::GetExtension($relative) -cne '.png' -or $relative -cnotin $list.files){throw 'Logo must be an exact allowlisted PNG source asset.'}
        $bytes=[PortableToolkit.OwnedNative]::ReadPublicFile($Context.Root,$relative)
        Assert-ToolkitPng $bytes
        $markup='<img class="brand-logo" alt="PatchCairn" src="data:image/png;base64,'+[Convert]::ToBase64String($bytes)+'">'
    }
    return $template.Replace('@@BRAND_LOGO@@',$markup)
}
function Build-ToolkitReport {param([string]$RunId,[string]$ToolkitRoot=$script:DefaultRoot)$c=Get-ToolkitContext $ToolkitRoot;$lock=Enter-ToolkitLock $c $RunId;try{$r=Get-ToolkitRun $c $RunId;$s=Read-ToolkitLedger $r;$l=$s.Ledger;$template=Get-ToolkitReportTemplate $c;$th=Get-ToolkitHash ($script:Utf8.GetBytes($template));$prefix='reports/'+$s.SHA256.Substring(0,16)+'-'+$th.Substring(0,12);$groups=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal);foreach($a in @($l.actions|Where-Object state -ceq 'completed')){$group=if($a.PSObject.Properties['group_id'] -and $a.group_id){$a.group_id}else{$a.id};$null=$groups.Add($group)};$summary=[ordered]@{schema_version='1.0';run_id=$RunId;mode=$l.run.mode;ledger_sha256=$s.SHA256;component_records=@($l.components).Count;update_states=(Get-ToolkitCounts @($l.components) 'update_state');security_states=(Get-ToolkitCounts @($l.components) 'security_state');compatibility_states=(Get-ToolkitCounts @($l.components) 'compatibility_state');completed_action_records=@($l.actions|Where-Object state -ceq 'completed').Count;completed_action_groups=$groups.Count;open_finding_records=@($l.findings|Where-Object state -in @('open','conditional','held','unknown')).Count;counts_are_not_security_clearance=$true;generated_from_one_ledger_snapshot=$true};$rows=foreach($e in @($l.components)){[pscustomobject]@{id=$e.id;name=$e.name;installed_version=$e.installed_version;reviewed_target=$e.reviewed_target;available_release=$e.available_release;update_state=$e.update_state;security_state=$e.security_state;compatibility_state=$e.compatibility_state;owner_scope=$e.owner_scope;agent_id=$e.agent_id;next_step=$e.next_step;ledger_sha256=$s.SHA256}};$csv=ConvertTo-ToolkitCsv @($rows) @('id','name','installed_version','reviewed_target','available_release','update_state','security_state','compatibility_state','owner_scope','agent_id','next_step','ledger_sha256');$payload=ConvertTo-ToolkitJson ([ordered]@{ledger=$l;summary=$summary});$payload=$payload.Replace('<','\u003c').Replace('>','\u003e').Replace('&','\u0026').Replace([string][char]0x2028,'\u2028').Replace([string][char]0x2029,'\u2029');$html=$template.Replace('@@LEDGER_SHA@@',$s.SHA256).Replace('@@DATA@@',$payload);Write-ToolkitOwnedBytes $r ($prefix+'/ledger.snapshot.json') 'report' $s.Bytes;Write-ToolkitOwnedBytes $r ($prefix+'/summary.json') 'report' ($script:Utf8.GetBytes((ConvertTo-ToolkitJson $summary)));Write-ToolkitOwnedBytes $r ($prefix+'/components.csv') 'report' ($script:Utf8.GetBytes($csv));Write-ToolkitOwnedBytes $r ($prefix+'/report.html') 'report' ($script:Utf8.GetBytes($html));$human=New-Object Collections.Generic.List[string];$human.Add('# PatchCairn run summary');$human.Add('');$human.Add($(if($l.run.mode -ceq 'fixture'){'FICTIONAL DEMONSTRATION - not this computer; no real audit or update performed.'}elseif(@($l.components).Count -eq 0){'Assessment has not started: no components have been inventoried. Zero recorded findings is not a clean-computer result.'}else{'Scoped saved evidence; uninspected areas remain unknown.'}));$human.Add('Run phase: '+$l.run.phase+'; state: '+$l.run.status);$human.Add('Component records: '+@($l.components).Count+'; completed action records: '+$summary.completed_action_records+'; completed action groups: '+$summary.completed_action_groups);$human.Add('Version, security and compatibility counts are independent dimensions, not an all-secure percentage.');$human.Add('Diagnosis: '+$l.diagnosis.status+'; original cause: '+$(if($l.diagnosis.original_cause){ConvertTo-ToolkitMarkdown $l.diagnosis.original_cause}else{'Not established'}));$human.Add('Uncertainty: '+(ConvertTo-ToolkitMarkdown $l.diagnosis.uncertainty));foreach($component in @($l.components)){$name=ConvertTo-ToolkitMarkdown $component.name;$next=ConvertTo-ToolkitMarkdown $component.next_step;$human.Add('- '+$name+' | update: '+$component.update_state+' | security: '+$component.security_state+' | compatibility: '+$component.compatibility_state+' | next: '+$next)};$human.Add('');$human.Add('Canonical ledger SHA-256: '+$s.SHA256);Write-ToolkitOwnedBytes $r ($prefix+'/summary.md') 'report' ($script:Utf8.GetBytes(([string]::Join("`n",$human))));Add-ToolkitAudit $r 'BuildReport' 'completed' @{ledger_sha256=$s.SHA256;report=$prefix+'/report.html'};return [pscustomobject]@{run_id=$RunId;ledger_sha256=$s.SHA256;report=(Join-Path $r.Path ($prefix+'/report.html'));summary=(Join-Path $r.Path ($prefix+'/summary.json'));csv=(Join-Path $r.Path ($prefix+'/components.csv'));summary_markdown=(Join-Path $r.Path ($prefix+'/summary.md'))}}finally{$lock.Dispose()}}function Get-ToolkitWorkArea($Context,[string]$Name) {
    if($Name -cnotmatch '\A_[a-z]+\z'){throw 'Unknown generated work area.'}
    Initialize-ToolkitWork $Context
    $path=Join-Path $Context.Work $Name
    New-ToolkitPrivateDirectory $path
    return $path
}
function Set-ToolkitPlan {param([string]$RunId,[string]$Content,[string]$ToolkitRoot=$script:DefaultRoot)$c=Get-ToolkitContext $ToolkitRoot;$lock=Enter-ToolkitLock $c $RunId;try{$r=Get-ToolkitRun $c $RunId;$state=Read-ToolkitLedger $r;if(@($state.Ledger.actions|Where-Object {$_.kind -cin @('update','repair','cleanup','retire') -and $_.state -cin @('approved','running')}).Count){throw 'Hold active approvals before changing their plan.'};$p=Join-Path $r.Path 'PLANS.md';$null=Assert-ToolkitOrdinary $p $false;$bytes=$script:Utf8.GetBytes($Content);$tmp=Join-Path $r.Path ('plan-write-'+[Guid]::NewGuid().ToString('N')+'.tmp');Write-ToolkitNew $tmp $bytes;[IO.File]::Replace($tmp,$p,[NullString]::Value);$row=@($r.Owned.files|Where-Object relative_path -ceq 'PLANS.md');if($row.Count -ne 1){throw 'Plan ownership record absent.'};$row[0].sha256=Get-ToolkitHash $bytes;$row[0].bytes=$bytes.Length;Write-ToolkitControl (Join-Path $r.Path 'owned-files.json') $r.Owned;Add-ToolkitAudit $r 'SetPlan' 'completed' @{plan_sha256=$row[0].sha256;maintenance_executed=$false}}finally{$lock.Dispose()}}
function Import-ToolkitNative($Context){if((-not (Test-ToolkitWindowsHost))){throw 'This native cleanup/export adapter is Windows-only; no cross-platform fallback.'};if('PortableToolkit.OwnedNative' -as [type]){return};$parent=Get-ToolkitWorkArea $Context '_compiler';$dir=Join-Path $parent ([Guid]::NewGuid().ToString('N'));New-ToolkitPrivateDirectory $dir;$oldTemp=$env:TEMP;$oldTmp=$env:TMP;try{$env:TEMP=$dir;$env:TMP=$dir;Add-Type -Path (Join-Path $PSScriptRoot 'Windows.Native.cs') -ErrorAction Stop}finally{$env:TEMP=$oldTemp;$env:TMP=$oldTmp}}
function Get-ToolkitOwnedEntries($Run){$entries=New-Object Collections.Generic.List[string];$entries.Add('D|');foreach($p in @($Run.Owned.directories)){$null=Assert-ToolkitRelative $p;$entries.Add('D|'+$p)};foreach($p in @('run-marker.json','ledger.json','owned-files.json','actions.jsonl')){$entries.Add('F|'+$p)};foreach($f in @($Run.Owned.files)){$null=Assert-ToolkitRelative $f.relative_path;if($f.sha256 -cnotmatch '\A[a-f0-9]{64}\z'){throw 'Owned-file hash missing.'};$entries.Add('F|'+$f.relative_path)};if(@($entries|ForEach-Object {$_.ToLowerInvariant()}|Sort-Object -Unique).Count -ne $entries.Count){throw 'Duplicate owned path.'};return $entries.ToArray()}
function Assert-ToolkitCleanupState($Ledger,$Owned,[string]$Scope,$Run){if($null -eq $Ledger.run.PSObject.Properties['pending_restart'] -or $Ledger.run.pending_restart -ne $false){throw 'Pending or unknown restart; no cleanup.'};if(@(Get-ToolkitUnresolvedActions $Ledger).Count){throw 'Active, unresolved or future action; no cleanup.'};if(@($Owned.files|Where-Object rollback_needed -eq $true).Count){throw 'Required rollback artifact retained; no cleanup.'};foreach($row in @($Owned.files|Where-Object {$_.PSObject.Properties['recovery_release']})){$decision=Assert-ToolkitRecoveryReleaseReceipt $row $Run;if($row.recovery_release.status -cne 'completed' -or -not (Test-ToolkitRecoveryReleaseAudit $Run $decision)){throw 'Unfinished recovery-release receipt; retain bytes and explicitly reconcile the exact decision. No cleanup.'}};if($Scope -ceq 'CompletedRun' -and ($Ledger.run.status -cne 'completed' -or $Ledger.run.phase -cne 'closed')){throw 'Full purge requires a closed completed run.'}}
function Get-ToolkitCleanupTargets($Run,[string]$Scope,[string[]]$Entries){if($Scope -ceq 'CompletedRun'){return @($Entries|ForEach-Object {$_.Substring(2)})};$targets=@($Run.Owned.files|Where-Object role -ceq 'temporary'|Select-Object -ExpandProperty relative_path);foreach($d in @($Run.Owned.directories|Where-Object {$_ -ceq 'temporary' -or $_.StartsWith('temporary/')})){$protected=@($Run.Owned.files|Where-Object {$_.relative_path.StartsWith($d+'/') -and $_.relative_path -cnotin $targets});if($protected.Count -eq 0){$targets+=@($d)}};return @($targets|Sort-Object -Unique)}
function New-ToolkitCleanupPlan {param([string]$RunId,[ValidateSet('Temporary','CompletedRun')][string]$Scope='Temporary',[string]$ToolkitRoot=$script:DefaultRoot)$c=Get-ToolkitContext $ToolkitRoot;$lock=Enter-ToolkitLock $c $RunId;try{$r=Get-ToolkitRun $c $RunId;$Scope=if($Scope -ieq 'Temporary'){'Temporary'}else{'CompletedRun'};$s=Read-ToolkitLedger $r;Assert-ToolkitCleanupState $s.Ledger $r.Owned $Scope $r;Import-ToolkitNative $c;$entries=@(Get-ToolkitOwnedEntries $r);$targets=@(Get-ToolkitCleanupTargets $r $Scope $entries);Add-ToolkitAudit $r 'PlanCleanup' 'preview' @{scope=$Scope;deletion_performed=$false};if($Scope -ceq 'CompletedRun'){$lock.ReleaseMarkerPin()};$records=@([PortableToolkit.OwnedNative]::Capture($c.Work,$r.Path,[string[]]$entries,[string[]]$targets));foreach($f in @($r.Owned.files)){$observed=@($records|Where-Object relative_path -ceq $f.relative_path);if($observed.Count -ne 1 -or $observed[0].sha256 -cne $f.sha256 -or $observed[0].bytes -ne $f.bytes){throw 'Owned artifact changed from creation record.'}};$id='plan-'+[Guid]::NewGuid().ToString('N');$parent=Join-Path $c.Work '_plans';New-ToolkitPrivateDirectory $parent;$dir=Join-Path $parent $id;New-ToolkitPrivateDirectory $dir;$selected=@($records|Where-Object {$_.relative_path -cin $targets});$plan=[ordered]@{schema_version='1.0';backend=$script:BackendId;toolkit_id=$c.Id;plan_id=$id;run_id=$RunId;scope=$Scope;action_id=('cleanup-'+[Guid]::NewGuid().ToString('N'));created_utc=[DateTime]::UtcNow.ToString('o');expires_utc=[DateTime]::UtcNow.AddHours(24).ToString('o');ledger_sha256=$s.SHA256;run_creation_nonce=$r.Marker.creation_nonce;allowed_entries=$entries;targets=$targets;inventory=$records;selected_files=@($selected|Where-Object kind -ceq 'file').Count;selected_directories=@($selected|Where-Object kind -ceq 'directory').Count;selected_logical_bytes=([long](@($selected|Measure-Object bytes -Sum).Sum));preview_only=$true;owner_approval_created=$false;purge_includes_records_and_backups=($Scope -ceq 'CompletedRun');no_follow=$true};$bytes=$script:Utf8.GetBytes((ConvertTo-ToolkitJson $plan));Write-ToolkitNew (Join-Path $dir 'plan.json') $bytes;return [pscustomobject]@{plan_id=$id;plan_sha256=(Get-ToolkitHash $bytes);plan_path=(Join-Path $dir 'plan.json');run_id=$RunId;scope=$Scope;files=$plan.selected_files;directories=$plan.selected_directories;logical_bytes=$plan.selected_logical_bytes;deletion_performed=$false}}finally{$lock.Dispose()}}
function Invoke-ToolkitCleanupCore {param([string]$PlanId,[string]$ExpectedPlanSHA256,[string]$ApprovalId,[string]$ToolkitRoot=$script:DefaultRoot)
 $c=Get-ToolkitContext $ToolkitRoot;if($PlanId -cnotmatch '\Aplan-[a-f0-9]{32}\z' -or $ApprovalId -cnotmatch '\Aapproval-[a-f0-9]{32}\z' -or $ExpectedPlanSHA256 -cnotmatch '\A[a-f0-9]{64}\z'){throw 'Exact plan/hash/approval identifiers are required.'};$planDir=Join-Path $c.Work ('_plans/'+$PlanId);Assert-ToolkitAncestors $planDir;$planPath=Join-Path $planDir 'plan.json';$null=Assert-ToolkitOrdinary $planPath $false;$pb=[IO.File]::ReadAllBytes($planPath);if((Get-ToolkitHash $pb) -cne $ExpectedPlanSHA256){throw 'Plan hash changed.'};$p=ConvertFrom-ToolkitJson ($script:Utf8.GetString($pb));Assert-ToolkitUtc $p.created_utc 'plan created UTC' $false $c.Contract;Assert-ToolkitUtc $p.expires_utc 'plan expires UTC' $false $c.Contract;foreach($field in @('allowed_entries','targets','inventory')){Assert-ToolkitArray $p.$field ('plan.'+$field)};if($p.backend -cne $script:BackendId -or $p.toolkit_id -cne $c.Id -or $p.plan_id -cne $PlanId -or $p.scope -cnotin @('Temporary','CompletedRun') -or [DateTimeOffset]::Parse($p.expires_utc) -lt [DateTimeOffset]::UtcNow){throw 'Wrong or expired cleanup plan.'};$approvalPath=Join-Path $c.Work ('_approvals/'+$ApprovalId+'.json');Assert-ToolkitAncestors (Split-Path -Parent $approvalPath);$null=Assert-ToolkitOrdinary $approvalPath $false;$a=Read-ToolkitJsonFile $approvalPath 65536;Assert-ToolkitArray $a.action_ids 'cleanup approval actions';Assert-ToolkitUtc $a.recorded_utc 'cleanup approval UTC' $false $c.Contract;Assert-ToolkitText $a.authorization_quote 'cleanup authorization';if($a.acknowledge_records_and_backups_deletion -isnot [bool]){throw 'Cleanup acknowledgment must be boolean.'};if($a.backend -cne $script:BackendId -or $a.approved -isnot [bool] -or $a.approved -ne $true -or $a.decision -cne 'approved' -or $a.actor -cne 'owner' -or $a.toolkit_id -cne $c.Id -or $a.run_id -cne $p.run_id -or $a.scope -cne $p.scope -or $a.plan_id -cne $PlanId -or $a.plan_sha256 -cne $ExpectedPlanSHA256 -or @($a.action_ids).Count -ne 1 -or $a.action_ids[0] -cne $p.action_id -or [string]::IsNullOrWhiteSpace([string]$a.authorization_quote) -or [DateTimeOffset]::Parse($a.recorded_utc) -lt [DateTimeOffset]::UtcNow.AddHours(-24) -or [DateTimeOffset]::Parse($a.recorded_utc) -gt [DateTimeOffset]::UtcNow.AddMinutes(1)){throw 'Exact owner-recorded approval missing or stale.'};if($p.scope -ceq 'CompletedRun' -and $a.acknowledge_records_and_backups_deletion -ne $true){throw 'Full purge requires explicit records/backups deletion acknowledgment.'}
 $lock=Enter-ToolkitLock $c $p.run_id;$receiptPath=Join-Path $planDir 'attempt.json';$attempt=$null;try{if([IO.File]::Exists($receiptPath)){throw 'This cleanup plan is consumed. Preserve receipt; no automatic retry.'};$r=Get-ToolkitRun $c $p.run_id;$s=Read-ToolkitLedger $r;Assert-ToolkitCleanupState $s.Ledger $r.Owned $p.scope $r;if($s.SHA256 -cne $p.ledger_sha256 -or $r.Marker.creation_nonce -cne $p.run_creation_nonce){throw 'Ledger/checkpoint/ownership changed after preview.'};$entries=@(Get-ToolkitOwnedEntries $r);$targets=@(Get-ToolkitCleanupTargets $r $p.scope $entries);if(($entries -join "`n") -cne (@($p.allowed_entries) -join "`n") -or ($targets -join "`n") -cne (@($p.targets) -join "`n")){throw 'Selected scope/ownership changed after preview.'};Import-ToolkitNative $c;$expected=New-Object 'PortableToolkit.OwnedRecord[]' @($p.inventory).Count;for($i=0;$i -lt $expected.Length;$i++){$v=New-Object PortableToolkit.OwnedRecord;foreach($n in @('relative_path','kind','bytes','write_ticks','attributes','volume','file_id','sha256')){if($null -ne $p.inventory[$i].$n){$v.$n=$p.inventory[$i].$n}};$expected[$i]=$v};$attempt=[ordered]@{status='running';plan_sha256=$ExpectedPlanSHA256;plan_id=$PlanId;run_id=$p.run_id;scope=$p.scope;approval_id=$ApprovalId;started_utc=[DateTime]::UtcNow.ToString('o');finished_utc=$null;files=0;directories=0;logical_bytes=0;partial_deletion_possible=$false;error=$null;automatic_retry=$false};Write-ToolkitNew $receiptPath ($script:Utf8.GetBytes((ConvertTo-ToolkitJson $attempt)));if($p.scope -ceq 'CompletedRun'){$lock.ReleaseMarkerPin()};$result=[PortableToolkit.OwnedNative]::Delete($c.Work,$r.Path,[string[]]$entries,[string[]]$targets,$expected);$attempt.files=$result.files;$attempt.directories=$result.directories;$attempt.logical_bytes=$result.logical_bytes;$attempt.status='completed';if($p.scope -ceq 'Temporary'){$r.Owned.files=@($r.Owned.files|Where-Object {$_.relative_path -cnotin $targets});$r.Owned.directories=@($r.Owned.directories|Where-Object {$_ -cnotin $targets});Write-ToolkitControl (Join-Path $r.Path 'owned-files.json') $r.Owned;Add-ToolkitAudit $r 'ApplyCleanup' 'completed' @{plan_id=$PlanId;scope=$p.scope;files=$result.files}};return [pscustomobject]$attempt
 }catch{if($attempt){$attempt.status='failed_or_partial';$attempt.error='Cleanup stopped; inspect exact plan and counters before proposing any new action.';$ex=$_.Exception;while($ex.InnerException){$ex=$ex.InnerException};foreach($pair in @(@('files','deleted_files'),@('directories','deleted_directories'),@('logical_bytes','deleted_logical_bytes'))){if($ex.Data.Contains($pair[1])){$attempt[$pair[0]]=$ex.Data[$pair[1]]}};$attempt.partial_deletion_possible=($attempt.files -gt 0 -or $attempt.directories -gt 0)};throw
 }finally{if($attempt){$attempt.finished_utc=[DateTime]::UtcNow.ToString('o');Write-ToolkitControl $receiptPath $attempt};$lock.Dispose()}
}
function Invoke-ToolkitCleanup {param([string]$PlanId,[string]$ExpectedPlanSHA256,[string]$ApprovalId,[string]$ToolkitRoot=$script:DefaultRoot)$c=Get-ToolkitContext $ToolkitRoot;
 if($PlanId -cnotmatch '\Aplan-[a-f0-9]{32}\z'){throw 'Invalid plan identifier before any operation write.'}
 $earlyPath=Join-Path $c.Work ('_plans/'+$PlanId+'/plan.json');Assert-ToolkitAncestors (Split-Path -Parent $earlyPath);$early=Read-ToolkitJsonFile $earlyPath
 if($early.backend -cne $script:BackendId -or $early.run_id -isnot [string]){throw 'Foreign or missing cleanup backend; no operation write.'}
 $earlyPin=Open-ToolkitRunMarker $c $early.run_id;try{$null=Get-ToolkitRun $c $early.run_id}finally{$earlyPin.Stream.Dispose()}
 try{return Invoke-ToolkitCleanupCore -PlanId $PlanId -ExpectedPlanSHA256 $ExpectedPlanSHA256 -ApprovalId $ApprovalId -ToolkitRoot $c.Root}catch{$primary=$_;try{$dir=Get-ToolkitWorkArea $c '_cleanup';$receipt=[ordered]@{schema_version='1.0';operation='ApplyCleanup';status='refused_or_failed';recorded_utc=[DateTime]::UtcNow.ToString('o');plan_id=$(if($PlanId -cmatch '\Aplan-[a-f0-9]{32}\z'){$PlanId}else{$null});error_type=$primary.Exception.GetType().Name;message='Stop and inspect the exact plan, preconditions and any attempt receipt. No automatic retry.';automatic_retry=$false;details_are_not_approval=$true};Write-ToolkitNew (Join-Path $dir ('refusal-'+[Guid]::NewGuid().ToString('N')+'.json')) ($script:Utf8.GetBytes((ConvertTo-ToolkitJson $receipt)))}catch{Write-Warning 'Could not write a refusal receipt; the original error is preserved.' -WarningAction Continue};throw $primary}}
function Assert-ToolkitRecoveryReleaseReceipt($Row,$Run) {
    $receipt=$Row.recovery_release
    foreach($field in @('status','decision','completed_utc')){if($null -eq $receipt -or $null -eq $receipt.PSObject.Properties[$field]){throw 'Incomplete recovery-release receipt; retain the artifact.'}}
    Assert-ToolkitEnum $receipt.status @('pending','completed') 'recovery-release receipt state'
    $decision=$receipt.decision
    foreach($field in @('release_id','run_id','relative_path','artifact_sha256','ledger_sha256','old_rollback_needed','new_rollback_needed','authorization_quote','reason','evidence_ids','decision_utc','artifact_bytes_deleted','not_independent_proof_of_human_consent')){if($null -eq $decision -or $null -eq $decision.PSObject.Properties[$field]){throw 'Incomplete original recovery-release decision; retain the artifact.'}}
    if($Row.role -cne 'backup' -or $Row.rollback_needed -isnot [bool] -or $Row.rollback_needed -ne $false -or $decision.release_id -isnot [string] -or $decision.release_id -cnotmatch '\Arelease-[a-f0-9]{32}\z' -or $decision.run_id -cne $Run.Id -or $decision.relative_path -cne $Row.relative_path -or $decision.artifact_sha256 -cne $Row.sha256 -or $decision.ledger_sha256 -cnotmatch '\A[a-f0-9]{64}\z'){throw 'Recovery-release decision is not bound to this exact run/artifact.'}
    foreach($field in @('old_rollback_needed','new_rollback_needed','artifact_bytes_deleted','not_independent_proof_of_human_consent')){if($decision.$field -isnot [bool]){throw 'Invalid recovery-release decision boolean.'}}
    if(-not $decision.old_rollback_needed -or $decision.new_rollback_needed -or $decision.artifact_bytes_deleted -or -not $decision.not_independent_proof_of_human_consent){throw 'Invalid recovery-release decision boundary.'}
    Assert-ToolkitText $decision.authorization_quote 'original owner quotation';Assert-ToolkitText $decision.reason 'original release reason';Assert-ToolkitArray $decision.evidence_ids 'original release evidence'
    if([string]::IsNullOrWhiteSpace($decision.authorization_quote) -or [string]::IsNullOrWhiteSpace($decision.reason) -or $decision.evidence_ids.Count -eq 0){throw 'Original recovery-release decision is incomplete.'}
    Assert-ToolkitUtc $decision.decision_utc 'recovery-release decision time' $false $Run.Context.Contract
    Assert-ToolkitUtc $receipt.completed_utc 'recovery-release completion time' ($receipt.status -ceq 'pending') $Run.Context.Contract
    if($receipt.status -ceq 'pending' -and $null -ne $receipt.completed_utc){throw 'Pending recovery release cannot claim completion.'}
    return $decision
}
function Test-ToolkitRecoveryReleaseAudit($Run,$Decision) {
    $path=Join-Path $Run.Path 'actions.jsonl';$item=Assert-ToolkitOrdinary $path $false
    if($item.Length -gt 20000000){throw 'Recovery-release audit exceeds its bounded review size; retain the artifact.'}
    $expected=ConvertTo-ToolkitJson $Decision;$intent=$false;$completed=$false
    foreach($line in $script:Utf8.GetString([IO.File]::ReadAllBytes($path)).Split("`n")) {
        if([string]::IsNullOrWhiteSpace($line)){continue}
        $record=ConvertFrom-ToolkitJson $line
        if($record.run_id -ceq $Run.Id -and $record.operation -ceq 'ReleaseRecovery' -and $record.details.release_id -ceq $Decision.release_id) {
            if((ConvertTo-ToolkitJson $record.details) -cne $expected){throw 'Recovery-release audit differs from its original decision; retain the artifact.'}
            if($record.status -ceq 'intent'){$intent=$true}
            elseif($record.status -ceq 'completed'){if(-not $intent){throw 'Recovery-release completion lacks a prior durable intent.'};$completed=$true}
        }
    }
    if(-not $intent){throw 'Original durable recovery-release intent is missing; retain the artifact.'}
    return $completed
}
function Release-ToolkitRecovery {
    param([string]$RunId,[string]$RelativePath,[string]$ExpectedSHA256,[string[]]$EvidenceIds,[string]$OwnerQuote,[string]$Reason,[string]$ToolkitRoot=$script:DefaultRoot)
    $context=Get-ToolkitContext $ToolkitRoot;$lock=Enter-ToolkitLock $context $RunId
    try {
        $run=Get-ToolkitRun $context $RunId;$snapshot=Read-ToolkitLedger $run;$ledger=$snapshot.Ledger
        if($ledger.run.phase -cne 'closed' -or $ledger.run.status -cne 'completed' -or $ledger.run.pending_restart -or @(Get-ToolkitUnresolvedActions $ledger).Count){throw 'Recovery release requires a closed completed run without pending or unresolved actions.'}
        $null=Assert-ToolkitRelative $RelativePath
        if($ExpectedSHA256 -cnotmatch '\A[a-f0-9]{64}\z'){throw 'Exact artifact SHA-256 required.'}
        Assert-ToolkitText $OwnerQuote 'actual owner quotation';Assert-ToolkitText $Reason 'release reason'
        if([string]::IsNullOrWhiteSpace($OwnerQuote) -or [string]::IsNullOrWhiteSpace($Reason)){throw 'Actual owner quotation and release reason must be nonblank.'}
        $unique=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        if($EvidenceIds.Count -eq 0){throw 'Evidence-backed completed verification is required before recovery release.'}
        foreach($id in $EvidenceIds) {
            if(-not $unique.Add($id)){throw 'Duplicate recovery release evidence id.'}
            $evidence=@($ledger.evidence|Where-Object id -ceq $id)
            $verification=@($ledger.actions|Where-Object {$_.kind -ceq 'verify' -and $_.state -ceq 'completed' -and $id -cin $_.evidence_ids})
            if($evidence.Count -ne 1 -or $verification.Count -eq 0){throw 'Release evidence must be owned and named by a completed verification action.'}
        }
        $row=@($run.Owned.files|Where-Object relative_path -ceq $RelativePath)
        if($row.Count -ne 1 -or $row[0].role -cne 'backup' -or $row[0].rollback_needed -isnot [bool] -or $row[0].sha256 -cne $ExpectedSHA256){throw 'Exact rollback-needed ownership/hash record required.'}
        Import-ToolkitNative $context
        $record=[PortableToolkit.OwnedNative]::InspectOwnedFile($run.Path,$RelativePath)
        if($record.sha256 -cne $ExpectedSHA256 -or $row[0].bytes -ne $record.bytes){throw 'Recovery artifact changed since its recorded ownership.'}
        $resuming=$false;$completionRecorded=$false
        if($row[0].PSObject.Properties['recovery_release']) {
            $decision=Assert-ToolkitRecoveryReleaseReceipt $row[0] $run
            if($row[0].recovery_release.status -cne 'pending'){throw 'This recovery release already completed; do not automatically repeat it.'}
            if($decision.ledger_sha256 -cne $snapshot.SHA256 -or $decision.authorization_quote -cne $OwnerQuote -or $decision.reason -cne $Reason -or (ConvertTo-ToolkitJson $decision.evidence_ids) -cne (ConvertTo-ToolkitJson @($EvidenceIds))){throw 'Pending release requires the identical original ledger, quote, reason and evidence. Retain the artifact; no substitute decision.'}
            $completionRecorded=Test-ToolkitRecoveryReleaseAudit $run $decision
            $resuming=$true
        } else {
            if($row[0].rollback_needed -ne $true){throw 'Exact rollback-needed ownership/hash record required.'}
            $decision=[pscustomobject][ordered]@{release_id=('release-'+[Guid]::NewGuid().ToString('N'));run_id=$RunId;relative_path=$RelativePath;artifact_sha256=$ExpectedSHA256;ledger_sha256=$snapshot.SHA256;old_rollback_needed=$true;new_rollback_needed=$false;authorization_quote=$OwnerQuote;reason=$Reason;evidence_ids=@($EvidenceIds);decision_utc=[DateTime]::UtcNow.ToString('o');artifact_bytes_deleted=$false;not_independent_proof_of_human_consent=$true}
            # The exact decision must be durable before changing retention. Pending metadata
            # travels atomically with the flag, so interruption cannot make cleanup eligible.
            Add-ToolkitAudit $run 'ReleaseRecovery' 'intent' $decision
            $row[0].rollback_needed=$false
            $row[0]|Add-Member -NotePropertyName recovery_release -NotePropertyValue ([pscustomobject]@{status='pending';decision=$decision;completed_utc=$null})
            Write-ToolkitControl (Join-Path $run.Path 'owned-files.json') $run.Owned
        }
        if(-not $completionRecorded){Add-ToolkitAudit $run 'ReleaseRecovery' 'completed' $decision}
        $row[0].recovery_release.status='completed';$row[0].recovery_release.completed_utc=[DateTime]::UtcNow.ToString('o')
        Write-ToolkitControl (Join-Path $run.Path 'owned-files.json') $run.Owned
        return [pscustomobject]@{run_id=$RunId;relative_path=$RelativePath;release_id=$decision.release_id;resumed_pending_release=$resuming;rollback_needed=$false;artifact_bytes_deleted=$false;fresh_cleanup_plan_and_approval_required=$true}
    } finally {$lock.Dispose()}
}
function Export-Toolkit {
    param([string]$ToolkitRoot=$script:DefaultRoot)
    $context=Get-ToolkitContext $ToolkitRoot
    Import-ToolkitNative $context
    $list=Read-ToolkitJsonFile (Join-Path $context.Root 'templates/export-allowlist.json') 1000000
    Assert-ToolkitArray $list.files 'export files'
    $unique=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $names=New-Object 'Collections.Generic.List[string]'
    foreach($name in $list.files) {
        Assert-ToolkitText $name 'export relative path';$null=Assert-ToolkitRelative $name
        if(-not $unique.Add($name)){throw 'Duplicate/case-colliding export path refused.'}
        if($name.Split('/') -imatch '^(work|\.git)$'){throw 'Generated/private export path refused.'}
        $extension=[IO.Path]::GetExtension($name)
        if($extension -cnotin @('.md','.json','.ps1','.psm1','.cs','.html','.css','.js','.cjs','.py','.yml','.yaml','.png') -and $name -cne '.gitattributes' -and $name -cne '.gitignore' -and $name -cne 'LICENSE'){throw 'Non-public export file type refused.'}
        if($extension -ceq '.png' -and -not $name.StartsWith('assets/',[StringComparison]::Ordinal)){throw 'Binary export is restricted to exact PNG source assets.'}
        $names.Add($name)
    }
    if($names.Count -eq 0){throw 'Exact nonempty public export allowlist required.'}
    $names.Sort([StringComparer]::Ordinal)
    $payloads=New-Object 'Collections.Generic.List[object]'
    foreach($name in $names) {
        $bytes=[PortableToolkit.OwnedNative]::ReadPublicFile($context.Root,$name)
        if([IO.Path]::GetExtension($name) -ceq '.png'){Assert-ToolkitPng $bytes}else{$text=$script:Utf8.GetString($bytes);if($name -cin @('LICENSE','.gitattributes') -and $text.IndexOf([char]0) -ge 0){throw 'LICENSE and .gitattributes must be bounded UTF-8 text without NUL.'}}
        $payloads.Add([pscustomobject]@{relative_path=$name;bytes=$bytes;sha256=(Get-ToolkitHash $bytes)})
    }
    $id='export-'+[Guid]::NewGuid().ToString('N');$parent=Get-ToolkitWorkArea $context '_exports'
    $dir=Join-Path $parent $id;New-ToolkitPrivateDirectory $dir
    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    $out=Join-Path $dir 'toolkit.zip'
    $file=New-ToolkitPrivateFileStream -Path $out
    try {
        $zip=New-Object IO.Compression.ZipArchive($file,[IO.Compression.ZipArchiveMode]::Create,$true)
        try {foreach($payload in $payloads){$entry=$zip.CreateEntry($payload.relative_path,[IO.Compression.CompressionLevel]::Optimal);$entry.LastWriteTime=[DateTimeOffset]::Parse('1980-01-01T00:00:00Z');$stream=$entry.Open();try{$stream.Write($payload.bytes,0,$payload.bytes.Length)}finally{$stream.Dispose()}}} finally {$zip.Dispose()}
    } finally {$file.Dispose()}
    $manifest=[ordered]@{schema_version='1.0';toolkit_id=$context.Id;export_id=$id;archive_sha256=(Get-ToolkitHash ([IO.File]::ReadAllBytes($out)));files=@($payloads|Select-Object relative_path,sha256);work_or_git_included=$false;publication_performed=$false;binary_assets_preserved_not_metadata_sanitized=$true}
    Write-ToolkitNew (Join-Path $dir 'export-manifest.json') ($script:Utf8.GetBytes((ConvertTo-ToolkitJson $manifest)))
    return [pscustomobject]@{archive=$out;manifest=(Join-Path $dir 'export-manifest.json');files=$payloads.Count;publication_performed=$false}
}
function Get-ToolkitWindowsBaseline {param([string]$RunId,[string]$ToolkitRoot=$script:DefaultRoot)$c=Get-ToolkitContext $ToolkitRoot;$r=Get-ToolkitRun $c $RunId;$s=Read-ToolkitLedger $r;if((-not (Test-ToolkitWindowsHost)) -or $s.Ledger.run.platform -cne 'windows' -or $s.Ledger.run.mode -cne 'real'){throw 'Windows baseline requires an explicit real Windows run; fixtures never collect host inventory.'};& (Join-Path $PSScriptRoot 'Collect-WindowsBaseline.ps1') -RunId $RunId -ToolkitRoot $c.Root}
Export-ModuleMember -Function Release-ToolkitRecovery,Get-ToolkitLedger,Set-ToolkitPlan,New-ToolkitRun,Set-ToolkitLedger,Write-ToolkitArtifact,Test-ToolkitLedger,Build-ToolkitReport,New-ToolkitCleanupPlan,Invoke-ToolkitCleanup,Export-Toolkit,Get-ToolkitWindowsBaseline
