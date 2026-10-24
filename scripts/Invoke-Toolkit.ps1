#requires -Version 5.1
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateSet('NewRun','ReadLedger','ValidateLedger','BuildReport','PlanCleanup','ApplyCleanup','ExportToolkit','CollectBaseline','ReleaseRecovery')][string]$Operation,
 [string]$RunId,[ValidateSet('fixture','real')][string]$Mode='fixture',[ValidateSet('windows','linux','macos','unknown')][string]$Platform='unknown',[string]$Purpose='Assessment record',
 [ValidateSet('Temporary','CompletedRun')][string]$Scope='Temporary',[string]$PlanId,[string]$ExpectedPlanSHA256,[string]$ApprovalId,
 [string]$RelativePath,[string]$ExpectedSHA256,[string[]]$EvidenceIds,[string]$OwnerQuote,[string]$Reason,
 [string]$ToolkitRoot=(Split-Path -Parent $PSScriptRoot)
)
$env:TZ='UTC'
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'Toolkit.Core.psm1') -Force
switch($Operation){
 'NewRun'{New-ToolkitRun -Mode $Mode -Platform $Platform -Purpose $Purpose -ToolkitRoot $ToolkitRoot}
 'ReadLedger'{Get-ToolkitLedger -RunId $RunId -ToolkitRoot $ToolkitRoot}
 'ValidateLedger'{Test-ToolkitLedger -RunId $RunId -ToolkitRoot $ToolkitRoot}
 'BuildReport'{Build-ToolkitReport -RunId $RunId -ToolkitRoot $ToolkitRoot}
 'PlanCleanup'{New-ToolkitCleanupPlan -RunId $RunId -Scope $Scope -ToolkitRoot $ToolkitRoot}
 'ApplyCleanup'{Invoke-ToolkitCleanup -PlanId $PlanId -ExpectedPlanSHA256 $ExpectedPlanSHA256 -ApprovalId $ApprovalId -ToolkitRoot $ToolkitRoot}
 'ExportToolkit'{Export-Toolkit -ToolkitRoot $ToolkitRoot}
 'ReleaseRecovery'{Release-ToolkitRecovery -RunId $RunId -RelativePath $RelativePath -ExpectedSHA256 $ExpectedSHA256 -EvidenceIds $EvidenceIds -OwnerQuote $OwnerQuote -Reason $Reason -ToolkitRoot $ToolkitRoot}
 'CollectBaseline'{Get-ToolkitWindowsBaseline -RunId $RunId -ToolkitRoot $ToolkitRoot}
}