param([Parameter(Mandatory=$true)][string]$ServiceBinary)
$ErrorActionPreference = 'Stop'
$resolvedBinary = (Resolve-Path -LiteralPath $ServiceBinary).Path
if (-not (Test-Path -LiteralPath $resolvedBinary -PathType Leaf)) { throw 'ServiceBinary must be an existing executable.' }
if ([System.IO.Path]::GetFileName($resolvedBinary) -ne 'ferxium-service.exe') { throw 'Expected ferxium-service.exe.' }
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $resolvedBinary
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'FerXium-UserProtection' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Current-user FerXium service. No elevated privileges.'
Write-Output 'Registered current-user startup. Start the task or sign in again to run the service.'
