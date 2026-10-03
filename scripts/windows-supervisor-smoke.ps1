# GitHub's Windows runner is elevated; exercise the real service as a standard
# user without changing the production elevation guard. Never run on user PCs.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This account-creation helper is only for disposable GitHub Windows runners. Run node scripts/supervisor-smoke.mjs as your normal user locally.'
}
$username = 'ferxium-ci-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$randomBytes = New-Object byte[] 32
$random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$random.GetBytes($randomBytes)
$random.Dispose()
$password = ConvertTo-SecureString ([Convert]::ToBase64String($randomBytes) + 'aA1!') -AsPlainText -Force
$credential = [PSCredential]::new(($env:COMPUTERNAME + '\' + $username), $password)
$workspace = (Get-Location).Path
$node = (Get-Command node.exe -ErrorAction Stop).Source
$test = Join-Path $workspace 'scripts/supervisor-smoke.mjs'
$temporary = Join-Path $env:RUNNER_TEMP $username
$stdout = Join-Path $env:RUNNER_TEMP ($username + '.stdout.log')
$stderr = Join-Path $env:RUNNER_TEMP ($username + '.stderr.log')
$previousTemp, $previousTmp = $env:TEMP, $env:TMP
$created = $false
try {
    New-LocalUser -Name $username -Password $password -AccountNeverExpires -PasswordNeverExpires -Description 'Ephemeral FerXium CI smoke account' | Out-Null
    $created = $true
    # The Users group SID is stable even on localized Windows installations.
    $users = Get-LocalGroup -SID 'S-1-5-32-545'
    $sid = (Get-LocalUser -Name $username).SID
    if (-not (Get-LocalGroupMember -Group $users.Name | Where-Object SID -eq $sid)) {
        Add-LocalGroupMember -Group $users.Name -Member $username
    }
    New-Item -ItemType Directory -Path $temporary | Out-Null
    & icacls.exe $temporary /grant ($username + ':(OI)(CI)M') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot grant isolated temporary directory access' }
    $env:TEMP = $temporary
    $env:TMP = $temporary
    Start-Service seclogon
    $process = Start-Process -FilePath $node -ArgumentList ('"' + $test + '"') -Credential $credential -LoadUserProfile -WorkingDirectory $workspace -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    $null = $process.Handle
    # All smoke phases are bounded; own the handle if a CI infrastructure hang occurs.
    if (-not $process.WaitForExit(180000)) {
        $process.Kill()
        $process.WaitForExit()
        throw 'Standard-user supervisor smoke exceeded three minutes'
    }
    $process.Refresh()
    $exitCode = $process.ExitCode
    Get-Content -LiteralPath $stdout
    Get-Content -LiteralPath $stderr
    if ($exitCode -ne 0) { throw "Standard-user supervisor smoke failed ($exitCode)" }
} finally {
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
    if ($created) { Remove-LocalUser -Name $username }
    $password.Dispose()
}
