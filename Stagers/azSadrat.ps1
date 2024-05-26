param (
    [switch]$winrm,
    [switch]$az,
    [string]$vmName,
    [string]$resourceGroup,
    [string]$scriptPath,
    [string]$url,
    [string]$zipName,
    [string]$exeName
)

if ($winrm) {
    $session = New-PSSession -ComputerName $vmName -Credential (Get-Credential)
    $remoteScriptPath = "C:\Temp\$(Split-Path -Leaf $scriptPath)"
    Copy-Item -Path $scriptPath -Destination $remoteScriptPath -ToSession $session
    Invoke-Command -Session $session -ScriptBlock {
        param($remoteScriptPath, $url, $zipName, $exeName)
        & $remoteScriptPath -url $using:url -zipName $using:zipName -exeName $using:exeName
    } -ArgumentList $remoteScriptPath, $url, $zipName, $exeName
    Remove-PSSession -Session $session
}

if ($az) {
    # Read the script content
    $scriptContent = Get-Content -Path $scriptPath -Raw

    # Prepare the parameters for the Azure VM run command
    $parameters = @(
        "url=$url",
        "zipName=$zipName",
        "exeName=$exeName"
    )

    # Run the script on the Azure VM with parameters
    az vm run-command invoke --command-id RunPowerShellScript --name $vmName --resource-group $resourceGroup --scripts $scriptContent --parameters $parameters
}
