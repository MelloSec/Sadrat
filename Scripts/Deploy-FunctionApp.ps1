[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$baseName,

    [Parameter(Mandatory = $false)]
    [string]$localFolderPath = "..\Sorrowsync\Serverlcessc2"

    [Parameter(Mandatory = $false)]
    [string]$location = "eastus"
)

$currentDate = Get-Date -Format "yyyyMMdd"
$resourceGroupName = "$baseName$currentDate"
$storageAccountName = "$baseName$currentDate"
$functionAppName = "$baseName$currentDate"
$planName = "$baseName$currentDate"
$location = "eastus"


# Login to Azure
az login

# Create a resource group
az group create --name $resourceGroupName --location $location

# Create a storage account
az storage account create --name $storageAccountName --location $location --resource-group $resourceGroupName --sku Standard_LRS

# Create an App Service plan
az appservice plan create --name $planName --resource-group $resourceGroupName --location $location --sku B1 --is-linux

# Create a Function App
az functionapp create --name $functionAppName --storage-account $storageAccountName --plan $planName --resource-group $resourceGroupName --runtime dotnet

# Zip the Function App project
$zipPath = Join-Path $localFolderPath "functionapp.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($localFolderPath, $zipPath)

# Deploy the Function App
az functionapp deployment source config-zip --resource-group $resourceGroupName --name $functionAppName --src $zipPath

Write-Output "Deployment completed."
