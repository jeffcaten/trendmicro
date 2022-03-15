<#
.SYNOPSIS
Create gLobal application control rules from CSV

.DESCRIPTION
This script will Create gLobal application control rules from CSV

.PARAMETER apikey
Required
The -apikey parameter requires a CLoud One API Key

.EXAMPLE
.\createGlobalRules.ps1 -apikey <API-Key>

.NOTES
Example Input CSV:
.\createGlobalRules.csv
sha256,description
F7225388C1D69D57E6251C9FDA50CBBF9E05131E5ADB81E5AA0422402F048162,test03

#>

#requires -version 5.0

param (
    [Parameter(Mandatory=$true, HelpMessage="Cloud One API Key")][string]$apikey
)

# Remove progress bar for web requests
$ProgressPreference = 'SilentlyContinue'

# Set Cert verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Headers to use for all API queries
$headers = @{
    "Api-Version" = "v1"
    "Authorization" = "ApiKey " +$apikey
}

function getApiKeyRegionFunction {
    param (
        [Parameter(Mandatory=$true)][string]$apikey
    )

    # Split the API Key in half.  The first half is the API Key ID
    $apikeyArray = $apikey.Split(":")
    $apiKeyID = $apikeyArray[0]

    # Describe API key to get region
    $describeApiKeyUrl = "https://accounts.cloudone.trendmicro.com/api/apikeys/$apiKeyID"
    $response = Invoke-WebRequest -Uri $describeApiKeyUrl -Method Get -ContentType "application/json" -Headers $headers | ConvertFrom-Json
    $apiKeyUrn = $response.urn
    if ($apiKeyUrn -match "us-1") {
        $c1Region = "us-1"
    }
    if ($apiKeyUrn -match "in-1") {
        $c1Region = "in-1"
    }
    if ($apiKeyUrn -match "gb-1") {
        $c1Region = "gb-1"
    }
    if ($apiKeyUrn -match "jp-1") {
        $c1Region = "jp-1"
    }
    if ($apiKeyUrn -match "de-1") {
        $c1Region = "de-1"
    }
    if ($apiKeyUrn -match "au-1") {
        $c1Region = "au-1"
    }
    if ($apiKeyUrn -match "ca-1") {
        $c1Region = "ca-1"
    }
    if ($apiKeyUrn -match "sg-1") {
        $c1Region = "sg-1"
    }
    return $c1Region
}

function createAcGlobalRuleFunction {
    param (
        [Parameter(Mandatory=$true)][string]$sha256,
        [Parameter(Mandatory=$true)][string]$description
    )
    
    $bodyHash = @{
        applicationControlGlobalRules = @(
            @{
                sha256 = $sha256
                description = $description
            }
        )
        sortByObjectID = 'true'
    }
    $body = $bodyHash | ConvertTo-Json
    $searchURL = $baseUrl+"/applicationcontrolglobalrules"
    
    $searchResults = Invoke-WebRequest -Uri $searchURL -Method Post -ContentType "application/json" -Headers $headers -Body $body -SkipHttpErrorCheck   | ConvertFrom-Json
    return $searchResults
}
get-date

$c1Region = getApiKeyRegionFunction $apikey
# Base Url for API Queries
$baseUrl = "https://workload.$c1Region.cloudone.trendmicro.com/api"

$globalRules = Import-Csv ".\createGlobalRules.csv"

foreach ($item in $globalRules) {
    createAcGlobalRuleFunction $item.sha256 $item.description    
}

get-date