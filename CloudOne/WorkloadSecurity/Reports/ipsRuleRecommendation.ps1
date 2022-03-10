<#
.SYNOPSIS
Powershell script is a template.

.DESCRIPTION
Some Description

.PARAMETER manager
Not Required.
The -manager parameter requires a hostname or IP and port in the format hostname.local:4119 or 198.51.100.10:443.
If this parameter is not supplied this script will assume you are trying to use C1WS.

.PARAMETER apikey
Required
The -apikey parameter requires a Deep Security Manager API key with the full access role.

.EXAMPLE
.\template.ps1 -apikey <API-Key>

.NOTES
Example Script Output:

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

function computerSearchFunction {
    param (
        [Parameter(Mandatory=$true)][string]$idValue
    )
    
    $computerSearchHash = @{
        maxItems = "5000"
        searchCriteria = @(
            @{
                idValue = $idValue
                idTest = 'greater-than'
            }
        )
        sortByObjectID = 'true'
    }
    $computerSearchBody = $computerSearchHash | ConvertTo-Json
    $computerSearchURL = $baseUrl+"computers/search?expand=none"
    
    $computerSearchResults = Invoke-WebRequest -Uri $computerSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $computerSearchBody  | ConvertFrom-Json
    return $computerSearchResults
}

$c1Region = getApiKeyRegionFunction $apikey

function computerIpsRuleRecommendationFunction {
    param (
        [Parameter(Mandatory=$true)][string]$hostID
    )

    $response = Invoke-WebRequest -Uri 'https://workload.us-1.cloudone.trendmicro.com/api/computers/129462/intrusionprevention/assignments' -Method Get -ContentType "application/json" -Headers $headers | ConvertFrom-Json
    return $response
}

# Base Url for API Queries
$baseUrl = "https://workload.$c1Region.cloudone.trendmicro.com/api/"

$loopStatus = 0
$hostID = 0
while ($loopStatus -eq 0) {
    $computerSearchResutls = computerSearchFunction $hostID
    if ($computerSearchResutls.computers) {
        foreach ($item in $computerSearchResutls.computers) {
            $item.ID
            $hostID = $item.ID
            $item.hostname
            $results = computerIpsRuleRecommendationFunction $item.ID
            $recommendedToAssignRuleIDs = $results.recommendedToAssignRuleIDs | measure
            $recommendedToUnassignRuleIDs = $results.recommendedToUnassignRuleIDs| measure
            [PSCustomObject]@{
                hostID = $hostID
                hostname = $item.hostname 
                recommendedToAssignRuleIdCount = $recommendedToAssignRuleIDs.Count
                recommendedToUnassignRuleIdCount = $recommendedToUnassignRuleIDs.Count
                LinkToComputer = "https://cloudone.trendmicro.com/_workload_iframe/ComputerEditor.screen?hostID="+$hostID

                } | Export-Csv C:\temp\ipsRuleRecommendation.csv -notype -Append 
        } 
    }
    else {
        $loopStatus = 1
    }    
}