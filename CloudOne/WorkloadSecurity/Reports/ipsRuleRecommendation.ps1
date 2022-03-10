<#
.SYNOPSIS
List all computers in a Cloud One Account and output IPS rule recommendation.

.DESCRIPTION
This script will list all computers in a Cloud One Workload Security account and output the IPS rules that are recommended to be assigned or unassigned.

.PARAMETER apikey
Required
The -apikey parameter requires a CLoud One API Key

.EXAMPLE
.\ipsRuleRecommendation.ps1 -apikey <API-Key>

.NOTES
Example CSV Output:
"hostID","hostname","recommendedToAssignRuleIdCount","recommendedToUnassignRuleIdCount","LinkToComputer"
"129431","ip-172-31-33-145.ec2.internal","11","0","https://cloudone.trendmicro.com/_workload_iframe/ComputerEditor.screen?hostID=129431"

#>

#requires -version 7.2.1

param (
    [Parameter(Mandatory=$true, HelpMessage="Cloud One API Key")][string]$apikey
)

# Remove progress bar for web requests
$ProgressPreference = 'SilentlyContinue'

# Set Cert verification and TLS version to 1.2.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$reportTime = get-date -f yyyy-MM-dd-HHmmss
$reportName = ".\ipsRuleRecommendation - $reportTime"

$reportFile = $reportName + ".csv"

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
    $computerSearchURL = $baseUrl+"/computers/search?expand=none"
    
    $computerSearchResults = Invoke-WebRequest -Uri $computerSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $computerSearchBody  | ConvertFrom-Json
    return $computerSearchResults
}

$c1Region = getApiKeyRegionFunction $apikey
# Base Url for API Queries
$baseUrl = "https://workload.$c1Region.cloudone.trendmicro.com/api"

function computerIpsRuleRecommendationFunction {
    param (
        [Parameter(Mandatory=$true)][string]$hostID
    )

    $response = Invoke-WebRequest -Uri "$baseUrl/computers/$hostID/intrusionprevention/assignments" -Method Get -ContentType "application/json" -Headers $headers | ConvertFrom-Json
    return $response
}



# Loop through all computers and output CSV.
$loopStatus = 0
$hostID = 0
while ($loopStatus -eq 0) {
    # Search for computer in C1WS account
    $computerSearchResutls = computerSearchFunction $hostID

    # Count the number of computers returned to give the user some feedback.
    $computerCount = $computerSearchResutls.computers | Measure-Object
    if ($computerCount.count -gt 0) {
        write-host "Processing"$computerCount.count "computer objects"
    }
    else {
        Write-host "Script no more computers found.  Script complete."
    }

    # Loop through the returned computer object
    if ($computerSearchResutls.computers) {
        foreach ($item in $computerSearchResutls.computers) {
            $hostID = $item.ID

            # Check if there are any rule that are recommended to be assigned/unassigned
            $results = computerIpsRuleRecommendationFunction $item.ID
            $recommendedToAssignRuleIDs = $results.recommendedToAssignRuleIDs | Measure-Object
            $recommendedToUnassignRuleIDs = $results.recommendedToUnassignRuleIDs| Measure-Object

            # Map data to columns and export data to CSV
            [PSCustomObject]@{
                hostID = $hostID
                hostname = $item.hostname 
                recommendedToAssignRuleIdCount = $recommendedToAssignRuleIDs.Count
                recommendedToUnassignRuleIdCount = $recommendedToUnassignRuleIDs.Count
                LinkToComputer = "https://cloudone.trendmicro.com/_workload_iframe/ComputerEditor.screen?hostID="+$hostID

            } | Export-Csv $reportFile -notype -Append 
        } 
    }
    else {
        $loopStatus = 1
    }    
}

# ToDo
# Test on powershell v5