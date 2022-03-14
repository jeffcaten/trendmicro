<#
.SYNOPSIS
List all gLobal application control rules in a Cloud One Account and output to CSV

.DESCRIPTION
This script will list all global application control rules in a Cloud One Workload Security account and output certain data to a CSV.

.PARAMETER apikey
Required
The -apikey parameter requires a CLoud One API Key

.EXAMPLE
.\listGlobalRules.ps1 -apikey <API-Key>

.NOTES
Example CSV Output:
"ruleID","sha256","description","action","lastUpdatedAdministrator","lastUpdated"
"207","E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855","Empty File","block","6801","1618276519920"

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
$reportName = ".\globalApplicationControlRules - $reportTime"

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

function acGlobalRulesSearchFunction {
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
    $computerSearchURL = $baseUrl+"/applicationcontrolglobalrules/search"
    
    $computerSearchResults = Invoke-WebRequest -Uri $computerSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $computerSearchBody  | ConvertFrom-Json
    return $computerSearchResults
}


get-date

$c1Region = getApiKeyRegionFunction $apikey
# Base Url for API Queries
$baseUrl = "https://workload.$c1Region.cloudone.trendmicro.com/api"

# Loop through all global application control rules and output CSV.
$loopStatus = 0
$ID = 0
while ($loopStatus -eq 0) {
    # Search for global application control rules in C1WS account
    $acGlobalRulesSearchResutls = acGlobalRulesSearchFunction $ID

    # Count the number of global application control rules returned to give the user some feedback.
    $objectCount = $acGlobalRulesSearchResutls.applicationControlGlobalRules | Measure-Object
    if ($objectCount.count -gt 0) {
        write-host "Processing"$objectCount.count "global application control rules"
    }
    else {
        Write-host "No more global application control rules found.  Script complete."
    }

    # Loop through the returned global application control rules
    if ($acGlobalRulesSearchResutls.applicationControlGlobalRules) {
        foreach ($item in $acGlobalRulesSearchResutls.applicationControlGlobalRules) {
            $ID = $item.ID            

            # Map data to columns and export data to CSV
            [PSCustomObject]@{
                ruleID = $item.ID
                sha256 = $item.sha256
                description = $item.description
                action = $item.action
                lastUpdatedAdministrator = $item.lastUpdatedAdministrator
                lastUpdated = $item.lastUpdated
            } | Export-Csv $reportFile -notype -Append 
        } 
    }
    else {
        $loopStatus = 1
    }    
}

get-date