<#
.SYNOPSIS
List all computers in a Cloud One Account and output to CSV

.DESCRIPTION
This script will list all computers in a Cloud One Workload Security account and output certain data to a CSV.

.PARAMETER apikey
Required
The -apikey parameter requires a CLoud One API Key

.EXAMPLE
.\computerReport.ps1 -apikey <API-Key>

.NOTES
Example CSV Output:
"hostID","hostname","provider","instanceID","platform","agentVersion","agentStatusMessages","antiMalwareState","webReputationState","activityMonitoringState","firewallState","intrusionPreventionState","integrityMonitoringState","logInspectionState","applicationControlState"
"87802","gc2-win2012-instance","GCP","885759568703017250","Microsoft Windows Server 2012 R2","0.0.0.0","Unmanaged (VM Stopped)","Not Activated","Not Activated","Not Activated","Not Activated","Not Activated","Not Activated","Not Activated","Not Activated"

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
$reportName = ".\computerReport - $reportTime"

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
    $computerSearchURL = $baseUrl+"/computers/search"
    
    $computerSearchResults = Invoke-WebRequest -Uri $computerSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $computerSearchBody  | ConvertFrom-Json
    return $computerSearchResults
}

function computerConnectorInformationFunction {
    param (
        [Parameter(Mandatory=$true)][string]$computer
    )
    if ($item.azureARMVirtualMachineSummary) {
        $instanceID = $item.azureARMVirtualMachineSummary.instanceID
        $provider = "Azure"
    }
    if ($item.azureVMVirtualMachineSummary) {
        $instanceID = $item.azureVMVirtualMachineSummary.instanceID
        $provider = "Azure"
    }
    if ($item.ec2VirtualMachineSummary) {
        $instanceID = $item.ec2VirtualMachineSummary.instanceID
        $provider = "AWS"
    }
    if ($item.gcpVirtualMachineSummary) {
        $instanceID = $item.gcpVirtualMachineSummary.instanceID
        $provider = "GCP"
    }
    if ($item.noConnectorVirtualMachineSummary) {
        $instanceID = $item.noConnectorVirtualMachineSummary.instanceID
        $provider = "noConnector"
    }
    if ($item.vcloudVMVirtualMachineSummary) {
        $instanceID = $item.vcloudVMVirtualMachineSummary.instanceID
        $provider = "vCloud"
    }
    if ($item.vmwareVMVirtualMachineSummary) {
        $instanceID = $item.vmwareVMVirtualMachineSummary.instanceID
        $provider = "vCenter"
    }
    $returnArray = @()

    $returnArray += $instanceID
    $returnArray += $provider
  
    return ,$returnArray
}

$c1Region = getApiKeyRegionFunction $apikey
# Base Url for API Queries
$baseUrl = "https://workload.$c1Region.cloudone.trendmicro.com/api"

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
        Write-host "No more computers found.  Script complete."
    }

    # Loop through the returned computer object
    if ($computerSearchResutls.computers) {
        foreach ($item in $computerSearchResutls.computers) {
            $hostID = $item.ID
           
            $connectorInformationResults = computerConnectorInformationFunction $item
            $instanceID = $connectorInformationResults[0]
            $provider = $connectorInformationResults[1]

            # Map data to columns and export data to CSV
            [PSCustomObject]@{
                hostID = $item.ID
                hostname = $item.hostname
                provider = $provider
                instanceID = $instanceID
                platform = $item.platform
                agentVersion = $item.agentVersion
                agentStatusMessages = [string]$item.computerStatus.agentStatusMessages
                antiMalwareState = $item.antiMalware.moduleStatus.agentStatusMessage
                webReputationState = $item.webReputation.moduleStatus.agentStatusMessage
                activityMonitoringState = $item.activityMonitoring.moduleStatus.agentStatusMessage
                firewallState =  $item.firewall.moduleStatus.agentStatusMessage
                intrusionPreventionState = $item.intrusionPrevention.moduleStatus.agentStatusMessage
                integrityMonitoringState = $item.integrityMonitoring.moduleStatus.agentStatusMessage
                logInspectionState = $item.logInspection.moduleStatus.agentStatusMessage
                applicationControlState = $item.applicationControl.moduleStatus.agentStatusMessage
            } | Export-Csv $reportFile -notype -Append 
        } 
    }
    else {
        $loopStatus = 1
    }    
}