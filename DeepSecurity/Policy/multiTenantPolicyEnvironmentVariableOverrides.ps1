<#
.SYNOPSIS
Powershell script to get the Environment Variable Overrides policy setting from a named policy in T0 and apply that setting to all policies in each tenant.

.DESCRIPTION
Definition:
    EVO = Environment Variable Overrides

This script will:
1. Search T0 for all active tenants
2. If there are active tenants the script will describe the template policy to get the Environment Variable Overrides policy setting
3. Generate an API key for a tenant
4. List all policies in the tenant
5. If the Environment Variable Overrides setting does not match the EVO from the template policy the EVO setting will be modify to match the template policy EVO setting
6. Delete the API key that was created on step 3
The script repeats steps 3 through 6 till all tenants have been checked/modified.

.PARAMETER manager
The -manager parameter requires a hostname or IP and port in the format hostname.local:4119 or 198.51.100.10:443

.PARAMETER apikey
The -apikey parameter requires a Deep Security Manager API key with the full access role.

.PARAMETER templateTemplateName
The -templateTemplateName requires the name of a tenant that you want to use as an example for the EVO.

.PARAMETER templatePolicyName
The -templatePolicyName parameter requires the name of a policy. Example "Base Policy"

.EXAMPLE
.\multiTenantPolicyEnvironmentVariableOverrides.ps1 -manager <DSM Hostname> -apikey <API-Key> -tenantTemplateName "<Tenant Template Name>" -templatePolicyName "<policyName>"

.NOTES
Example script console output:

Tenant Name, Message
T0, Get environment variable overrides from policy:  Template - Environment Variable Overrides
test01, Generate temp API Key
test01, Searching for policies
test01, modifying policyID: 1
test01, modifying policyID: 2
test01, Delete temp API Key
test02, Generate temp API Key
test02, Searching for policies
test02, modifying policyID: 1
test02, modifying policyID: 2
test02, Delete temp API Key

This script should clean up the ApiKeys that it creates.  If the script can't delete the modifyPolicy ApiKey for some reason an adminitrator will need to clean up the left over ApiKey from the effected tenants.
If this script fails to delete the API key, the API key is set to expire about 30 minutes after it was created.
#>
#requires -version 7.0

param (
    [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
    [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$apikey,
    [Parameter(Mandatory=$true, HelpMessage="Template Policy Name")][string]$tenantTemplateName,
    [Parameter(Mandatory=$true, HelpMessage="Template Policy Name")][string]$templatePolicyName
)

# Remove progress bar for web requests
$ProgressPreference = 'SilentlyContinue' 

# Set Cert verification and TLS version to 1.2.
#[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$false}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Headers to use for all Api queries to T0
$headers = @{
    "api-version" = "v1"
    "api-secret-key" = $apikey
}

function tenatSearchFunction {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager
    )

    $tenantSearchURL = "https://$manager/api/tenants/search"

    $tenantSearchHash = @{
    maxItems = '5000'
    searchCriteria = @(
            @{
                choiceValue = 'active'
                choiseTest = 'equal'
                fieldName = 'tenantState'
            }
        )
    }
    $tenantSearchBody = $tenantSearchHash | ConvertTo-Json
    
    $tenantSearchResults = Invoke-WebRequest -Uri $tenantSearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $tenantSearchBody -SkipCertificateCheck  | ConvertFrom-Json

    return $tenantSearchResults
}

function createTenantApiKeyFunction {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Tenant ID")][string]$tenantID
    )

    $createTenantApiKeyURL = "https://$manager/api/tenants/$tenantID/apikeys"

    [long]$timestamp = (([datetime]::UtcNow)-(Get-Date -Date '1/1/1970')).TotalMilliseconds + 2000000

    $createTenantApiKeyHash = @{
        keyName = 'modifyPolicy'
        description = 'Temp API Key for modifying policies'
        locale = 'en-US'
        timeZone = 'America/Chicago'
        active = 'true'
        expiryDate = $timestamp
    }
    $createTenantApiKeyBody = $createTenantApiKeyHash | ConvertTo-Json
    
    try {
        $createTenantApiKeyResults = Invoke-WebRequest -Uri $createTenantApiKeyURL -Method Post -ContentType "application/json" -Headers $headers -Body $createTenantApiKeyBody -SkipCertificateCheck  | ConvertFrom-Json
    }
    catch {
        $tenantApiKeyCreateStatus = "Failed"
        Write-host "Unable to create API Key.  API Key may already exist in this tenat" -ForegroundColor Red
    }

    if ($createTenantApiKeyResults.secretKey) {
        $tenantApiKeyCreateStatus = "Success"
    }
    else {
        $tenantApiKeyCreateStatus = "Failed"
    }

    $tenantApiKeyID = $createTenantApiKeyResults.ID
    $tenantApiKey = $createTenantApiKeyResults.secretKey
    $returnArray = @()

    $returnArray += $tenantApiKeyID
    $returnArray += $tenantApiKey
    $returnArray += $tenantApiKeyCreateStatus

    return ,$returnArray

}

function deleteTenantApiKey {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$tenantApiKey,
        [Parameter(Mandatory=$true, HelpMessage="Tenant API Key ID")][string]$apiKeyID
    )

    $deleteTenantApiKeyheaders = @{
        "api-version" = "v1"
        "api-secret-key" = $tenantApiKey
    }

    $deleteTenantApiKeyURL = "https://$manager/api/apikeys/$apiKeyID"
    try {
        $deleteTenantApiKeyResults = Invoke-WebRequest -Uri $deleteTenantApiKeyURL -Method DELETE -ContentType "application/json" -Headers $deleteTenantApiKeyheaders -SkipCertificateCheck
    }
    catch {
        $deleteTenantApiKeyStatus = "Failed"
    }

    $statusCodeResults = $deleteTenantApiKeyResults.StatusCode
    if ($statusCodeResults -eq 204) {
        $deleteTenantApiKeyStatus = "Success"
    }
    else {
        $deleteTenantApiKeyStatus = "Failed"
    }
    return $deleteTenantApiKeyStatus
}

function EnvironmentVariableOverridesLookupFunction{
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$apikey,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security policy name")][string]$policyName
    )

    $headers = @{
        "api-version" = "v1"
        "api-secret-key" = $apikey
    }

    $policySearchURL = "https://$manager/api/policies/search"

    $policySearchHash = @{
    maxItems = '1'
    searchCriteria = @(
            @{
                stringValue = $policyName
                stringTest = 'equal'
                fieldName = 'name'
            }
        )
    }
    $policySearchBody = $policySearchHash | ConvertTo-Json
    
    $policySearchResults = Invoke-WebRequest -Uri $policySearchURL -Method Post -ContentType "application/json" -Headers $headers -Body $policySearchBody  -SkipCertificateCheck | ConvertFrom-Json

    return $policySearchResults
}

function policySearchFunction {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$tenantApiKey
    )

    $policySearchFunctionHeaders = @{
            "api-version" = "v1"
            "api-secret-key" = $tenantApiKey
    }
    
    $policySearchUrl = "https://$manager/api/policies/search"

    $policySearchHash = @{
        maxItems = "5000"
        searchCriteria = @(
            @{
                idValue = '0'
                idTest = 'greater-than'
            }
        )
    }
    $policySearchBody = $policySearchHash | ConvertTo-Json
    
    $policySearchResults = Invoke-WebRequest -Uri $policySearchUrl -Method Post -ContentType "application/json" -Headers $policySearchFunctionHeaders -Body $policySearchBody -SkipCertificateCheck  | ConvertFrom-Json   

    return $policySearchResults

}

function policyModifyFunction {
    param (
        [Parameter(Mandatory=$true, HelpMessage="FQDN and port for Deep Security Manager; ex dsm.example.com:443--")][string]$manager,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security Manager API Key")][string]$tenantApiKey,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security policy ID")][string]$policyID,
        [Parameter(Mandatory=$true, HelpMessage="Deep Security policy setting value")][string]$policySettingValue
    )

    $policyModifyFunctionHeaders = @{
        "api-version" = "v1"
        "api-secret-key" = $tenantApiKey
    }

    $policyModifyUrl = "https://$manager/api/policies/"+$policyID

    $policyModifyHash = @{
        policySettings = @{
            platformSettingEnvironmentVariableOverrides =@{
                    value = $policySettingValue
            }
        }
    }
    $policyModifyBody = $policyModifyHash | ConvertTo-Json
    
    $policyModifyResults = Invoke-WebRequest -Uri $policyModifyUrl -Method Post -ContentType "application/json" -Headers $policyModifyFunctionHeaders -Body $policyModifyBody -SkipCertificateCheck | ConvertFrom-Json 
    return $policyModifyResults
}

# Search for all tenants in T0
$tenantSearchResults = tenatSearchFunction $manager

# Loop through all tenants to find the tenant template
foreach ($tenant in $tenantSearchResults.tenants) {
    if ($tenant.name -eq $tenantTemplateName) {        
        $tenantTeamplateID = $tenant.ID
        write-host $tenantTeamplateID
        break
    }
}


write-host "Tenant Name, Message"
if ($tenantSearchResults.tenants) {

    # Generate API Key for tenant Template
    $tenantTemplateApiKeyArray = createTenantApiKeyFunction $manager $tenantTeamplateID
    $tenantTemplateApiKeyID = $tenantTemplateApiKeyArray[0]
    $tenantTemplateApiKey = $tenantTemplateApiKeyArray[1]
    $tenantTemplateApiKeyCreateStatus = $tenantTemplateApiKeyArray[2]

    # Get EVO from tenant template policy
    $policySearchResults = EnvironmentVariableOverridesLookupFunction $manager $tenantTemplateApiKey $templatePolicyName
    $templatePolicyEVO = $policySearchResults.policies.policySettings.platformSettingEnvironmentVariableOverrides.value
    
    if($templatePolicyEVO){
        # Loop Through each tenant
        foreach ($i in $tenantSearchResults.tenants) {
            $tenantID = $i.ID
            $TenantName = $i.name

            # Check to see if the tenant name matches the tenant teamplate.
            if ($i.name -ne $tenantTemplateName) {
                write-host $TenantName", Generate temp API Key"

                # Create an API key for each tenant
                $tenantApiKeyArray = createTenantApiKeyFunction $manager $tenantID
                # If the createTenantApiKeyFunction was successful then continue on to modify the policy
                if ($tenantApiKeyArray[0]) {
                    $apiKeyID = $tenantApiKeyArray[0]
                    $tenantApiKey = $tenantApiKeyArray[1]
                    $tenantApiKeyCreateStatus = $tenantApiKeyArray[2]
                    
                    # Search for a policies in tenant
                    write-host $TenantName", Searching for policies"
                    $policySearchResults = policySearchFunction $manager $tenantApiKey

                    # Loop through each policy to see if the EVO match the templatePolicy
                    foreach ($policy in $policySearchResults.policies) {
                        $policyID = $policy.ID
                        if ($policy.policySettings.platformSettingEnvironmentVariableOverrides.value -eq $templatePolicyEVO) {
                            write-host $TenantName", Policy already has matching Environment Variable Overrides. Skipping policyID: "$policyID
                        }
                        else{
                            Write-Host $TenantName", modifying policyID: "$policyID
                            $policyModifyResults = policyModifyFunction $manager $tenantApiKey $policyID $templatePolicyEVO
                        }
                        # This is only here to reduce the chance of hitting API rate limiting
                        Start-Sleep -m 10
                    }
                    
                    # Delete the API key from each tenant.
                    write-host $TenantName", Delete temp API Key"
                    $deleteTenantApiKeyStatus =  deleteTenantApiKey $manager $tenantApiKey $apiKeyID
                }
                # This is only here to reduce the chance of hitting API rate limiting
                Start-Sleep -m 40
            }
            else {
                write-host $tenantTemplateName", skip tenant template"
                
            }            
        }
    }
    else {
        write-host $tenantTemplateName", Unable to find policy or Environment Variable Overrides are blank in policy: "$templatePolicyName
    }
}
else {
    Write-Host "T0, Unable to find active tenants in Deep Security Manager"
}
#>

$deleteTenantApiKeyStatus = deleteTenantApiKey $manager $tenantTemplateApiKey $tenantTemplateApiKeyID
write-host $tenantTemplateName", Delete temp API Key"