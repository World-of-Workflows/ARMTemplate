# Declare all of these as variables 
#param ($ClientappName, $ServerappName, $BaseAddress, $redirectUris, $SignInAudience)



$ClientappName = "World of Workflows Client"
$ServerappName = "World of Workflows Server"
$BaseAddress = "https://mytest.azure.com"



# Needs to be type list<string>
$redirectUris = @(
    "$BaseAddress/authentication/login-callback",
    "$BaseAddress/swagger/oauth-redirect.html"
)



$SignInAudience = "AzureADMyOrg"



# WOWF Permissions
$WOWPermissionsJson = 
'[
  {
    "adminConsentDescription": "Allows the app to read data.",
    "adminConsentDisplayName": "Read data",
    "type": "User",
    "value": "Data.Read"
  },
  {
    "adminConsentDescription": "Allows the app to write data.",
    "adminConsentDisplayName": "Write data",
    "type": "User",
    "value": "Data.Write"
  }
]'



# Variables around MSGraph Permissions
$MSGraphPermissionsJson = 
'[
    {
    "ResourceAppId": "00000003-0000-0000-c000-000000000000",
    "ResourceAccess": 
     [
        {
            "Id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d",
            "Type": "Scope"
        },
        {
            "Id": "b340eb25-3456-403f-be2f-af7a0d370277",
            "Type": "Scope"
        }
      ]
    }
]'


$requiredMSGraphPermissions = @(

    [PSCustomObject]@{
        ResourceAppId = $MSGraphResourceId
        ResourceAccess = @(

            [PSCustomObject]@{
                Id = $MSGraphUserReadPermission
                Type = "Scope"
            },

            [PSCustomObject]@{
                Id = $MSGraphUserReadBasicAll
                Type = "Scope"
            }
        )
    }
)



# Function to create a unique app name
function CreateUniqueApp {
    param (
        [string]$AppName
    )

    # Function to check if the app exists and return the app list
    function Get-AppList {
        param ($DisplayName)
       # $appList1 = az ad app list --display-name "$DisplayName" | ConvertFrom-Json
        $appList = Get-AzureADApplication -Filter "DisplayName eq '$DisplayName'"
        return $appList
    }

    # Check how many applications already exist with the similar name
    $appList = Get-AppList -DisplayName $AppName
    $count = $appList.Count

    # If applications exist, start numbering from the next available number
    if ($count -gt 0) {
        $suffix = $count + 1
        $newAppName = "$AppName $suffix"

        # Check for the existence of the newly named application
        $appList = Get-AppList -DisplayName $newAppName

        while ($appList.Count -gt 0) {
            $suffix++
            $newAppName = "$AppName $suffix"
            $appList = Get-AppList -DisplayName $newAppName
        }

        $AppName = $newAppName
    }

    # Return the unique application name
    return $AppName
}


Write-Host "Adding World of Workflows to Tenancy"



## Creating the Client Application
Write-Host "Requested to build Client Application with name '$ClientappName'"
$ClientappName = CreateUniqueApp -AppName $ClientappName

Write-Host "Creating Client Application with name '$ClientappName'"
$ClientApp = New-AzureADApplication -DisplayName "$ClientappName" -ReplyUrls $redirectUris -RequiredResourceAccess  $($MSGraphPermissionsJson | ConvertFrom-Json) 

Write-Host 'Updating Client Application with required Sign in Audience'
Update-AzADApplication -ObjectId  $ClientApp.ObjectId   -SignInAudience $SignInAudience


Write-Host "Client Application '$ClientAppName' built with Id: $ClientApp.AppId"


#####  Creating the Server Application


# Read and parse the permissions from the JSON file
Write-Host "Building World of Workflows Permissions"
$permissions = $WOWPermissionsJson | ConvertFrom-Json

# Initialize an array to hold the permission scopes with generated GUIDs
$oauth2PermissionScopes = @()
$delegatedPermissionIds = @()

foreach ($perm in $permissions) {
  # Generate a new GUID for each permission
  $guid = [guid]::NewGuid()

  # Create a custom object for the permission scope
  $scope = [PSCustomObject]@{
    Id                      = $guid.ToString()
    Type                    = $perm.type
    AdminConsentDescription = $perm.adminConsentDescription
    AdminConsentDisplayName = $perm.adminConsentDisplayName
    Value                   = $perm.value
  }
    

  # Add the permission scope object to the array
  $oauth2PermissionScopes += $scope
  $delegatedPermissionIds += $guid
}


$preAuthorizedApplication = New-Object 'Microsoft.Open.AzureAD.Model.PreAuthorizedApplication'
$preAuthorizedApplication.AppId = $ClientApp.Appid
$preAuthorizedApplication.Permissions = $delegatedPermissionIds

$PreAuthorizedApplications = New-Object 'System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.PreAuthorizedApplication]'
$PreAuthorizedApplications.Add($preAuthorizedApplication)




$PreAuthorizedApplication  = [PSCustomObject]@{
        AppId = $ClientApp.Appid
        DelegatedPermissionIds = $delegatedPermissionIds
}



Write-Host "Requested to build Server Application with name '$ServerappName'"
$ServerappName = CreateUniqueApp -AppName $ServerappName

Write-Host "Creating Server Application with name '$ServerappName'"
$ServerApp = New-AzureADApplication -DisplayName "$ServerappName" -Oauth2Permissions $oauth2PermissionRequest -PreAuthorizedApplications $PreAuthorizedApplication

#### Creating Secret for the Server Application
Write-Host 'Generating Password for Server Application'
$passwordCred = @{
    displayName = "Automated Secret"
    endDateTime = (Get-Date).AddYears(1)
}

Write-Host 'Updating Password to Server Application' 
$ServerSecret = New-AzureADApplicationPasswordCredential -ObjectId $ServerApp.ObjectId  -CustomKeyIdentifier $passwordCred.displayName -EndDate $passwordCred.endDateTime
# $ServerSecret =  az ad app credential reset --id $ServerApp.appId --display-name $passwordCred.displayName --end-date $passwordCred.endDateTime | ConvertFrom-Json

Write-Host "Server Application '$ServerAppName' built with Id: $($ServerApp.AppId)"



#####  Creating the Scopes

Write-Host "Definiting Identifier Uris"
$identifierUris = @("api://$($ServerApp.AppId)")

Write-Host "Updating Server with  Identifier Uris"
Update-AzADApplication -ObjectId  $ServerApp.ObjectId -IdentifierUri  $identifierUris




Write-Host "Retrieving Tenancies First Verified Domain"
$response = az rest --method get --uri https://graph.microsoft.com/v1.0/domains | ConvertFrom-Json

$verifiedDomainName = $response.value | Where-Object { $_.isVerified -eq $true } | Select-Object -First 1 -ExpandProperty id


Write-Host 'Retrieving Tenant Id for Outputs'
$orgId=$(az account show --query tenantId -o tsv)


Write-Host 'Building Output Variable'

$AppInfo = [PSCustomObject]@{
    ClientAppId = $ClientApp.appId
    ServerAppId = $ServerApp.appId
    OrgId = $orgId
    VerifiedDomainName = $verifiedDomainName
    Secret = $ServerSecret.password
    BaseAddress = $BaseAddress    
}


echo $AppInfo > $AZ_SCRIPTS_OUTPUT_PATH

Write-Host 'Done'




# echo $appInfo > $AZ_SCRIPTS_OUTPUT_PATH






#      "properties": {
 #       "applicationId": "[reference(variables('cliResourceName')).outputs.appId]"
 #     }

# Things I need to output
# $org.Id
# $ClientApp.AppId

# $ServerApp.AppId

# $org.VerifiedDomains[0].Name


# $ServerSecret.SecretText

#$BaseAddress