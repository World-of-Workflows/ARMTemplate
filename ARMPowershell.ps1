
# Declare all of these as variables 
# SignInAudience "AzureADMyOrg"
#param ($ClientappName, $ServerappName, $BaseAddress, $redirectUris, $SignInAudience)

$ClientappName = "World of Workflows Client"
$ServerappName = "World of Workflows Server"

$BaseAddress = "https://mytest.azure.com"

$redirectUris = @(
    "$BaseAddress/authentication/login-callback",
    "$BaseAddress/swagger/oauth-redirect.html"
)
# Odd behaviour for redirect URI's 
$redirectUrisStr = $redirectUris -join ","

$redirectUris = "$BaseAddress/authentication/login-callback"

$SignInAudience = "AzureADMyOrg"

# Define the path to your permissions JSON file
$permissionsJsonContent = 
'[
  {
    \"adminConsentDescription\": \"Allows the app to read data.\",
    \"adminConsentDisplayName\": \"Read data\",
    \"value\": \"Data.Read\"
  },
  {
    \"adminConsentDescription\": \"Allows the app to write data.\",
    \"adminConsentDisplayName\": \"Write data\",
    \"value\": \"Data.Write\"
  }
]'



$AdminScopeDescription = "Administrator of World of Workflows."
$AdminScopeDisplayName = "Administrator"
$AdminScopeIsEnabled = $true
$AdminScopeValue = "Administrator"
$AdminScopeAllowedMemberTypes = @("User")




$MSGraphResourceId = "00000003-0000-0000-c000-000000000000"
$MSGraphUserReadPermission = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
$MSGraphUserReadBasicAll = "b340eb25-3456-403f-be2f-af7a0d370277"

$requiredPermissions = @(

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
        $appList = az ad app list --display-name "$DisplayName" | ConvertFrom-Json
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

$ClientApp = az ad app create --display-name "$ClientappName" --web-redirect-uris $redirectUrisStr --sign-in-audience "$SignInAudience" | ConvertFrom-Json


Write-Host 'Building MSGraph scopes for Client Application'
$requiredPermissionsString = $($requiredPermissions  | ConvertTo-Json -Compress) -replace "`"", "\`"" -replace ":\\", ": \"


Write-Host 'Updating Client Application with required scopes'
az ad app update --id $ClientApp.Id --required-resource-accesses "$requiredPermissionsString"

Write-Host "Client Application '$ClientAppName' built with Id: $ClientApp.AppId"


#####  Creating the Server Application
Write-Host "Requested to build Server Application with name '$ServerappName'"
$ServerappName = CreateUniqueApp -AppName $ServerappName

Write-Host "Creating Server Application with name '$ServerappName'"
$ServerApp = az ad app create --display-name $ServerappName --sign-in-audience $SignInAudience | ConvertFrom-Json


#### Creating Secret for the Server Application
Write-Host 'Generating Password for Server Application'
$passwordCred = @{
    displayName = "Automated Secret"
    endDateTime = (Get-Date).AddYears(1)
}

Write-Host 'Updating Password to Server Application' 
$ServerSecret =  az ad app credential reset --id $ServerApp.appId --display-name $passwordCred.displayName --end-date $passwordCred.endDateTime | ConvertFrom-Json

Write-Host "Server Application '$ServerAppName' built with Id: $($ServerApp.AppId)"



#####  Creating the Scopes

Write-Host "Definiting Identifier Uris"
$identifierUris = "api://$($ServerApp.AppId)"

Write-Host "Updating Server with  Identifier Uris"
az ad app update --id $ServerApp.Id  --identifier-uris "$identifierUris"



Write-Host "Building Admin Scope"
$AdminGuid = new-guid
$appRole = @{
    AllowedMemberTypes = $AdminScopeAllowedMemberTypes
    Description = $AdminScopeDescription
    DisplayName = $AdminScopeDisplayName
    Id = $AdminGuid.Guid
    IsEnabled = $AdminScopeIsEnabled
    Value = $AdminScopeValue
}


$jsonAppRole = $($appRole | ConvertTo-Json -Compress) -replace "`"", "\`"" -replace ":\\", ": \"

Write-Host "Updating Server App with Admin Scope"
az ad app update --id $ServerApp.Id --app-roles $jsonAppRole



############# Configuring permissions


# Read and parse the permissions from the JSON file
Write-Host "Building World of Workflows Permissions"
$permissions = $permissionsJsonContent | ConvertFrom-Json

# Initialize an array to hold the permission scopes with generated GUIDs
$oauth2PermissionScopes = @()
$delegatedPermissionIds = @()

foreach ($perm in $permissions) {
  # Generate a new GUID for each permission
  $guid = [guid]::NewGuid()

  # Create a custom object for the permission scope
  $scope = [PSCustomObject]@{
    id                      = $guid.ToString()
    type                    = "User"
    adminConsentDescription = $perm.adminConsentDescription
    adminConsentDisplayName = $perm.adminConsentDisplayName
    value                   = $perm.value
  }
    

  # Add the permission scope object to the array
  $oauth2PermissionScopes += $scope
  $delegatedPermissionIds += $guid
}

# Convert the permission scopes array to JSON
$oauth2PermissionRequest = [PSCustomObject]@{
  api = [PSCustomObject]@{
    oauth2PermissionScopes = $oauth2PermissionScopes
  }
}

$delegatedPermissionIdsRequest = [PSCustomObject]@{
  api = [PSCustomObject]@{
    preAuthorizedApplications = @([PSCustomObject]@{
        appId = $ClientApp.Appid
        delegatedPermissionIds = $delegatedPermissionIds
     })
  }
}

$oauth2PermissionJson = $($oauth2PermissionRequest | ConvertTo-Json -Depth 10 -Compress) -replace "`"", "\`"" -replace ":\\", ": \"
$delegatedPermissionIdJson = $($delegatedPermissionIdsRequest | ConvertTo-Json -Depth 10 -Compress) -replace "`"", "\`"" -replace ":\\", ": \"

Write-Host "Updating Server App with new permissions"
az rest --method PATCH `
        --uri "https://graph.microsoft.com/v1.0/applications/$($ServerApp.Id)" `
        --headers 'Content-Type=application/json' `
        --body "$oauth2PermissionJson"

az rest --method PATCH `
        --uri "https://graph.microsoft.com/v1.0/applications/$($ServerApp.Id)" `
        --headers 'Content-Type=application/json' `
        --body "$delegatedPermissionIdJson"



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