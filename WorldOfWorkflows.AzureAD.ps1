# Declare all of these as variables 
#param ($ClientappName, $ServerappName, $BaseAddress, $redirectUris, $SignInAudience)
#Install-Module Microsoft.Graph -Force
#Import-Module -Name Microsoft.Graph
#Connect-MgGraph -Identity

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
        $appList = Get-MgApplication -Filter "DisplayName eq '$DisplayName'"
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
$ClientApp = New-MgApplication -DisplayName "$ClientappName" -Spa @{ RedirectUris = $redirectUris } -RequiredResourceAccess  $($MSGraphPermissionsJson | ConvertFrom-Json) 


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



Write-Host "Requested to build Server Application with name '$ServerappName'"
$ServerappName = CreateUniqueApp -AppName $ServerappName

Write-Host "Creating Server Application with name '$ServerappName'"
# $ServerApp = New-AzureADApplication -DisplayName "$ServerappName" -Oauth2Permissions $oauth2PermissionRequest -PreAuthorizedApplications $PreAuthorizedApplication

New-MgApplication -DisplayName "$ServerappName" -Api @{ 
    Oauth2PermissionScopes = $oauth2PermissionScopes 
    PreAuthorizedApplications = $PreauthApplication
}



#### Creating Secret for the Server Application
Write-Host 'Generating Password for Server Application'

# Define the client secret parameters
$passwordCred = @{
    displayName = "Automated Secret"
    endDateTime = (Get-Date).AddYears(1)
}


Write-Host 'Updating Password to Server Application' 
# Create the client secret
$ServerSecret = Add-MgApplicationPassword -ApplicationId $ServerApp.Id -PasswordCredential $passwordCred

#####  Creating the Identifier URI
Write-Host "Definiting Identifier Uris"
$identifierUris = @("api://$($ServerApp.AppId)")

Write-Host "Updating Server with  Identifier Uris"
Update-MgApplication -ObjectId  $ServerApp.ObjectId -IdentifierUri  $identifierUris


Write-Host "Server Application '$ServerAppName' built with Id: $($ServerApp.AppId)"

Write-Host 'Building Output Variables'

Write-Host "Retrieving Organisation"
$org = Get-MgOrganization


Write-Host 'Outputting Variable'

$AppInfo = [PSCustomObject]@{
    ClientAppId = $ClientApp.appId
    ServerAppId = $ServerApp.appId
    OrgId = $org.Id
    VerifiedDomainName = $org.VerifiedDomains[0].Name
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