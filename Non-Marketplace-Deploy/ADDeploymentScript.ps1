param(
	[Parameter(Mandatory)]
	[string] $ClientappName, 
	[Parameter(Mandatory)]
	[string] $ServerappName,
	[Parameter(Mandatory)]
	[string] $BaseAddress,
    [Parameter(Mandatory)]
    [string] $TenantId,
	# NEW - used to enter into Service: your user’s UPN (e.g. jim@worldofworkflows.com)
    [Parameter(Mandatory)]
    [string] $AdminUserPrincipalName,
    [Parameter(Mandatory = $false)]
    [string] $SubscriptionId,
    [Parameter(Mandatory = $false)]
    [string] $AccountId,
    [Parameter(Mandatory = $false)]
    [string[]] $GuestAdmins
)
# Setup Variables

trap {
    Write-Host ""
    Write-Host "TERMINATING ERROR: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.InvocationInfo) {
        $inv = $_.InvocationInfo
        Write-Host ("  File : {0}" -f $inv.PSCommandPath) -ForegroundColor Yellow
        Write-Host ("  Line : {0}" -f $inv.ScriptLineNumber) -ForegroundColor Yellow
        if ($inv.Line) {
            Write-Host ("  Code : {0}" -f $inv.Line.Trim()) -ForegroundColor DarkCyan
        }
    }
    if ($_.ScriptStackTrace) {
        Write-Host "Stack Trace:" -ForegroundColor Yellow
        Write-Host $_.ScriptStackTrace
    }
    break
}

function Get-ServerApplicationRoles {
    param(
        [Parameter(Mandatory)]
        [string] $ApplicationObjectId
    )

    try {
        $uri = "https://graph.microsoft.com/v1.0/applications/$ApplicationObjectId?`$select=id,appRoles"
        $response = Invoke-AzRestMethod -Method Get -Uri $uri -ErrorAction Stop
        if ($response.Content) {
            $appJson = $response.Content | ConvertFrom-Json
            return $appJson.appRoles
        }
    }
    catch {
        Write-Warning "Failed to retrieve appRoles via Graph for application ${ApplicationObjectId}: $($_.Exception.Message)"
    }

    return $null
}

function Invoke-WithClaimsChallenge {
    param(
        [Parameter(Mandatory)]
        [ScriptBlock] $ScriptBlock,

        [Parameter(Mandatory)]
        [string] $TenantId,

        [Parameter(Mandatory = $false)]
        [string] $SubscriptionId,

        [Parameter(Mandatory = $false)]
        [string] $AccountId
    )

    $attempt = 0
    $maxAttempts = 2

    while ($attempt -lt $maxAttempts) {
        try {
            return & $ScriptBlock
        }
        catch {
            $attempt++
            $message = $_.Exception.Message
            if ($attempt -ge $maxAttempts) {
                throw
            }

            if ($message -match 'ClaimsChallenge\s+"([^"]+)"') {
                $claimsChallenge = $matches[1]
                if ($message -match 'LocationConditionEvaluationSatisfied') {
                    $accountUsed = $AccountId

                    if (-not $accountUsed) {
                        try {
                            $currentContext = Get-AzContext -ErrorAction Stop
                            if ($currentContext.Account -and $currentContext.Account.Id) {
                                $accountUsed = $currentContext.Account.Id
                            }
                        }
                        catch {
                            # ignore failures retrieving the context
                        }
                    }

                    if (-not $accountUsed) {
                        $accountUsed = "an unknown account"
                    }

                    Write-Error "Conditional access blocked the automated login attempt because it was made with $accountUsed. Please close this session, sign in with the correct administrator account, and rerun the deployment."
                    throw "Aborting deployment because login was attempted with $accountUsed."
                }
                else {
                    Write-Warning "Entra ID requested re-authentication (claims challenge). Launching Connect-AzAccount..."
                    $connectParams = @{
                        Tenant = $TenantId
                        ClaimsChallenge = $claimsChallenge
                    }
                    if ($SubscriptionId) {
                        $connectParams['Subscription'] = $SubscriptionId
                    }
                    if ($AccountId) {
                        $connectParams['AccountId'] = $AccountId
                    }
                    Connect-AzAccount @connectParams | Out-Null
                    Write-Host "Re-authenticated. Retrying the previous operation..." -ForegroundColor Yellow
                }
            }
            else {
                throw
            }
        }
    }
}

$script:GraphAccessToken = $null
function Get-GraphAccessToken {
    if ($script:GraphAccessToken) {
        return $script:GraphAccessToken
    }

    Write-Host "Getting Microsoft Graph token..."
    $tokenResponse = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"

    if ($tokenResponse -is [System.Security.SecureString]) {
        $bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenResponse)
        $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    elseif ($null -ne $tokenResponse.Token -and $tokenResponse.Token -is [System.Security.SecureString]) {
        $bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenResponse.Token)
        $token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    elseif ($null -ne $tokenResponse.Token) {
        $token = [string]$tokenResponse.Token
    }
    else {
        throw "Get-AzAccessToken did not return a usable Microsoft Graph token. Type: $($tokenResponse.GetType().FullName)"
    }

    $script:GraphAccessToken = $token
    return $script:GraphAccessToken
}

function Write-GraphResponseDetails {
    param(
        [Parameter(Mandatory)]
        $Response
    )

    if ($null -eq $Response) { return }

    if ($Response.PSObject.Properties.Match('StatusCode')) {
        Write-Host ("Status code: {0} {1}" -f $Response.StatusCode, $Response.StatusDescription) -ForegroundColor Yellow
    }
    if ($Response.PSObject.Properties.Match('Content') -and $Response.Content) {
        Write-Host "Response body from Graph:" -ForegroundColor Cyan
        Write-Host $Response.Content
    }
}


function Get-OrCreateServicePrincipal {
    param(
        [Parameter(Mandatory)]
        $Application,

        [Parameter(Mandatory)]
        [string] $DisplayName
    )
    $servicePrincipals = Get-AzADServicePrincipal -Filter "appId eq '$($Application.AppId)'" -ErrorAction SilentlyContinue
    if ($servicePrincipals -and $servicePrincipals.Count -gt 0) {
        if ($servicePrincipals.Count -gt 1) {
            Write-Warning "Multiple service principals found for application '$DisplayName'. Using the first entry."
            return $servicePrincipals[0]
        }

        Write-Host "Service principal for '$DisplayName' already exists."
        return $servicePrincipals
    }

    Write-Host "Creating service principal for application '$DisplayName'..."
    return New-AzADServicePrincipal -ApplicationId $Application.AppId
}

function Ensure-ServicePrincipalOwner {
    param(
        [Parameter(Mandatory)]
        $ServicePrincipal,

        [Parameter(Mandatory)]
        $User
    )

    if (-not $ServicePrincipal -or -not $User) { return }

    $spName = $ServicePrincipal.DisplayName
    $userUpn = $User.UserPrincipalName
    Write-Host "Ensuring $userUpn is an owner of enterprise app '$spName'..."

    $existingOwners = @()
   # try {
   #     $existingOwners = Get-AzADServicePrincipalOwner -ObjectId $ServicePrincipal.Id -ErrorAction Stop
   # }
   # catch {
   #     Write-Warning "Unable to retrieve current owners for '$spName': $($_.Exception.Message)"
   # }

<#     if ($existingOwners) {
        $ownerMatch = $existingOwners | Where-Object { $_.Id -eq $User.Id }
        if ($ownerMatch) {
            Write-Host "$userUpn is already an owner of '$spName'."
            return
        }
    }

    $addOwnerCmd = Get-Command -Name Add-AzADServicePrincipalOwner -ErrorAction SilentlyContinue
 #>
    try {
        if ($addOwnerCmd) {
            Add-AzADServicePrincipalOwner -ObjectId $ServicePrincipal.Id -RefObjectId $User.Id -ErrorAction Stop | Out-Null
            Write-Host "Added $userUpn as an owner of '$spName'."
        }
        else {
            $ownerUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$($ServicePrincipal.Id)/owners/`$ref"
            $graphToken = Get-GraphAccessToken
            $ownerBody = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($User.Id)"
            } | ConvertTo-Json
            $ownerHeaders = @{
                "Authorization" = "Bearer $graphToken"
                "Content-Type"  = "application/json"
            }

            $ownerResponse = Invoke-WebRequest `
                -Uri $ownerUri `
                -Method Post `
                -Headers $ownerHeaders `
                -Body $ownerBody `
                -SkipHttpErrorCheck

            if ($ownerResponse.StatusCode -ge 200 -and $ownerResponse.StatusCode -lt 300) {
                Write-Host "Added $userUpn as an owner of '$spName' via Microsoft Graph."
            }
            else {
                Write-Warning "Microsoft Graph call failed while adding $userUpn as an owner of '$spName' (HTTP $($ownerResponse.StatusCode))."
                Write-GraphResponseDetails -Response $ownerResponse
            }
        }
    }
    catch {
        Write-Warning "Failed to add $userUpn as an owner of '$spName': $($_.Exception.Message)"
    }
}

function Ensure-AppRoleAssignment {
    param(
        [Parameter(Mandatory)]
        $User,

        [Parameter(Mandatory)]
        $ServicePrincipal,

        [Parameter(Mandatory)]
        [Guid] $AppRoleId,

        [Parameter(Mandatory)]
        [string] $RoleDescription
    )

    if (-not $User -or -not $ServicePrincipal) { return }

    $roleGuid = [Guid]$AppRoleId
    $roleGuidString = $roleGuid.ToString()

    $graphToken = Get-GraphAccessToken
    $headers = @{
        "Authorization" = "Bearer $graphToken"
        "Content-Type"  = "application/json"
    }

    $assignmentExists = $false
    $assignmentCheckUrl = "https://graph.microsoft.com/v1.0/users/$($User.Id)/appRoleAssignments?`$top=999"
    try {
        $checkResponse = Invoke-WebRequest `
            -Uri $assignmentCheckUrl `
            -Method Get `
            -Headers $headers `
            -SkipHttpErrorCheck

        if ($checkResponse.StatusCode -ge 200 -and $checkResponse.StatusCode -lt 300) {
            $existingAssignments = $checkResponse.Content | ConvertFrom-Json
            if ($existingAssignments.value) {
                $matchingAssignment = $existingAssignments.value | Where-Object {
                    $_.resourceId -eq $ServicePrincipal.Id -and $_.appRoleId -eq $roleGuidString
                }
                if ($matchingAssignment) {
                    $assignmentExists = $true
                    Write-Host "$RoleDescription already assigned to $($User.UserPrincipalName) – skipping."
                }
            }
        }
        elseif ($checkResponse.StatusCode -ne 404) {
            Write-Warning "Unable to verify existing app role assignments for $($User.UserPrincipalName) (HTTP $($checkResponse.StatusCode))."
            Write-GraphResponseDetails -Response $checkResponse
        }
    }
    catch {
        Write-Warning "Unable to verify existing app role assignments for $($User.UserPrincipalName). Attempting to assign anyway."
        Write-Host $_.Exception.Message -ForegroundColor Yellow
    }

    if ($assignmentExists) { return }

    $assignUrl = "https://graph.microsoft.com/v1.0/users/$($User.Id)/appRoleAssignments"
    $assignmentBody = @{
        principalId = $User.Id
        resourceId  = $ServicePrincipal.Id
        appRoleId   = $roleGuidString
    } | ConvertTo-Json

    try {
        $assignResponse = Invoke-WebRequest `
            -Uri $assignUrl `
            -Method Post `
            -Headers $headers `
            -Body $assignmentBody `
            -ContentType "application/json" `
            -SkipHttpErrorCheck

        if ($assignResponse.StatusCode -ge 200 -and $assignResponse.StatusCode -lt 300) {
            Write-Host "Successfully assigned $RoleDescription to $($User.UserPrincipalName)."
        }
        else {
            Write-Host "Failed to assign $RoleDescription to $($User.UserPrincipalName)." -ForegroundColor Red
            Write-GraphResponseDetails -Response $assignResponse
        }
    }
    catch {
        Write-Host "Failed to assign $RoleDescription to $($User.UserPrincipalName) due to unexpected error." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Yellow
    }
}

$redirectUris = @(
    "$($BaseAddress)/authentication/login-callback",
    "$($BaseAddress)/swagger/oauth-redirect.html"
)

Write-Host "Looking for existing client app '$ClientappName'..."

# Try to find an existing app registration by display name
$existingClientApps = Get-AzADApplication -Filter "displayName eq '$ClientappName'" -ErrorAction SilentlyContinue

Write-Host "found "($existingClientApps.Count) " app regstrations"
if ($existingClientApps -and $existingClientApps.Count -gt 0) {
    if ($existingClientApps.Count -gt 1) {
        $existingClientApp = $existingClientApps[0]
    }
    else {
        $existingClientApp = $existingClientApps
    }
       
    Write-Host "Found existing client app:"
    Write-Host "  DisplayName : $($existingClientApp.DisplayName)"
    Write-Host "  AppId       : $($existingClientApp.AppId)"
    Write-Host "  ObjectId    : $($existingClientApp.Id)"

    if ([string]::IsNullOrWhiteSpace($existingClientApp.Id)) {
        throw "Existing client app has empty ObjectId. Aborting to avoid invalid Update-AzADApplication call."
    }

    Write-Host "Updating client app redirect URIs to match current installation..."
    Update-AzADApplication -ObjectId $existingClientApp.Id -SPARedirectUri $redirectUris -ErrorAction Stop

    # Make sure $ClientApp is set for later parts of the script
    $ClientApp = Get-AzADApplication -ObjectId $existingClientApp.Id
}
else {
    Write-Host "No existing client app found. Creating a new one: '$ClientappName'..."
    $ClientApp = Invoke-WithClaimsChallenge -TenantId $TenantId -SubscriptionId $SubscriptionId -AccountId $AccountId -ScriptBlock {
        New-AzADApplication `
            -DisplayName $ClientappName `
            -SPARedirectUri $redirectUris `
            -AvailableToOtherTenants $false `
            -ErrorAction Stop
    }

    Write-Host "Created client app:"
    Write-Host "  DisplayName : $($ClientApp.DisplayName)"
    Write-Host "  AppId       : $($ClientApp.AppId)"
    Write-Host "  ObjectId    : $($ClientApp.Id)"
}

if (-not $ClientApp -or [string]::IsNullOrWhiteSpace($ClientApp.Id)) {
    throw "ClientApp is not correctly initialised. ObjectId is empty or null; cannot continue."
}

$graphSp=Get-AzADServicePrincipal -Filter "displayName eq 'Microsoft Graph'"
$userReadId = $graphSp.Oauth2PermissionScope | Where-Object { $_.Value -eq 'User.Read' } | Select-Object -ExpandProperty Id
$userReadAllId = $graphSp.Oauth2PermissionScope | Where-Object { $_.Value -eq 'User.ReadBasic.All' } | Select-Object -ExpandProperty Id



Write-Host "Looking for existing server app '$ServerappName'..."

$existingServerApps = Get-AzADApplication -DisplayName $ServerappName
$serverAppIsNew = $false

if ($existingServerApps -and $existingServerApps.Count -gt 0) {
        if ($existingServerApps.Count -gt 1) {
            $existingServerApp = $existingServerApps[0]
        }
        else {
            $existingServerApp = $existingServerApps
        }
        Write-Host "Found existing server app:"
        Write-Host "  DisplayName : $($existingServerApp.DisplayName)"
        Write-Host "  AppId       : $($existingServerApp.AppId)"
        Write-Host "  ObjectId    : $($existingServerApp.Id)"

        if ([string]::IsNullOrWhiteSpace($existingServerApp.Id)) {
            throw "Existing server app has empty ObjectId. Aborting."
        }

        $ServerApp = $existingServerApp

        # Optionally, **refresh** credentials only if you want to rotate secrets:
        $ServerSecret = Invoke-WithClaimsChallenge -TenantId $TenantId -SubscriptionId $SubscriptionId -AccountId $AccountId -ScriptBlock {
            New-AzADAppCredential -ObjectId $ServerApp.Id -EndDate ((Get-Date).AddMonths(23)) -ErrorAction Stop
        }
    }
    else {
        Write-Host "No existing server app found. Creating a new one: '$ServerappName'..."
        $serverAppIsNew = $true

        # Create the Administrator app role up-front
        $script:AdminAppRoleId = [Guid]::NewGuid()

        $adminRole = @{
            AllowedMemberTypes = @("User")
            Description        = "Administrator of World of Workflows."
            DisplayName        = "Administrator"
            Id                 = $script:AdminAppRoleId
            IsEnabled          = $true
            Value              = "Administrator"
        }

        # Create the server application with this app role already attached
        $ServerApp = Invoke-WithClaimsChallenge -TenantId $TenantId -SubscriptionId $SubscriptionId -AccountId $AccountId -ScriptBlock {
            New-AzAdApplication `
                -DisplayName    $ServerappName `
                -SignInAudience "AzureADMyOrg" `
                -AppRole        @($adminRole)
        }

        Write-Host "Created server app '$ServerappName' with Administrator app role Id: $script:AdminAppRoleId"
        $ServerSecret = Invoke-WithClaimsChallenge -TenantId $TenantId -SubscriptionId $SubscriptionId -AccountId $AccountId -ScriptBlock {
            New-AzADAppCredential -ObjectId $ServerApp.Id -EndDate ((Get-Date).AddMonths(23)) -ErrorAction Stop
        }
    }

if (-not $ServerApp -or [string]::IsNullOrWhiteSpace($ServerApp.Id)) {
    throw "ServerApp is not correctly initialised. ObjectId is empty or null."
}


$serverAppCurrent = Get-AzADApplication -ObjectId $ServerApp.Id -Select "AppRoles" -ErrorAction Stop
if ($serverAppCurrent.AppRoles) {
    Write-Host "Server app has $($serverAppCurrent.AppRoles.Count) existing app roles."
    $serverAppCurrent.AppRoles | ForEach-Object {
        Write-Host ("  Role: {0} ({1}) Enabled={2}" -f $_.DisplayName, $_.Id, $_.IsEnabled)
    }
} else {
    Write-Host "Server app has no existing app roles."
}

if ($serverAppIsNew) {
    # Now Creating Identifier URLs
     $identifierUris = @(
        "api://" + $ServerApp.AppId
    )
    $requiredPermissions = @(
        @{
            "ResourceAppId" = "00000003-0000-0000-c000-000000000000"
            "ResourceAccess" = @(
                @{
                    "Id" = $userReadId 
                    "Type" = "Scope"
                },
                @{
                    "Id" = $userReadAllId 
                    "Type" = "Scope"
                }
            )
        }
    )
    Update-AzAdApplication -ObjectId $ServerApp.Id -RequiredResourceAccess $requiredPermissions | Out-Null

    # Set the identifier URIs for the application
    Update-AzAdApplication -ObjectId $ServerApp.Id -IdentifierUri $identifierUris  | Out-Null

    $scopeFile = Join-Path $PSScriptRoot "ServerAppScopes.json"
    if (-not (Test-Path $scopeFile)) {
        throw "ServerAppScopes.json not found in $PSScriptRoot. Ensure the scope definitions file is deployed with ADDeploymentScript.ps1."
    }

    $scopeDefinitions = Get-Content -Path $scopeFile -Raw | ConvertFrom-Json
    if (-not $scopeDefinitions) {
        throw "ServerAppScopes.json is empty or malformed."
    }

    $oauthScopes = @()
    $delegatedPermissionIds = @()

    foreach ($definition in $scopeDefinitions) {
        if (-not $definition.value) {
            throw "Scope definition missing 'value' field in ServerAppScopes.json."
        }

        $scopeGuid = [Guid]::NewGuid()
        $scope = @{
            Id = $scopeGuid
            Type = $definition.type
            AdminConsentDescription = $definition.adminConsentDescription
            AdminConsentDisplayName = $definition.adminConsentDisplayName
            Value = $definition.value
        }

        if ($definition.userConsentDisplayName) {
            $scope.UserConsentDisplayName = $definition.userConsentDisplayName
        }
        if ($definition.userConsentDescription) {
            $scope.UserConsentDescription = $definition.userConsentDescription
        }

        $oauthScopes += $scope
        $delegatedPermissionIds += $scopeGuid
    }

    Update-AzAdApplication -ObjectId $ServerApp.Id -Api @{ Oauth2PermissionScope = $oauthScopes }

    $PreauthApplication = @{
        AppId = $ClientApp.AppId
        DelegatedPermissionIds = $delegatedPermissionIds
    }

    Update-AzAdApplication -ObjectId $ServerApp.Id -Api @{ PreAuthorizedApplication = @($PreauthApplication)}
}
else {
    Write-Host "Server app already contains API scopes; skipping scope and pre-authorization configuration."
}

$serverAppRoles = Get-ServerApplicationRoles -ApplicationObjectId $ServerApp.Id
$serverAppCurrent = Get-AzADApplication -ObjectId $ServerApp.Id -ErrorAction Stop
if (-not $serverAppRoles -and $serverAppCurrent.AppRoles) {
    $serverAppRoles = $serverAppCurrent.AppRoles
}

if ($serverAppRoles) {
    Write-Host "Server app has $($serverAppRoles.Count) existing app roles."
    $serverAppRoles | ForEach-Object {
        Write-Host ("  Role: {0} ({1}) Enabled={2}" -f $_.DisplayName, $_.Id, $_.IsEnabled)
    }
}
else {
    Write-Host "Server app has no existing app roles."
}

# Now add the Administrator Role

# See if an Administrator role already exists
$existingAdminRole = $serverAppRoles | Where-Object { $_.Value -eq "Administrator" }

if ($existingAdminRole) {
    Write-Host "Administrator appRole already exists with Id $($existingAdminRole.Id)"
    $adminAppRoleId = $existingAdminRole.Id
}
else {
    $adminGuid = [Guid]::NewGuid()
    $appRole = @{
        AllowedMemberTypes = @("User")
        Description        = "Administrator of World of Workflows."
        DisplayName        = "Administrator"
        Id                 = $adminGuid
        IsEnabled          = $true
        Value              = "Administrator"
    }

    # Merge with any existing roles instead of replacing them
    $newAppRoles = @($serverAppRoles + $appRole)

    Update-AzAdApplication -ObjectId $ServerApp.Id -AppRole $newAppRoles

    $retryCount = 0
    $maxRetry = 5
    do {
        Start-Sleep -Seconds 2
        $serverAppRoles = Get-ServerApplicationRoles -ApplicationObjectId $ServerApp.Id
        if (-not $serverAppRoles -and $serverAppCurrent.AppRoles) {
            $serverAppRoles = $serverAppCurrent.AppRoles
        }
        $retryCount++
    } while ((-not $serverAppRoles) -and $retryCount -lt $maxRetry)

    Write-Host "Created Administrator appRole with Id $adminGuid"
    $adminAppRoleId = $adminGuid
}

if (-not $adminAppRoleId) {
    throw "Administrator app role Id could not be determined. Check the existing AppRoles on $ServerappName."
}

$roleExistsOnApplication = $serverAppRoles | Where-Object { $_.Id -eq $adminAppRoleId }
if (-not $roleExistsOnApplication) {
    Write-Warning "App role Id $adminAppRoleId not found on application $($ServerApp.DisplayName). Available roles:"
    $serverAppRoles | ForEach-Object {
        Write-Host ("  {0} - {1}" -f $_.DisplayName, $_.Id)
    }
}
# --- Ensure service principals (enterprise apps) exist for the server and client apps ---
$ServerSp = Get-OrCreateServicePrincipal -Application $ServerApp -DisplayName $ServerappName
$ClientSp = Get-OrCreateServicePrincipal -Application $ClientApp -DisplayName $ClientappName

$domains = Get-AzDomain -TenantId $TenantId

# --- NEW: Add the admin user as a member of the server enterprise app (Administrator role) ---

Write-Host "Processing admin and guest administrators for server app access..."

$allGuestAdmins = @()
if ($GuestAdmins) {
    $allGuestAdmins = $GuestAdmins | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
}

if (-not ($allGuestAdmins | Where-Object { $_ -eq $AdminUserPrincipalName })) {
    $allGuestAdmins += $AdminUserPrincipalName
}

$guestUsers = @()

if ($allGuestAdmins -and $allGuestAdmins.Count -gt 0) {
    foreach ($guestUpn in $allGuestAdmins) {
        Write-Host "Locating user '$guestUpn'..."
        $user = Get-AzADUser -Filter "userPrincipalName eq '$guestUpn'"

        if (-not $user) {
            Write-Warning "Could not find user with UPN '$guestUpn' in the tenant. Skipping."
            continue
        }

        $guestUsers += $user
    }
}

if (-not $guestUsers -or $guestUsers.Count -eq 0) {
    throw "No valid guest administrators were found. At least one valid user is required."
}

Write-Host "Ensuring admin user is configured as owner of both enterprise apps..."
$adminUser = $guestUsers | Where-Object { $_.UserPrincipalName -eq $AdminUserPrincipalName } | Select-Object -First 1
if ($adminUser) {
    Ensure-ServicePrincipalOwner -ServicePrincipal $ServerSp -User $adminUser
    Ensure-ServicePrincipalOwner -ServicePrincipal $ClientSp -User $adminUser
}
else {
    Write-Warning "Admin user '$AdminUserPrincipalName' was not found in the resolved user list; skipping owner assignment."
}

Write-Host "Ensuring listed administrators are assigned to the server enterprise app as users..."

Write-Host "Ensuring admin user is assigned to server app with Administrator role..."
# Get token for Microsoft Graph
# 1. Get a proper Graph token

$token = Get-GraphAccessToken

# ARM / Management token (for stopping/starting Web App)
$armTokenResponse = Get-AzAccessToken -ResourceUrl "https://management.azure.com/"

$armToken = $null
if ($armTokenResponse -is [System.Security.SecureString]) {
    $bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($armTokenResponse)
    $armToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}
elseif ($null -ne $armTokenResponse.Token -and $armTokenResponse.Token -is [System.Security.SecureString]) {
    $bstr  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($armTokenResponse.Token)
    $armToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}
elseif ($null -ne $armTokenResponse.Token) {
    $armToken = [string]$armTokenResponse.Token
}
else {
    throw "Get-AzAccessToken for ARM did not return a usable token."
}

$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}
# Quick sanity check:
try {
    $me = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers -Method Get -ErrorAction Stop
    Write-Host "Graph /me OK. User:" $me.userPrincipalName
}
catch {
    Write-Host "Graph call /ME FAILED:" -ForegroundColor Red
    Write-Host "Exception message: $($_.Exception.Message)" -ForegroundColor Yellow

    $resp = $_.Exception.Response
    if ($resp -ne $null) {
        Write-Host "Status code: $($resp.StatusCode.value__) $($resp.StatusDescription)" -ForegroundColor Yellow

        try {
            $stream = $resp.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $body   = $reader.ReadToEnd()
            Write-Host "Response body from Graph:" -ForegroundColor Cyan
            Write-Host $body
        }
        catch {
            Write-Host "Failed to read response body: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "No HTTP response object on the exception." -ForegroundColor Yellow
    }

    throw    # rethrow so ARM sees the failure
}
Write-Host "Ensuring listed administrators are assigned as users of $ServerappName, the server enterprise app..."
#$defaultServerRoleId = [Guid]::Empty

foreach ($guestUser in $guestUsers) {
    Ensure-AppRoleAssignment `
        -User $guestUser `
        -ServicePrincipal $ServerSp `
        -AppRoleId  $adminAppRoleId `
        -RoleDescription "default access role on $ServerappName"
}

Write-Host "Ensuring listed administrators are assigned as users of $ClientappName, the client enterprise app..."
$defaultClientRoleId = [Guid]::Empty
foreach ($guestUser in $guestUsers) {
    Ensure-AppRoleAssignment `
        -User $guestUser `
        -ServicePrincipal $ClientSp `
        -AppRoleId $defaultClientRoleId `
        -RoleDescription "default access to $ClientappName"
}

$DeploymentScriptOutputs = @{}
$DeploymentScriptOutputs['ClientClientId'] = $ClientApp.AppId
$DeploymentScriptOutputs['ServerClientId'] = $ServerApp.AppId
$DeploymentScriptOutputs['AzureToken']= $token
$DeploymentScriptOutputs['ARMToken']= $armToken
$DeploymentScriptOutputs['ServerSecret'] = $ServerSecret.SecretText
$DeploymentScriptOutputs['TenantId'] = $TenantId
$DeploymentScriptOutputs['TenantDomain']= $domains[0].Domains[0]


return $DeploymentScriptOutputs
