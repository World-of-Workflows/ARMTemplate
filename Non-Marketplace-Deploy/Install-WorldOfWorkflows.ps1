<#
.SYNOPSIS
    Installs World of Workflows (Business Edition) into a customer Azure subscription
    WITHOUT using the Marketplace managed application.

.DESCRIPTION
    - Logs into Azure (or uses existing login)
    - Lets the user choose the target subscription from a list
    - Creates / reuses:
        * Resource Group
        * Storage Account
        * App Service Plan (Linux)
        * Web App (Linux, .NET 8)
    - Runs ADDeploymentScript.ps1 to create Entra ID applications & roles
    - Runs WowCentralDeployRequest.ps1 to notify WoWCentral (including Kudu profile)

    Run this as a user who is:
      - Global Admin in Entra ID
      - Owner (or Contributor + User Access Admin) on the target subscription
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [string]$Location = "australiaeast",

    [Parameter(Mandatory = $false)]
    [string]$WebAppName,

    [Parameter(Mandatory = $false)]
    [string]$AppServicePlanName,

    [Parameter(Mandatory = $false)]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $false)]
    [string]$ClientAppName,

    [Parameter(Mandatory = $false)]
    [string]$ServerAppName,

    [Parameter(Mandatory = $false)]
    [string]$CompanyNameForWoWLicence,

    [Parameter(Mandatory = $false)]
    [string]$BillingEmailForWoWLicence,

    [Parameter(Mandatory = $false)]
    [string]$AdminUserPrincipalName,

    [Parameter(Mandatory = $false)]
    [string[]]$GuestAdmins,

    [Parameter(Mandatory = $false)]
    [ValidateSet("standard","enhanced")]
    [string]$BusinessEditionSolution = "standard"
)


function Read-HostDefault($prompt, $default) {
    # Write prompt normally
    Write-Host -NoNewline "$prompt "
    # Write default value in yellow
    Write-Host -NoNewline "[" -ForegroundColor Gray
    Write-Host -NoNewline $default -ForegroundColor Yellow
    Write-Host -NoNewline "] "

    # Now read input
    $answer = Read-Host

    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $default
    }
    return $answer
}

function Read-HostChooseDefault($prompt, $default, $choices) {
    $choiceText = ($choices -join ", ")
    $answer = Read-Host "$prompt ($choiceText) [Default: $default]"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $default }
    return $answer
}

function New-WowStorageAccountName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SiteName,

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName
    )

    # 1. Base prefix: "wow" + site name without dashes
    $siteSanitized = ($SiteName -replace '-', '')
    $prefix = "$siteSanitized"

    # 2. Build a deterministic suffix similar in spirit to ARM uniqueString()
    #    We hash "subscriptionId/resourceGroupName" and take first 8 hex chars.
    $seed = "$SubscriptionId/$ResourceGroupName"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($seed)
        $hashBytes = $sha.ComputeHash($bytes)
    } finally {
        $sha.Dispose()
    }

    $suffix = -join ($hashBytes[0..7] | ForEach-Object { $_.ToString('x2') })  # 16 hex chars

    # 3. Combine and force lowercase
    $baseName = ($prefix +"stg"+ $suffix).ToLower()

    # 4. Storage account must be 3–24 chars, only lowercase letters and digits
    $baseName = ($baseName -replace '[^a-z0-9]', '')

    if ($baseName.Length -gt 24) {
        $finalName = $baseName.Substring(0, 24)
    } else {
        $finalName = $baseName
    }

    return $finalName
}

function Ensure-WowFileShare {
    param(
        [Parameter(Mandatory)]
        [string] $ResourceGroupName,

        [Parameter(Mandatory)]
        [string] $StorageAccountName,

        [string] $ShareName = "wowdata"
    )

    Write-Host "Ensuring Azure File share '$ShareName' exists in storage account '$StorageAccountName'..."

    # Get the storage account
    $sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop

    # Get a storage context
    $ctx = $sa.Context

    # Check if the share already exists
    $share = Get-AzStorageShare -Name $ShareName -Context $ctx -ErrorAction SilentlyContinue

    if (-not $share) {
        Write-Host "Share '$ShareName' does not exist. Creating..."

        # For most Az.Storage versions:
        # - SMB is the default protocol
        # - Standard shares default to TransactionOptimized
        # If your Az.Storage supports it, you can add:
        #   -EnabledProtocol SMB -AccessTier TransactionOptimized
        $share = New-AzStorageShare `
            -Name $ShareName `
            -Context $ctx `
            

        Write-Host "Share '$ShareName' created "
    }
    else {
        Write-Host "Share '$ShareName' already exists."

        # Optionally bump quota up to desired level if it's lower
        try {
            if ($share.Quota -lt $QuotaGiB) {
                Write-Host "Updating share quota from $($share.Quota)GiB to ${QuotaGiB}GiB..."
                $share.Properties.ShareQuota = $QuotaGiB
                $share.SetShareProperties()
            }
        }
        catch {
            Write-Warning "Failed to update share quota: $($_.Exception.Message)"
        }
    }

    return $share
}

function Wait-ForWebAppContent {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Url,

        [Parameter(Mandatory = $true)]
        [string] $ExpectedText,

        [int] $TimeoutSeconds      = 900,  # 15 minutes
        [int] $PollIntervalSeconds = 15    # 15 seconds
    )

    Write-Host ""
    Write-Host "Waiting for '$Url' to return content containing '$ExpectedText'..." -ForegroundColor Yellow
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        try {
            # Short timeout so we don't hang forever on a dead endpoint
            $response = Invoke-WebRequest -Uri $Url -TimeoutSec 30 -ErrorAction Stop

            $status = $response.StatusCode
            Write-Host "  HTTP $status from $Url" -ForegroundColor DarkGray

            if ($response.Content -like "*$ExpectedText*") {
                Write-Host "  ✅ Found expected text '$ExpectedText' in response." -ForegroundColor Green
                return $true
            }
            else {
                Write-Host "  ❌ Response did not yet contain expected text. Retrying in $PollIntervalSeconds seconds..." -ForegroundColor DarkYellow
            }
        }
        catch {
            # Covers DNS errors, connection refused, 5xx, etc.
            Write-Host "  ⚠️  Request failed: $($_.Exception.Message). Retrying in $PollIntervalSeconds seconds..." -ForegroundColor DarkYellow
        }

        Start-Sleep -Seconds $PollIntervalSeconds
    }

    Write-Host ""
    Write-Host "❌ Timed out after $TimeoutSeconds seconds waiting for '$Url' to contain '$ExpectedText'." -ForegroundColor Red
    return $false
}

$ErrorActionPreference = "Stop"
$ErrorView = 'DetailedView'

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

# Resolve script root so we can call the companion scripts
$ScriptRoot = Split-Path -Parent $PSCommandPath

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "        WORLD OF WORKFLOWS INSTALLER          " -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will guide you through installing" -ForegroundColor White
Write-Host "World of Workflows into your Azure tenancy." -ForegroundColor White
Write-Host ""
Write-Host "------------------ PRE-REQUISITES ------------------" -ForegroundColor Yellow
Write-Host "  • You must be able to log in to Entra ID as a" -ForegroundColor Cyan
Write-Host "    Global Administrator for your organisation." -ForegroundColor Cyan
Write-Host ""
Write-Host "  • You must also be able to log in as an Owner" -ForegroundColor Cyan
Write-Host "    of the Azure subscription where WoW will run." -ForegroundColor Cyan
Write-Host ""
Write-Host "  • You will need to choose a hostname for your" -ForegroundColor Cyan
Write-Host "    new World of Workflows web site." -ForegroundColor Cyan
Write-Host ""
Write-Host "    The installer will *default* this to:" -ForegroundColor White
Write-Host "        <FirstWordOfYourTenantName> + 'Workflows'" -ForegroundColor Yellow
Write-Host "    Example: Tribetech → TribetechWorkflows" -ForegroundColor Yellow
Write-Host ""
Write-Host "    You may press ENTER to accept the default," -ForegroundColor White
Write-Host "    or type a different value if preferred." -ForegroundColor White
Write-Host ""
Write-Host "-----------------------------------------------------" -ForegroundColor Cyan
Write-Host ""
# ------------------------------------------------
# 1. Connect to Azure and choose a subscription
# ------------------------------------------------

Write-Host "Connecting to Azure..." -ForegroundColor Cyan

try {
    # Try to reuse existing Az context
    $ctx = Get-AzContext -ErrorAction SilentlyContinue

    if (-not $ctx -or -not $ctx.Account) {
        Write-Host "Ensure your browser is in the correct profile to log in to Azure with your GA account," -ForegroundColor White
        Write-Host "then press Enter to continue." -ForegroundColor White
        $null = Read-Host
        Connect-AzAccount | Out-Null #-Tenant $TenantId -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        $ctx = Get-AzContext
    }
    else {
        Write-Host "Using existing Azure login:"
        Write-Host "  Account:      $($ctx.Account.Id)"
        Write-Host "  Tenant:       $($ctx.Tenant.Id)"
        Write-Host "  Subscription: $($ctx.Subscription.Name) ($($ctx.Subscription.Id))"
    }
}
catch {
    Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
    return
}

Write-Host "Fetching list of subscriptions..." -ForegroundColor Cyan

$subscriptions = Get-AzSubscription -ErrorAction Stop

if (-not $subscriptions -or $subscriptions.Count -eq 0) {
    Write-Error "No subscriptions found for the signed-in account."
    return
}

Write-Host ""
Write-Host "Available subscriptions:" -ForegroundColor Cyan

# Show numbered list
for ($i = 0; $i -lt $subscriptions.Count; $i++) {
    $s = $subscriptions[$i]

    # Build the index [0] in yellow
    $indexText = "{0}" -f $i
    Write-Host "[" -ForegroundColor Green -NoNewline
    Write-Host $indexText -ForegroundColor White -NoNewline
    Write-Host "] " -ForegroundColor Green -NoNewline
    
    # Print the rest normally
    Write-Host (" {0} ({1}) Tenant: {2}" -f $s.Name, $s.Id, $s.TenantId)
}

Write-Host ""
$index = Read-Host "Enter the number of the subscription to use"

if (-not ($index -as [int]) -or $index -lt 0 -or $index -ge $subscriptions.Count) {
    Write-Error "Invalid selection. Aborting."
    return
}

$selectedSub = $subscriptions[$index]
$SubscriptionId = $selectedSub.Id
$TenantId       = $selectedSub.TenantId
$subscriptionName = $selectedSub.Name

# Write-Host ""
# Write-Host "Using subscription:" -ForegroundColor Cyan
# Write-Host "  Name:    $($selectedSub.Name)"
# Write-Host "  ID:      $SubscriptionId"
# Write-Host "  Tenant:  $TenantId"
# Write-Host ""

Write-Host "Setting Az context..." -ForegroundColor Cyan
Set-AzContext -SubscriptionId $SubscriptionId -Tenant $TenantId -ErrorAction Stop | Out-Null

$ctx = Get-AzContext

Write-Host "Current Azure context:"
Write-Host "  Account:      $($ctx.Account.Id)"
Write-Host "  Tenant:       $($ctx.Tenant.Id)"
Write-Host "  Subscription: $($ctx.Subscription.Name) ($($ctx.Subscription.Id))"
Write-Host ""

#Write-Host "Ensuring Azure CLI is logged into correct tenant & subscription..."

# 1. Make sure we’re logged in to the same tenant as the subscription
# (You already know $TenantId and $SubscriptionId at this point)
$azLoginCmd = "az login --tenant $TenantId --only-show-errors"
#Write-Host "Running: $azLoginCmd"
Write-Host "Ensure your browser is in the correct profile to log in to Azure with your GA account," -ForegroundColor White
Write-Host "then press Enter to continue." -ForegroundColor White
$null = Read-Host
$loginResult = az login --tenant $TenantId --only-show-errors 2>&1

#Write-Host $loginResult 

# 2. Check if the subscription exists in the current account context
$subsJson = az account list --output json --only-show-errors
$subs = $subsJson | ConvertFrom-Json
$targetSub = $subs | Where-Object { $_.id -eq $SubscriptionId }

if (-not $targetSub) {
    Write-Error "Subscription $SubscriptionId is not visible for the current az login. 
Make sure this user has access to that subscription in tenant $TenantId."
    return
}

# 3. Set the subscription
#Write-Host "Setting Azure CLI subscription to $SubscriptionId..."
$setResult = az account set --subscription $SubscriptionId 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "az account set failed: $setResult"

} else {
    #Write-Host "Azure CLI subscription set to $SubscriptionId."
}

# ------------------------------------------------
# 2. Collect any remaining inputs
# ------------------------------------------------

if (-not $WebAppName) {
    $WebAppName = Read-HostDefault "Enter Web App name (e.g. TribetechWorkflows)" (($ctx.Tenant.Name -split '\s+')[0]+"Workflows")
}

if (-not $ResourceGroupName) {
    $ResourceGroupName = Read-HostDefault "Enter Resource Group name to create/use (e.g. TribetechWorkflowsRG)" ( $WebAppName+"RG")
}

if (-not $AppServicePlanName) {
    $AppServicePlanName = Read-HostDefault "Enter App Service Plan name (e.g. TribetechWorkflowsPlan)" ( $WebAppName+"Plan")
}
if (-not $StorageAccountName) {
    $storageAccountName = New-WowStorageAccountName -SiteName $WebAppName `
                                                -SubscriptionId $subscriptionId `
                                                -ResourceGroupName $ResourceGroupName

    $StorageAccountName = Read-HostDefault "Enter Storage Account name (lowercase letters + digits only, 3-24 chars)"  $storageAccountName
}
if (-not $ClientAppName) {
    $ClientAppName = Read-HostDefault "Enter Entra ID Client Application name (e.g. TribetechWorkflowsClient)" ( $WebAppName+"Client")
}
if (-not $ServerAppName) {
    $ServerAppName = Read-HostDefault "Enter Entra ID Server Application name (e.g. TribetechWorkflowsWoWServer)" ( $WebAppName+"Server")
}
if (-not $CompanyNameForWoWLicence) {
    $CompanyNameForWoWLicence = Read-HostDefault "Enter Company Name for WoW licence" $ctx.Tenant.Name
}
if (-not $BillingEmailForWoWLicence) {
    $BillingEmailForWoWLicence = Read-HostDefault "Enter Billing Email for WoW licence" ("accounts@"+$ctx.Tenant.ExtendedProperties.DefaultDomain)
}
if (-not $AdminUserPrincipalName) {
    $AdminUserPrincipalName = Read-HostDefault "Enter Admin user UPN (e.g. jimc.admin@customer.com)" $ctx.Account.Id
}

$resolvedGuestAdmins = New-Object System.Collections.Generic.List[string]
if ($GuestAdmins) {
    foreach ($ga in $GuestAdmins) {
        if (-not [string]::IsNullOrWhiteSpace($ga)) {
            $resolvedGuestAdmins.Add($ga.Trim())
        }
    }
}

Write-Host ""
Write-Host "Enter any guest administrators (UPNs) already existing in this tenant. Leave blank to finish." -ForegroundColor Cyan
while ($true) {
    $entry = Read-Host "Guest admin UPN (leave empty to finish)"
    if ([string]::IsNullOrWhiteSpace($entry)) { break }
    $resolvedGuestAdmins.Add($entry.Trim())
}
if (-not ($resolvedGuestAdmins | Where-Object { $_ -eq $AdminUserPrincipalName })) {
    $resolvedGuestAdmins.Add($AdminUserPrincipalName)
}

if (-not $PSBoundParameters.ContainsKey('Location') -or [string]::IsNullOrWhiteSpace($Location)) {
    $defaultLocation = "australiaeast"
    $resolvedLocation = $null

    try {
        Write-Host "Please wait a moment while we get a list of available locations from Microsoft Azure..." -ForegroundColor Gray
        $availableLocations = Get-AzLocation -ErrorAction Stop | Sort-Object Location
    }
    catch {
        Write-Warning "Unable to retrieve Azure locations for this subscription. Defaulting to $defaultLocation."
        $availableLocations = @()
    }

    if ($availableLocations -and $availableLocations.Count -gt 0) {
        $locationOptions = $availableLocations | Select-Object -Property Location, DisplayName

        Write-Host ""
        Write-Host "Available Azure locations:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $locationOptions.Count; $i++) {
            $entry = $locationOptions[$i]
            Write-Host ("  [{0}] {1} ({2})" -f $i, $entry.DisplayName, $entry.Location)
        }

        do {
            Write-Host ""
            $rawInput = Read-HostChooseDefault "Enter location number or short name" $defaultLocation ($locationOptions.Location)
            if ([string]::IsNullOrWhiteSpace($rawInput)) {
                $rawInput = $defaultLocation
            }

            $candidate = $null
            if ($rawInput -match '^\d+$') {
                $index = [int]$rawInput
                if ($index -ge 0 -and $index -lt $locationOptions.Count) {
                    $candidate = $locationOptions[$index]
                }
            }
            else {
                $rawInputLower = $rawInput.ToLower()
                $candidate = $locationOptions | Where-Object {
                    $_.Location.ToLower() -eq $rawInputLower -or $_.DisplayName.ToLower() -eq $rawInputLower
                }
            }

            if ($candidate) {
                $resolvedLocation = $candidate.Location.ToLower()
            }
            else {
                Write-Host "Invalid location selection. Please try again." -ForegroundColor Yellow
            }
        } while (-not $resolvedLocation)

        $Location = $resolvedLocation
    }
    else {
        $Location = $defaultLocation
    }
}
else {
    $Location = $Location.ToLower()
}

# Friendly numeric choice for Business Edition solution

$defaultChoice = '1'

Write-Host ""
Write-Host "Choose your World of Workflows edition:"
Write-Host "  1) Standard installation" -ForegroundColor Cyan
Write-Host "  2) Standard installation with additional server"
Write-Host ""

do {
    $choice = Read-Host "Enter 1 or 2 (default: $defaultChoice)"

    if ([string]::IsNullOrWhiteSpace($choice)) {
        $choice = $defaultChoice
    }

    switch ($choice) {
        '1' { $BusinessEditionSolution = 'standard'; $valid = $true }
        '2' { $BusinessEditionSolution = 'standardAdditionalServer'; $valid = $true }
        default {
            Write-Host "Invalid choice. Please enter 1 or 2." -ForegroundColor Yellow
            $valid = $false
        }
    }
}
while (-not $valid)

Write-Host "Selected option: $choice => $BusinessEditionSolution"

Write-Host ""
Write-Host "====================================" -ForegroundColor Cyan
Write-Host " App Service Plan Size"             -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host "You can change the plan size later in the Azure Portal or via PowerShell." -ForegroundColor Yellow
Write-Host ""
Write-Host "Choose the initial App Service Plan size:" -ForegroundColor White
Write-Host "  1) Basic  B2   (1x Medium instance)    [recommended default]" -ForegroundColor Yellow
Write-Host "  2) Basic  B3   (1x Large  instance)"                         -ForegroundColor Cyan
Write-Host "  3) Premium v3 P0v3"                                         -ForegroundColor Cyan
Write-Host "  4) Premium v3 P1v3"                                         -ForegroundColor Cyan
Write-Host "  5) Premium v3 P2v3"                                         -ForegroundColor Cyan
Write-Host "  6) Premium v3 P3v3"                                         -ForegroundColor Cyan
Write-Host ""

# Read and validate choice (default = 1)
$planChoice = $null
do {
    $planChoice = Read-Host "Enter choice (1-6, default 1)"
    if ([string]::IsNullOrWhiteSpace($planChoice)) {
        $planChoice = "1"
    }
} while ($planChoice -notin @("1","2","3","4","5","6"))

# Map choice -> Tier / SkuName / WorkerSize
$planTier     = $null
$planSkuName  = $null
$workerSize   = $null

switch ($planChoice) {
    "1" {
        # Basic B2
        $planTier    = "Basic"
        $planSkuName = "B2"
        $workerSize  = "Medium"   # matches what you have now
        $planDescription =  "Basic B2 (1x Medium instance)" 
    }
    "2" {
        # Basic B3
        $planTier    = "Basic"
        $planSkuName = "B3"
        $workerSize  = "Large"
        $planDescription =  "Basic B3 (1x Large instance)" 
    }
    "3" {
        # Premium v3 P0v3
        $planTier    = "PremiumV3"
        $planSkuName = "P0v3"
        $workerSize  = $null
        $planDescription =  "Premium v3 P0v3" 
    }
    "4" {
        # Premium v3 P1v3
        $planTier    = "PremiumV3"
        $planSkuName = "P1v3"
        $workerSize  = $null
        $planDescription =   "Premium v3 P1v3" 
    }
    "5" {
        # Premium v3 P2v3
        $planTier    = "PremiumV3"
        $planSkuName = "P2v3"
        $workerSize  = $null
        $planDescription =   "Premium v3 P2v3" 
    }
    "6" {
        # Premium v3 P3v3
        $planTier    = "PremiumV3"
        $planSkuName = "P3v3"
        $workerSize  = $null
        $planDescription =   "Premium v3 P3v3" 
    }
}


Write-Host ""
Write-Host "Inputs:" -ForegroundColor Cyan
Write-Host "  Tenant:                    $TenantId"
Write-Host "  Subscription:              $subscriptionName / $SubscriptionId"
Write-Host "  Resource Group:            $ResourceGroupName"
Write-Host "  Location:                  $Location"
Write-Host "  Web App:                   $WebAppName"
Write-Host "  App Service Plan:          $AppServicePlanName"
Write-Host "  Storage Account:           $StorageAccountName"
Write-Host "  Client App (Entra):        $ClientAppName"
Write-Host "  Server App (Entra):        $ServerAppName"
Write-Host "  Company (Licence):         $CompanyNameForWoWLicence"
Write-Host "  Billing Email:             $BillingEmailForWoWLicence"
Write-Host "  Admin UPN:                 $AdminUserPrincipalName"
Write-Host "  Business Edition solution: $BusinessEditionSolution"
Write-Host ""
Write-Host "  Storage Plan:              $planDescription" -ForegroundColor Yellow
Write-Host ""

$validYes = @("y","yes")
$validNo  = @("n","no")

while ($true) {
    $confirm = Read-Host "Proceed with installation? (Y/N)"

    if ($validYes -contains $confirm.ToLower()) {
        Write-Host "Proceeding with installation..."
        break
    }
    elseif ($validNo -contains $confirm.ToLower()) {
        Write-Warning "Installation cancelled by user."
        return
    }
    else {
        Write-Host "Please enter Y or N." -ForegroundColor Yellow
    }
}

# ------------------------------------------------
# 3. Ensure Resource Group
# ------------------------------------------------

Write-Host "Ensuring Resource Group '$ResourceGroupName' in $Location..." -ForegroundColor Cyan

$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $rg) {
    Write-Host "Creating resource group..."
    $rg = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Stop
} else {
    Write-Host "Resource group already exists."
}

# ------------------------------------------------
# 4. Ensure Storage Account
# ------------------------------------------------

Write-Host ""
Write-Host "Ensuring Storage Account '$StorageAccountName'..." -ForegroundColor Cyan

$stg = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $stg) {
    Write-Host "Creating storage account..."
    $stg = New-AzStorageAccount `
        -Name $StorageAccountName `
        -ResourceGroupName $ResourceGroupName `
        -Location $Location `
        -SkuName Standard_LRS `
        -Kind StorageV2 `
        -AccessTier Hot `
        -ErrorAction Stop | Out-Null
} else {
    Write-Host "Storage account already exists."
}
# ------------------------------------------------
# 5. Ensure App Service Plan (Linux)
# ------------------------------------------------

 # Check if a plan with this name already exists in the RG
$existingPlan = Get-AzAppServicePlan `
    -Name $AppServicePlanName `
    -ResourceGroupName $ResourceGroupName `
    -ErrorAction SilentlyContinue

if ($existingPlan) {
    Write-Host ""
    Write-Host "App Service Plan '$AppServicePlanName' already exists in resource group '$ResourceGroupName' – skipping creation." -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "Creating App Service Plan '$AppServicePlanName' in resource group '$ResourceGroupName'..." -ForegroundColor Yellow

    # Build parameter hashtable so we can conditionally include WorkerSize
    $planParams = @{
        Name              = $AppServicePlanName
        ResourceGroupName = $ResourceGroupName
        Location          = $Location
        Tier              = $planTier
        NumberOfWorkers   = 1
        Linux             = $true
        ErrorAction       = 'Stop'
    }

    # If your Az.Websites module supports -SkuName (it should on recent versions), include it:
    if ($planSkuName) {
#        $planParams['SkuName'] = $planSkuName
    }

    # For Basic tiers we still want explicit WorkerSize
    if ($workerSize) {
        $planParams['WorkerSize'] = $workerSize
    }

    $plan = New-AzAppServicePlan @planParams | Out-Null
    Write-Host "App Service Plan created successfully." -ForegroundColor Green
    Write-Host ""
}



Write-Information "$AppServicePlanName Plan is " (Get-AzAppServicePlan -ResourceGroupName $ResourceGroupName -Name $AppServicePlanName).Kind
Write-Host ""


# ------------------------------------------------
# 5a. Ensure file share is created
# ------------------------------------------------

$share = Ensure-WowFileShare -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName
# ------------------------------------------------
# 6. Ensure Web App (Linux, .NET 8)
# ------------------------------------------------

Write-Host ""
Write-Host "Ensuring Web App '$WebAppName'..." -ForegroundColor Cyan

$web = Get-AzWebApp -Name $WebAppName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $web) {
    Write-Host "Creating Web App..."
    $previousProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        $web = New-AzWebApp `
            -Name $WebAppName `
            -ResourceGroupName $ResourceGroupName `
            -Location $Location `
            -AppServicePlan $AppServicePlanName `
            -ErrorAction Stop | Out-Null
    }
    finally {
        $ProgressPreference = $previousProgressPreference
        Write-Progress -Activity "Web App deployment" -Completed
    }

    Write-Host "Configuring Web App for Linux .NET 8..."

    $siteConfigObject = @{
        linuxFxVersion = "DOTNETCORE|8.0"  # same as your ARM template
        alwaysOn       = $true             # or $false if you prefer
    }

    Set-AzResource `
        -ResourceGroupName $ResourceGroupName `
        -ResourceType "Microsoft.Web/sites/config" `
        -ResourceName "$WebAppName/web" `
        -ApiVersion "2023-01-01" `
        -PropertyObject $siteConfigObject `
        -Force `
        -ErrorAction Stop | Out-Null
} else {
    Write-Host "Web App already exists."
}

$BaseAddress = "https://$WebAppName.azurewebsites.net"
Write-Host "Your new websie will be at this address: $BaseAddress" -ForegroundColor White
Write-Host ""

# ------------------------------------------------
# 5a. Ensure Storage mounted on existing storage
# ------------------------------------------------

$storageKey = (Get-AzStorageAccountKey `
    -ResourceGroupName $ResourceGroupName `
    -Name $StorageAccountName `
    -ErrorAction Stop)[0].Value

Write-Host "Configuring Azure Files mount (wowstorage -> /data)..."

# First, check if wowstorage is already configured
$alreadyConfigured = $false
try {
    $listJson = az webapp config storage-account list `
        --resource-group $ResourceGroupName `
        --name $WebAppName `
        -o json 2>$null

    if ($LASTEXITCODE -eq 0 -and $listJson) {
        $mounts = $listJson | ConvertFrom-Json

        # In different CLI versions this property might be 'name' or 'customId'
        $wowMount = $mounts | Where-Object {
            $_.name -eq "wowstorage" -or $_.customId -eq "wowstorage"
        }

        if ($wowMount) {
            # Mount already exists – silently skip
            # (or uncomment this if you want a tiny bit of feedback)
            # Write-Host "Azure Files mount 'wowstorage' already configured – skipping."
            $alreadyConfigured = $true
        }
    }
}
catch {
    # If the list call fails, just fall through and try to add.
}


if (-not $alreadyConfigured) {
    $azArgs = @(
        "webapp", "config", "storage-account", "add",
        "--resource-group", $ResourceGroupName,
        "--name", $WebAppName,
        "--custom-id", "wowstorage",
        "--storage-type", "AzureFiles",
        "--share-name", "wowdata",
        "--account-name", $StorageAccountName,
        "--access-key", $storageKey,
        "--mount-path", "/data"
    )

    $azOutput = az @azArgs 2>&1

    if ($LASTEXITCODE -ne 0) {
        $outputText = if ($azOutput) { [string]::Join([Environment]::NewLine, $azOutput) } else { "" }

        if ($outputText -like "*Site already configured with an Azure storage account with the id 'wowstorage'*") {
            Write-Host "Azure Files mount 'wowstorage' already configured – skipping."
        }
        else {
            Write-Warning "Failed to configure Azure Files mount."
            if ($outputText) {
                Write-Host "Exception message:" -ForegroundColor Yellow
                Write-Host $outputText
            }
            throw "az webapp config storage-account add failed with exit code $LASTEXITCODE"
        }
    }
    else {
        Write-Host "Azure Files mount configured: wowstorage -> /data"
    }

}
# ------------------------------------------------
# 7. Run Entra ID setup (ADDeploymentScript.ps1)
# ------------------------------------------------

$adScript = Join-Path $ScriptRoot "ADDeploymentScript.ps1"
if (-not (Test-Path $adScript)) {
    throw "ADDeploymentScript.ps1 not found in $ScriptRoot. Please place it next to Install-WorldOfWorkflows.ps1."
}

Write-Host "Running ADDeploymentScript.ps1 to create Entra ID apps..." -ForegroundColor Cyan

$DeploymentScriptOutputs = & $adScript `
    -ClientappName $ClientAppName `
    -ServerappName $ServerAppName `
    -BaseAddress $BaseAddress `
    -TenantId $TenantId `
    -AdminUserPrincipalName $AdminUserPrincipalName `
    -SubscriptionId $SubscriptionId `
    -GuestAdmins $resolvedGuestAdmins.ToArray() `
    -AccountId $ctx.Account.Id

Write-Host "Entra ID applications and permissions configured." -ForegroundColor Green
Write-Host ""

# ------------------------------------------------
# 7a. Update the Web app with it's settings
# ------------------------------------------------

$ServerClientId     = $DeploymentScriptOutputs.ServerClientId
$ClientClientId     = $DeploymentScriptOutputs.ClientClientId
$ServerClientSecret = $DeploymentScriptOutputs.ServerSecret
$TenantDomain       = $DeploymentScriptOutputs.TenantDomain
$AzureToken         = $DeploymentScriptOutputs.AzureToken
$ARMToken         = $DeploymentScriptOutputs.ARMToken

# Write-Host "got token"
# Write-Host $AzureToken

# --- Load Web App config from JSON ---
$webAppConfigPath = Join-Path $PSScriptRoot 'WebAppConfig.json'

if (-not (Test-Path $webAppConfigPath)) {
    throw "Missing WebAppConfig.json at $webAppConfigPath"
}

$webAppConfig = Get-Content $webAppConfigPath -Raw | ConvertFrom-Json

Write-Host "Applying siteConfig updates..."

# Get current web app and its siteConfig
$webAppConfig = Get-Content $webAppConfigPath -Raw | ConvertFrom-Json

# Build a patch object for Microsoft.Web/sites/config
$siteConfigPatch = @{}

if ($webAppConfig.siteConfig) {

    if ($webAppConfig.siteConfig.numberOfWorkers -ne $null) {
        $siteConfigPatch.numberOfWorkers = [int]$webAppConfig.siteConfig.numberOfWorkers
    }

    if ($webAppConfig.siteConfig.linuxFxVersion) {
        $siteConfigPatch.linuxFxVersion = [string]$webAppConfig.siteConfig.linuxFxVersion
    }

    if ($webAppConfig.siteConfig.alwaysOn -ne $null) {
        $siteConfigPatch.alwaysOn = [bool]$webAppConfig.siteConfig.alwaysOn
    }

    if ($webAppConfig.siteConfig.http20Enabled -ne $null) {
        $siteConfigPatch.http20Enabled = [bool]$webAppConfig.siteConfig.http20Enabled
    }

    # add any other siteConfig properties you care about, e.g.:
    # if ($webAppConfig.siteConfig.ftpsState) {
    #     $siteConfigPatch.ftpsState = [string]$webAppConfig.siteConfig.ftpsState
    # }
}

# Only call ARM if we actually have something to set
if ($siteConfigPatch.Count -gt 0) {
    # Read-Host "about to update Microsoft.Web/sites/config via Set-AzResource (press Enter to continue)"
    
    Set-AzResource `
        -ResourceGroupName $ResourceGroupName `
        -ResourceType "Microsoft.Web/sites/config" `
        -ResourceName "$WebAppName/web" `
        -ApiVersion "2023-01-01" `
        -PropertyObject $siteConfigPatch `
        -Force `
        -ErrorAction Stop | Out-Null
}
  
Write-Host "Applying appSettings from WebAppConfig.json..."

function Resolve-AppSettingSource {
    param(
        [Parameter(Mandatory)][string]$sourceName
    )

    switch ($sourceName) {
        "ServerClientId"     { return $ServerClientId }
        "ClientClientId"     { return $ClientClientId }
        "ServerClientSecret" { return $ServerClientSecret }
        "TenantDomain"       { return $TenantDomain }
        "TenantId"           { return $TenantId }
        "BaseAddress"        { return $BaseAddress }
        default {
            throw "Unknown appSettings source '$sourceName' in WebAppConfig.json"
        }
    }
}

# 1. Start with a clean hashtable
$appSettingsHash = @{}

# 2. Seed with existing settings (so we don't blow anything away)
$existingSiteConfig = (Get-AzWebApp -Name $WebAppName -ResourceGroupName $ResourceGroupName -ErrorAction Stop).SiteConfig
$existing = $existingSiteConfig.AppSettings

if ($existing) {
    foreach ($s in $existing) {
        if ($null -eq $s) { continue }
        if ([string]::IsNullOrWhiteSpace($s.Name)) { continue }

        $appSettingsHash[$s.Name] = if ($null -eq $s.Value) { "" } else { [string]$s.Value }
    }
}

# 3. Work out where appSettings are in the JSON
$appSettingsSource = $null

if ($webAppConfig.appSettings) {
    $appSettingsSource = $webAppConfig.appSettings
}
elseif ($webAppConfig.siteConfig -and $webAppConfig.siteConfig.appSettings) {
    $appSettingsSource = $webAppConfig.siteConfig.appSettings
}

if ($appSettingsSource) {
    foreach ($item in $appSettingsSource) {
        if ($null -eq $item) { continue }

        $name = [string]$item.name
        if ([string]::IsNullOrWhiteSpace($name)) {
            Write-Warning "Skipping appSetting with blank name from WebAppConfig.json"
            continue
        }

        $formatString = $null
        if ($item.PSObject.Properties.Name -contains 'format' -and -not [string]::IsNullOrWhiteSpace($item.format)) {
            $formatString = [string]$item.format
        }

        # Dynamic source → Resolve-AppSettingSource
        if ($item.PSObject.Properties.Name -contains 'source' -and -not [string]::IsNullOrWhiteSpace($item.source)) {
            try {
                $resolved = Resolve-AppSettingSource -sourceName $item.source
                $value = if ($null -eq $resolved) { "" } else { [string]$resolved }
            }
            catch {
                Write-Error "Failed to resolve appSetting source '$($item.source)' for '$name': $($_.Exception.Message)"
                throw
            }
        }
        else {
            # Literal value from JSON
            $value = if ($null -eq $item.value) { "" } else { [string]$item.value }
        }

        if ($formatString) {
            try {
                $value = [string]::Format($formatString, $value)
            }
            catch {
                Write-Error "Failed to format value for appSetting '$name' with format '$formatString': $($_.Exception.Message)"
                throw
            }
        }

        # Overwrite or add
        $appSettingsHash[$name] = $value
    }
}
else {
    Write-Warning "No appSettings block found in WebAppConfig.json (checked appSettings and siteConfig.appSettings)."
}

# Debug type, just to be sure
# Write-Host "AppSettings object type: $($appSettingsHash.GetType().FullName)"

if ($appSettingsHash.Keys.Count -eq 0) {
    Write-Warning "No appSettings to apply (hashtable is empty) – skipping Set-AzWebApp -AppSettings."
}
else {
    # Write-Host "Applying Web App appSettings via Set-AzWebApp..."
    # Optional debug:
    # $appSettingsHash.GetEnumerator() | Sort-Object Name | Format-Table Name, Value

    Set-AzWebApp `
        -Name $WebAppName `
        -ResourceGroupName $ResourceGroupName `
        -AppSettings $appSettingsHash `
        -ErrorAction Stop |Out-Null

    Write-Host "Web App appSettings updated."
}

Write-Host ""
Write-Host "Configuring Web App connection strings from WebAppConfig.json..." -ForegroundColor Cyan

# 1. Work out where connectionStrings live in the JSON
$connectionStringsSource = $null

if ($webAppConfig.connectionStrings) {
    # Your current layout: connectionStrings at the root
    $connectionStringsSource = $webAppConfig.connectionStrings
}
elseif ($webAppConfig.siteConfig -and $webAppConfig.siteConfig.connectionStrings) {
    # Fallback layout if you ever nest them under siteConfig
    $connectionStringsSource = $webAppConfig.siteConfig.connectionStrings
}

if (-not $connectionStringsSource) {
    Write-Warning "No connectionStrings block found in WebAppConfig.json (checked connectionStrings and siteConfig.connectionStrings). Skipping connection string configuration."
}
else {
    try {
        # 2. Start with existing connection strings from the Web App
        $currentWeb = Get-AzWebApp -Name $WebAppName -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        $existingCs = $currentWeb.SiteConfig.ConnectionStrings

        # Hashtable in the shape Set-AzWebApp expects:
        #   @{
        #     "Name" = @{ Type = "Custom"; Value = "..." }
        #   }
        $connectionStringsHash = @{}

        if ($existingCs) {
            foreach ($cs in $existingCs) {
                if (-not $cs.Name) { continue }

                $connectionStringsHash[$cs.Name] = @{
                    Type  = $cs.Type
                    Value = $cs.ConnectionString
                }
            }
        }

        # 3. Overlay / add from WebAppConfig.json
        foreach ($csItem in $connectionStringsSource) {
            if ($null -eq $csItem) { continue }

            $name = [string]$csItem.name
            if ([string]::IsNullOrWhiteSpace($name)) {
                Write-Warning "Skipping connectionString entry with blank name in WebAppConfig.json"
                continue
            }

            $value = if ($null -eq $csItem.connectionString) { "" } else { [string]$csItem.connectionString }
            $type  = if ($null -eq $csItem.type) { "Custom" } else { [string]$csItem.type }

            $connectionStringsHash[$name] = @{
                Type  = $type
                Value = $value
            }
        }

        if (-not $connectionStringsHash.Keys.Count) {
            Write-Warning "connectionStringsHash is empty – nothing to apply."
        }
        else {
            Write-Host "Applying Web App connection strings via Set-AzWebApp..." -ForegroundColor Yellow

            Set-AzWebApp `
                -Name $WebAppName `
                -ResourceGroupName $ResourceGroupName `
                -ConnectionStrings $connectionStringsHash `
                -ErrorAction Stop | Out-Null

            Write-Host "Web App connection strings updated from WebAppConfig.json." -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to configure Web App connection strings: $($_.Exception.Message)"
        throw
    }
}

Write-Host "Enforcing HTTPS-only on Web App..."

$azResult = az webapp update `
    --name $WebAppName `
    --resource-group $ResourceGroupName `
    --set httpsOnly=true 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Warning "Failed to enable HTTPS-only via az webapp update:"
    Write-Warning $azResult
} else {
    Write-Host "HTTPS-only enabled on $WebAppName"
}




# ------------------------------------------------
# 8. Fetch Kudu publishing profile
# ------------------------------------------------

Write-Host "Fetching Web App publishing profile..." -ForegroundColor Cyan

$publishXml = [xml](Get-AzWebAppPublishingProfile `
    -ResourceGroupName $ResourceGroupName `
    -Name $WebAppName `
    -ErrorAction Stop)

$kuduProfile = $publishXml.publishData.publishProfile |
    Where-Object { $_.publishMethod -eq "MSDeploy" }

if (-not $kuduProfile) {
    throw "Could not find MSDeploy publishing profile for web app $WebAppName."
}

$kuduUsername = $kuduProfile.userName
$kuduPassword = $kuduProfile.userPWD

# Write-Host "Kudu username: $kuduUsername"

# ------------------------------------------------
# 8.5 RBAC for WoW to access client app
# ------------------------------------------------


# *** Publisher control-plane app (multi-tenant) ***
$publisherAppId = "492855a6-9cb6-4500-bc22-85c3cbba47d0"  # real appId from WoW tenant // WoWClientManagement App registration

Write-Host "Ensuring publisher service principal exists in this tenant..."

# This runs in the customer tenant, under customer GA / Owner
$publisherSp = Get-AzADServicePrincipal -Filter "appId eq '$publisherAppId'"

if (-not $publisherSp) {
    Write-Host "Creating service principal for publisher appId $publisherAppId in customer tenant..."
    $publisherSp = New-AzADServicePrincipal -ApplicationId $publisherAppId -ErrorAction Stop
} else {
    Write-Host "Publisher service principal already exists in customer tenant. ObjectId: $($publisherSp.Id)"
}

# Now assign RBAC on the WoW resource group (or subscription)
$scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"

Write-Host "Granting Contributor on $scope to publisher SP $($publisherSp.Id)..."

# You can use Contributor, Owner, or a custom role definition here
$roleName = "Owner"

# Check if assignment already exists
$existingAssignment = Get-AzRoleAssignment -ObjectId $publisherSp.Id -Scope $scope -ErrorAction SilentlyContinue

if (-not $existingAssignment) {
    New-AzRoleAssignment `
        -ObjectId $publisherSp.Id `
        -RoleDefinitionName $roleName `
        -Scope $scope `
        -ErrorAction Stop | Out-Null

    Write-Host "Role assignment created."
}
else {
    Write-Host "Role assignment already exists – skipping creation."
}

# ------------------------------------------------
# 10. Notify WoWCentral (WowCentralDeployRequest.ps1)
# ------------------------------------------------

Write-Host "Building payload to send to WoWCentral for the code deployment..."

# Hard-coded WowCentral endpoint
$WowCentralUrl = 'https://wowcentral.azurewebsites.net/deploymentRequest'

# Build payload sent to WowCentral
$payload = @{
    managedResourceGroup = $ResourceGroupName
    webAppName          = $WebAppName
    subscriptionId      = $SubscriptionId
    tenantId            = $TenantId
    subscriptionName    = $subscriptionName
    appServicePlanName  = $AppServicePlanName
    location            = $Location
    clientAppName       = $ClientAppName
    serverAppName       = $ServerAppName
    storageAccountName  = $StorageAccountName
    companyNameForWoWLicence = $CompanyNameForWoWLicence
    billingEmailForWoWLicence = $BillingEmailForWoWLicence
    adminUserPrincipalName = $AdminUserPrincipalName
    businessEditionSolution  = $BusinessEditionSolution
    kuduPassword = $kuduPassword
    kuduUsername = $kuduUsername
    AzureToken = $AzureToken
    ARMToken = $ARMToken
    guestAdmins = $resolvedGuestAdmins.ToArray()
}

$body = $payload | ConvertTo-Json -Depth 6
#Write-Host $body
Write-Host ""
Write-Host "Deploying your new instance to $BaseAddress ..." -ForegroundColor Cyan

$null = Invoke-RestMethod -Uri $WowCentralUrl -Method Post -Body $body -ContentType 'application/json'

#Write-Host "Payload sent successfully."


Write-Host ""
Write-Host "===========================================================================" -ForegroundColor Cyan
Write-Host "  Deployment usually is comoplete within 10 minutes.  "-ForegroundColor Yellow
Write-Host ""
Write-Host "  Your new websie will be at this address: " -ForegroundColor Yellow
Write-Host "       $BaseAddress " -ForegroundColor White
Write-Host "  within 10 minutes." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Contact us at " -ForegroundColor Yellow -NoNewline
Write-Host " support@worldofworkflows.com" -ForegroundColor White -NoNewline
Write-Host " if you have any questions." -ForegroundColor Yellow
Write-Host ""
Write-Host "===========================================================================" -ForegroundColor Cyan
Write-Host ""

# Assume you already have something like:
# $WebAppName      = "TRIBETECHWorkflows"
# $ResourceGroupName = "TRIBETECHWorkflowsRG"
# $BaseAddress       = "https://$WebAppName.azurewebsites.net/"

Write-Host ""
Write-Host " Checking that World of Workflows front-end is up..." -ForegroundColor White

$expectedText = "World of Workflows"  # or some other stable string in your HTML

$ok = Wait-ForWebAppContent -Url $BaseAddress -ExpectedText $expectedText -TimeoutSeconds 900

if (-not $ok) {
    throw "Web app '$BaseAddress' did not return expected text '$expectedText' within the 900 second timeout."
}

Write-Host ""
Write-Host "World of Workflows appears to be running successfully at $WebAppUrl" -ForegroundColor Yellow
Write-Host ""
Write-Host "===========================================================================" -ForegroundColor Cyan
Write-Host "   World of Workflows deployment script completed.   "
Write-Host "===========================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press enter to launch your new World of Workflows instance.  "
Write-Host "Please login with your admin username " -ForegroundColor Yellow
 # -----------------------------
                # LAUNCH WEBSITE AUTOMATICALLY
                # -----------------------------
                Write-Host ""
                
                if ($IsWindows) {
                    Start-Process $BaseAddress
                }
                elseif ($IsMacOS) {
                    & open -u $BaseAddress
                }
                elseif ($IsLinux) {
                    & xdg-open $BaseAddress
                }
                else {
                    Write-Host "⚠️ Cannot auto-open browser on this OS. Please open: $BaseAddress" -ForegroundColor Yellow
                }

                return $true
