# World of Workflows - Setup Diagnostics
# ======================================
# Run this script to diagnose setup issues

param(
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$false)]
    [string]$ResourceGroupName = "WorldOfWorkflows-Setup",
    
    [Parameter(Mandatory=$false)]
    [string]$IdentityName = "WoW-Installer"
)

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  World of Workflows - Setup Diagnostics                   ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$issues = @()
$warnings = @()

# Check 1: Azure PowerShell Module
Write-Host "Checking Azure PowerShell modules..." -ForegroundColor Cyan
if (Get-Module -ListAvailable -Name Az.Accounts) {
    Write-Host "✅ Az.Accounts module installed" -ForegroundColor Green
} else {
    Write-Host "❌ Az.Accounts module NOT installed" -ForegroundColor Red
    $issues += "Install Az.Accounts: Install-Module Az.Accounts -Scope CurrentUser"
}

if (Get-Module -ListAvailable -Name Az.ManagedServiceIdentity) {
    Write-Host "✅ Az.ManagedServiceIdentity module installed" -ForegroundColor Green
} else {
    Write-Host "❌ Az.ManagedServiceIdentity module NOT installed" -ForegroundColor Red
    $issues += "Install Az.ManagedServiceIdentity: Install-Module Az.ManagedServiceIdentity -Scope CurrentUser"
}

if (Get-Module -ListAvailable -Name Microsoft.Graph) {
    Write-Host "✅ Microsoft.Graph module installed" -ForegroundColor Green
} else {
    Write-Host "⚠️  Microsoft.Graph module NOT installed" -ForegroundColor Yellow
    $warnings += "Install Microsoft.Graph: Install-Module Microsoft.Graph -Scope CurrentUser"
}

Write-Host ""

# Check 2: Azure Login
Write-Host "Checking Azure login..." -ForegroundColor Cyan
try {
    $context = Get-AzContext
    if ($context) {
        Write-Host "✅ Logged into Azure" -ForegroundColor Green
        Write-Host "   Account: $($context.Account.Id)" -ForegroundColor Gray
        Write-Host "   Subscription: $($context.Subscription.Name)" -ForegroundColor Gray
        Write-Host "   Tenant: $($context.Tenant.Id)" -ForegroundColor Gray
    } else {
        Write-Host "❌ Not logged into Azure" -ForegroundColor Red
        $issues += "Login to Azure: Connect-AzAccount"
    }
} catch {
    Write-Host "❌ Not logged into Azure" -ForegroundColor Red
    $issues += "Login to Azure: Connect-AzAccount"
}

Write-Host ""

# Check 3: Subscription Selection
if ($context) {
    Write-Host "Checking subscription..." -ForegroundColor Cyan
    
    if ($SubscriptionId) {
        try {
            $null = Set-AzContext -SubscriptionId $SubscriptionId
            $context = Get-AzContext
            Write-Host "✅ Switched to subscription: $($context.Subscription.Name)" -ForegroundColor Green
        } catch {
            Write-Host "❌ Failed to switch to subscription: $SubscriptionId" -ForegroundColor Red
            $issues += "Verify subscription ID is correct"
        }
    } else {
        Write-Host "ℹ️  Using current subscription: $($context.Subscription.Name)" -ForegroundColor Cyan
        $subscriptions = Get-AzSubscription
        if ($subscriptions.Count -gt 1) {
            Write-Host "⚠️  You have access to multiple subscriptions:" -ForegroundColor Yellow
            foreach ($sub in $subscriptions) {
                $marker = if ($sub.Id -eq $context.Subscription.Id) { "→" } else { " " }
                Write-Host "   $marker $($sub.Name) ($($sub.Id))" -ForegroundColor Gray
            }
            Write-Host ""
            Write-Host "   To use a different subscription, run:" -ForegroundColor Gray
            Write-Host "   Set-AzContext -SubscriptionId 'YOUR-SUBSCRIPTION-ID'" -ForegroundColor Gray
        }
    }
    
    Write-Host ""
}

# Check 4: Resource Group
if ($context) {
    Write-Host "Checking resource group..." -ForegroundColor Cyan
    try {
        $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
        Write-Host "✅ Resource group exists: $ResourceGroupName" -ForegroundColor Green
        Write-Host "   Location: $($rg.Location)" -ForegroundColor Gray
        Write-Host "   Subscription: $($context.Subscription.Name)" -ForegroundColor Gray
    } catch {
        Write-Host "❌ Resource group NOT found: $ResourceGroupName" -ForegroundColor Red
        Write-Host "   Subscription: $($context.Subscription.Name)" -ForegroundColor Gray
        $issues += "Create resource group: New-AzResourceGroup -Name '$ResourceGroupName' -Location 'australiaeast'"
    }
    
    Write-Host ""
}

# Check 5: Managed Identity
if ($context) {
    Write-Host "Checking managed identity..." -ForegroundColor Cyan
    try {
        $identity = Get-AzUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $IdentityName -ErrorAction Stop
        Write-Host "✅ Managed identity exists: $IdentityName" -ForegroundColor Green
        Write-Host "   Resource Group: $ResourceGroupName" -ForegroundColor Gray
        Write-Host "   Location: $($identity.Location)" -ForegroundColor Gray
        Write-Host "   Principal ID: $($identity.PrincipalId)" -ForegroundColor Gray
        Write-Host "   Client ID: $($identity.ClientId)" -ForegroundColor Gray
        Write-Host "   Resource ID: $($identity.Id)" -ForegroundColor Gray
        


Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Step 3: Connecting to Microsoft Graph" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

Write-Host "⚠️  IMPORTANT: Browser Profile Switch May Be Required" -ForegroundColor Yellow -BackgroundColor Black
Write-Host ""
Write-Host "You may need to sign in with a DIFFERENT account for Graph/Entra ID:" -ForegroundColor Yellow
Write-Host "  • Azure login: Your regular Azure account (e.g., user@company.com)" -ForegroundColor Gray
Write-Host "  • Graph login: Global Administrator account (e.g., admin@company.com)" -ForegroundColor Gray
Write-Host ""
Write-Host "If these are different accounts:" -ForegroundColor Yellow
Write-Host "  1. The browser will open for authentication" -ForegroundColor Gray
Write-Host "  2. You may need to switch browser profiles" -ForegroundColor Gray
Write-Host "  3. Or use InPrivate/Incognito mode" -ForegroundColor Gray
Write-Host "  4. Sign in with your Global Administrator account" -ForegroundColor Gray
Write-Host ""
Read-Host "Press Enter when ready to proceed with Graph authentication"

Write-Host ""
Write-Host "Opening browser for Global Administrator authentication..." -ForegroundColor Cyan
Write-Host ""


        # Check if we can connect to Graph to check permissions
        Write-Host ""
        Write-Host "   Checking Azure AD permissions..." -ForegroundColor Cyan
        try {
            Connect-MgGraph -Scopes "Directory.Read.All" -NoWelcome -ErrorAction Stop
            $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $identity.PrincipalId -ErrorAction Stop
            
            $hasPermission = $false
            foreach ($assignment in $assignments) {
                $resource = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId -ErrorAction SilentlyContinue
                if ($resource) {
                    $role = $resource.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }
                    if ($role.Value -eq "Application.ReadWrite.All") {
                        $hasPermission = $true
                        Write-Host "   ✅ Has Application.ReadWrite.All permission" -ForegroundColor Green
                        break
                    }
                }
            }
            
            if (-not $hasPermission) {
                Write-Host "   ❌ Does NOT have Application.ReadWrite.All permission" -ForegroundColor Red
                $issues += "Grant permissions: .\Grant-WoWPermissions.ps1 -SubscriptionId '$($context.Subscription.Id)' -ManagedResourceGroupName '$ResourceGroupName' -SiteName '$IdentityName'"
            }
            
            Disconnect-MgGraph | Out-Null
            
        } catch {
            Write-Host "   ⚠️  Could not check Azure AD permissions" -ForegroundColor Yellow
            Write-Host "      (This is OK if you haven't granted them yet)" -ForegroundColor Gray
            $warnings += "To grant permissions: .\Grant-WoWPermissions.ps1 -SubscriptionId '$($context.Subscription.Id)' -ManagedResourceGroupName '$ResourceGroupName' -SiteName '$IdentityName'"
        }
        
    } catch {
        Write-Host "❌ Managed identity NOT found: $IdentityName" -ForegroundColor Red
        Write-Host "   Resource Group: $ResourceGroupName" -ForegroundColor Gray
        Write-Host "   Subscription: $($context.Subscription.Name)" -ForegroundColor Gray
        $issues += "Create managed identity: New-AzUserAssignedIdentity -Name '$IdentityName' -ResourceGroupName '$ResourceGroupName' -Location 'australiaeast'"
    }
    
    Write-Host ""
}

# Summary
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Diagnostics Summary" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

if ($issues.Count -eq 0 -and $warnings.Count -eq 0) {
    Write-Host "✅ All checks passed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Your setup appears to be correct. You can proceed with deployment." -ForegroundColor Green
} else {
    if ($issues.Count -gt 0) {
        Write-Host "❌ Issues Found ($($issues.Count)):" -ForegroundColor Red
        Write-Host ""
        foreach ($issue in $issues) {
            Write-Host "   • $issue" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    
    if ($warnings.Count -gt 0) {
        Write-Host "⚠️  Warnings ($($warnings.Count)):" -ForegroundColor Yellow
        Write-Host ""
        foreach ($warning in $warnings) {
            Write-Host "   • $warning" -ForegroundColor Gray
        }
        Write-Host ""
    }
}

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "For help, contact: support@worldofworkflows.com" -ForegroundColor Gray
Write-Host "Documentation: https://world-of-workflows.github.io/WorkflowsUniversity/" -ForegroundColor Gray
Write-Host ""
