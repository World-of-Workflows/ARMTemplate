# ARMTemplate
ARM Template Support Files

Here’s a structured write-up you can drop into a README / internal doc for the solution.

⸻

World of Workflows – Managed Application ARM Template Flow

This document explains how the World of Workflows Business Edition Managed Application is deployed using Azure ARM templates, deployment scripts, and the supporting PowerShell scripts.

It’s written from the point of view of:
	•	Publisher / developer maintaining the templates and scripts.
	•	Operators debugging or verifying a deployment.

⸻

1. High-Level Overview

The solution is published as an Azure Managed Application. When a customer deploys it from the Marketplace:
	1.	Azure asks for Managed Application details (subscription, Application Name, Managed Resource Group, etc.).
	2.	Your createUiDefinition.json drives the “Instance details” UI:
	•	App name, admin UPN, company/billing info.
	•	A 90-day trial checkbox.
	3.	Your mainTemplate.json is deployed into the Managed Resource Group, creating:
	•	Storage account, App Service plan, App Service, Key Vault (if used), etc.
	•	Several Microsoft.Resources/deploymentScripts resources to:
	•	Create Entra ID applications (client + server).
	•	Call WowCentral with deployment context and Kudu credentials.
	4.	The App Service starts; WowCentral orchestrates the actual application deployment (ZIP deploy) using the information it receives.

The customer sees a “simple” Marketplace experience; the complexity is encapsulated in the template and scripts.

⸻

2. Key Files

2.1 createUiDefinition.json

Defines the Instance details experience and the values that flow into mainTemplate.json:
	•	Core app / infra inputs
	•	sites_BETemplate_name – Web App name.
	•	serverfarms_BETemplatePlan_name – App Service plan name.
	•	location – Region (often constrained to australiaeast via config.basics.location.allowedValues).
	•	Entra ID / identity
	•	entraId_Application_ClientName – Client app registration name.
	•	entraId_Application_ServerName – Server app registration name.
	•	adminUserPrincipalName – UPN of the admin user to be assigned to the server app’s Enterprise application.
	•	Licensing / commercial
	•	companyNameForWoWLicence – Company name for the World of Workflows licence.
	•	billingEmailForWoWLicence – Billing / licensing contact email.
	•	acceptTrialLicence – Checkbox: “I accept the 90-day free licence…”
	•	Information / UX
	•	Microsoft.Common.InfoBox explaining the 90-day trial and licensing contact.
	•	Microsoft.Common.CheckBox enforcing acceptance of trial terms.

In the outputs section, these values are mapped to outputs like:

"outputs": {
  "sites_BETemplate_name": "[basics('sites_BETemplate_name')]",
  "serverfarms_BETemplatePlan_name": "[basics('serverfarms_BETemplatePlan_name')]",
  "location": "[location()]",
  "entraId_Application_ClientName": "[basics('entraId_Application_ClientName')]",
  "entraId_Application_ServerName": "[basics('entraId_Application_ServerName')]",
  "adminUserPrincipalName": "[basics('adminUserPrincipalName')]",
  "companyNameForWoWLicence": "[basics('companyNameForWoWLicence')]",
  "billingEmailForWoWLicence": "[basics('billingEmailForWoWLicence')]",
  "acceptTrialLicence": "[basics('acceptTrialLicence')]",
  "applicationResourceName": "[basics('sites_BETemplate_name')]"
}

applicationResourceName controls the name of the Managed Application resource itself.
The Managed Resource Group name is still provided directly in the Marketplace “Managed resource group” field by the customer.

⸻

2.2 mainTemplate.json

This ARM template:
	•	Is deployed into the Managed Resource Group.
	•	Declares parameters matching the outputs from createUiDefinition.json.
	•	Creates the core Azure resources (storage account, plan, App Service, etc.).
	•	Declares several Microsoft.Resources/deploymentScripts resources to do “dynamic” work that plain ARM can’t.

Key parameters (examples):

"parameters": {
  "sites_BETemplate_name": { "type": "string" },
  "serverfarms_BETemplatePlan_name": { "type": "string" },
  "location": { "type": "string" },
  "entraId_Application_ClientName": { "type": "string" },
  "entraId_Application_ServerName": { "type": "string" },
  "adminUserPrincipalName": { "type": "string" },
  "companyNameForWoWLicence": { "type": "string" },
  "billingEmailForWoWLicence": { "type": "string" },
  "managedIdentityName": {
    "type": "object"
    // contains { "type": "UserAssigned", "userAssignedIdentities": { "<MI resourceId>": {} } }
  },
  "scriptForceRunId": { "type": "string" }
}

The App Service, storage account and other infra are standard ARM resources, wired together with dependsOn.

The interesting parts are the deployment scripts.

⸻

3. Deployment Scripts

3.1 CreateAzureADObjectsAndOutput (Entra ID setup)

Resource type:

"type": "Microsoft.Resources/deploymentScripts",
"kind": "AzurePowerShell"

Purpose:
	•	Create two Entra ID app registrations:
	•	Client app (ClientappName) – used by the front-end.
	•	Server app (ServerappName) – API / backend.
	•	Configure redirect URIs for the client app.
	•	Configure API scopes and app roles on the server app.
	•	Grant Microsoft Graph delegated permissions (User.Read, User.ReadBasic.All).
	•	Pre-authorize the client app against the server app.
	•	Create a client secret for the server app.
	•	Create a service principal (Enterprise application) for the server app and assign the admin user (by UPN) to the “Administrator” app role.
	•	Return key values to ARM as outputs.

Script file:
	•	primaryScriptUri → ADDeploymentScript.ps1 hosted in GitHub.  https://github.com/World-of-Workflows/Business-Edition/blob/main/Deployment/ADDeploymentScript.ps1

Arguments (simplified):

"arguments": "[concat(
  '-TenantId ', subscription().tenantId,
  ' -ServerappName \\\"', parameters('entraId_Application_ServerName'), '\\\"',
  ' -ClientappName \\\"', parameters('entraId_Application_ClientName'), '\\\"',
  ' -BaseAddress \\\"https://', parameters('sites_BETemplate_Name'), '.azurewebsites.net\\\"',
  ' -AdminUserPrincipalName \\\"', parameters('adminUserPrincipalName'), '\\\"'
)]"

Inside ADDeploymentScript.ps1 (high level):
	•	Creates $ClientApp = New-AzADApplication ...
	•	Creates $ServerApp = New-AzADApplication ...
	•	Adds scopes and an “Administrator” app role to $ServerApp.
	•	Calls Update-AzAdApplication to set API scopes and preauthorized app.
	•	Creates a server secret with New-AzADAppCredential.
	•	Ensures a service principal exists for $ServerApp with New-AzADServicePrincipal if needed.
	•	Looks up the admin user ($AdminUserPrincipalName) and uses Microsoft Graph to create an app role assignment so that user is a member of the server Enterprise app with the “Administrator” role.
	•	Populates $DeploymentScriptOutputs:
	•	ClientClientId
	•	ServerClientId
	•	ServerSecret
	•	TenantId
	•	TenantDomain

These outputs can be consumed in mainTemplate.json via:

"[reference('CreateAzureADObjectsAndOutput', '2023-08-01', 'Full').outputs.ClientClientId]"

and typically get written into the App Service’s app settings / connection strings.

⸻

3.2 WowCentralDeployRequest (notify WowCentral)

Resource type:

"type": "Microsoft.Resources/deploymentScripts",
"kind": "AzurePowerShell"

Purpose:

Collect environment & identity details and send them to WowCentral so that WowCentral can orchestrate deployment (ZIP deploy) and record licensing context.

Script file:
	•	primaryScriptUri → WowCentralDeployRequest.ps1 hosted in GitHub. https://github.com/World-of-Workflows/Business-Edition/blob/main/Deployment/WowCentralDeployRequest.ps1

Arguments:

"arguments": "[concat(
  '-ResourceGroupName ', resourceGroup().name,
  ' -WebAppName ', '\"', parameters('sites_BETemplate_name'), '\"',
  ' -ManagedResourceGroup ', '\"', resourceGroup().name, '\"',
  ' -SubscriptionId ', subscription().subscriptionId,
  ' -AppServicePlanName ', '\"', parameters('serverfarms_BETemplatePlan_name'), '\"',
  ' -Location ', '\"', parameters('location'), '\"',
  ' -ClientAppName ', '\"', parameters('entraId_Application_ClientName'), '\"',
  ' -ServerAppName ', '\"', parameters('entraId_Application_ServerName'), '\"',
  ' -StorageAccountName ', '\"', variables('storageAccountNameFinal'), '\"',
  ' -CompanyNameForWoWLicence ', '\"', parameters('companyNameForWoWLicence'), '\"',
  ' -BillingEmailForWoWLicence ', '\"', parameters('billingEmailForWoWLicence'), '\"'
)]"

Inside WowCentralDeployRequest.ps1 (high level):
	•	Hard-codes the WowCentral endpoint, e.g.:

$WowCentralUrl = 'https://wowcentral.azurewebsites.net/deploymentNotification'


	•	Resolves the subscription name using Get-AzSubscription.
	•	Fetches the Web App publishing profile via Get-AzWebAppPublishingProfile.
	•	Extracts Kudu credentials (MSDeploy profile):
	•	$kuduUsername
	•	$kuduPassword
	•	Builds a JSON payload including:
	•	managedResourceGroup
	•	webAppName
	•	subscriptionId, subscriptionName
	•	kuduUsername, kuduPassword
	•	appServicePlanName, location
	•	clientAppName, serverAppName
	•	storageAccountName
	•	companyNameForWoWLicence
	•	billingEmailForWoWLicence
	•	Sends the payload to WowCentral via Invoke-RestMethod -Method Post.
	•	Optionally sets $DeploymentScriptOutputs['status'] = 'sent'.

WowCentral can then:
	•	Use Kudu credentials + storageAccountName / webAppName to perform ZIP deployment.
	•	Associate the deployment with companyNameForWoWLicence / billingEmailForWoWLicence.
	•	Track licence state for the 90-day trial.

⸻

4. Licence & UX Behaviour

From the customer’s perspective:
	1.	On the “Instance details” page:
	•	They see licensing information in an InfoBox.
	•	They must tick a checkbox indicating acceptance of a 90-day free licence and that they consent to being contacted about licensing.
	•	They provide:
	•	Company name (companyNameForWoWLicence).
	•	Billing / licensing contact email (billingEmailForWoWLicence).
	2.	That information flows into:
	•	mainTemplate.json → deploymentScripts → WowCentralDeployRequest.ps1.
	•	WowCentral receives all of it in the payload and can drive follow-up communication and licence management.

The ARM template itself does not enforce any licensing logic; it only collects and forwards the required information.

⸻

5. Execution Order Summary

A typical deployment sequence looks like:
	1.	Customer deploys the Managed Application from the Marketplace.
	2.	Portal presents Instance details (from createUiDefinition.json), including the 90-day trial info, admin UPN and company/billing info.
	3.	Once the customer submits:
	•	Azure creates the Managed Application resource in the Application Resource Group.
	•	Azure creates the Managed Resource Group, then deploys mainTemplate.json into it.
	4.	mainTemplate.json:
	1.	Creates core infra (storage, plan, App Service, identity, etc.).
	2.	Runs CreateAzureADObjectsAndOutput.  This is a DeploymentScript that runs 
	•	Creates Entra apps, scopes, secret, service principal.
	•	Assigns admin user to server Enterprise app.
	•	Outputs client/server IDs and secrets back to ARM.
	3.	Uses those outputs to configure the App Service (app settings).
	4.	Runs WowCentralDeployRequest:
	•	Collects Kudu credentials, subscription and environment details.
	•	Sends them, plus company/licensing data, to WowCentral.
	5.	WowCentral receives the payload and:
	•	Performs ZIP deployment using Kudu.
	•	Tracks licence and contacts the billing email during the 90-day trial.
	6.	The App Service becomes available; on first admin sign-in, the client app Enterprise application is created and admin consent is granted, matching the server-side setup from ADDeploymentScript.ps1.

⸻

6. Security Considerations (for reviewers / internal notes)
	•	Kudu credentials:
	•	Treated as secrets.
	•	Only transmitted over HTTPS to a known WowCentral endpoint.
	•	Not exposed in ARM outputs or portal UI.
	•	Entra ID permissions:
	•	ADDeploymentScript.ps1 requires directory write permissions (app registration, app role assignment).
	•	The managed identity used by deployment scripts must be scoped appropriately.
	•	Customer data:
	•	Company name + billing email are collected explicitly and only sent to WowCentral as part of deployment context for licensing.
	•	Region:
	•	If required, deployments can be constrained to australiaeast via config.basics.location.allowedValues to ensure data residency.

⸻
