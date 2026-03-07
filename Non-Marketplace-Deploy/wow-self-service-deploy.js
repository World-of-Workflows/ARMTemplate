(function () {
  "use strict";

  // Configure once during integration.
  const config = {
    apiBase: "/api/wow/deployment",
    apiScope: "api://wow-deployment-api/.default",
    pollMs: 5000
  };

  const el = {
    btnLogin: document.getElementById("btnLogin"),
    btnLoadSubs: document.getElementById("btnLoadSubs"),
    authState: document.getElementById("authState"),
    form: document.getElementById("deployForm"),

    subscriptionId: document.getElementById("subscriptionId"),
    tenantId: document.getElementById("tenantId"),
    webAppName: document.getElementById("webAppName"),
    resourceGroupName: document.getElementById("resourceGroupName"),
    appServicePlanName: document.getElementById("appServicePlanName"),
    storageAccountName: document.getElementById("storageAccountName"),
    location: document.getElementById("location"),
    clientAppName: document.getElementById("clientAppName"),
    serverAppName: document.getElementById("serverAppName"),
    companyNameForWoWLicence: document.getElementById("companyNameForWoWLicence"),
    billingEmailForWoWLicence: document.getElementById("billingEmailForWoWLicence"),
    adminUserPrincipalName: document.getElementById("adminUserPrincipalName"),
    guestAdmins: document.getElementById("guestAdmins"),
    planChoice: document.getElementById("planChoice"),
    confirmProceed: document.getElementById("confirmProceed"),

    btnCheckName: document.getElementById("btnCheckName"),
    nameState: document.getElementById("nameState"),

    btnStart: document.getElementById("btnStart"),
    btnCancelJob: document.getElementById("btnCancelJob"),

    jobState: document.getElementById("jobState"),
    jobOutputs: document.getElementById("jobOutputs"),
    jobLogs: document.getElementById("jobLogs")
  };

  let state = {
    user: null,
    subscriptions: [],
    webAppConfigVersion: null,
    activeJobId: null,
    pollTimer: null
  };

  function setText(node, text, cls) {
    node.textContent = text || "";
    node.className = "state" + (cls ? " " + cls : "");
  }

  function appendLog(line) {
    const current = el.jobLogs.textContent || "";
    el.jobLogs.textContent = current + (current ? "\n" : "") + line;
    el.jobLogs.scrollTop = el.jobLogs.scrollHeight;
  }

  function clearSelect(select) {
    while (select.options.length) {
      select.remove(0);
    }
  }

  function addOption(select, value, text) {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = text;
    select.appendChild(opt);
  }

  function normalizeWebAppName(name) {
    return (name || "").trim().toLowerCase();
  }

  function deriveStorageDefault(webAppName, subscriptionId, resourceGroupName) {
    // Browser-side deterministic default (PowerShell uses hash-based helper).
    const clean = (webAppName || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    const seed = (subscriptionId || "") + (resourceGroupName || "");
    let hash = 0;
    for (let i = 0; i < seed.length; i += 1) {
      hash = ((hash << 5) - hash) + seed.charCodeAt(i);
      hash |= 0;
    }
    const suffix = Math.abs(hash).toString().slice(0, 8);
    return (clean + suffix).slice(0, 24).replace(/[^a-z0-9]/g, "");
  }

  function parseGuestAdmins(text) {
    const lines = (text || "").split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    return Array.from(new Set(lines));
  }

  function selectedBusinessEdition() {
    const checked = document.querySelector("input[name='businessEditionSolution']:checked");
    return checked ? checked.value : "standard";
  }

  function getAuthAdapter() {
    return window.wowAuth || null;
  }

  async function getApiToken() {
    const auth = getAuthAdapter();
    if (!auth || typeof auth.getAccessToken !== "function") {
      return null;
    }
    try {
      const token = await auth.getAccessToken([config.apiScope]);
      return token || null;
    } catch (err) {
      appendLog("Token acquisition failed: " + (err && err.message ? err.message : String(err)));
      return null;
    }
  }

  async function apiFetch(path, options) {
    const token = await getApiToken();
    const headers = Object.assign({}, options && options.headers ? options.headers : {});
    if (token) {
      headers.Authorization = "Bearer " + token;
    }
    if (!headers["Content-Type"] && options && options.body) {
      headers["Content-Type"] = "application/json";
    }

    const res = await fetch(config.apiBase + path, {
      method: (options && options.method) || "GET",
      headers,
      body: options && options.body ? options.body : undefined,
      credentials: "include"
    });

    const text = await res.text();
    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch (_err) {
        data = text;
      }
    }

    if (!res.ok) {
      const msg = typeof data === "string" ? data : (data && (data.error || data.message)) || "Request failed";
      throw new Error(path + " -> " + res.status + ": " + msg);
    }

    return data;
  }

  function validateInputs() {
    const webAppName = normalizeWebAppName(el.webAppName.value);
    const webAppValid = /^[a-z0-9](?:[a-z0-9-]{0,58}[a-z0-9])?$/.test(webAppName);
    if (!webAppValid) {
      return "Web App name is invalid.";
    }

    const storage = (el.storageAccountName.value || "").trim().toLowerCase();
    const storageValid = /^[a-z0-9]{3,24}$/.test(storage);
    if (!storageValid) {
      return "Storage Account name must be 3-24 lowercase letters or digits.";
    }

    if (!el.confirmProceed.checked) {
      return "You must confirm before starting deployment.";
    }

    if (!el.subscriptionId.value || !el.tenantId.value || !el.location.value) {
      return "Subscription, tenant, and location are required.";
    }

    return null;
  }

  function syncDefaultsFromWebApp() {
    const webApp = normalizeWebAppName(el.webAppName.value);
    el.webAppName.value = webApp;

    if (!el.resourceGroupName.value.trim()) {
      el.resourceGroupName.value = webApp + "RG";
    }
    if (!el.appServicePlanName.value.trim()) {
      el.appServicePlanName.value = webApp + "Plan";
    }
    if (!el.clientAppName.value.trim()) {
      el.clientAppName.value = webApp + "Client";
    }
    if (!el.serverAppName.value.trim()) {
      el.serverAppName.value = webApp + "Server";
    }

    if (!el.storageAccountName.value.trim()) {
      el.storageAccountName.value = deriveStorageDefault(webApp, el.subscriptionId.value, el.resourceGroupName.value);
    }
  }

  async function doLogin() {
    const auth = getAuthAdapter();
    if (!auth || typeof auth.login !== "function") {
      setText(el.authState, "window.wowAuth.login() is not wired.", "err");
      return;
    }

    setText(el.authState, "Signing in...", "warn");
    try {
      const user = await auth.login();
      state.user = user || null;

      if (state.user && state.user.upn && !el.adminUserPrincipalName.value.trim()) {
        el.adminUserPrincipalName.value = state.user.upn;
      }
      if (state.user && state.user.companyName && !el.companyNameForWoWLicence.value.trim()) {
        el.companyNameForWoWLicence.value = state.user.companyName;
      }
      if (state.user && state.user.defaultDomain && !el.billingEmailForWoWLicence.value.trim()) {
        el.billingEmailForWoWLicence.value = "accounts@" + state.user.defaultDomain;
      }

      setText(el.authState, "Signed in.", "ok");
    } catch (err) {
      setText(el.authState, "Sign in failed: " + err.message, "err");
    }
  }

  async function loadSubscriptions() {
    setText(el.authState, "Loading subscriptions...", "warn");
    try {
      const subs = await apiFetch("/subscriptions");
      state.subscriptions = Array.isArray(subs) ? subs : [];

      clearSelect(el.subscriptionId);
      if (!state.subscriptions.length) {
        addOption(el.subscriptionId, "", "No subscriptions found");
        setText(el.authState, "No subscriptions available for this user.", "err");
        return;
      }

      for (const s of state.subscriptions) {
        addOption(el.subscriptionId, s.id, s.name + " (" + s.id + ")");
      }

      const selected = state.subscriptions[0];
      el.tenantId.value = selected.tenantId || "";
      await loadLocations(selected.id);
      syncDefaultsFromWebApp();

      setText(el.authState, "Loaded " + state.subscriptions.length + " subscriptions.", "ok");
    } catch (err) {
      setText(el.authState, "Failed loading subscriptions: " + err.message, "err");
    }
  }

  async function loadLocations(subscriptionId) {
    clearSelect(el.location);
    try {
      const data = await apiFetch("/locations?subscriptionId=" + encodeURIComponent(subscriptionId));
      const locations = (data && data.locations) || [];
      const defaultLocation = (data && data.defaultLocation) || "australiaeast";

      if (!locations.length) {
        addOption(el.location, defaultLocation, defaultLocation);
        return;
      }

      for (const loc of locations) {
        addOption(el.location, loc.name, loc.displayName + " (" + loc.name + ")");
      }

      el.location.value = defaultLocation;
    } catch (_err) {
      addOption(el.location, "australiaeast", "australiaeast");
      el.location.value = "australiaeast";
    }
  }

  async function checkWebAppNameAvailability() {
    const webAppName = normalizeWebAppName(el.webAppName.value);
    el.webAppName.value = webAppName;

    if (!/^[a-z0-9](?:[a-z0-9-]{0,58}[a-z0-9])?$/.test(webAppName)) {
      setText(el.nameState, "Invalid web app name format.", "err");
      return;
    }

    setText(el.nameState, "Checking availability...", "warn");
    try {
      const result = await apiFetch("/validate-webapp-name", {
        method: "POST",
        body: JSON.stringify({
          subscriptionId: el.subscriptionId.value,
          name: webAppName
        })
      });

      if (result && result.nameAvailable) {
        setText(el.nameState, "Name is available.", "ok");
      } else {
        const msg = (result && (result.message || result.reason)) || "Name unavailable.";
        setText(el.nameState, msg, "err");
      }
    } catch (err) {
      setText(el.nameState, "Availability check failed: " + err.message, "err");
    }
  }

  async function loadWebAppConfigTemplateVersion() {
    try {
      const data = await apiFetch("/webapp-config-template");
      state.webAppConfigVersion = data && data.version ? data.version : null;
      if (state.webAppConfigVersion) {
        appendLog("Using WebAppConfig template version: " + state.webAppConfigVersion);
      }
    } catch (err) {
      appendLog("Failed to load WebAppConfig template version: " + err.message);
    }
  }

  function buildPayload() {
    const guestAdmins = parseGuestAdmins(el.guestAdmins.value);
    const admin = el.adminUserPrincipalName.value.trim();
    if (admin && !guestAdmins.includes(admin)) {
      guestAdmins.push(admin);
    }

    return {
      tenantId: el.tenantId.value.trim(),
      subscriptionId: el.subscriptionId.value,
      resourceGroupName: el.resourceGroupName.value.trim(),
      location: el.location.value,
      webAppName: normalizeWebAppName(el.webAppName.value),
      appServicePlanName: el.appServicePlanName.value.trim(),
      storageAccountName: el.storageAccountName.value.trim().toLowerCase(),
      clientAppName: el.clientAppName.value.trim(),
      serverAppName: el.serverAppName.value.trim(),
      companyNameForWoWLicence: el.companyNameForWoWLicence.value.trim(),
      billingEmailForWoWLicence: el.billingEmailForWoWLicence.value.trim(),
      adminUserPrincipalName: admin,
      guestAdmins,
      businessEditionSolution: selectedBusinessEdition(),
      planChoice: el.planChoice.value,
      webAppConfigVersion: state.webAppConfigVersion
    };
  }

  async function startDeployment(ev) {
    ev.preventDefault();
    const validationError = validateInputs();
    if (validationError) {
      setText(el.jobState, validationError, "err");
      return;
    }

    el.btnStart.disabled = true;
    el.btnCancelJob.disabled = false;
    el.jobLogs.textContent = "";
    appendLog("Starting deployment job...");

    try {
      await loadWebAppConfigTemplateVersion();
      const payload = buildPayload();
      const created = await apiFetch("/jobs", {
        method: "POST",
        body: JSON.stringify(payload)
      });

      state.activeJobId = created.jobId;
      setText(el.jobState, "Job queued: " + state.activeJobId, "warn");
      appendLog("Job created: " + state.activeJobId);

      startPollingJob();
    } catch (err) {
      setText(el.jobState, "Failed to start deployment: " + err.message, "err");
      el.btnStart.disabled = false;
      el.btnCancelJob.disabled = true;
    }
  }

  async function pollJob() {
    if (!state.activeJobId) {
      return;
    }

    try {
      const job = await apiFetch("/jobs/" + encodeURIComponent(state.activeJobId));
      const status = job.status || "Unknown";
      const step = job.currentStep ? " | " + job.currentStep : "";
      const percent = typeof job.percent === "number" ? " (" + job.percent + "%)" : "";
      setText(el.jobState, "Status: " + status + step + percent, status === "Failed" ? "err" : (status === "Succeeded" ? "ok" : "warn"));

      if (job.outputs) {
        const out = [];
        if (job.outputs.baseAddress) {
          out.push("Base Address: " + job.outputs.baseAddress);
        }
        if (job.outputs.consentUrl) {
          out.push("Admin Consent URL: " + job.outputs.consentUrl);
        }
        el.jobOutputs.textContent = out.join("\n");
      }

      if (Array.isArray(job.logs) && job.logs.length) {
        el.jobLogs.textContent = job.logs.join("\n");
      } else {
        appendLog("Polled at " + new Date().toISOString() + " -> " + status);
      }

      if (status === "Succeeded" || status === "Failed" || status === "Cancelled") {
        stopPolling();
        el.btnStart.disabled = false;
        el.btnCancelJob.disabled = true;
      }
    } catch (err) {
      appendLog("Polling failed: " + err.message);
    }
  }

  function startPollingJob() {
    stopPolling();
    pollJob();
    state.pollTimer = window.setInterval(pollJob, config.pollMs);
  }

  function stopPolling() {
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  async function cancelJob() {
    if (!state.activeJobId) {
      return;
    }

    try {
      await apiFetch("/jobs/" + encodeURIComponent(state.activeJobId) + "/cancel", {
        method: "POST"
      });
      appendLog("Cancellation requested for job: " + state.activeJobId);
      setText(el.jobState, "Cancellation requested.", "warn");
    } catch (err) {
      setText(el.jobState, "Cancel failed: " + err.message, "err");
    }
  }

  function onSubscriptionChange() {
    const selected = state.subscriptions.find(s => s.id === el.subscriptionId.value);
    el.tenantId.value = selected && selected.tenantId ? selected.tenantId : "";
    loadLocations(el.subscriptionId.value);
    syncDefaultsFromWebApp();
  }

  function init() {
    addOption(el.subscriptionId, "", "Sign in and load subscriptions");
    addOption(el.location, "australiaeast", "australiaeast");
    el.location.value = "australiaeast";

    el.btnLogin.addEventListener("click", doLogin);
    el.btnLoadSubs.addEventListener("click", loadSubscriptions);
    el.btnCheckName.addEventListener("click", checkWebAppNameAvailability);
    el.subscriptionId.addEventListener("change", onSubscriptionChange);
    el.webAppName.addEventListener("blur", syncDefaultsFromWebApp);
    el.form.addEventListener("submit", startDeployment);
    el.btnCancelJob.addEventListener("click", cancelJob);

    appendLog("Ready. Sign in, load subscriptions, then complete deployment inputs.");
  }

  init();
})();
