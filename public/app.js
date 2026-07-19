"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const state = {
  jobs: [],
  runtime: { running: false, logs: [] },
  settings: {},
  selected: new Set(),
  autoScroll: true,
  credentialJobId: "",
  credentialUri: "",
  credentialRemaining: 0,
  credentialTimer: null,
  polling: false,
  settingsInitialized: false,
  settingsDirty: false,
  credentialExpiresAt: 0,
  credentialRequestSeq: 0,
  credentialEmail: "",
  credentialSessionJson: "",
  credentialSessionRequestSeq: 0,
  phoneBindingRequestSeq: 0,
  phoneBindingSubmitting: false,
  manualPhoneRequestSeq: 0,
  manualPhoneSubmitting: false,
  manualPhonePolling: false,
  manualPhoneState: { phase: "idle", active: false },
  mfaEnableSubmitting: false,
  emailOtpRequestSeq: 0,
  proxyPoolClearRequested: false,
  page: 1,
  pageSize: 20,
  groups: [],
  plans: [],
  groupFilter: "all",
  archiveFilter: "active",
  noteSaveTimers: {},
};

const STATUS_LABELS = {
  queued: "等待运行",
  registering: "注册中",
  registered: "已注册",
  session_pending: "登录态待补全",
  session_recovering: "补全登录态",
  phone_required: "待绑手机号",
  registration_failed: "注册失败",
  mfa_enrolling: "开启中",
  mfa_failed: "2FA 失败",
  mfa_secret_missing: "密钥缺失",
  ready: "已完成",
  stopped: "已停止",
  interrupted: "已中断",
  pending: "等待",
  running: "处理中",
  failed: "失败",
  enrolling: "开启中",
  enabled: "已开启",
  secret_saved: "密钥已保存",
  secret_missing: "密钥缺失",
  available: "可用",
  expired: "已过期",
  missing: "未获取",
  refreshing: "刷新中",
  refresh_failed: "刷新失败",
  phone_unknown: "未知",
  phone_queued: "等待绑定",
  phone_binding: "绑定中",
  phone_bound: "已绑定",
  phone_failed: "绑定失败",
  phone_stopped: "已停止",
};

const STAGE_LABELS = {
  queued: "等待启动",
  registering: "创建账号",
  registered: "准备 2FA",
  mfa_info: "检查 2FA",
  mfa_secret_saved: "密钥已落盘",
  mfa_retry_queued: "等待重试 2FA",
  mfa_failed: "2FA 需重试",
  mfa_secret_missing: "需要人工恢复",
  registration_failed: "注册需重试",
  ready: "流程完成",
  stopped: "任务停止",
  interrupted: "任务中断",
  registration_recovered: "恢复注册态",
  registration_session_recovered: "登录态已补全",
  session_pending: "等待补全登录态",
  session_recovering: "邮箱登录补全中",
  session_retry_queued: "等待重试登录",
  registration_phone_required: "等待后期绑定手机号",
  at_refreshing: "获取最新 AT",
  at_refresh_failed: "AT 刷新失败",
  phone_queued: "等待绑定手机号",
  phone_binding: "绑定手机号",
  phone_bound: "手机号已绑定",
  phone_failed: "手机号绑定失败",
  phone_stopped: "手机号绑定已停止",
};

const PHONE_BINDABLE_STATUSES = new Set(["phone_unknown", "phone_failed", "phone_stopped"]);

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });
  const payload = await response.json().catch(() => ({ ok: false, error: `HTTP ${response.status}` }));
  if (!response.ok || payload.ok === false) {
    throw new Error(payload.error || `HTTP ${response.status}`);
  }
  return payload;
}

let toastTimer = null;
function showToast(message, isError = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("visible"), 2800);
}

function currentMode() {
  return $("input[name='otpMode']:checked").value;
}

function updateModeFields() {
  const mode = currentMode();
  $("#apiFields").hidden = mode !== "api";
  $("#imapFields").hidden = mode !== "imap";
  $("#outlookFields").hidden = mode !== "outlook_oauth";
  const placeholders = {
    api: "email@example.com----https://mail-api.example/latest",
    imap: "email@example.com----mailbox@example.com----mail-password",
    outlook_oauth: "email@outlook.com----email@outlook.com----client-id----refresh-token",
  };
  $("#importText").placeholder = placeholders[mode];
}

function providerDefaults() {
  const mode = currentMode();
  if (mode === "api") {
    return { apiUrl: $("#apiUrl").value.trim() };
  }
  if (mode === "imap") {
    return {
      host: $("#imapHost").value.trim(),
      port: Number($("#imapPort").value || 993),
      username: $("#imapUser").value.trim(),
      password: $("#imapPassword").value,
      folder: $("#imapFolder").value.trim() || "Inbox",
      latestN: Number($("#imapLatestN").value || 80),
    };
  }
  return {
    host: $("#outlookHost").value.trim() || "outlook.office365.com",
    port: Number($("#outlookPort").value || 993),
    username: $("#outlookUser").value.trim(),
    clientId: $("#outlookClientId").value.trim(),
    refreshToken: $("#outlookRefreshToken").value.trim(),
    folder: $("#outlookFolder").value.trim() || "INBOX",
    latestN: Number($("#outlookLatestN").value || 80),
    pop3Fallback: $("#pop3Fallback").checked,
  };
}

function accountDefaults() {
  return {
    accountPassword: $("#accountPassword").value,
    fullName: $("#fullName").value.trim(),
    birthDate: $("#birthDate").value,
  };
}

async function importQueue() {
  const result = $("#importResult");
  result.className = "status-message";
  const text = $("#importText").value.trim();
  if (!text) {
    result.textContent = "请输入账号或选择 CSV";
    result.classList.add("error");
    return;
  }
  $("#importBtn").disabled = true;
  try {
    const payload = await api("/api/jobs/import", {
      method: "POST",
      body: JSON.stringify({
        text,
        mode: currentMode(),
        defaults: providerDefaults(),
        accountDefaults: accountDefaults(),
      }),
    });
    const errorLines = (payload.errors || []).slice(0, 4).map((item) => `第 ${item.line} 行：${item.errors.join("；")}`);
    const errorSuffix = payload.errors.length ? `，${payload.errors.length} 行未通过\n${errorLines.join("\n")}` : "";
    result.textContent = `已加入 ${payload.added} 个任务${errorSuffix}`;
    result.classList.add(payload.added ? "success" : "error");
    if (payload.added) {
      await refreshState();
    }
    if (payload.added && !payload.errors.length) {
      $("#importText").value = "";
      $("#imapPassword").value = "";
      $("#outlookRefreshToken").value = "";
      $("#accountPassword").value = "";
    }
  } catch (error) {
    result.textContent = error.message;
    result.classList.add("error");
  } finally {
    $("#importBtn").disabled = false;
  }
}

async function testMailSource() {
  const button = $("#testSourceBtn");
  button.disabled = true;
  try {
    const payload = await api("/api/source/test", {
      method: "POST",
      body: JSON.stringify({
        mode: currentMode(),
        provider: providerDefaults(),
        text: $("#importText").value.trim(),
      }),
    });
    const codeText = payload.mode === "api" ? (payload.codeDetected ? "，响应中检测到 6 位码" : "，响应中暂未检测到 6 位码") : "";
    showToast(`${payload.message}${codeText}`);
  } catch (error) {
    showToast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

let smsCountriesCache = [];
let smsCountriesProvider = "";
let smsCountriesSource = "static";

function smsForm() {
  return $("#smsSettingsForm") || $("#settingsForm");
}

function updateSmsSettingsFields() {
  const form = smsForm();
  if (!form) return;
  const enabled = Boolean(form.elements.namedItem("smsProvider")?.value);
  [
    "smsApiKey",
    "smsCountry",
    "smsService",
    "smsMaxPrice",
    "smsPhoneSuccessMax",
    "smsReusePhone",
    "smsAutoCountry",
    "smsAutoMinStock",
    "smsAutoMaxPrice",
    "smsStrictWhitelist",
    "smsMaxPhoneAttempts",
    "smsPerPhoneTimeout",
  ].forEach((name) => {
    const input = form.elements.namedItem(name);
    if (input) input.disabled = !enabled;
  });
  const search = $("#smsCountrySearch");
  const clearBtn = $("#btnClearAllowedCountries");
  const testBtn = $("#btnTestSms");
  if (search) search.disabled = !enabled;
  if (clearBtn) clearBtn.disabled = !enabled;
  if (testBtn) testBtn.disabled = !enabled;
  $("#smsAllowedCountriesBox")?.querySelectorAll("input[type=checkbox]").forEach((input) => {
    input.disabled = !enabled;
  });
}

function getAllowedCountriesValue() {
  return Array.from($("#smsAllowedCountriesBox")?.querySelectorAll("input[type=checkbox]:checked") || [])
    .map((input) => String(input.value || "").trim())
    .filter(Boolean);
}

function updateAllowedCountryCount() {
  const count = getAllowedCountriesValue().length;
  const node = $("#smsAllowedCountryCount");
  if (node) node.textContent = `已选 ${count} 个国家`;
}

function renderSmsCountrySelect(selectedId = "52") {
  const select = $("#smsCountry");
  if (!select) return;
  const current = String(selectedId || select.value || "52");
  select.innerHTML = smsCountriesCache.map((country) => {
    const id = String(country.id || "");
    const name = String(country.name_cn || `国家${id}`);
    const safe = country.openai_sms_safe ? " ✓" : "";
    return `<option value="${escapeHtml(id)}">${escapeHtml(id)} · ${escapeHtml(name)}${safe}</option>`;
  }).join("");
  if (![...select.options].some((option) => option.value === current) && current) {
    select.insertAdjacentHTML("afterbegin", `<option value="${escapeHtml(current)}">${escapeHtml(current)}</option>`);
  }
  select.value = current;
}

function renderSmsAllowedCountriesBox(selectedList = []) {
  const box = $("#smsAllowedCountriesBox");
  if (!box) return;
  const selected = new Set((selectedList || []).map((item) => String(item || "").trim()).filter(Boolean));
  if (!smsCountriesCache.length) {
    box.innerHTML = "<em>暂无国家列表</em>";
    updateAllowedCountryCount();
    return;
  }
  box.innerHTML = smsCountriesCache.map((country) => {
    const id = String(country.id || "");
    const name = String(country.name_cn || `国家${id}`);
    const checked = selected.has(id) ? "checked" : "";
    const price = country.price != null && country.price !== "" ? `¥${country.price}` : "";
    const stock = country.count != null && country.count !== "" ? `库存${country.count}` : "";
    const meta = [price, stock].filter(Boolean).join(" / ");
    const safe = country.openai_sms_safe ? '<span class="safe-tag">稳妥</span>' : "";
    return `<label data-id="${escapeHtml(id)}" data-name="${escapeHtml(name.toLowerCase())}">
      <input type="checkbox" value="${escapeHtml(id)}" ${checked}>
      <span>${escapeHtml(id)} · ${escapeHtml(name)}</span>
      ${safe}
      ${meta ? `<span class="price-tag">${escapeHtml(meta)}</span>` : ""}
    </label>`;
  }).join("");
  updateAllowedCountryCount();
}

async function ensureSmsCountries(provider = "", selectedId = "52", selectedAllowed = null) {
  const form = smsForm();
  const providerValue = String(provider || form?.elements?.namedItem("smsProvider")?.value || "smsbower");
  const allowed = selectedAllowed != null
    ? selectedAllowed
    : (state.settings?.smsAllowedCountries || getAllowedCountriesValue());
  if (smsCountriesCache.length && smsCountriesProvider === providerValue) {
    renderSmsCountrySelect(selectedId || state.settings?.smsCountry || "52");
    renderSmsAllowedCountriesBox(allowed);
    return smsCountriesCache;
  }
  try {
    const result = await api(`/api/settings/sms/countries?provider=${encodeURIComponent(providerValue)}`);
    smsCountriesCache = Array.isArray(result.countries) ? result.countries : [];
    smsCountriesProvider = providerValue;
    smsCountriesSource = String(result.source || "static");
  } catch (error) {
    smsCountriesCache = [];
    smsCountriesProvider = providerValue;
    smsCountriesSource = "error";
    const box = $("#smsAllowedCountriesBox");
    if (box) box.innerHTML = `<em>国家列表加载失败：${escapeHtml(error.message)}</em>`;
  }
  renderSmsCountrySelect(selectedId || state.settings?.smsCountry || "52");
  renderSmsAllowedCountriesBox(allowed);
  return smsCountriesCache;
}

function filterSmsAllowedCountries(keyword = "") {
  const query = String(keyword || "").trim().toLowerCase();
  $("#smsAllowedCountriesBox")?.querySelectorAll("label").forEach((label) => {
    const id = String(label.dataset.id || "");
    const name = String(label.dataset.name || "");
    label.hidden = Boolean(query) && !id.includes(query) && !name.includes(query);
  });
}

function setSmsSettings(settings) {
  const form = smsForm();
  if (!form) return;
  const keys = [
    "smsProvider",
    "smsCountry",
    "smsService",
    "smsMaxPrice",
    "smsPhoneSuccessMax",
    "smsReusePhone",
    "smsAutoCountry",
    "smsAutoMinStock",
    "smsAutoMaxPrice",
    "smsStrictWhitelist",
    "smsMaxPhoneAttempts",
    "smsPerPhoneTimeout",
  ];
  for (const key of keys) {
    const input = form.elements.namedItem(key);
    if (!input) continue;
    const value = settings?.[key];
    if (input.type === "checkbox") input.checked = Boolean(value);
    else if (key === "smsMaxPrice" || key === "smsAutoMaxPrice") {
      input.value = Number(value || -1) > 0 ? value : "";
    } else if (key === "smsMaxPhoneAttempts") {
      input.value = Number(value || 0) > 0 ? value : "";
    } else {
      input.value = value ?? "";
    }
  }
  const smsApiKeyInput = form.elements.namedItem("smsApiKey");
  if (smsApiKeyInput) {
    const smsApiKeyProvided = Boolean(settings?.smsApiKeyProvided ?? settings?.smsApiKeyConfigured);
    smsApiKeyInput.value = "";
    smsApiKeyInput.dataset.configured = smsApiKeyProvided ? "true" : "false";
    smsApiKeyInput.placeholder = smsApiKeyProvided
      ? "已配置，留空保持不变"
      : "请输入接码平台 API Key";
  }
  ensureSmsCountries(
    settings?.smsProvider || "",
    settings?.smsCountry || "52",
    settings?.smsAllowedCountries || [],
  );
  updateSmsSettingsFields();
}

function setSettings(settings) {
  const form = $("#settingsForm");
  for (const [key, value] of Object.entries(settings || {})) {
    if (String(key).startsWith("sms")) continue;
    const input = form.elements.namedItem(key);
    if (!input) continue;
    if (input.type === "checkbox") input.checked = Boolean(value);
    else input.value = value ?? "";
  }
  const proxyInput = form.elements.namedItem("proxy");
  proxyInput.dataset.configured = settings?.proxyConfigured ? "true" : "false";
  proxyInput.placeholder = settings?.proxyConfigured
    ? "已配置，留空保持不变"
    : "http://user:pass@host:port";
  const proxyPoolInput = form.elements.namedItem("proxyPool");
  proxyPoolInput.value = "";
  proxyPoolInput.dataset.configured = settings?.proxyPoolConfigured ? "true" : "false";
  proxyPoolInput.dataset.count = String(settings?.proxyPoolCount || 0);
  proxyPoolInput.placeholder = settings?.proxyPoolConfigured
    ? `已配置 ${settings.proxyPoolCount} 个代理，粘贴新列表可整体替换`
    : "每行一个代理";
  state.proxyPoolClearRequested = false;
  const labels = settings?.proxyPoolLabels || [];
  if (labels.length && !$("#networkResult").dataset.detected) {
    $("#networkResult").innerHTML = `<strong>已保存代理池</strong><span>${labels.map(escapeHtml).join("<br>")}</span>`;
  }
  setSmsSettings(settings || {});
  state.settingsInitialized = true;
}

async function saveSettings(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const proxyInput = event.currentTarget.elements.namedItem("proxy");
  const proxyPoolInput = event.currentTarget.elements.namedItem("proxyPool");
  const payload = {
    concurrency: Number(form.get("concurrency") || 1),
    registerTimeoutSeconds: Number(form.get("registerTimeoutSeconds") || 360),
    otpTimeoutSeconds: Number(form.get("otpTimeoutSeconds") || 180),
    otpIntervalSeconds: Number(form.get("otpIntervalSeconds") || 2),
    proxyStrategy: String(form.get("proxyStrategy") || "round_robin"),
    trace: form.get("trace") === "on",
  };
  const proxyValue = String(form.get("proxy") || "").trim();
  if (proxyValue || proxyInput.dataset.configured !== "true") payload.proxy = proxyValue;
  const proxyPoolValue = String(form.get("proxyPool") || "").trim();
  if (proxyPoolValue) payload.proxyPool = proxyPoolValue;
  else if (state.proxyPoolClearRequested || proxyPoolInput.dataset.configured !== "true") payload.proxyPool = [];
  try {
    const result = await api("/api/settings", { method: "POST", body: JSON.stringify(payload) });
    state.settingsDirty = false;
    state.settings = result.settings || {};
    setSettings(result.settings);
    updateSelectionUi();
    if ($("#credentialDialog").open && state.credentialJobId) {
      const credentialJob = state.jobs.find((job) => job.id === state.credentialJobId);
      if (credentialJob) renderCredentialPhone(credentialJob);
      refreshManualPhoneStatus();
    }
    showToast("运行参数已保存");
  } catch (error) {
    showToast(error.message, true);
  }
}

async function saveSmsSettings(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = {
    smsProvider: String(form.elements.namedItem("smsProvider").value || ""),
    smsCountry: String(form.elements.namedItem("smsCountry").value || "52").trim() || "52",
    smsService: String(form.elements.namedItem("smsService").value || "dr").trim() || "dr",
    smsMaxPrice: Number(form.elements.namedItem("smsMaxPrice").value || -1),
    smsReusePhone: form.elements.namedItem("smsReusePhone").checked,
    smsPhoneSuccessMax: Number(form.elements.namedItem("smsPhoneSuccessMax").value || 3),
    smsAutoCountry: form.elements.namedItem("smsAutoCountry").checked,
    smsAllowedCountries: getAllowedCountriesValue(),
    smsAutoMinStock: Number(form.elements.namedItem("smsAutoMinStock").value || 20),
    smsAutoMaxPrice: Number(form.elements.namedItem("smsAutoMaxPrice").value || -1),
    smsStrictWhitelist: form.elements.namedItem("smsStrictWhitelist").checked,
    smsMaxPhoneAttempts: Number(form.elements.namedItem("smsMaxPhoneAttempts").value || 0),
    smsPerPhoneTimeout: Number(form.elements.namedItem("smsPerPhoneTimeout").value || 80),
  };
  const smsApiKeyInput = form.elements.namedItem("smsApiKey");
  const smsApiKeyValue = String(smsApiKeyInput.value || "").trim();
  if (smsApiKeyValue || smsApiKeyInput.dataset.configured !== "true") payload.smsApiKey = smsApiKeyValue;
  try {
    const result = await api("/api/settings", { method: "POST", body: JSON.stringify(payload) });
    state.settings = result.settings || {};
    setSmsSettings(result.settings);
    updateSelectionUi();
    if ($("#credentialDialog").open && state.credentialJobId) {
      const credentialJob = state.jobs.find((job) => job.id === state.credentialJobId);
      if (credentialJob) renderCredentialPhone(credentialJob);
      refreshManualPhoneStatus();
    }
    showToast("接码配置已保存");
  } catch (error) {
    showToast(error.message, true);
  }
}

async function testSmsBalance() {
  const resultNode = $("#smsCfgResult");
  if (resultNode) resultNode.textContent = "测试中...";
  try {
    const result = await api("/api/settings/sms/test", { method: "POST", body: "{}" });
    if (resultNode) resultNode.textContent = result.message || "测试成功";
    showToast(result.message || "接码余额测试成功");
  } catch (error) {
    if (resultNode) resultNode.textContent = error.message;
    showToast(error.message, true);
  }
}

function setNetworkResult(html, tone = "") {
  const result = $("#networkResult");
  result.className = `network-result ${tone}`.trim();
  result.dataset.detected = "true";
  result.innerHTML = html;
}

async function detectLocalNetwork() {
  const button = $("#detectLocalBtn");
  button.disabled = true;
  setNetworkResult("<span>正在检测本机网络出口…</span>");
  try {
    const result = await api("/api/network/local");
    const localIps = (result.localIps || []).length ? result.localIps.join(", ") : "未识别";
    const publicIp = result.publicIp || "检测失败";
    const geo = result.geo || {};
    const geoLocation = geo.location || "位置未知";
    const geoOrganization = geo.organization || "运营商未知";
    setNetworkResult(`
      <div class="network-summary"><span>主机名</span><strong>${escapeHtml(result.hostname || "-")}</strong></div>
      <div class="network-summary"><span>本地 IP</span><code>${escapeHtml(localIps)}</code></div>
      <div class="network-summary"><span>直连出口 IP</span><code>${escapeHtml(publicIp)}</code><small>${Number(result.elapsedMs || 0)} ms</small></div>
      <div class="network-summary"><span>地理位置</span><code>${escapeHtml(geoLocation)}</code></div>
      <div class="network-summary"><span>运营商</span><code>${escapeHtml(geoOrganization)}</code></div>
      ${result.publicIpError ? `<div class="network-error">${escapeHtml(result.publicIpError)}</div>` : ""}
    `, result.publicIpOk ? "success" : "error");
  } catch (error) {
    setNetworkResult(`<div class="network-error">${escapeHtml(error.message)}</div>`, "error");
  } finally {
    button.disabled = false;
  }
}

async function testProxyPool() {
  const button = $("#testProxyPoolBtn");
  const poolValue = $("#proxyPool").value.trim();
  const singleValue = String($("#settingsForm").elements.namedItem("proxy").value || "").trim();
  const candidates = poolValue || singleValue;
  button.disabled = true;
  setNetworkResult("<span>正在并行检测代理出口…</span>");
  try {
    const result = await api("/api/proxies/test", {
      method: "POST",
      body: JSON.stringify(candidates ? { proxyPool: candidates } : {}),
    });
    if (!result.results.length) {
      setNetworkResult('<div class="network-error">代理池为空</div>', "error");
      return;
    }
    const rows = result.results.map((item) => `
      <div class="proxy-result-row ${item.ok ? "success" : "failed"}">
        <span>${item.index}</span>
        <code title="${escapeHtml(item.proxy)}">${escapeHtml(item.proxy)}</code>
        <strong>${escapeHtml(item.ip || "失败")}</strong>
        <small>${Number(item.elapsedMs || 0)} ms</small>
        ${item.geo?.ok ? `<b class="proxy-geo" title="${escapeHtml(item.geo.organization || "")}">${escapeHtml(item.geo.location || "位置未知")}${item.geo.organization ? ` · ${escapeHtml(item.geo.organization)}` : ""}</b>` : ""}
        ${item.error ? `<em title="${escapeHtml(item.error)}">${escapeHtml(item.error)}</em>` : ""}
      </div>`).join("");
    setNetworkResult(`<div class="network-result-head"><strong>可用 ${result.success}/${result.count}</strong><span>代理 / 出口 IP / 地理位置 / 延迟</span></div>${rows}`, result.success === result.count ? "success" : "warning");
  } catch (error) {
    setNetworkResult(`<div class="network-error">${escapeHtml(error.message)}</div>`, "error");
  } finally {
    button.disabled = false;
  }
}

function phoneStatus(job) {
  return String(job?.phoneStatus || "phone_unknown");
}

function isPhoneBindable(job) {
  return ["registered", "phone_required"].includes(job?.registrationStatus)
    && PHONE_BINDABLE_STATUSES.has(phoneStatus(job));
}

function isMfaEnableEligible(job) {
  return job?.registrationStatus === "registered" && job?.mfaStatus !== "enabled";
}

function combinedRegistrationStatus(job) {
  const registration = String(job?.registrationStatus || "queued");
  if (registration !== "registered") return registration;
  const mfa = String(job?.mfaStatus || "pending");
  if (mfa === "enabled") return "ready";
  if (mfa === "failed") return "mfa_failed";
  if (mfa === "secret_missing") return "mfa_secret_missing";
  return mfa;
}

function smsBindingConfigured() {
  const settings = state.settings || {};
  return Boolean(settings.smsProvider && (settings.smsApiKeyProvided ?? settings.smsApiKeyConfigured));
}

function statusTone(status) {
  if (["ready", "registered", "enabled", "available", "phone_bound"].includes(status)) return "success";
  if (["registering", "session_recovering", "mfa_enrolling", "running", "enrolling", "secret_saved", "refreshing", "phone_queued", "phone_binding"].includes(status)) return "running";
  if (["registration_failed", "mfa_failed", "failed", "secret_missing", "mfa_secret_missing", "refresh_failed", "phone_failed"].includes(status)) return "failed";
  if (["session_pending", "phone_required", "stopped", "interrupted", "expired", "phone_stopped"].includes(status)) return "warning";
  return "pending";
}

function pill(status) {
  return `<span class="status-pill ${statusTone(status)}">${escapeHtml(STATUS_LABELS[status] || status || "-")}</span>`;
}

function formatElapsed(seconds) {
  const value = Number(seconds || 0);
  if (value < 60) return `${value}s`;
  const minutes = Math.floor(value / 60);
  return `${minutes}m ${value % 60}s`;
}

function statusMatches(job, filter) {
  if (!filter) return true;
  if (filter === "running") return ["registering", "mfa_enrolling"].includes(job.status) || ["phone_queued", "phone_binding"].includes(phoneStatus(job));
  if (filter === "failed") return job.status.endsWith("failed") || job.status === "mfa_secret_missing" || phoneStatus(job) === "phone_failed";
  return job.status === filter;
}

function jobGroupName(job) {
  return String(job?.group || "").trim() || "未分组";
}

function jobPlanType(job) {
  return String(job?.planType || "").trim().toLowerCase() || "unknown";
}

function planPill(plan) {
  const value = String(plan || "unknown").trim().toLowerCase() || "unknown";
  const cls = value.replace(/[^a-z0-9_]+/g, "_") || "unknown";
  return `<span class="plan-pill ${escapeHtml(cls)}">${escapeHtml(value)}</span>`;
}

function filteredJobs() {
  const search = $("#searchInput").value.trim().toLowerCase();
  const status = $("#statusFilter").value;
  const mode = $("#modeFilter").value;
  const plan = $("#planFilter")?.value || "";
  return state.jobs.filter((job) => {
    const archived = Boolean(job.archived);
    if (state.archiveFilter === "active" && archived) return false;
    if (state.archiveFilter === "archived" && !archived) return false;
    if (state.groupFilter === "ungrouped" && jobGroupName(job) !== "未分组") return false;
    if (state.groupFilter !== "all" && state.groupFilter !== "ungrouped" && jobGroupName(job) !== state.groupFilter) return false;
    const haystack = [
      job.email,
      job.fullName,
      job.note,
      jobGroupName(job),
      jobPlanType(job),
    ].join(" ").toLowerCase();
    return (!search || haystack.includes(search))
      && statusMatches(job, status)
      && (!mode || job.provider?.mode === mode)
      && (!plan || jobPlanType(job) === plan);
  });
}

function renderGroups() {
  const list = $("#groupList");
  if (!list) return;
  const total = state.jobs.length;
  const active = state.jobs.filter((job) => !job.archived).length;
  const archived = state.jobs.filter((job) => job.archived).length;
  const ungrouped = state.jobs.filter((job) => jobGroupName(job) === "未分组").length;
  const items = [
    { key: "all", label: "全部账户", count: total, kind: "scope" },
    { key: "active", label: "未归档", count: active, kind: "archive" },
    { key: "archived", label: "已归档", count: archived, kind: "archive" },
    { key: "ungrouped", label: "未分组", count: ungrouped, kind: "group" },
    ...((state.groups || []).filter((item) => item.name && item.name !== "未分组").map((item) => ({
      key: item.name,
      label: item.name,
      count: item.count,
      kind: "group",
    }))),
  ];
  list.innerHTML = items.map((item) => {
    let activeItem = false;
    if (item.kind === "scope") activeItem = state.groupFilter === "all" && state.archiveFilter === "active";
    if (item.kind === "archive") activeItem = state.archiveFilter === item.key && state.groupFilter === "all";
    if (item.kind === "group") activeItem = state.groupFilter === item.key;
    return `<button type="button" class="group-item ${activeItem ? "active" : ""}" data-group-key="${escapeHtml(item.key)}" data-group-kind="${escapeHtml(item.kind)}"><span>${escapeHtml(item.label)}</span><span class="count">${escapeHtml(item.count)}</span></button>`;
  }).join("");
}

async function updateJobsMeta(ids, changes, { silent = false } = {}) {
  const targetIds = (ids || []).map((value) => String(value || "")).filter(Boolean);
  if (!targetIds.length) {
    if (!silent) showToast("请先选择任务", true);
    return null;
  }
  const result = await api("/api/jobs/meta", {
    method: "POST",
    body: JSON.stringify({ ids: targetIds, ...changes }),
  });
  await refreshState();
  if (!silent) {
    const updated = Number(result.updated || 0);
    showToast(`已更新 ${updated} 个账号`);
  }
  return result;
}

async function archiveSelected(archived = true) {
  const ids = Array.from(state.selected);
  if (!ids.length) {
    showToast("请先选择任务", true);
    return;
  }
  await updateJobsMeta(ids, { archived: Boolean(archived) });
  state.selected.clear();
}

async function assignGroupSelected(groupName) {
  const ids = Array.from(state.selected);
  if (!ids.length) {
    showToast("请先选择任务", true);
    return;
  }
  const name = String(groupName || "").trim();
  await updateJobsMeta(ids, { group: name });
  if (name) {
    state.groupFilter = name;
    state.archiveFilter = "all";
  }
  state.selected.clear();
}

function scheduleNoteSave(jobId, note) {
  if (state.noteSaveTimers[jobId]) clearTimeout(state.noteSaveTimers[jobId]);
  state.noteSaveTimers[jobId] = setTimeout(async () => {
    try {
      await updateJobsMeta([jobId], { note: String(note || "") }, { silent: true });
    } catch (error) {
      showToast(error.message || "备注保存失败", true);
    }
  }, 450);
}

function visibleJobs() {
  const filtered = filteredJobs();
  const start = (state.page - 1) * state.pageSize;
  return filtered.slice(start, start + state.pageSize);
}

function renderPagination(total) {
  const totalPages = Math.max(1, Math.ceil(total / state.pageSize));
  const start = total ? ((state.page - 1) * state.pageSize) + 1 : 0;
  const end = total ? Math.min(total, state.page * state.pageSize) : 0;
  $("#pageSummary").textContent = total ? `${start}-${end} / ${total} 条任务` : "0 条任务";
  $("#pageIndicator").textContent = `${state.page} / ${totalPages}`;
  $("#firstPageBtn").disabled = state.page <= 1;
  $("#prevPageBtn").disabled = state.page <= 1;
  $("#nextPageBtn").disabled = state.page >= totalPages;
  $("#lastPageBtn").disabled = state.page >= totalPages;
}

function isRtExportable(job) {
  return phoneStatus(job) === "phone_bound" || Boolean(job?.rtPresent) || String(job?.rtStatus || "") === "available";
}

function exportRtSelected() {
  const selectedJobs = state.jobs.filter((job) => state.selected.has(job.id));
  const exportable = (selectedJobs.length ? selectedJobs : state.jobs).filter(isRtExportable);
  if (!exportable.length) {
    showToast("没有可导出 RT 的已绑号账号", true);
    return;
  }
  const ids = exportable.map((job) => job.id).filter(Boolean);
  const params = new URLSearchParams({
    format: "sub2api",
    phoneBoundOnly: "1",
  });
  if (selectedJobs.length) params.set("ids", ids.join(","));
  window.location.href = `/api/export/rt?${params.toString()}`;
}

function updateSelectionUi() {
  const visible = visibleJobs();
  const selectedVisible = visible.filter((job) => state.selected.has(job.id)).length;
  const selectAll = $("#selectAll");
  selectAll.checked = visible.length > 0 && selectedVisible === visible.length;
  selectAll.indeterminate = selectedVisible > 0 && selectedVisible < visible.length;
  const count = state.selected.size;
  const selectedJobs = state.jobs.filter((job) => state.selected.has(job.id));
  const phoneEligibleCount = selectedJobs.filter(isPhoneBindable).length;
  const phoneSkippedCount = Math.max(0, selectedJobs.length - phoneEligibleCount);
  const phoneButton = $("#bindPhoneSelectedBtn");
  const rtJobs = (count ? selectedJobs : state.jobs).filter(isRtExportable);
  const exportRtButton = $("#exportRtBtn");
  $("#startBtn").innerHTML = count
    ? `<span aria-hidden="true">▶</span> 注册 + 2FA (${count})`
    : '<span aria-hidden="true">▶</span> 注册全部 + 2FA';
  $("#startBtn").title = count
    ? `为所选 ${count} 个任务执行邮箱注册并开启 TOTP 2FA；手机号仍需单独绑定`
    : "执行全部可注册任务，并在注册成功后开启 TOTP 2FA";
  $("#refreshAtBtn").disabled = count === 0 || Boolean(state.runtime.running);
  $("#refreshAtBtn").title = count ? `为所选 ${count} 个账号获取最新 AT` : "请先选择任务";
  $("#bindPhoneSelectedLabel").textContent = phoneEligibleCount ? `批量绑手机 (${phoneEligibleCount})` : "批量绑手机";
  phoneButton.disabled = phoneEligibleCount === 0 || Boolean(state.runtime.running) || state.phoneBindingSubmitting || !smsBindingConfigured();
  phoneButton.title = !count
    ? "请先选择任务"
    : !smsBindingConfigured()
      ? "请先保存接码服务和 API Key"
      : !phoneEligibleCount
        ? "所选账号中没有可绑定手机号的已注册账号"
        : `选中 ${count} 个，可绑定 ${phoneEligibleCount} 个${phoneSkippedCount ? `，将跳过 ${phoneSkippedCount} 个` : ""}`;
  $("#exportRtLabel").textContent = rtJobs.length ? `导出 RT (${rtJobs.length})` : "导出 RT";
  exportRtButton.disabled = rtJobs.length === 0;
  exportRtButton.title = rtJobs.length
    ? (count ? `导出所选 ${rtJobs.length} 个已绑号账号的 Sub2API RT JSON` : `导出全部 ${rtJobs.length} 个已绑号账号的 Sub2API RT JSON`)
    : "没有可导出 RT 的已绑号账号";
  const archiveButton = $("#archiveSelectedBtn");
  const groupButton = $("#groupSelectedBtn");
  const selectedArchivedCount = selectedJobs.filter((job) => job.archived).length;
  const archiveMode = count > 0 && selectedArchivedCount === count;
  $("#archiveSelectedLabel").textContent = archiveMode ? `取消归档 (${count})` : (count ? `归档 (${count})` : "归档");
  archiveButton.disabled = count === 0;
  archiveButton.title = count
    ? (archiveMode ? `取消归档所选 ${count} 个账号` : `归档所选 ${count} 个账号`)
    : "请先选择任务";
  archiveButton.dataset.mode = archiveMode ? "unarchive" : "archive";
  groupButton.disabled = count === 0;
  groupButton.title = count ? `为所选 ${count} 个账号设置分类` : "请先选择任务";
  $("#createGroupBtn").disabled = count === 0;
  $("#deleteSelectedBtn").disabled = count === 0 || Boolean(state.runtime.running);
  $("#deleteSelectedBtn").title = count ? `删除所选 ${count} 个任务` : "请先选择任务";
}

function renderJobs() {
  renderGroups();
  const filtered = filteredJobs();
  const totalPages = Math.max(1, Math.ceil(filtered.length / state.pageSize));
  if (state.page > totalPages) state.page = totalPages;
  if (state.page < 1) state.page = 1;
  const jobs = visibleJobs();
  const rows = $("#jobRows");
  if (!jobs.length) {
    rows.innerHTML = '<tr><td colspan="13" class="empty-row">暂无符合条件的任务</td></tr>';
    renderPagination(filtered.length);
    updateSelectionUi();
    return;
  }
  rows.innerHTML = jobs.map((job) => {
    const retryable = ["registration_failed", "session_pending", "mfa_failed", "stopped", "interrupted"].includes(job.status);
    const canView = ["registered", "phone_required"].includes(job.registrationStatus) || job.status === "ready" || job.localSecretPresent;
    const actions = [
      retryable ? `<button class="row-button" type="button" data-action="retry" data-id="${escapeHtml(job.id)}">重试</button>` : "",
      canView ? `<button class="row-button" type="button" data-action="credentials" data-id="${escapeHtml(job.id)}">凭据</button>` : "",
      `<button class="row-button" type="button" data-action="email-otp" data-id="${escapeHtml(job.id)}">邮箱码</button>`,
      job.registrationStatus === "registered" ? `<button class="row-button" type="button" data-action="refresh-at" data-id="${escapeHtml(job.id)}">AT</button>` : "",
      `<button class="row-button" type="button" data-action="toggle-archive" data-id="${escapeHtml(job.id)}">${job.archived ? "取消归档" : "归档"}</button>`,
      `<button class="row-button delete-row-button" type="button" data-action="delete" data-id="${escapeHtml(job.id)}">删</button>`,
    ].join("");
    const checked = state.selected.has(job.id) ? "checked" : "";
    const stage = STAGE_LABELS[job.stage] || job.stage || "-";
    const currentPhoneStatus = phoneStatus(job);
    const phoneMasked = String(job.phoneMasked || job.phoneNumberMasked || "");
    const displayError = ["phone_failed", "phone_stopped"].includes(currentPhoneStatus) && job.phoneError
      ? job.phoneError
      : job.error;
    const groupName = jobGroupName(job);
    const plan = jobPlanType(job);
    return `
      <tr class="${job.archived ? "archived-row" : ""}">
        <td class="check-cell"><input type="checkbox" data-select="${escapeHtml(job.id)}" aria-label="选择 ${escapeHtml(job.email)}" ${checked}></td>
        <td class="email-cell" title="${escapeHtml(job.email)}"><strong>${escapeHtml(job.email)}</strong><small>${escapeHtml(job.fullName || "-")}${job.archived ? " · 已归档" : ""}</small></td>
        <td title="${escapeHtml(job.planUpdatedAt ? `更新：${job.planUpdatedAt}` : "套餐未知")}">${planPill(plan)}</td>
        <td><span class="group-tag" title="${escapeHtml(groupName)}">${escapeHtml(groupName)}</span></td>
        <td><input class="note-input" data-note-id="${escapeHtml(job.id)}" value="${escapeHtml(job.note || "")}" placeholder="添加备注" maxlength="200"></td>
        <td title="${escapeHtml((job.provider?.label || '') + ' ' + (job.provider?.endpoint || '') + ' ' + (job.proxyLabel || ''))}"><strong>${escapeHtml(job.provider?.label || "-")}</strong><div class="endpoint-cell">${escapeHtml(job.provider?.endpoint || "-")}</div></td>
        <td title="注册：${escapeHtml(STATUS_LABELS[job.registrationStatus] || job.registrationStatus || "-")}；2FA：${escapeHtml(STATUS_LABELS[job.mfaStatus] || job.mfaStatus || "-")}">${pill(combinedRegistrationStatus(job))}</td>
        <td title="${escapeHtml(job.atExpiresAt ? `过期：${job.atExpiresAt}` : job.atError || "")}">${pill(job.atStatus || "missing")}</td>
        <td class="phone-cell" title="${escapeHtml(job.phoneError || phoneMasked)}">${pill(currentPhoneStatus)}${phoneMasked ? `<small>${escapeHtml(phoneMasked)}</small>` : ""}</td>
        <td class="stage-cell" title="${escapeHtml(stage)}">${escapeHtml(stage)}</td>
        <td class="elapsed-cell">${formatElapsed(job.elapsedSeconds)}</td>
        <td class="error-cell" title="${escapeHtml(displayError)}">${escapeHtml(displayError || "-")}</td>
        <td class="action-cell">${actions || "-"}</td>
      </tr>`;
  }).join("");
  renderPagination(filtered.length);
  updateSelectionUi();
}

function renderMetrics(counts) {
  $("#totalCount").textContent = counts.total || 0;
  if ($("#activeCount")) $("#activeCount").textContent = counts.active ?? Math.max(0, Number(counts.total || 0) - Number(counts.archived || 0));
  $("#queuedCount").textContent = counts.queued || 0;
  $("#runningCount").textContent = counts.running || 0;
  $("#readyCount").textContent = counts.ready || 0;
  $("#failedCount").textContent = counts.failed || 0;
  if ($("#archivedCount")) $("#archivedCount").textContent = counts.archived || 0;
}

function renderRuntime(runtime) {
  const service = $("#serviceState");
  service.className = `service-state ${runtime.running ? "busy" : "online"}`;
  const operationLabels = {
    registration: "注册 + 2FA",
    mfa_enable: "继续注册 + 2FA",
    mfa_enrollment: "继续注册 + 2FA",
    at_refresh: "刷新 AT",
    phone_binding: "批量绑定手机号",
    manual_phone_binding: "手动绑定手机号",
  };
  const operation = operationLabels[runtime.operation] || "执行任务";
  const total = Number(runtime.totalCount || (runtime.activeJobIds || []).length || runtime.activeCount || 0);
  const completed = Math.min(total, Number(runtime.completedCount || 0));
  const progress = runtime.operation === "phone_binding" && total
    ? `${completed}/${total}`
    : `${(runtime.activeJobIds || []).length || runtime.activeCount || 0}`;
  service.innerHTML = `<i></i>${runtime.running ? `${operation} · ${progress}` : "服务在线"}`;
  $("#startBtn").disabled = Boolean(runtime.running);
  $("#stopBtn").disabled = !runtime.running;
  updateSelectionUi();
}

function notifyPhoneBatchCompletion(previousRuntime, runtime) {
  if (!previousRuntime?.running || previousRuntime.operation !== "phone_binding") return;
  if (runtime?.running && runtime.operation === "phone_binding") return;
  const result = Number(runtime?.totalCount || 0) ? runtime : previousRuntime;
  const success = Number(result.successCount || 0);
  const failed = Number(result.failedCount || 0);
  const completed = Number(result.completedCount || success + failed);
  showToast(`批量绑号完成：成功 ${success}，失败 ${failed}${completed > success + failed ? `，其余 ${completed - success - failed}` : ""}`);
}

function renderLogs(logs) {
  const box = $("#logBox");
  const latest = (logs || []).slice(-300);
  if (!latest.length) {
    box.innerHTML = '<div class="log-empty">等待任务日志</div>';
    return;
  }
  box.innerHTML = latest.map((entry) => `
    <div class="log-line ${escapeHtml(entry.level)}">
      <span class="log-time">${escapeHtml(entry.at)}</span>
      <span class="log-level">${escapeHtml(entry.level)}</span>
      <span class="log-email" title="${escapeHtml(entry.email)}">${escapeHtml(entry.email || entry.stage)}</span>
      <span class="log-message">${escapeHtml(entry.message)}</span>
    </div>`).join("");
  if (state.autoScroll) box.scrollTop = box.scrollHeight;
}

async function refreshState() {
  if (state.polling) return;
  state.polling = true;
  try {
    const payload = await api("/api/state");
    const previousRuntime = state.runtime;
    state.jobs = payload.jobs || [];
    state.groups = payload.groups || [];
    state.plans = payload.plans || [];
    const currentIds = new Set(state.jobs.map((job) => job.id));
    state.selected.forEach((id) => { if (!currentIds.has(id)) state.selected.delete(id); });
    state.runtime = payload.runtime || {};
    state.settings = payload.settings || {};
    renderMetrics(payload.counts || {});
    renderRuntime(state.runtime);
    renderJobs();
    renderLogs(state.runtime.logs || []);
    if ($("#credentialDialog").open && state.credentialJobId) {
      const credentialJob = state.jobs.find((job) => job.id === state.credentialJobId);
      if (credentialJob) renderCredentialPhone(credentialJob);
      refreshManualPhoneStatus();
    }
    if (!state.settingsInitialized || !state.settingsDirty) setSettings(payload.settings || {});
    notifyPhoneBatchCompletion(previousRuntime, state.runtime);
  } catch (error) {
    const service = $("#serviceState");
    service.className = "service-state offline";
    service.innerHTML = "<i></i>连接失败";
  } finally {
    state.polling = false;
  }
}

async function startSelected(ids = null) {
  const selectedIds = ids || Array.from(state.selected);
  const modeText = "注册成功后将自动开启 TOTP 2FA；手机号仍需单独绑定。";
  if (ids === null && selectedIds.length === 0 && !window.confirm(`未选择任务，将启动全部可注册任务。${modeText}继续？`)) return;
  try {
    const result = await api("/api/start", {
      method: "POST",
      body: JSON.stringify({ ids: selectedIds }),
    });
    state.selected.clear();
    updateSelectionUi();
    showToast(result.count
      ? `已启动 ${result.count} 个注册 + 2FA 任务`
      : "没有可注册任务");
    await refreshState();
  } catch (error) {
    showToast(error.message, true);
  }
}

async function enableMfaSelected(ids = null) {
  if (state.mfaEnableSubmitting || state.runtime.running) {
    showToast("请等待当前批次完成", true);
    return;
  }
  const explicitIds = Array.from(new Set((ids || Array.from(state.selected))
    .map((value) => String(value || ""))
    .filter(Boolean)));
  if (!explicitIds.length) {
    showToast("请先选择要继续的注册任务", true);
    return;
  }
  const selectedJobs = explicitIds
    .map((id) => state.jobs.find((job) => job.id === id))
    .filter(Boolean);
  const eligibleJobs = selectedJobs.filter(isMfaEnableEligible);
  const skippedCount = Math.max(0, explicitIds.length - eligibleJobs.length);
  if (!eligibleJobs.length) {
    showToast("所选任务不需要继续处理 2FA", true);
    return;
  }

  state.mfaEnableSubmitting = true;
  updateSelectionUi();
  try {
    const result = await api("/api/mfa/enable", {
      method: "POST",
      body: JSON.stringify({ ids: eligibleJobs.map((job) => job.id) }),
    });
    state.selected.clear();
    const accepted = Number(result.count ?? eligibleJobs.length);
    showToast(accepted
      ? `已继续 ${accepted} 个注册 + 2FA 任务${skippedCount ? `，跳过 ${skippedCount} 个` : ""}`
      : "没有需要继续的注册 + 2FA 任务");
    await refreshState();
  } catch (error) {
    showToast(error.message, true);
  } finally {
    state.mfaEnableSubmitting = false;
    updateSelectionUi();
  }
}

async function stopAll() {
  try {
    await api("/api/stop", { method: "POST", body: "{}" });
    showToast("停止请求已发送");
    await refreshState();
  } catch (error) {
    showToast(error.message, true);
  }
}

async function clearFinished() {
  if (!window.confirm("清理失败、停止和中断任务？已完成账号及其本地凭据会保留。")) return;
  try {
    const result = await api("/api/clear", { method: "POST", body: JSON.stringify({ onlyFinished: true, includeReady: false }) });
    state.selected.clear();
    showToast(`已清理 ${result.removed} 个任务`);
    await refreshState();
  } catch (error) {
    showToast(error.message, true);
  }
}

async function refreshAccessTokens(ids = null) {
  const selectedIds = ids || Array.from(state.selected);
  if (!selectedIds.length) return;
  try {
    const result = await api("/api/at/refresh", {
      method: "POST",
      body: JSON.stringify({ ids: selectedIds }),
    });
    state.selected.clear();
    showToast(result.count ? `已启动 ${result.count} 个 AT 刷新任务` : "所选任务中没有已注册账号");
    await refreshState();
  } catch (error) {
    showToast(error.message, true);
  }
}

async function startPhoneBinding(ids, { clearSelection = false, credentialJobId = "" } = {}) {
  if (state.phoneBindingSubmitting || state.runtime.running) {
    showToast("请等待当前批次完成", true);
    return;
  }
  const explicitIds = Array.from(new Set((ids || []).map((value) => String(value || "")).filter(Boolean)));
  if (!explicitIds.length) {
    showToast("请先明确选择要绑定手机号的账号", true);
    return;
  }
  if (!smsBindingConfigured()) {
    showToast("请先保存接码服务和 API Key", true);
    return;
  }
  const selectedJobs = explicitIds
    .map((id) => state.jobs.find((job) => job.id === id))
    .filter(Boolean);
  const eligibleJobs = selectedJobs.filter(isPhoneBindable);
  const skippedCount = Math.max(0, explicitIds.length - eligibleJobs.length);
  if (!eligibleJobs.length) {
    showToast("所选账号中没有可绑定手机号的已注册账号", true);
    return;
  }
  const feeText = eligibleJobs.length === 1
    ? `将为 ${eligibleJobs[0].email || "该账号"} 租用一个手机号，可能产生 1 笔接码费用。`
    : `将为 ${eligibleJobs.length} 个账号租用手机号，最多产生 ${eligibleJobs.length} 笔接码费用。`;
  const skipText = skippedCount ? `\n另有 ${skippedCount} 个账号不符合条件，将跳过。` : "";
  if (!window.confirm(`${feeText}${skipText}\n确认继续？`)) return;

  const requestSeq = ++state.phoneBindingRequestSeq;
  state.phoneBindingSubmitting = true;
  updateSelectionUi();
  if (credentialJobId === state.credentialJobId) {
    const currentJob = state.jobs.find((job) => job.id === credentialJobId);
    if (currentJob) renderCredentialPhone(currentJob);
  }
  try {
    const result = await api("/api/phone/bind", {
      method: "POST",
      body: JSON.stringify({ ids: eligibleJobs.map((job) => job.id) }),
    });
    if (clearSelection) state.selected.clear();
    const parsedAccepted = Number(result.count ?? eligibleJobs.length);
    const accepted = Number.isFinite(parsedAccepted) ? parsedAccepted : eligibleJobs.length;
    const parsedBackendSkipped = Array.isArray(result.skipped)
      ? result.skipped.length
      : Number(result.skippedCount ?? result.skipped ?? 0);
    const backendSkipped = Number.isFinite(parsedBackendSkipped) ? parsedBackendSkipped : 0;
    showToast(accepted
      ? `已启动 ${accepted} 个手机号绑定任务${skippedCount + backendSkipped ? `，跳过 ${skippedCount + backendSkipped} 个` : ""}`
      : "没有可绑定手机号的账号");
    await refreshState();
  } catch (error) {
    if (!credentialJobId || requestSeq === state.phoneBindingRequestSeq) showToast(error.message, true);
  } finally {
    state.phoneBindingSubmitting = false;
    updateSelectionUi();
    if (credentialJobId === state.credentialJobId) {
      const currentJob = state.jobs.find((job) => job.id === credentialJobId);
      if (currentJob) renderCredentialPhone(currentJob);
    }
  }
}

async function deleteJobs(ids = null) {
  const selectedIds = ids || Array.from(state.selected);
  if (!selectedIds.length) return;
  const label = selectedIds.length === 1 ? "这个任务" : `所选 ${selectedIds.length} 个任务`;
  if (!window.confirm(`确定删除${label}？账号登录态、TOTP 和 AT 文件会保留。`)) return;
  try {
    const result = await api("/api/jobs/delete", {
      method: "POST",
      body: JSON.stringify({ ids: selectedIds }),
    });
    selectedIds.forEach((id) => state.selected.delete(id));
    showToast(`已删除 ${result.removed} 个任务`);
    await refreshState();
  } catch (error) {
    showToast(error.message, true);
  }
}

async function loadEmailOtp(jobId) {
  const dialog = $("#emailOtpDialog");
  const copyButton = $("#emailOtpDialog .copy-button");
  const requestSeq = ++state.emailOtpRequestSeq;
  const job = state.jobs.find((item) => item.id === jobId);
  $("#emailOtpTitle").textContent = job?.email || "最新验证码";
  $("#emailOtpCode").textContent = "------";
  $("#emailOtpSource").textContent = job?.provider?.label || "-";
  $("#emailOtpFetchedAt").textContent = "-";
  $("#emailOtpElapsed").textContent = "-";
  $("#emailOtpStatus").textContent = "正在读取最新邮件…";
  $("#emailOtpStatus").className = "otp-status";
  copyButton.disabled = true;
  if (!dialog.open) dialog.showModal();
  try {
    const result = await api(`/api/jobs/${encodeURIComponent(jobId)}/otp`);
    if (requestSeq !== state.emailOtpRequestSeq) return;
    $("#emailOtpTitle").textContent = result.email || job?.email || "最新验证码";
    $("#emailOtpCode").textContent = result.code || "------";
    $("#emailOtpSource").textContent = result.source || result.mode || "-";
    $("#emailOtpFetchedAt").textContent = result.fetchedAt || "-";
    $("#emailOtpElapsed").textContent = `${Number(result.elapsedMs || 0)} ms`;
    $("#emailOtpStatus").textContent = "已读取最新验证码";
    $("#emailOtpStatus").className = "otp-status success";
    copyButton.disabled = !result.code;
  } catch (error) {
    if (requestSeq !== state.emailOtpRequestSeq) return;
    $("#emailOtpStatus").textContent = error.message;
    $("#emailOtpStatus").className = "otp-status error";
  }
}

async function copyText(value) {
  if (!value || value === "-") return;
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    const area = document.createElement("textarea");
    area.value = value;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  showToast("已复制");
}

function updateCountdown() {
  const remaining = Math.max(0, Math.ceil((state.credentialExpiresAt - Date.now()) / 1000));
  state.credentialRemaining = remaining;
  $("#countdownText").textContent = `${remaining} 秒`;
  $("#countdownBar").style.width = `${(remaining / 30) * 100}%`;
}

const MANUAL_PHONE_PHASE_LABELS = {
  idle: "填写完整手机号后发送验证码。",
  starting: "正在建立并保持登录会话…",
  authenticating: "正在登录并进入手机号验证步骤…",
  waiting_phone: "登录会话已保持，可以填写或更换手机号。",
  switching_phone: "已收到新手机号，正在切换并重新发码…",
  sending_code: "正在向该手机号发送验证码…",
  waiting_code: "验证码已发送，请填写收到的验证码。",
  verifying: "正在验证手机号验证码…",
  retry_phone: "本次验证失败，请修改手机号后重新发送。",
  completed: "手机号绑定成功。",
  failed: "手动绑定会话已结束，原登录态仍然保留，可重新开始。",
  stopped: "手动绑定会话已停止，原登录态仍然保留。",
};

function updateManualPhoneControls() {
  const job = state.jobs.find((item) => item.id === state.credentialJobId) || {};
  const manual = state.manualPhoneState || { phase: "idle", active: false };
  const registered = ["registered", "phone_required"].includes(job.registrationStatus);
  const bound = phoneStatus(job) === "phone_bound" || manual.phase === "completed";
  const activeJobIds = Array.isArray(state.runtime.activeJobIds)
    ? state.runtime.activeJobIds.map((value) => String(value || ""))
    : [];
  const ownsManualRuntime = Boolean(state.runtime.running)
    && state.runtime.operation === "manual_phone_binding"
    && activeJobIds.includes(String(state.credentialJobId || ""));
  const busyElsewhere = Boolean(state.runtime.running) && !ownsManualRuntime;
  const phoneValue = $("#manualPhoneNumber").value.trim();
  const codeValue = $("#manualPhoneOtp").value.replace(/\D/g, "");
  const sendButton = $("#sendManualPhoneOtpBtn");
  const verifyButton = $("#verifyManualPhoneOtpBtn");

  sendButton.textContent = bound
    ? "手机号已绑定"
    : manual.active
      ? "换号并重新发送"
      : "发送验证码";
  sendButton.disabled = !registered
    || bound
    || state.manualPhoneSubmitting
    || busyElsewhere
    || !/^\+[1-9]\d{7,14}$/.test(phoneValue);
  verifyButton.disabled = bound
    || state.manualPhoneSubmitting
    || busyElsewhere
    || manual.phase !== "waiting_code"
    || codeValue.length < 4;
}

function renderManualPhoneStatus(payload = {}) {
  state.manualPhoneState = {
    phase: String(payload.phase || "idle"),
    active: Boolean(payload.active),
    attemptId: Number(payload.attemptId || 0),
    phoneMasked: String(payload.phoneMasked || ""),
    error: String(payload.error || ""),
  };
  const status = $("#manualPhoneStatus");
  const phase = state.manualPhoneState.phase;
  const masked = state.manualPhoneState.phoneMasked;
  const error = state.manualPhoneState.error;
  let message = MANUAL_PHONE_PHASE_LABELS[phase] || "手动手机号会话状态已更新。";
  if (phase === "waiting_code" && masked) message = `验证码已发送至 ${masked}，请输入验证码。`;
  if (error) message = `${error} 当前登录会话仍保持，可更换手机号后重试。`;
  status.textContent = message;
  status.className = `manual-phone-status ${error || ["retry_phone", "failed"].includes(phase) ? "error" : phase === "completed" ? "success" : state.manualPhoneState.active ? "running" : ""}`;
  updateManualPhoneControls();
}

async function refreshManualPhoneStatus() {
  if (state.manualPhonePolling
    || state.manualPhoneSubmitting
    || !state.credentialJobId
    || !$("#credentialDialog").open) return;
  const jobId = state.credentialJobId;
  const requestSeq = state.manualPhoneRequestSeq;
  state.manualPhonePolling = true;
  try {
    const payload = await api(`/api/jobs/${encodeURIComponent(jobId)}/phone/manual`);
    if (requestSeq === state.manualPhoneRequestSeq
      && state.credentialJobId === jobId
      && $("#credentialDialog").open) renderManualPhoneStatus(payload);
  } catch (_error) {
    // The normal credential refresh keeps running; a transient status read must not clear user input.
  } finally {
    state.manualPhonePolling = false;
  }
}

async function sendManualPhoneOtp() {
  if (!state.credentialJobId || state.manualPhoneSubmitting) return;
  const phoneNumber = $("#manualPhoneNumber").value.trim();
  if (!/^\+[1-9]\d{7,14}$/.test(phoneNumber)) {
    renderManualPhoneStatus({ ...state.manualPhoneState, error: "手机号格式无效，请填写 +国家码手机号。" });
    return;
  }
  const jobId = state.credentialJobId;
  const requestSeq = ++state.manualPhoneRequestSeq;
  state.manualPhoneSubmitting = true;
  renderManualPhoneStatus({ ...state.manualPhoneState, phase: state.manualPhoneState.active ? "switching_phone" : "starting", error: "" });
  try {
    const payload = await api(`/api/jobs/${encodeURIComponent(jobId)}/phone/manual/send`, {
      method: "POST",
      body: JSON.stringify({ phoneNumber }),
    });
    if (requestSeq !== state.manualPhoneRequestSeq || state.credentialJobId !== jobId) return;
    $("#manualPhoneOtp").value = "";
    renderManualPhoneStatus(payload);
    showToast("手机号已提交，正在保持会话并发送验证码");
    await refreshState();
  } catch (error) {
    if (requestSeq !== state.manualPhoneRequestSeq || state.credentialJobId !== jobId) return;
    renderManualPhoneStatus({ ...state.manualPhoneState, error: error.message });
  } finally {
    if (requestSeq === state.manualPhoneRequestSeq) {
      state.manualPhoneSubmitting = false;
      updateManualPhoneControls();
    }
  }
}

async function verifyManualPhoneOtp() {
  if (!state.credentialJobId || state.manualPhoneSubmitting) return;
  const code = $("#manualPhoneOtp").value.replace(/\D/g, "");
  if (code.length < 4) {
    renderManualPhoneStatus({ ...state.manualPhoneState, error: "请填写收到的验证码。" });
    return;
  }
  const jobId = state.credentialJobId;
  const requestSeq = ++state.manualPhoneRequestSeq;
  state.manualPhoneSubmitting = true;
  renderManualPhoneStatus({ ...state.manualPhoneState, phase: "verifying", error: "" });
  try {
    const payload = await api(`/api/jobs/${encodeURIComponent(jobId)}/phone/manual/verify`, {
      method: "POST",
      body: JSON.stringify({ code }),
    });
    if (requestSeq !== state.manualPhoneRequestSeq || state.credentialJobId !== jobId) return;
    renderManualPhoneStatus({ ...payload, phase: "verifying", active: true });
    showToast("验证码已提交，正在确认绑定");
  } catch (error) {
    if (requestSeq !== state.manualPhoneRequestSeq || state.credentialJobId !== jobId) return;
    renderManualPhoneStatus({ ...state.manualPhoneState, error: error.message });
  } finally {
    if (requestSeq === state.manualPhoneRequestSeq) {
      state.manualPhoneSubmitting = false;
      updateManualPhoneControls();
    }
  }
}

function renderCredentialPhone(source = {}) {
  const currentStatus = phoneStatus(source);
  const statusElement = $("#credentialPhoneStatus");
  const button = $("#bindCredentialPhoneBtn");
  const errorElement = $("#credentialPhoneError");
  const masked = String(source.phoneMasked || source.phoneNumberMasked || "");
  const error = String(source.phoneError || "");
  const registered = ["registered", "phone_required"].includes(source.registrationStatus);
  const active = ["phone_queued", "phone_binding"].includes(currentStatus);
  const manualActive = active && String(source.phoneProvider || "").toLowerCase() === "manual";

  statusElement.textContent = STATUS_LABELS[currentStatus] || currentStatus;
  statusElement.className = `phone-status-value ${statusTone(currentStatus)}`;
  $("#credentialPhoneMasked").textContent = masked || "-";
  $("#credentialPhoneBoundAt").textContent = source.phoneBoundAt || (currentStatus === "phone_bound" ? source.phoneUpdatedAt : "") || "-";
  errorElement.textContent = error;
  errorElement.hidden = !error;

  if (currentStatus === "phone_bound") {
    button.textContent = "手机号已绑定";
  } else if (active) {
    button.textContent = manualActive
      ? "手动绑定会话中…"
      : currentStatus === "phone_queued" ? "等待自动接码…" : "正在自动接码…";
  } else if (["phone_failed", "phone_stopped"].includes(currentStatus)) {
    button.textContent = "重试自动接码";
  } else {
    button.textContent = "自动接码绑定";
  }
  button.disabled = !registered
    || !PHONE_BINDABLE_STATUSES.has(currentStatus)
    || Boolean(state.runtime.running)
    || state.phoneBindingSubmitting
    || !smsBindingConfigured();
  button.title = !registered
    ? "账号尚未注册完成"
    : !smsBindingConfigured()
      ? "请先保存接码服务和 API Key"
      : currentStatus === "phone_bound"
        ? "该账号已完成手机号绑定"
        : active
          ? "手机号绑定任务正在运行"
          : state.runtime.running
            ? "请等待当前批次完成"
            : "租用接码手机号并绑定到此账号";
  updateManualPhoneControls();
}

async function loadCredentials(jobId, openDialog = true) {
  const dialog = $("#credentialDialog");
  if (!openDialog && !dialog.open) return;
  const requestSeq = ++state.credentialRequestSeq;
  try {
    const payload = await api(`/api/jobs/${encodeURIComponent(jobId)}/credentials`);
    if (requestSeq !== state.credentialRequestSeq) return;
    const credentials = payload.credentials;
    state.credentialJobId = jobId;
    state.credentialEmail = credentials.email || "";
    state.credentialUri = credentials.otpauthUri || "";
    $("#copyUriBtn").disabled = !state.credentialUri;
    state.credentialRemaining = Number(credentials.secondsRemaining || 0);
    state.credentialExpiresAt = Number(credentials.validUntilEpoch || 0) * 1000;
    $("#credentialEmail").textContent = credentials.email || "账号凭据";
    $("#credentialPassword").textContent = credentials.accountPassword || "-";
    const remotePasswordLabels = {
      set: "已设置",
      failed: "设置失败",
      not_attempted: "未尝试",
      unknown: "未知",
    };
    const remotePasswordStatus = credentials.remotePasswordStatus
      || (credentials.remotePasswordSet ? "set" : "unknown");
    $("#credentialPasswordStatus").textContent = remotePasswordLabels[remotePasswordStatus] || remotePasswordStatus;
    $("#credentialSecret").textContent = credentials.totpSecret || "-";
    $("#credentialAccessToken").textContent = credentials.accessToken || "-";
    $("#credentialCode").textContent = credentials.totpCode || "------";
    $("#factorId").textContent = credentials.factorId || "-";
    $("#credentialUpdated").textContent = credentials.updatedAt || "-";
    $("#credentialAtSource").textContent = credentials.atSource || "-";
    $("#credentialAtUpdated").textContent = credentials.atUpdatedAt || "-";
    $("#credentialAtExpires").textContent = credentials.atExpiresAt || "-";
    const currentJob = state.jobs.find((job) => job.id === jobId) || {};
    renderCredentialPhone({ ...currentJob, ...credentials });
    updateCountdown();
    if (openDialog && !dialog.open) {
      dialog.showModal();
    }
    refreshManualPhoneStatus();
    clearInterval(state.credentialTimer);
    if (state.credentialExpiresAt > 0) {
      state.credentialTimer = setInterval(() => {
        updateCountdown();
        if (state.credentialRemaining <= 0) {
          clearInterval(state.credentialTimer);
          loadCredentials(state.credentialJobId, false);
        }
      }, 250);
    }
  } catch (error) {
    if (requestSeq !== state.credentialRequestSeq) return;
    $("#credentialCode").textContent = "已过期";
    state.credentialExpiresAt = 0;
    updateCountdown();
    showToast(error.message, true);
    if (dialog.open) {
      clearInterval(state.credentialTimer);
      state.credentialTimer = setTimeout(() => loadCredentials(jobId, false), 2500);
    }
  }
}

async function fetchCredentialSession() {
  if (!state.credentialJobId) return;
  const jobId = state.credentialJobId;
  const requestSeq = ++state.credentialSessionRequestSeq;
  const dialog = $("#credentialDialog");
  const button = $("#fetchCredentialSessionBtn");
  const originalText = button.textContent;
  state.credentialSessionJson = "";
  $("#credentialSessionFetchedAt").textContent = "-";
  $("#credentialSessionPreview").textContent = "-";
  $("#credentialSessionPanel").hidden = true;
  $("#copyCredentialSessionBtn").disabled = true;
  $("#downloadCredentialSessionBtn").disabled = true;
  button.disabled = true;
  button.textContent = "正在获取…";
  try {
    const payload = await api(`/api/jobs/${encodeURIComponent(jobId)}/session`, {
      method: "POST",
    });
    if (requestSeq !== state.credentialSessionRequestSeq || state.credentialJobId !== jobId || !dialog.open) return;
    state.credentialSessionJson = `${JSON.stringify(payload.session || {}, null, 2)}\n`;
    $("#credentialSessionPreview").textContent = state.credentialSessionJson;
    $("#credentialSessionFetchedAt").textContent = payload.fetchedAt || "-";
    $("#credentialSessionPanel").hidden = false;
    $("#copyCredentialSessionBtn").disabled = false;
    $("#downloadCredentialSessionBtn").disabled = false;
    await loadCredentials(jobId, false);
    if (requestSeq !== state.credentialSessionRequestSeq || state.credentialJobId !== jobId || !dialog.open) return;
    showToast("已获取完整 Session");
  } catch (error) {
    if (requestSeq !== state.credentialSessionRequestSeq || state.credentialJobId !== jobId || !dialog.open) return;
    showToast(error.message, true);
  } finally {
    if (requestSeq === state.credentialSessionRequestSeq && state.credentialJobId === jobId) {
      button.disabled = false;
      button.textContent = originalText;
    }
  }
}

function downloadCredentialSession() {
  if (!state.credentialSessionJson) return;
  const safeEmail = String(state.credentialEmail || "account").replace(/[^A-Za-z0-9@._-]+/g, "_");
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  const blob = new Blob([state.credentialSessionJson], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `chatgpt-session-${safeEmail}-${stamp}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function clearCredentialData() {
  state.credentialRequestSeq += 1;
  state.credentialSessionRequestSeq += 1;
  state.phoneBindingRequestSeq += 1;
  state.manualPhoneRequestSeq += 1;
  clearInterval(state.credentialTimer);
  state.credentialTimer = null;
  state.credentialJobId = "";
  state.credentialEmail = "";
  state.credentialSessionJson = "";
  state.credentialUri = "";
  $("#copyUriBtn").disabled = true;
  state.credentialRemaining = 0;
  state.credentialExpiresAt = 0;
  $("#credentialEmail").textContent = "账号凭据";
  $("#credentialPassword").textContent = "-";
  $("#credentialPasswordStatus").textContent = "-";
  $("#credentialSecret").textContent = "-";
  $("#credentialAccessToken").textContent = "-";
  $("#credentialCode").textContent = "------";
  $("#factorId").textContent = "-";
  $("#credentialUpdated").textContent = "-";
  $("#credentialAtSource").textContent = "-";
  $("#credentialAtUpdated").textContent = "-";
  $("#credentialAtExpires").textContent = "-";
  $("#credentialPhoneStatus").textContent = "未知";
  $("#credentialPhoneStatus").className = "phone-status-value";
  $("#credentialPhoneMasked").textContent = "-";
  $("#credentialPhoneBoundAt").textContent = "-";
  $("#credentialPhoneError").textContent = "";
  $("#credentialPhoneError").hidden = true;
  $("#credentialSessionFetchedAt").textContent = "-";
  $("#credentialSessionPreview").textContent = "-";
  $("#credentialSessionPanel").hidden = true;
  $("#copyCredentialSessionBtn").disabled = true;
  $("#downloadCredentialSessionBtn").disabled = true;
  $("#fetchCredentialSessionBtn").disabled = false;
  $("#fetchCredentialSessionBtn").textContent = "获取完整 Session";
  $("#bindCredentialPhoneBtn").disabled = true;
  $("#bindCredentialPhoneBtn").textContent = "自动接码绑定";
  $("#manualPhoneNumber").value = "";
  $("#manualPhoneOtp").value = "";
  state.manualPhoneSubmitting = false;
  state.manualPhoneState = { phase: "idle", active: false };
  $("#manualPhoneStatus").textContent = MANUAL_PHONE_PHASE_LABELS.idle;
  $("#manualPhoneStatus").className = "manual-phone-status";
  $("#sendManualPhoneOtpBtn").disabled = true;
  $("#sendManualPhoneOtpBtn").textContent = "发送验证码";
  $("#verifyManualPhoneOtpBtn").disabled = true;
  updateCountdown();
}

function bindEvents() {
  $$('input[name="otpMode"]').forEach((input) => input.addEventListener("change", updateModeFields));
  $("#importBtn").addEventListener("click", importQueue);
  $("#testSourceBtn").addEventListener("click", testMailSource);
  $("#settingsForm").addEventListener("submit", saveSettings);
  $("#settingsForm").addEventListener("input", () => { state.settingsDirty = true; });
  $("#smsSettingsForm")?.addEventListener("submit", saveSmsSettings);
  $("#smsSettingsForm")?.addEventListener("input", () => { state.settingsDirty = true; });
  smsForm()?.elements?.namedItem("smsProvider")?.addEventListener("change", async (event) => {
    updateSmsSettingsFields();
    smsCountriesCache = [];
    smsCountriesProvider = "";
    await ensureSmsCountries(event.target.value || "", $("#smsCountry")?.value || "52", getAllowedCountriesValue());
    updateSmsSettingsFields();
  });
  $("#smsCountrySearch")?.addEventListener("input", (event) => filterSmsAllowedCountries(event.target.value));
  $("#smsAllowedCountriesBox")?.addEventListener("change", () => {
    state.settingsDirty = true;
    updateAllowedCountryCount();
  });
  $("#btnClearAllowedCountries")?.addEventListener("click", () => {
    $("#smsAllowedCountriesBox")?.querySelectorAll("input[type=checkbox]").forEach((input) => {
      input.checked = false;
    });
    state.settingsDirty = true;
    updateAllowedCountryCount();
  });
  $("#btnTestSms")?.addEventListener("click", testSmsBalance);
  $("#detectLocalBtn").addEventListener("click", detectLocalNetwork);
  $("#testProxyPoolBtn").addEventListener("click", testProxyPool);
  $("#clearProxyPoolBtn").addEventListener("click", () => {
    $("#proxyPool").value = "";
    state.proxyPoolClearRequested = true;
    state.settingsDirty = true;
    setNetworkResult('<span>保存运行参数后清空代理池</span>', "warning");
  });
  $("#fileBtn").addEventListener("click", () => $("#fileInput").click());
  $("#fileInput").addEventListener("change", async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    $("#fileName").textContent = file.name;
    $("#importText").value = await file.text();
  });
  $("#startBtn").addEventListener("click", () => startSelected());
  $("#stopBtn").addEventListener("click", stopAll);
  $("#clearBtn").addEventListener("click", clearFinished);
  $("#refreshAtBtn").addEventListener("click", () => refreshAccessTokens());
  $("#bindPhoneSelectedBtn").addEventListener("click", () => {
    startPhoneBinding(Array.from(state.selected), { clearSelection: true });
  });
  $("#sendManualPhoneOtpBtn").addEventListener("click", sendManualPhoneOtp);
  $("#verifyManualPhoneOtpBtn").addEventListener("click", verifyManualPhoneOtp);
  $("#manualPhoneNumber").addEventListener("input", updateManualPhoneControls);
  $("#manualPhoneOtp").addEventListener("input", (event) => {
    event.target.value = event.target.value.replace(/\D/g, "").slice(0, 8);
    updateManualPhoneControls();
  });
  $("#deleteSelectedBtn").addEventListener("click", () => deleteJobs());
  $("#archiveSelectedBtn").addEventListener("click", () => {
    const mode = $("#archiveSelectedBtn").dataset.mode || "archive";
    archiveSelected(mode !== "unarchive");
  });
  $("#groupSelectedBtn").addEventListener("click", async () => {
    const name = window.prompt("输入分类名（留空=移出分类）", "");
    if (name === null) return;
    await assignGroupSelected(name);
  });
  $("#createGroupBtn").addEventListener("click", async () => {
    const name = $("#newGroupInput").value.trim();
    if (!name) {
      showToast("请输入分类名", true);
      return;
    }
    await assignGroupSelected(name);
    $("#newGroupInput").value = "";
  });
  $("#groupList").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-group-key]");
    if (!button) return;
    const key = button.dataset.groupKey;
    const kind = button.dataset.groupKind;
    if (kind === "scope") {
      state.groupFilter = "all";
      state.archiveFilter = "active";
    } else if (kind === "archive") {
      state.groupFilter = "all";
      state.archiveFilter = key;
    } else {
      state.groupFilter = key;
      if (state.archiveFilter === "active") state.archiveFilter = "all";
    }
    state.page = 1;
    state.selected.clear();
    renderJobs();
  });
  $("#exportBtn").addEventListener("click", () => { window.location.href = "/api/export"; });
  $("#exportRtBtn").addEventListener("click", exportRtSelected);
  $("#searchInput").addEventListener("input", () => { state.page = 1; state.selected.clear(); renderJobs(); });
  $("#statusFilter").addEventListener("change", () => { state.page = 1; state.selected.clear(); renderJobs(); });
  $("#modeFilter").addEventListener("change", () => { state.page = 1; state.selected.clear(); renderJobs(); });
  $("#planFilter").addEventListener("change", () => { state.page = 1; state.selected.clear(); renderJobs(); });
  $("#pageSize").addEventListener("change", (event) => {
    state.pageSize = Number(event.target.value || 20);
    state.page = 1;
    renderJobs();
  });
  $("#firstPageBtn").addEventListener("click", () => { state.page = 1; renderJobs(); });
  $("#prevPageBtn").addEventListener("click", () => { state.page = Math.max(1, state.page - 1); renderJobs(); });
  $("#nextPageBtn").addEventListener("click", () => { state.page += 1; renderJobs(); });
  $("#lastPageBtn").addEventListener("click", () => {
    state.page = Math.max(1, Math.ceil(filteredJobs().length / state.pageSize));
    renderJobs();
  });
  $("#selectAll").addEventListener("change", (event) => {
    visibleJobs().forEach((job) => event.target.checked ? state.selected.add(job.id) : state.selected.delete(job.id));
    renderJobs();
  });
  $("#jobRows").addEventListener("change", (event) => {
    const id = event.target.dataset.select;
    if (id) {
      event.target.checked ? state.selected.add(id) : state.selected.delete(id);
      updateSelectionUi();
      return;
    }
  });
  $("#jobRows").addEventListener("input", (event) => {
    const noteId = event.target.dataset.noteId;
    if (!noteId) return;
    scheduleNoteSave(noteId, event.target.value);
  });
  $("#jobRows").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    if (button.dataset.action === "retry") {
      const job = state.jobs.find((item) => item.id === button.dataset.id);
      if (job?.registrationStatus === "registered" && job?.mfaStatus !== "enabled") {
        enableMfaSelected([button.dataset.id]);
      } else {
        startSelected([button.dataset.id]);
      }
    }
    if (button.dataset.action === "credentials") loadCredentials(button.dataset.id);
    if (button.dataset.action === "email-otp") loadEmailOtp(button.dataset.id);
    if (button.dataset.action === "refresh-at") refreshAccessTokens([button.dataset.id]);
    if (button.dataset.action === "toggle-archive") {
      const job = state.jobs.find((item) => item.id === button.dataset.id);
      updateJobsMeta([button.dataset.id], { archived: !Boolean(job?.archived) });
    }
    if (button.dataset.action === "delete") deleteJobs([button.dataset.id]);
  });
  $("#logToggle").addEventListener("click", () => {
    state.autoScroll = !state.autoScroll;
    $("#logToggle").textContent = state.autoScroll ? "暂停滚动" : "继续滚动";
  });
  $("#credentialDialog").addEventListener("close", clearCredentialData);
  $("#emailOtpDialog").addEventListener("close", () => { state.emailOtpRequestSeq += 1; });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && $("#credentialDialog").open && state.credentialJobId) {
      loadCredentials(state.credentialJobId, false);
    }
  });
  $$(".copy-button").forEach((button) => button.addEventListener("click", () => copyText($(`#${button.dataset.copy}`).textContent)));
  $("#copyUriBtn").addEventListener("click", () => copyText(state.credentialUri));
  $("#refreshCredentialAtBtn").addEventListener("click", () => {
    if (state.credentialJobId) refreshAccessTokens([state.credentialJobId]);
  });
  $("#fetchCredentialSessionBtn").addEventListener("click", fetchCredentialSession);
  $("#bindCredentialPhoneBtn").addEventListener("click", () => {
    if (state.credentialJobId) {
      startPhoneBinding([state.credentialJobId], { credentialJobId: state.credentialJobId });
    }
  });
  $("#copyCredentialSessionBtn").addEventListener("click", () => copyText(state.credentialSessionJson));
  $("#downloadCredentialSessionBtn").addEventListener("click", downloadCredentialSession);
}

bindEvents();
updateModeFields();
updateSmsSettingsFields();
refreshState();
setInterval(refreshState, 2000);
