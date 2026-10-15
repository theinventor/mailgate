"use strict";
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
let csrf = "", setup = false, tokens = [], editing = null, view = "tokens";
let noticeTimer;

function notify(message) {
  $("#notice").textContent = message;
  $("#notice").hidden = false;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => { $("#notice").hidden = true; }, 7000);
}
const friendlyErrors = {
  unauthorized: "Your session has ended. Please sign in again.", incorrect_password: "That password doesn't match.",
  rate_limit_exceeded: "Too many requests. Please wait a minute and try again.", password_check_busy: "A password check is in progress. Please try again shortly.",
  invalid_token_policy: "Check the name, permissions, limits, email addresses, and expiration date.",
  setup_already_completed: "Setup is already complete. Reload this page to sign in.",
  invalid_csrf: "Please reload the page and try again.", invalid_origin: "Open the configured HTTPS address to continue.",
  password_required: "Enter a password.",
  password_change_failed: "Enter a nonempty password of at most 1,024 bytes.",
  audit_unavailable: "The audit log is unavailable. The service has paused this request.",
  unavailable: "The service is temporarily unavailable. Please try again.", busy: "The service is busy. Please try again shortly."
};
async function api(path, method = "GET", body) {
  const headers = {};
  if (method !== "GET") { headers["Content-Type"] = "application/json"; headers["X-CSRF-Token"] = csrf; }
  const res = await fetch("/admin/api/" + path, {method, headers, credentials:"same-origin", cache:"no-store", body:body === undefined ? undefined : JSON.stringify(body)});
  const data = await res.json();
  if (!res.ok) {
    if (res.status === 401 && path !== "login" && path !== "session") { showAuth(false); }
    throw new Error(friendlyErrors[data.error] || "Unable to complete that request. Please check your entries and try again.");
  }
  return data;
}
function showAuth(firstVisit) {
  csrf = ""; tokens = []; setup = firstVisit;
  $("#app").hidden = true; $("#auth").hidden = false; $("#auth-form").hidden = false;
  $("#auth-title").textContent = setup ? "Welcome." : "Welcome back.";
  $("#auth-description").textContent = setup ? "Set your admin password to make this gateway yours." : "Sign in to manage your agents and their access.";
  $("#auth-submit").textContent = setup ? "Set password & continue" : "Sign in";
  $("#setup-options").hidden = !setup;
  $("#confirm-password").required = setup;
  $("#password").autocomplete = setup ? "new-password" : "current-password";
  $("#auth-form").reset(); $("#auth-error").textContent = "";
  $("#password").type = "password"; $("#show-password").textContent = "Show";
  $("#token-secret").value = "";
  $$("dialog[open]").forEach(d => d.close());
  $("#tokens-body").replaceChildren(); $("#activity-body").replaceChildren();
  $("#password").focus();
}
async function enterApp() {
  const session = await api("session");
  csrf = session.csrf;
  $("#account").textContent = session.owner_email;
  $("#auth-form").reset(); $("#auth").hidden = true; $("#app").hidden = false;
  await refresh();
}
$("#show-password").addEventListener("click", () => {
  const visible = $("#password").type === "password";
  $("#password").type = visible ? "text" : "password";
  $("#show-password").textContent = visible ? "Hide" : "Show";
});
$("#generate-password").addEventListener("click", () => {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const password = [...bytes].map(b => alphabet[b & 63]).join("");
  $("#password").value = password; $("#confirm-password").value = password;
  $("#password").type = "text"; $("#show-password").textContent = "Hide";
});
$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault(); $("#auth-error").textContent = "";
  if (setup && $("#password").value !== $("#confirm-password").value) { $("#auth-error").textContent = "The passwords don't match."; return; }
  $("#auth-submit").disabled = true;
  try { await api(setup ? "setup" : "login", "POST", {password:$("#password").value}); await enterApp(); }
  catch (error) { $("#auth-error").textContent = error.message; }
  finally { $("#auth-submit").disabled = false; }
});
$("#logout").addEventListener("click", async () => {
  try { await api("logout", "POST", {}); showAuth(false); } catch (error) { notify(error.message); }
});
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function cell(row, text, className) { const td = el("td", text, className); row.append(td); return td; }
function localDate(value) { return new Date(value).toLocaleString([], {month:"short",day:"numeric",hour:"numeric",minute:"2-digit"}); }
function renderTokens() {
  const tbody = $("#tokens-body"); tbody.replaceChildren();
  $("#tokens-empty").hidden = tokens.length > 0;
  $("#token-count").textContent = tokens.length + (tokens.length === 1 ? " token" : " tokens");
  for (const token of tokens) {
    const row = el("tr");
    const name = cell(row); name.append(el("strong", token.name), el("small", token.id.slice(0,12) + "…", "mono"));
    const permissions = cell(row);
    token.policy.scopes.forEach(scope => permissions.append(el("span", scope.replace("mail.", ""), "badge " + (scope === "mail.send" ? "send" : ""))));
    if ((token.policy.allowed_label_ids || []).length || (token.policy.allowed_senders || []).length || (token.policy.allowed_recipients || []).length) permissions.append(el("small", "Restricted access"));
    const limits = cell(row); limits.append(el("strong", token.policy.requests_per_minute + " / min"), el("small", token.policy.reads_per_day + " reads · " + (token.policy.scopes.includes("mail.send") ? token.policy.sends_per_day : 0) + " sends / day"));
    cell(row, token.policy.copy_owner === "none" ? "None" : "Always " + token.policy.copy_owner.toUpperCase());
    const inactive = token.revoked || new Date(token.expires_at) <= new Date();
    const status = cell(row); status.append(el("span", token.revoked ? "Revoked" : inactive ? "Expired" : "Active", "badge " + (inactive ? "inactive" : "active")), el("small", "Until " + localDate(token.expires_at)));
    const actions = el("div", undefined, "cell-actions");
    const edit = el("button", "Edit", "plain"); edit.addEventListener("click", () => openToken(token)); actions.append(edit);
    if (!token.revoked) {
      const revoke = el("button", "Revoke", "plain");
      revoke.addEventListener("click", async () => { if (confirm("Revoke access for “" + token.name + "”?")) await changeToken(token.id + "/revoke", "POST"); }); actions.append(revoke);
    }
    const remove = el("button", "Delete", "plain danger");
    remove.addEventListener("click", async () => { if (confirm("Delete “" + token.name + "” and end its access? Its audit history will be kept.")) await changeToken(token.id, "DELETE"); }); actions.append(remove);
    cell(row).append(actions); tbody.append(row);
  }
}
async function changeToken(path, method) {
  try { await api("tokens/" + path, method, {}); await refresh(); } catch (error) { notify(error.message); }
}
const viewText = {
  tokens:["Access tokens", "Give each agent exactly the access it needs."],
  activity:["Activity", "Follow the requests coming through your gateway."],
  alerts:["Alerts", "Keep an eye on delivery and events that need your attention."],
  settings:["Settings", "Manage your private admin account."]
};
function selectView(next) {
  view = next;
  for (const key of Object.keys(viewText)) $("#view-" + key).hidden = key !== view;
  $$("[data-view]").forEach(button => button.classList.toggle("active", button.dataset.view === view));
  $("#page-title").textContent = viewText[view][0]; $("#breadcrumb").textContent = viewText[view][0];
  $("#page-description").textContent = viewText[view][1]; $("#new-token").hidden = view !== "tokens";
}
$$("[data-view]").forEach(button => button.addEventListener("click", async () => { selectView(button.dataset.view); try { await refresh(); } catch (error) { notify(error.message); } }));
async function refresh() {
  const overview = await api("overview");
  $("#stat-tokens").textContent = overview.active_tokens; $("#stat-requests").textContent = overview.requests_today;
  $("#stat-flags").textContent = overview.flags_today; $("#stat-alerts").textContent = overview.pending_alerts;
  if (view === "tokens") { tokens = await api("tokens"); renderTokens(); }
  if (view === "activity") {
    const events = await api("audit"); $("#activity-body").replaceChildren();
    for (const item of events) {
      const row = el("tr"); cell(row, localDate(item.at)); cell(row, item.action);
      cell(row, item.token_id || "—", "mono"); cell(row, item.status || "—");
      const detail = item.details || {};
      cell(row, [item.route, detail.rule, detail.name, detail.returned === undefined ? "" : detail.returned + " returned", detail.withheld ? detail.withheld + " withheld" : ""].filter(Boolean).join(" · "), "details-cell");
      $("#activity-body").append(row);
    }
  }
  if (view === "alerts") {
    const data = await api("alerts");
    $("#alert-channels").textContent = data.configured_channels.length ? "Delivery channels: " + data.configured_channels.join(" + ") + ". Failed deliveries are retried." : "No delivery channels configured.";
    $("#alerts-list").replaceChildren();
    for (const item of data.pending) {
      const entry = el("div", undefined, "event-item");
      entry.append(el("strong", item.channel + " · " + item.attempts + " attempts"), el("p", item.message), el("small", item.last_error || "Waiting for delivery"));
      $("#alerts-list").append(entry);
    }
    if (!data.pending.length) $("#alerts-list").append(el("p", "All clear. No alerts waiting for delivery.", "muted"));
    const sends = await api("sends"); $("#sends-list").replaceChildren();
    sends.forEach(item => { const entry = el("div", undefined, "event-item"); entry.append(el("strong", item.state + " · " + localDate(item.created_at)), el("p", "Token " + item.token_id), el("small", "Idempotency key hash: " + item.key_hash)); $("#sends-list").append(entry); });
    if (!sends.length) $("#sends-list").append(el("p", "No send outcomes need review.", "muted"));
  }
}
$("#refresh").addEventListener("click", async () => { try { await refresh(); } catch (error) { notify(error.message); } });
function dateInput(date) { return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0,16); }
function openToken(token) {
  editing = token || null; $("#token-form").reset(); $("#token-error").textContent = "";
  $("#token-dialog-title").textContent = token ? "Edit token" : "Create a token";
  $("#token-submit").textContent = token ? "Save changes" : "Create token";
  $("#expiry").value = dateInput(token ? new Date(token.expires_at) : new Date(Date.now() + 30*86400000));
  if (token) {
    $("#token-name").value = token.name;
    $$("input[name=scope]").forEach(input => { input.checked = token.policy.scopes.includes(input.value); });
    $("#rpm").value = token.policy.requests_per_minute; $("#reads").value = token.policy.reads_per_day; $("#sends").value = token.policy.sends_per_day;
    $("#owner-copy").value = token.policy.copy_owner;
    $("#allowed-labels").value = (token.policy.allowed_label_ids || []).join("\n");
    $("#allowed-senders").value = (token.policy.allowed_senders || []).join("\n");
    $("#allowed-recipients").value = (token.policy.allowed_recipients || []).join("\n");
  }
  $("#token-dialog").showModal(); $("#token-name").focus();
}
$("#new-token").addEventListener("click", () => openToken(null));
$("#empty-create").addEventListener("click", () => openToken(null));
$$(".close-dialog").forEach(button => button.addEventListener("click", () => $("#token-dialog").close()));
const entries = (id) => $(id).value.split(/[,\n]/).map(value => value.trim()).filter(Boolean);
$("#token-form").addEventListener("submit", async (event) => {
  event.preventDefault(); $("#token-error").textContent = ""; $("#token-submit").disabled = true;
  try {
    const payload = {name:$("#token-name").value.trim(), expires_at:new Date($("#expiry").value).toISOString(), policy:{scopes:$$("input[name=scope]:checked").map(input => input.value), requests_per_minute:Number($("#rpm").value), reads_per_day:Number($("#reads").value), sends_per_day:Number($("#sends").value), copy_owner:$("#owner-copy").value, allowed_label_ids:entries("#allowed-labels"), allowed_senders:entries("#allowed-senders"), allowed_recipients:entries("#allowed-recipients")}};
    const result = await api(editing ? "tokens/" + editing.id : "tokens", editing ? "PUT" : "POST", payload);
    $("#token-dialog").close();
    if (result.secret) { $("#token-secret").value = result.secret; $("#copy-secret").textContent = "Copy token"; $("#secret-dialog").showModal(); }
    await refresh();
  } catch (error) { $("#token-error").textContent = error.message; }
  finally { $("#token-submit").disabled = false; }
});
$("#copy-secret").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText($("#token-secret").value); $("#copy-secret").textContent = "Copied"; }
  catch { $("#token-secret").select(); $("#copy-secret").textContent = "Select & copy manually"; }
});
$("#secret-done").addEventListener("click", () => { $("#token-secret").value = ""; $("#secret-dialog").close(); });
$("#secret-dialog").addEventListener("close", () => { $("#token-secret").value = ""; });
$("#password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if ($("#new-password").value !== $("#repeat-password").value) { notify("The new passwords don't match."); return; }
  const button = $("#password-form button"); button.disabled = true;
  try {
    await api("password", "POST", {current_password:$("#current-password").value, new_password:$("#new-password").value});
    $("#password-form").reset(); showAuth(false); notify("Password changed. Sign in with your new password.");
  } catch (error) { notify(error.message); }
  finally { button.disabled = false; }
});
window.addEventListener("pageshow", event => { if (event.persisted) location.reload(); });
(async () => {
  try {
    const state = await api("state");
    if (state.setup_required) { showAuth(true); return; }
    try { await enterApp(); } catch { showAuth(false); }
  } catch (error) { $("#auth-title").textContent = "Unable to connect"; $("#auth-description").textContent = error.message; }
})();
