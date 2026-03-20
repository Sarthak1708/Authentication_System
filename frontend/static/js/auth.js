const TOKEN_KEY = "authToken";

function saveToken(token) { localStorage.setItem(TOKEN_KEY, token); }
function getToken()       { return localStorage.getItem(TOKEN_KEY); }
function clearToken()     { localStorage.removeItem(TOKEN_KEY); }
function isLoggedIn()     { return !!getToken(); }

const API = window.location.origin + "/api";

async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(API + path, { ...options, headers });
  const data = await res.json();
  return { ok: res.ok, status: res.status, data };
}

function showAlert(msg, type = "error") {
  const el = document.getElementById("alert");
  if (!el) return;
  el.textContent = "";
  const icon = document.createElement("span");
  icon.textContent = type === "error" ? "⚠ " : "✓ ";
  const txt = document.createElement("span");
  txt.textContent = msg;
  el.appendChild(icon); el.appendChild(txt);
  el.className = `alert alert-${type} show`;
}

function hideAlert() {
  const el = document.getElementById("alert");
  if (el) el.className = "alert";
}

function setLoading(btn, loading) {
  if (loading) { btn.classList.add("loading"); btn.disabled = true; }
  else         { btn.classList.remove("loading"); btn.disabled = false; }
}