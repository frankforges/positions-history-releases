// Positions History user admin. Static page (GitHub Pages) that edits users.txt in the private repo
// through the GitHub API with a fine-grained token. The token is kept in this browser only,
// encrypted with the user's password (PBKDF2-SHA256 600k -> AES-256-GCM); the page holds no secrets.
// After a change the existing "Publish licenses" Action signs and publishes the list, as before.
"use strict";

const OWNER = "frankforges";
const REPO = "nt8-positions-history";
const FILE = "users.txt";
const WORKFLOW = "publish-licenses.yml";
const STORE_KEY = "ph-admin-token-v1";
const ID_PATTERN = /^[0-9A-Za-z-]{16,64}$/; // same rule as tools/build_licenses.py

let token = null;   // decrypted token, memory only
let fileSha = null; // users.txt blob sha, required by the API to update it
let lines = [];     // users.txt lines, comments included

const $ = (id) => document.getElementById(id);

// ---- token storage ----------------------------------------------------------------------
const bytesToB64 = (bytes) => btoa(String.fromCharCode(...bytes));
const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

async function deriveKey(password, salt) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function storeToken(plain, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plain)));
  localStorage.setItem(STORE_KEY, JSON.stringify({ salt: bytesToB64(salt), iv: bytesToB64(iv), ct: bytesToB64(ct) }));
}

async function readToken(password) {
  const saved = JSON.parse(localStorage.getItem(STORE_KEY));
  const key = await deriveKey(password, b64ToBytes(saved.salt));
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64ToBytes(saved.iv) }, key, b64ToBytes(saved.ct));
  return new TextDecoder().decode(plain); // a wrong password makes decrypt throw
}

function hasStoredToken() {
  try { return !!localStorage.getItem(STORE_KEY); } catch { return false; }
}

// ---- GitHub API -------------------------------------------------------------------------
async function api(path, options = {}) {
  const response = await fetch("https://api.github.com" + path, {
    ...options,
    headers: {
      Authorization: "Bearer " + token,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
    cache: "no-store",
  });
  if (response.status === 401) throw new Error("GitHub rejected the token (expired or revoked). Use a different token.");
  const data = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) {
    const error = new Error((data && data.message) || "GitHub error " + response.status);
    error.status = response.status;
    throw error;
  }
  return data;
}

const utf8ToB64 = (text) => bytesToB64(new TextEncoder().encode(text));
const b64ToUtf8 = (b64) => new TextDecoder().decode(b64ToBytes(b64.replace(/\s/g, "")));

function parseUser(line) {
  const text = line.trim();
  if (!text || text.startsWith("#")) return null;
  const match = text.match(/^(\S+)\s*(.*)$/);
  return { id: match[1], name: match[2] };
}

async function loadUsers() {
  const data = await api(`/repos/${OWNER}/${REPO}/contents/${FILE}`);
  fileSha = data.sha;
  lines = b64ToUtf8(data.content).replace(/\r/g, "").split("\n");
  renderUsers();
}

async function saveUsers(newLines, message) {
  const content = newLines.join("\n").replace(/\n*$/, "\n");
  try {
    const result = await api(`/repos/${OWNER}/${REPO}/contents/${FILE}`, {
      method: "PUT",
      body: JSON.stringify({ message, content: utf8ToB64(content), sha: fileSha }),
    });
    fileSha = result.content.sha;
    lines = content.split("\n");
    renderUsers();
    watchPublish(Date.now());
  } catch (error) {
    if (error.status === 409 || error.status === 422) {
      await loadUsers(); // users.txt changed elsewhere meanwhile
      throw new Error("The list was changed elsewhere meanwhile. It has been reloaded; please try again.");
    }
    throw error;
  }
}

// ---- UI ---------------------------------------------------------------------------------
function show(view) {
  for (const id of ["setup", "unlock", "app"]) $(id).hidden = id !== view;
  $("lock").hidden = view !== "app";
}

function message(text) { $("msg").textContent = text || ""; }

function shortId(id) { return id.length > 14 ? id.slice(0, 8) + "…" + id.slice(-4) : id; }

function renderUsers() {
  const list = $("users");
  list.replaceChildren();
  const users = lines.map(parseUser).filter(Boolean);
  $("empty").hidden = users.length > 0;
  for (const user of users) {
    const item = document.createElement("li");
    const id = document.createElement("code");
    id.textContent = shortId(user.id);
    id.title = user.id;
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = user.name || "(no name)";
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "Remove";
    remove.addEventListener("click", () => removeUser(user));
    item.append(id, name, remove);
    list.append(item);
  }
}

async function busy(button, work) {
  button.disabled = true;
  message("");
  try { await work(); } catch (error) { message(error.message); } finally { button.disabled = false; }
}

async function addUser() {
  const id = $("machineId").value.trim().toUpperCase();
  const name = $("userName").value.trim().replace(/\s+/g, " ");
  if (!ID_PATTERN.test(id)) throw new Error("That doesn't look like a Machine ID (16-64 letters, digits or dashes).");
  if (!name) throw new Error("Add a name or note, so you know later who this is.");
  if (lines.map(parseUser).some((u) => u && u.id.toUpperCase() === id)) throw new Error("This Machine ID is already on the list.");
  const kept = lines.slice();
  while (kept.length && kept[kept.length - 1].trim() === "") kept.pop();
  await saveUsers([...kept, `${id}  ${name}`], `Add user: ${name}`);
  $("machineId").value = "";
  $("userName").value = "";
}

async function removeUser(user) {
  if (!confirm(`Remove "${user.name || user.id}"?\nThey lose access within about a minute (at their next check).`)) return;
  message("");
  try {
    await saveUsers(lines.filter((l) => { const u = parseUser(l); return !(u && u.id.toUpperCase() === user.id.toUpperCase()); }),
      `Remove user: ${user.name || user.id}`);
  } catch (error) { message(error.message); }
}

// Follows the Publish licenses run started by a change (or shows the last one).
let watchTimer = null;
async function watchPublish(since) {
  clearTimeout(watchTimer);
  const status = $("publish");
  const started = Date.now();
  const tick = async () => {
    try {
      const data = await api(`/repos/${OWNER}/${REPO}/actions/workflows/${WORKFLOW}/runs?per_page=1`);
      const run = data.workflow_runs[0];
      const isNew = run && (!since || Date.parse(run.created_at) >= since - 15000);
      if (!isNew) {
        status.textContent = "Waiting for publishing to start…";
      } else if (run.status !== "completed") {
        status.textContent = "Publishing…";
      } else {
        const when = new Date(run.updated_at).toLocaleString();
        if (run.conclusion === "success") {
          status.replaceChildren();
          status.append(Object.assign(document.createElement("span"), { className: "ok", textContent: "✓ Published " }),
            since ? "— users can press Check again (allow up to a minute)." : `(${when}).`);
        } else {
          status.replaceChildren();
          const link = Object.assign(document.createElement("a"), { href: run.html_url, target: "_blank", rel: "noopener", textContent: "see the run" });
          status.append(Object.assign(document.createElement("span"), { className: "bad", textContent: "✗ Publishing failed " }),
            `(${when}) — the previous list stays live; `, link, ".");
        }
        return;
      }
    } catch (error) {
      status.textContent = "Couldn't read the publishing status: " + error.message;
      return;
    }
    if (Date.now() - started < 4 * 60 * 1000) watchTimer = setTimeout(tick, 4000);
  };
  tick();
}

async function enterApp() {
  await loadUsers();
  show("app");
  watchPublish(0);
}

$("saveToken").addEventListener("click", (e) => busy(e.target, async () => {
  const value = $("token").value.trim();
  const password = $("newPassword").value;
  if (!value) throw new Error("Paste the token first.");
  if (password.length < 8) throw new Error("Use a password of at least 8 characters.");
  if (password !== $("newPassword2").value) throw new Error("The two passwords don't match.");
  token = value;
  await loadUsers(); // proves the token works before storing it
  await storeToken(value, password);
  $("token").value = $("newPassword").value = $("newPassword2").value = "";
  show("app");
  watchPublish(0);
}));

$("unlockButton").addEventListener("click", (e) => busy(e.target, async () => {
  try { token = await readToken($("password").value); } catch { throw new Error("Wrong password."); }
  $("password").value = "";
  await enterApp();
}));
$("password").addEventListener("keydown", (e) => { if (e.key === "Enter") $("unlockButton").click(); });

$("forget").addEventListener("click", () => {
  if (!confirm("Forget the saved token on this device? You'll need to paste a token again.")) return;
  try { localStorage.removeItem(STORE_KEY); } catch { /* storage blocked */ }
  message("");
  show("setup");
});

$("lock").addEventListener("click", () => {
  token = null;
  lines = [];
  $("users").replaceChildren();
  $("publish").textContent = "";
  clearTimeout(watchTimer);
  show("unlock");
});

$("addButton").addEventListener("click", (e) => busy(e.target, addUser));

show(hasStoredToken() ? "unlock" : "setup");
