// Device Inventory server with login.
// Files kept next to this one:  data.json (inventory), users.json (accounts), sessions.json (signed-in browsers)
// Run:  node server.js   then open http://localhost:3000
// First visit: you'll be asked to create the admin account.
const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const PORT = process.env.PORT || 3000;
const SECURE = process.env.HTTPS === "1";            // set HTTPS=1 only when served over https
const SESSION_DAYS = 30;
const DATA = path.join(__dirname, "data.json"), USERS = path.join(__dirname, "users.json"), SESS = path.join(__dirname, "sessions.json");

if (!fs.existsSync(DATA)) fs.writeFileSync(DATA, JSON.stringify({ employees: [], devices: [] }, null, 2));
const readJSON = (f, d) => { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch { return d; } };
const writeJSON = (f, o) => { fs.writeFileSync(f + ".tmp", JSON.stringify(o, null, 2), { mode: 0o600 }); fs.renameSync(f + ".tmp", f); };
let users = readJSON(USERS, []);          // [{username, salt, hash, role}]
let sessions = readJSON(SESS, {});        // { sha256(token): {username, exp} }

/* ---------- passwords & sessions ---------- */
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString("hex");
function makeUser(username, pw, role) {
  const salt = crypto.randomBytes(16).toString("hex");
  return { username, salt, hash: hashPw(pw, salt), role };
}
function checkPw(u, pw) {
  return crypto.timingSafeEqual(Buffer.from(hashPw(pw, u.salt), "hex"), Buffer.from(u.hash, "hex"));
}
const sha = t => crypto.createHash("sha256").update(t).digest("hex");
function saveSessions() {
  const now = Date.now();
  for (const k in sessions) if (sessions[k].exp < now) delete sessions[k];
  writeJSON(SESS, sessions);
}
function startSession(username) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions[sha(token)] = { username, exp: Date.now() + SESSION_DAYS * 864e5 };
  saveSessions();
  return `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_DAYS * 86400}${SECURE ? "; Secure" : ""}`;
}
const cookieToken = req => (/(?:^|;\s*)sid=([a-f0-9]{64})/.exec(req.headers.cookie || "") || [])[1];
function currentUser(req) {
  const t = cookieToken(req); if (!t) return null;
  const s = sessions[sha(t)];
  if (!s || s.exp < Date.now()) return null;
  return users.find(u => u.username === s.username) || null;
}
const dropSessionsFor = name => { for (const k in sessions) if (sessions[k].username === name) delete sessions[k]; saveSessions(); };

/* ---------- brute-force limiter: 5 bad tries per IP, then 15 minutes locked ---------- */
const fails = {};
const locked = ip => { const f = fails[ip]; if (!f) return false; if (f.until && Date.now() > f.until) { delete fails[ip]; return false; } return f.n >= 5; };
const failed = ip => { const f = fails[ip] || (fails[ip] = { n: 0 }); f.n++; if (f.n >= 5) f.until = Date.now() + 15 * 60e3; };

/* ---------- pages ---------- */
const CSS = `:root{--bg:#eef2f5;--sf:#fff;--ink:#16212e;--mut:#5b6b7c;--line:#d5dde5;--ac:#0b6e6e;--dn:#b3261e}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#0f1720;--sf:#17212c;--ink:#e6edf3;--mut:#93a4b5;--line:#2a3846;--ac:#4cc2bd;--dn:#ff8f87}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--ink);font:15px/1.5 "Public Sans",system-ui,-apple-system,"Segoe UI",sans-serif;padding:20px}
.box{background:var(--sf);border:1px solid var(--line);border-radius:12px;padding:24px;width:min(420px,100%)}.wide{width:min(640px,100%)}
h1{font-size:22px;margin:0 0 4px}p{color:var(--mut);margin:0 0 16px}label{display:block;font-size:13px;font-weight:600;color:var(--mut);margin-top:12px}
input,select{width:100%;margin-top:4px;padding:9px 10px;border:1px solid var(--line);border-radius:8px;background:var(--sf);color:var(--ink);font:inherit}
button{margin-top:16px;background:var(--ac);color:var(--sf);border:0;border-radius:8px;padding:9px 16px;font:inherit;font-weight:600;cursor:pointer}
button.sec{background:none;color:var(--dn);border:1px solid var(--dn);margin:0;padding:4px 10px}
a{color:var(--ac)}#err{color:var(--dn);min-height:22px;margin-top:10px;font-size:14px}
table{width:100%;border-collapse:collapse;margin:8px 0 4px}td,th{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line)}th{font-size:13px;color:var(--mut)}
:focus-visible{outline:2px solid var(--ac);outline-offset:2px}`;
const shell = (title, body, script) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>${CSS}</style></head><body>${body}<script>${script}</script></body></html>`;

const authScript = (url, needConfirm) => `
const f=document.getElementById("f"),err=document.getElementById("err");
f.addEventListener("submit",async e=>{e.preventDefault();err.textContent="";
  const username=f.username.value.trim(),password=f.password.value;
  ${needConfirm ? `if(password!==f.confirm.value){err.textContent="Passwords don’t match.";return}` : ""}
  try{const r=await fetch("${url}",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username,password})});
    if(r.ok){location="/";return}err.textContent=(await r.text())||"Something went wrong."}catch(x){err.textContent="Can’t reach the server."}});`;

const loginPage = shell("Sign in", `<form id="f" class="box"><h1>Device Inventory</h1><p>Sign in to continue.</p>
<label>Username<input name="username" autocomplete="username" autofocus required></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required></label>
<div id="err" role="alert"></div><button>Sign in</button></form>`, authScript("/login", false));

const setupPage = shell("First-time setup", `<form id="f" class="box"><h1>Create the admin account</h1><p>This is the first run, so no accounts exist yet. The admin can add everyone else.</p>
<label>Username<input name="username" autocomplete="username" autofocus required></label>
<label>Password (8+ characters)<input name="password" type="password" autocomplete="new-password" minlength="8" required></label>
<label>Confirm password<input name="confirm" type="password" autocomplete="new-password" minlength="8" required></label>
<div id="err" role="alert"></div><button>Create admin</button></form>`, authScript("/setup", true));

const usersPage = shell("Users", `<div class="box wide"><h1>Users</h1><p><a href="/">Back to inventory</a></p>
<table><thead><tr><th>Username</th><th>Role</th><th></th></tr></thead><tbody id="list"></tbody></table>
<form id="f"><h1 style="font-size:17px;margin-top:20px">Add a user or reset a password</h1>
<label>Username<input name="username" required></label>
<label>Password (8+ characters)<input name="password" type="password" autocomplete="new-password" minlength="8" required></label>
<label>Role<select name="role"><option value="user">User</option><option value="admin">Admin</option></select></label>
<div id="err" role="alert"></div><button>Save user</button></form></div>`, `
const list=document.getElementById("list"),f=document.getElementById("f"),err=document.getElementById("err");
async function load(){const r=await fetch("/api/users");if(!r.ok){location="/";return}
  const us=await r.json();list.textContent="";
  for(const u of us){const tr=list.insertRow();tr.insertCell().textContent=u.username;tr.insertCell().textContent=u.role;
    const b=document.createElement("button");b.className="sec";b.type="button";b.textContent="Delete";
    b.onclick=async()=>{if(!confirm("Delete "+u.username+"?"))return;
      const d=await fetch("/api/users?name="+encodeURIComponent(u.username),{method:"DELETE"});
      if(!d.ok)err.textContent=await d.text();else{err.textContent="";load()}};
    tr.insertCell().append(b)}}
f.addEventListener("submit",async e=>{e.preventDefault();err.textContent="";
  const r=await fetch("/api/users",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({username:f.username.value.trim(),password:f.password.value,role:f.role.value})});
  if(r.ok){f.reset();load()}else err.textContent=await r.text()});
load();`);

/* ---------- server ---------- */
const readBody = (req, limit) => new Promise((ok, bad) => {
  let b = "";
  req.on("data", c => { b += c; if (b.length > limit) { req.destroy(); bad(new Error("too big")); } });
  req.on("end", () => ok(b)); req.on("error", bad);
});
const validName = n => typeof n === "string" && /^[A-Za-z0-9._@-]{2,64}$/.test(n);

http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://x"), p = u.pathname, ip = req.socket.remoteAddress;
  const send = (code, type, txt, h) => {
    res.writeHead(code, { "Content-Type": type, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", ...h });
    res.end(txt);
  };
  const html = (code, t) => send(code, "text/html; charset=utf-8", t);
  const text = (code, t, h) => send(code, "text/plain; charset=utf-8", t, h);
  const json = (code, o) => send(code, "application/json", JSON.stringify(o));
  const redirect = to => { res.writeHead(302, { Location: to }); res.end(); };
  const isJson = () => (req.headers["content-type"] || "").startsWith("application/json");
  try {
    /* first run: no accounts yet */
    if (!users.length) {
      if (p === "/setup" && req.method === "GET") return html(200, setupPage);
      if (p === "/setup" && req.method === "POST" && isJson()) {
        const { username, password } = JSON.parse(await readBody(req, 1e4));
        if (!validName(username)) return text(400, "Username must be 2-64 characters: letters, numbers, . _ @ -");
        if (typeof password !== "string" || password.length < 8) return text(400, "Password must be at least 8 characters.");
        users.push(makeUser(username, password, "admin")); writeJSON(USERS, users);
        return text(200, "ok", { "Set-Cookie": startSession(username) });
      }
      return p.startsWith("/api/") ? text(401, "Not set up") : redirect("/setup");
    }

    /* sign in / out */
    if (p === "/login" && req.method === "GET") return currentUser(req) ? redirect("/") : html(200, loginPage);
    if (p === "/login" && req.method === "POST" && isJson()) {
      if (locked(ip)) return text(429, "Too many failed attempts. Try again in 15 minutes.");
      const { username, password } = JSON.parse(await readBody(req, 1e4));
      const user = users.find(x => x.username.toLowerCase() === String(username || "").toLowerCase());
      if (!user || typeof password !== "string" || !checkPw(user, password)) { failed(ip); return text(401, "Wrong username or password."); }
      delete fails[ip];
      return text(200, "ok", { "Set-Cookie": startSession(user.username) });
    }
    if (p === "/logout" && req.method === "POST") {
      const t = cookieToken(req); if (t) { delete sessions[sha(t)]; saveSessions(); }
      return text(200, "ok", { "Set-Cookie": "sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" });
    }

    /* everything below requires a signed-in user */
    const me = currentUser(req);
    if (!me) return p.startsWith("/api/") ? text(401, "Sign in required") : redirect("/login");

    if (p === "/api/me") return json(200, { username: me.username, role: me.role });

    if (p === "/api/data") {
      if (req.method === "GET") return send(200, "application/json", fs.readFileSync(DATA));
      if (req.method === "POST") {
        if (!isJson()) return text(400, "bad request");
        const j = JSON.parse(await readBody(req, 5e7));
        if (!Array.isArray(j.employees) || !Array.isArray(j.devices)) return text(400, "bad request");
        writeJSON(DATA, j);
        return text(200, "ok");
      }
    }

    /* user management (admins only) */
    if (p === "/users" && req.method === "GET") return me.role === "admin" ? html(200, usersPage) : redirect("/");
    if (p === "/api/users") {
      if (me.role !== "admin") return text(403, "Admins only");
      if (req.method === "GET") return json(200, users.map(({ username, role }) => ({ username, role })));
      if (req.method === "POST" && isJson()) {
        const { username, password, role } = JSON.parse(await readBody(req, 1e4));
        if (!validName(username)) return text(400, "Username must be 2-64 characters: letters, numbers, . _ @ -");
        if (typeof password !== "string" || password.length < 8) return text(400, "Password must be at least 8 characters.");
        const r = role === "admin" ? "admin" : "user", i = users.findIndex(x => x.username.toLowerCase() === username.toLowerCase());
        if (i >= 0) {
          if (users[i].role === "admin" && r !== "admin" && users.filter(x => x.role === "admin").length === 1) return text(400, "There must be at least one admin.");
          users[i] = makeUser(users[i].username, password, r); dropSessionsFor(users[i].username);
          if (users[i].username === me.username) { writeJSON(USERS, users); return text(200, "ok", { "Set-Cookie": startSession(me.username) }); }
        } else users.push(makeUser(username, password, r));
        writeJSON(USERS, users);
        return text(200, "ok");
      }
      if (req.method === "DELETE") {
        const name = u.searchParams.get("name"), i = users.findIndex(x => x.username === name);
        if (i < 0) return text(404, "No such user");
        if (name === me.username) return text(400, "You can’t delete your own account.");
        users.splice(i, 1); writeJSON(USERS, users); dropSessionsFor(name);
        return text(200, "ok");
      }
    }

    if (p === "/" || p === "/index1.html") return html(200, fs.readFileSync(path.join(__dirname, "index1.html")));
    text(404, "Not found");
  } catch (e) {
    try { text(400, "bad request"); } catch {}
  }
}).listen(PORT, () => console.log("Device Inventory running at http://localhost:" + PORT));
