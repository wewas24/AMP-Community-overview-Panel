import { createServer } from "node:http";
import { createReadStream } from "node:fs";
import { mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import { extname, resolve, sep } from "node:path";

const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 3100);
const cookieSecure = process.env.COOKIE_SECURE !== "false";
const publicDirectory = resolve("public");
const dataDirectory = resolve("data");
const serverFile = resolve(dataDirectory, "servers.json");
const settingsFile = resolve(dataDirectory, "settings.json");
const adminsFile = resolve(dataDirectory, "admins.json");
const legacyAdminFile = resolve(dataDirectory, "admin.json");
const sessionLifetimeMs = 12 * 60 * 60 * 1000;
const loginWindowMs = 5 * 60 * 1000;
const maxLoginAttempts = 5;
const maxServers = 100;
const maxAdmins = 20;
const defaultRefreshIntervalSeconds = 10;
const sessions = new Map();
const loginAttempts = new Map();

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml"
};

function setSecurityHeaders(response) {
  response.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-src https:; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'");
  response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "SAMEORIGIN");
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
}

function sendJson(response, status, body, headers = {}) {
  setSecurityHeaders(response);
  response.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  response.end(JSON.stringify(body));
}

function sendError(response, status, message) {
  sendJson(response, status, { error: message });
}

async function readJson(filePath, fallback) {
  try {
    return JSON.parse(await readFile(filePath, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return fallback;
    throw error;
  }
}

async function writeJson(filePath, value) {
  const temporaryFile = `${filePath}.${randomUUID()}.tmp`;
  await writeFile(temporaryFile, JSON.stringify(value, null, 2), { mode: 0o600 });
  await rename(temporaryFile, filePath);
}

function cleanText(value, fallback, maximum) {
  const text = typeof value === "string" ? value.trim() : "";
  return (text || fallback).slice(0, maximum);
}

function validUsername(value) {
  return typeof value === "string" && /^[a-zA-Z0-9_.-]{3,32}$/.test(value);
}

function publicAdmin(admin) {
  return { username: admin.username, createdAt: admin.createdAt };
}

function passwordRecord(password) {
  const salt = randomBytes(16).toString("base64url");
  return { salt, hash: scryptSync(password, salt, 64).toString("base64url") };
}

function validPassword(value) {
  return typeof value === "string" && value.length >= 12 && value.length <= 512;
}

function normalizeRefreshInterval(value, fallback = defaultRefreshIntervalSeconds) {
  const seconds = Number(value);
  return Number.isInteger(seconds) && seconds >= 5 && seconds <= 3600 ? seconds : fallback;
}

function refreshIntervalFromInput(value) {
  const seconds = Number(value);
  if (!Number.isInteger(seconds) || seconds < 5 || seconds > 3600) {
    throw new Error("Die Aktualisierungszeit muss zwischen 5 und 3.600 Sekunden liegen.");
  }
  return seconds;
}

function normalizeServer(input, index = 0) {
  const name = cleanText(input?.name, "Unbenannter Server", 60);
  const url = typeof input?.url === "string" ? input.url.trim() : "";
  const category = cleanText(input?.category, "Allgemein", 40);
  const description = cleanText(input?.description, "", 300);
  const visibility = ["visible", "maintenance", "hidden"].includes(input?.visibility) ? input.visibility : "visible";
  const status = ["auto", "online", "offline"].includes(input?.status) ? input.status : "auto";
  const sortOrder = Number.isInteger(input?.sortOrder) && input.sortOrder >= 0 ? input.sortOrder : index;
  return {
    id: typeof input?.id === "string" && /^[a-zA-Z0-9-]{8,80}$/.test(input.id) ? input.id : randomUUID(),
    name,
    url,
    category,
    description,
    visibility,
    status,
    sortOrder,
    createdAt: typeof input?.createdAt === "string" ? input.createdAt : new Date().toISOString()
  };
}

function validateCommunityUrl(value) {
  const url = typeof value === "string" ? value.trim() : "";
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("Bitte eine gültige Community-URL eingeben.");
  }
  if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password) {
    throw new Error("Bitte eine öffentliche HTTPS-Adresse deines AMP-Servers oder seiner Community-Seite eingeben.");
  }
  return parsed.toString();
}

function serverFromInput(input, existing, sortOrder) {
  const name = cleanText(input?.name, "", 60);
  if (!name) throw new Error("Der Servername muss 1–60 Zeichen lang sein.");
  const category = cleanText(input?.category, "Allgemein", 40);
  const description = cleanText(input?.description, "", 300);
  const visibility = ["visible", "maintenance", "hidden"].includes(input?.visibility) ? input.visibility : "visible";
  const status = ["auto", "online", "offline"].includes(input?.status) ? input.status : "auto";
  return {
    id: existing?.id || randomUUID(),
    name,
    url: validateCommunityUrl(input?.url),
    category,
    description,
    visibility,
    status,
    sortOrder,
    createdAt: existing?.createdAt || new Date().toISOString()
  };
}

function publicServer(server) {
  return {
    id: server.id,
    name: server.name,
    url: server.url,
    category: server.category,
    description: server.description,
    visibility: server.visibility,
    status: server.status,
    sortOrder: server.sortOrder,
    createdAt: server.createdAt
  };
}

async function getServers() {
  const raw = await readJson(serverFile, []);
  const list = Array.isArray(raw) ? raw : [];
  const ids = new Set();
  const urls = new Set();
  const servers = [];
  for (const [index, input] of list.entries()) {
    const server = normalizeServer(input, index);
    try {
      server.url = validateCommunityUrl(server.url);
    } catch {
      continue;
    }
    if (ids.has(server.id)) server.id = randomUUID();
    if (urls.has(server.url)) continue;
    ids.add(server.id);
    urls.add(server.url);
    servers.push(server);
  }
  servers.sort((left, right) => left.sortOrder - right.sortOrder || left.createdAt.localeCompare(right.createdAt));
  servers.forEach((server, index) => { server.sortOrder = index; });
  return servers;
}

async function saveServers(servers) {
  const ordered = servers.map((server, index) => ({ ...server, sortOrder: index }));
  await writeJson(serverFile, ordered);
  return ordered;
}

async function getSettings() {
  const settings = await readJson(settingsFile, {});
  return { defaultRefreshIntervalSeconds: normalizeRefreshInterval(settings?.defaultRefreshIntervalSeconds) };
}

async function getAdmins() {
  const saved = await readJson(adminsFile, null);
  if (Array.isArray(saved)) return saved.filter((admin) => validUsername(admin?.username) && typeof admin?.salt === "string" && typeof admin?.hash === "string");
  const legacy = await readJson(legacyAdminFile, null);
  if (legacy && validUsername(legacy.username) && typeof legacy.salt === "string" && typeof legacy.hash === "string") {
    const migrated = [{ username: legacy.username, salt: legacy.salt, hash: legacy.hash, createdAt: legacy.createdAt || new Date().toISOString() }];
    await writeJson(adminsFile, migrated);
    return migrated;
  }
  return [];
}

async function ensureDataFiles() {
  await mkdir(dataDirectory, { recursive: true });
  if (await readJson(serverFile, null) === null) await writeJson(serverFile, []);
  if (await readJson(settingsFile, null) === null) await writeJson(settingsFile, { defaultRefreshIntervalSeconds });
}

function getCookie(request, name) {
  const cookies = request.headers.cookie?.split(";") ?? [];
  for (const item of cookies) {
    const [key, ...value] = item.trim().split("=");
    if (key === name) return value.join("=");
  }
  return null;
}

function getSession(request) {
  const token = getCookie(request, "amp_dashboard_session");
  if (!token) return null;
  const session = sessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { token, ...session };
}

function createSession(username) {
  const token = randomBytes(32).toString("base64url");
  sessions.set(token, { username, expiresAt: Date.now() + sessionLifetimeMs });
  return token;
}

function sessionCookie(token, expiresInSeconds = sessionLifetimeMs / 1000) {
  return [
    `amp_dashboard_session=${token}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${Math.floor(expiresInSeconds)}`,
    cookieSecure ? "Secure" : ""
  ].filter(Boolean).join("; ");
}

function isSameOrigin(request) {
  const origin = request.headers.origin;
  if (!origin) return false;
  const forwardedProtocol = request.headers["x-forwarded-proto"]?.split(",")[0]?.trim();
  const protocol = forwardedProtocol || (cookieSecure ? "https" : "http");
  return origin === `${protocol}://${request.headers.host}`;
}

function requestIp(request) {
  const forwarded = request.headers["x-forwarded-for"];
  if (typeof forwarded === "string") return forwarded.split(",")[0].trim();
  return request.socket.remoteAddress || "unknown";
}

function loginAllowed(ip) {
  const now = Date.now();
  const attempts = (loginAttempts.get(ip) || []).filter((time) => time > now - loginWindowMs);
  loginAttempts.set(ip, attempts);
  return attempts.length < maxLoginAttempts;
}

function recordFailedLogin(ip) {
  const now = Date.now();
  const attempts = (loginAttempts.get(ip) || []).filter((time) => time > now - loginWindowMs);
  attempts.push(now);
  loginAttempts.set(ip, attempts);
}

async function requestBody(request, maximum = 128_000) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maximum) throw new Error("Die Anfrage ist zu groß.");
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error("Ungültige Eingabe.");
  }
}

async function requireAdmin(request, response) {
  const session = getSession(request);
  if (!session) {
    sendError(response, 401, "Bitte zuerst anmelden.");
    return null;
  }
  const admins = await getAdmins();
  if (!admins.some((admin) => admin.username === session.username)) {
    sessions.delete(session.token);
    sendError(response, 401, "Dieses Administratorkonto existiert nicht mehr.");
    return null;
  }
  return session;
}

async function handleApi(request, response, url) {
  const path = url.pathname;

  if (request.method === "GET" && path === "/api/servers") {
    const [servers, settings] = await Promise.all([getServers(), getSettings()]);
    return sendJson(response, 200, { servers: servers.filter((server) => server.visibility !== "hidden").map(publicServer), ...settings });
  }

  if (request.method === "GET" && path === "/api/session") {
    const session = getSession(request);
    return sendJson(response, 200, { authenticated: Boolean(session), username: session?.username ?? null });
  }

  if (request.method === "POST" && path === "/api/login") {
    const ip = requestIp(request);
    if (!loginAllowed(ip)) return sendError(response, 429, "Zu viele Anmeldeversuche. Bitte in fünf Minuten erneut versuchen.");
    const body = await requestBody(request, 8_192);
    const username = typeof body?.username === "string" ? body.username.trim() : "";
    const password = typeof body?.password === "string" ? body.password : "";
    const admins = await getAdmins();
    const admin = admins.find((item) => item.username === username);
    const suppliedHash = admin ? scryptSync(password, admin.salt, 64).toString("base64url") : "";
    const valid = Boolean(admin && suppliedHash.length === admin.hash.length && timingSafeEqual(Buffer.from(suppliedHash), Buffer.from(admin.hash)));
    if (!valid) {
      recordFailedLogin(ip);
      return sendError(response, 401, "Benutzername oder Passwort ist nicht korrekt.");
    }
    loginAttempts.delete(ip);
    const token = createSession(admin.username);
    return sendJson(response, 200, { username: admin.username }, { "Set-Cookie": sessionCookie(token) });
  }

  if (request.method === "POST" && path === "/api/logout") {
    const session = await requireAdmin(request, response);
    if (!session) return;
    if (!isSameOrigin(request)) return sendError(response, 403, "Ungültige Anfragequelle.");
    sessions.delete(session.token);
    return sendJson(response, 200, { ok: true }, { "Set-Cookie": sessionCookie("", 0) });
  }

  const session = await requireAdmin(request, response);
  if (!session) return;
  if (request.method !== "GET" && !isSameOrigin(request)) return sendError(response, 403, "Ungültige Anfragequelle.");

  if (request.method === "GET" && path === "/api/admin/servers") {
    return sendJson(response, 200, { servers: (await getServers()).map(publicServer) });
  }

  if (request.method === "GET" && path === "/api/admins") {
    return sendJson(response, 200, { admins: (await getAdmins()).map(publicAdmin) });
  }

  if (request.method === "GET" && path === "/api/settings") {
    return sendJson(response, 200, await getSettings());
  }

  if (request.method === "GET" && path === "/api/export") {
    return sendJson(response, 200, { version: 3, exportedAt: new Date().toISOString(), settings: await getSettings(), servers: (await getServers()).map(publicServer) }, { "Content-Disposition": "attachment; filename=amp-community-backup.json" });
  }

  if (request.method === "POST" && path === "/api/settings") {
    const body = await requestBody(request, 8_192);
    const settings = { defaultRefreshIntervalSeconds: refreshIntervalFromInput(body?.defaultRefreshIntervalSeconds) };
    await writeJson(settingsFile, settings);
    return sendJson(response, 200, settings);
  }

  if (request.method === "POST" && path === "/api/servers") {
    const input = await requestBody(request);
    const servers = await getServers();
    if (servers.length >= maxServers) return sendError(response, 400, `Es können maximal ${maxServers} Server gespeichert werden.`);
    const server = serverFromInput(input, null, servers.length);
    if (servers.some((item) => item.url === server.url)) return sendError(response, 409, "Diese Community-Seite ist bereits gespeichert.");
    servers.push(server);
    await saveServers(servers);
    return sendJson(response, 201, { server: publicServer(server) });
  }

  if (request.method === "POST" && path === "/api/servers/order") {
    const body = await requestBody(request);
    const ids = Array.isArray(body?.ids) ? body.ids : [];
    const servers = await getServers();
    if (ids.length !== servers.length || new Set(ids).size !== ids.length || !ids.every((id) => typeof id === "string" && servers.some((server) => server.id === id))) {
      return sendError(response, 400, "Die Sortierung ist ungültig.");
    }
    const byId = new Map(servers.map((server) => [server.id, server]));
    const ordered = ids.map((id) => byId.get(id));
    await saveServers(ordered);
    return sendJson(response, 200, { servers: ordered.map(publicServer) });
  }

  if (request.method === "POST" && path === "/api/import") {
    const body = await requestBody(request);
    const incoming = Array.isArray(body?.servers) ? body.servers : null;
    if (!incoming) return sendError(response, 400, "Die Sicherungsdatei enthält keine Serverliste.");
    if (incoming.length > maxServers) return sendError(response, 400, `Es können maximal ${maxServers} Server importiert werden.`);
    const urls = new Set();
    const ids = new Set();
    const imported = incoming.map((input, index) => {
      const server = serverFromInput(input, input, index);
      if (urls.has(server.url)) throw new Error("Die Sicherung enthält denselben Community-Link mehrmals.");
      if (ids.has(server.id)) server.id = randomUUID();
      urls.add(server.url);
      ids.add(server.id);
      return server;
    });
    const settings = body?.settings && typeof body.settings === "object"
      ? { defaultRefreshIntervalSeconds: refreshIntervalFromInput(body.settings.defaultRefreshIntervalSeconds) }
      : await getSettings();
    const saved = await saveServers(imported);
    await writeJson(settingsFile, settings);
    return sendJson(response, 200, { servers: saved.map(publicServer), ...settings });
  }

  if (request.method === "POST" && path === "/api/admins") {
    const body = await requestBody(request, 8_192);
    const username = typeof body?.username === "string" ? body.username.trim() : "";
    const password = body?.password;
    if (!validUsername(username)) return sendError(response, 400, "Der Benutzername muss 3–32 Zeichen lang sein und darf nur Buchstaben, Zahlen, Punkt, Bindestrich oder Unterstrich enthalten.");
    if (!validPassword(password)) return sendError(response, 400, "Das Passwort muss mindestens 12 Zeichen lang sein.");
    const admins = await getAdmins();
    if (admins.length >= maxAdmins) return sendError(response, 400, `Es können maximal ${maxAdmins} Administratorkonten angelegt werden.`);
    if (admins.some((admin) => admin.username === username)) return sendError(response, 409, "Dieser Benutzername ist bereits vergeben.");
    const record = { username, ...passwordRecord(password), createdAt: new Date().toISOString() };
    admins.push(record);
    await writeJson(adminsFile, admins);
    return sendJson(response, 201, { admin: publicAdmin(record) });
  }

  const serverMatch = path.match(/^\/api\/servers\/([a-zA-Z0-9-]+)$/);
  if (serverMatch && request.method === "PATCH") {
    const servers = await getServers();
    const index = servers.findIndex((server) => server.id === serverMatch[1]);
    if (index < 0) return sendError(response, 404, "Server nicht gefunden.");
    const updated = serverFromInput(await requestBody(request), servers[index], index);
    if (servers.some((server) => server.id !== updated.id && server.url === updated.url)) return sendError(response, 409, "Diese Community-Seite ist bereits gespeichert.");
    servers[index] = updated;
    await saveServers(servers);
    return sendJson(response, 200, { server: publicServer(updated) });
  }

  if (serverMatch && request.method === "DELETE") {
    const servers = await getServers();
    const nextServers = servers.filter((server) => server.id !== serverMatch[1]);
    if (nextServers.length === servers.length) return sendError(response, 404, "Server nicht gefunden.");
    await saveServers(nextServers);
    return sendJson(response, 200, { ok: true });
  }

  const adminMatch = path.match(/^\/api\/admins\/([a-zA-Z0-9_.-]+)$/);
  if (adminMatch && request.method === "DELETE") {
    const username = decodeURIComponent(adminMatch[1]);
    const admins = await getAdmins();
    if (username === session.username) return sendError(response, 400, "Das eigene Administratorkonto kann nicht gelöscht werden.");
    if (admins.length <= 1) return sendError(response, 400, "Das letzte Administratorkonto kann nicht gelöscht werden.");
    const nextAdmins = admins.filter((admin) => admin.username !== username);
    if (nextAdmins.length === admins.length) return sendError(response, 404, "Administratorkonto nicht gefunden.");
    await writeJson(adminsFile, nextAdmins);
    for (const [token, activeSession] of sessions) if (activeSession.username === username) sessions.delete(token);
    return sendJson(response, 200, { ok: true });
  }

  return sendError(response, 404, "Nicht gefunden.");
}

async function handleStatic(request, response, url) {
  const requested = url.pathname === "/" ? "/index.html" : url.pathname;
  const filePath = resolve(publicDirectory, `.${requested}`);
  if (!filePath.startsWith(`${publicDirectory}${sep}`) && filePath !== resolve(publicDirectory, "index.html")) return sendError(response, 403, "Nicht erlaubt.");
  try {
    const file = await stat(filePath);
    if (!file.isFile()) return sendError(response, 404, "Nicht gefunden.");
    setSecurityHeaders(response);
    response.writeHead(200, { "Content-Type": contentTypes[extname(filePath)] || "application/octet-stream", "Cache-Control": "no-cache" });
    if (request.method === "HEAD") return response.end();
    createReadStream(filePath).pipe(response);
  } catch {
    sendError(response, 404, "Nicht gefunden.");
  }
}

await ensureDataFiles();

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    if (url.pathname.startsWith("/api/")) await handleApi(request, response, url);
    else if (request.method === "GET" || request.method === "HEAD") await handleStatic(request, response, url);
    else sendError(response, 405, "Methode nicht erlaubt.");
  } catch (error) {
    console.error(error);
    if (!response.headersSent) sendError(response, 400, error.message || "Ungültige Anfrage.");
    else response.end();
  }
});

server.listen(port, host, () => {
  console.log(`AMP Community Dashboard läuft auf http://${host}:${port}`);
});
