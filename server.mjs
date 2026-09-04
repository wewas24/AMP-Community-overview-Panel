import { createServer } from "node:http";
import { createReadStream } from "node:fs";
import { mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import { createSocket } from "node:dgram";
import { connect, isIP } from "node:net";
import { extname, resolve, sep } from "node:path";

const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 3100);
const cookieSecure = process.env.COOKIE_SECURE !== "false";
const publicDirectory = resolve("public");
const dataDirectory = resolve("data");
const serverFile = resolve(dataDirectory, "servers.json");
const settingsFile = resolve(dataDirectory, "settings.json");
const adminsFile = resolve(dataDirectory, "admins.json");
const activityLogFile = resolve(dataDirectory, "activity-log.json");
const legacyAdminFile = resolve(dataDirectory, "admin.json");
const sessionLifetimeMs = 12 * 60 * 60 * 1000;
const loginWindowMs = 5 * 60 * 1000;
const maxLoginAttempts = 5;
const maxServers = 100;
const maxAdmins = 20;
const defaultRefreshIntervalSeconds = 10;
const defaultSiteTitle = "Meine Gameserver";
const gameStatusIntervalMs = 30_000;
const gameStatusTimeoutMs = 3_500;
const defaultTeamSpeakQueryPort = 10011;
const activityLogRetentionMs = 7 * 24 * 60 * 60 * 1000;
const activityLogCleanupIntervalMs = 60 * 60 * 1000;
const sessions = new Map();
const loginAttempts = new Map();
const availabilityByServer = new Map();
let availabilityRefresh = null;

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

function sendText(response, status, body, headers = {}) {
  setSecurityHeaders(response);
  response.writeHead(status, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", ...headers });
  response.end(body);
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

function activityEntryFromStored(input) {
  if (!input || typeof input !== "object") return null;
  const createdAt = typeof input.createdAt === "string" && Number.isFinite(Date.parse(input.createdAt)) ? input.createdAt : null;
  const username = validUsername(input.username) ? input.username : null;
  const action = cleanText(input.action, "", 100);
  if (!createdAt || !username || !action) return null;
  return {
    id: typeof input.id === "string" && /^[a-zA-Z0-9-]{8,80}$/.test(input.id) ? input.id : randomUUID(),
    createdAt,
    username,
    action,
    detail: cleanText(input.detail, "", 240)
  };
}

function retainedActivityEntries(input) {
  const oldestAllowed = Date.now() - activityLogRetentionMs;
  const records = Array.isArray(input) ? input : [];
  return records
    .map(activityEntryFromStored)
    .filter((entry) => entry && Date.parse(entry.createdAt) >= oldestAllowed)
    .sort((left, right) => Date.parse(right.createdAt) - Date.parse(left.createdAt));
}

async function getActivityLog() {
  const stored = await readJson(activityLogFile, []);
  const retained = retainedActivityEntries(stored);
  if (JSON.stringify(stored) !== JSON.stringify(retained)) await writeJson(activityLogFile, retained);
  return retained;
}

async function addActivityLog(username, action, detail = "") {
  const entries = await getActivityLog();
  entries.unshift({ id: randomUUID(), createdAt: new Date().toISOString(), username, action: cleanText(action, "Änderung", 100), detail: cleanText(detail, "", 240) });
  await writeJson(activityLogFile, entries);
}

function activityLogText(entries) {
  const plain = (value) => String(value || "").replace(/[\r\n]+/g, " ").trim();
  const lines = ["AMP Community Dashboard – Änderungsprotokoll", `Erstellt: ${new Date().toISOString()}`, "Aufbewahrung: Einträge werden nach sieben Tagen automatisch gelöscht.", ""];
  if (!entries.length) return `${lines.join("\n")}Keine Änderungen in den letzten sieben Tagen.\n`;
  entries.forEach((entry, index) => {
    lines.push(`${index + 1}. ${plain(entry.createdAt)} · ${plain(entry.username)}`);
    lines.push(`   ${plain(entry.action)}${entry.detail ? ` – ${plain(entry.detail)}` : ""}`);
  });
  return `${lines.join("\n")}\n`;
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

function normalizeSiteTitle(value, fallback = defaultSiteTitle) {
  return cleanText(value, fallback, 70);
}

function siteTitleFromInput(value, fallback = defaultSiteTitle) {
  const title = typeof value === "string" ? value.trim() : "";
  if (title.length < 3 || title.length > 70) {
    throw new Error("Der Webseitenname muss zwischen 3 und 70 Zeichen lang sein.");
  }
  return title;
}

function cleanGameHost(value) {
  const host = typeof value === "string" ? value.trim() : "";
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function validGameHost(host) {
  if (isIP(host)) return true;
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(host);
}

function validateGameConnection(hostValue, portValue) {
  const host = cleanGameHost(hostValue);
  const port = Number(portValue);
  if (!validGameHost(host) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Bitte eine gültige Spielserver-Adresse und einen Port zwischen 1 und 65.535 eingeben.");
  }
  return { host, port };
}

function normalizeServiceHint(value) {
  return value === "teamspeak" ? "teamspeak" : null;
}

function optionalPort(value) {
  if (value === undefined || value === null || String(value).trim() === "") return null;
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65535 ? port : null;
}

function connectionFromStored(input) {
  const connection = input?.connection && typeof input.connection === "object"
    ? input.connection
    : { host: input?.connectionHost, port: input?.connectionPort, serviceHint: input?.connectionHint, teamSpeakQueryPort: input?.teamSpeakQueryPort };
  const host = cleanGameHost(connection?.host);
  const hasPort = connection?.port !== undefined && connection?.port !== null && String(connection.port).trim() !== "";
  if (!host && !hasPort) return null;
  try {
    const saved = validateGameConnection(host, connection.port);
    const serviceHint = normalizeServiceHint(connection?.serviceHint);
    const teamSpeakQueryPort = optionalPort(connection?.teamSpeakQueryPort);
    return { ...saved, ...(serviceHint ? { serviceHint } : {}), ...(teamSpeakQueryPort ? { teamSpeakQueryPort } : {}) };
  } catch {
    return null;
  }
}

function connectionFromInput(input) {
  const connection = input?.connection && typeof input.connection === "object"
    ? input.connection
    : { host: input?.connectionHost, port: input?.connectionPort, serviceHint: input?.connectionHint, teamSpeakQueryPort: input?.teamSpeakQueryPort };
  const host = cleanGameHost(connection?.host);
  const hasPort = connection?.port !== undefined && connection?.port !== null && String(connection.port).trim() !== "";
  if (!host && !hasPort) return null;
  if (!host || !hasPort) {
    throw new Error("Für die automatische Statusprüfung werden Spielserver-Adresse und Port zusammen benötigt.");
  }
  const saved = validateGameConnection(host, connection.port);
  const serviceHint = normalizeServiceHint(connection?.serviceHint ?? input?.connectionHint);
  const queryPortValue = connection?.teamSpeakQueryPort ?? input?.teamSpeakQueryPort;
  const teamSpeakQueryPort = optionalPort(queryPortValue);
  if (queryPortValue !== undefined && queryPortValue !== null && String(queryPortValue).trim() !== "" && !teamSpeakQueryPort) {
    throw new Error("Der TeamSpeak-ServerQuery-Port muss zwischen 1 und 65.535 liegen.");
  }
  return { ...saved, ...(serviceHint ? { serviceHint } : {}), ...(teamSpeakQueryPort ? { teamSpeakQueryPort } : {}) };
}

function normalizeServer(input, index = 0) {
  const name = cleanText(input?.name, "Unbenannter Server", 60);
  const url = typeof input?.url === "string" ? input.url.trim() : "";
  const category = cleanText(input?.category, "Allgemein", 40);
  const description = cleanText(input?.description, "", 300);
  const visibility = ["visible", "maintenance", "hidden"].includes(input?.visibility) ? input.visibility : "visible";
  const connection = connectionFromStored(input);
  const sortOrder = Number.isInteger(input?.sortOrder) && input.sortOrder >= 0 ? input.sortOrder : index;
  return {
    id: typeof input?.id === "string" && /^[a-zA-Z0-9-]{8,80}$/.test(input.id) ? input.id : randomUUID(),
    name,
    url,
    category,
    description,
    visibility,
    status: "auto",
    connection,
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
  const connection = connectionFromInput(input);
  return {
    id: existing?.id || randomUUID(),
    name,
    url: validateCommunityUrl(input?.url),
    category,
    description,
    visibility,
    status: "auto",
    connection,
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
    availability: availabilityFor(server),
    sortOrder: server.sortOrder,
    createdAt: server.createdAt
  };
}

function adminServer(server) {
  return { ...publicServer(server), connection: server.connection ? { ...server.connection } : null };
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

function availabilityFor(server) {
  const cached = availabilityByServer.get(server.id);
  if (cached) return cached;
  if (!server.connection) {
    return { state: "unknown", checkedAt: null, detail: "Keine Spielserver-Adresse hinterlegt." };
  }
  return { state: "checking", checkedAt: null, detail: "Spielserver wird geprüft." };
}

function probeTcpConnection(connection) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    let done = false;
    const socket = connect({ host: connection.host, port: connection.port });
    const finish = (state, detail) => {
      if (done) return;
      done = true;
      clearTimeout(timeout);
      socket.destroy();
      resolve({ state, detail, checkedAt: new Date().toISOString(), latencyMs: Date.now() - startedAt });
    };
    const timeout = setTimeout(() => finish("unknown", "Der Spielport hat nicht rechtzeitig geantwortet."), gameStatusTimeoutMs);
    timeout.unref?.();
    socket.once("connect", () => finish("online", "Der Spielport antwortet."));
    socket.once("error", (error) => {
      if (error?.code === "ECONNREFUSED") return finish("offline", "Der Spielport ist geschlossen.");
      return finish("unknown", "Der Spielport konnte nicht eindeutig geprüft werden.");
    });
  });
}

function probeUdpConnection(connection, port, payload, acceptsResponse, successDetail) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    let done = false;
    let socket;
    try {
      socket = createSocket(isIP(connection.host) === 6 ? "udp6" : "udp4");
    } catch {
      return resolve({ state: "unknown", detail: "Die UDP-Abfrage konnte nicht vorbereitet werden.", checkedAt: new Date().toISOString() });
    }
    const finish = (state, detail) => {
      if (done) return;
      done = true;
      clearTimeout(timeout);
      socket.close();
      resolve({ state, detail, checkedAt: new Date().toISOString(), latencyMs: Date.now() - startedAt });
    };
    const timeout = setTimeout(() => finish("unknown", "Die UDP-Abfrage hat nicht geantwortet."), gameStatusTimeoutMs);
    timeout.unref?.();
    socket.once("message", (message) => {
      if (acceptsResponse(message)) finish("online", successDetail);
    });
    socket.once("error", () => finish("unknown", "Die UDP-Abfrage konnte nicht eindeutig geprüft werden."));
    socket.send(payload, port, connection.host, (error) => {
      if (error) finish("unknown", "Die UDP-Abfrage konnte nicht gesendet werden.");
    });
  });
}

function probeSteamQuery(connection, port) {
  const payload = Buffer.concat([Buffer.from([0xff, 0xff, 0xff, 0xff, 0x54]), Buffer.from("Source Engine Query\0")]);
  return probeUdpConnection(
    connection,
    port,
    payload,
    (message) => message.length >= 5 && (message.readInt32LE(0) === -1 || message.readInt32LE(0) === -2),
    "Der Server antwortet auf eine Steam-Abfrage."
  );
}

function probeTeamSpeakQuery(connection) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    let done = false;
    let selectedVoiceServer = false;
    let responseText = "";
    const socket = connect({ host: connection.host, port: connection.teamSpeakQueryPort || defaultTeamSpeakQueryPort });
    const finish = (state, detail) => {
      if (done) return;
      done = true;
      clearTimeout(timeout);
      socket.destroy();
      resolve({ state, detail, checkedAt: new Date().toISOString(), latencyMs: Date.now() - startedAt });
    };
    const timeout = setTimeout(() => finish("unknown", "Die TeamSpeak-Abfrage hat nicht geantwortet."), gameStatusTimeoutMs);
    timeout.unref?.();
    socket.on("data", (message) => {
      responseText += message.toString("utf8");
      if (!selectedVoiceServer && (responseText.includes("TS3") || responseText.includes("TeamSpeak"))) {
        selectedVoiceServer = true;
        responseText = "";
        socket.write(`use port=${connection.port}\n`);
        return;
      }
      if (!selectedVoiceServer) return;
      if (responseText.includes("error id=0 msg=ok")) {
        finish("online", "Der TeamSpeak-Voice-Server antwortet auf ServerQuery.");
      } else if (/error id=[1-9]\d*/.test(responseText)) {
        finish("offline", "Der TeamSpeak-ServerQuery-Dienst läuft, aber dieser Voice-Port ist nicht aktiv.");
      }
    });
    socket.once("error", () => finish("unknown", "Der TeamSpeak-Query-Port ist nicht erreichbar oder deaktiviert."));
  });
}

function isLikelyTeamSpeak(connection) {
  return connection.serviceHint === "teamspeak" || Boolean(connection.teamSpeakQueryPort) || (Number.isInteger(connection.port) && connection.port >= 9987 && connection.port <= 9999);
}

async function probeGameConnection(connection) {
  const checks = [probeTcpConnection(connection), probeSteamQuery(connection, connection.port)];
  if (connection.port < 65535) checks.push(probeSteamQuery(connection, connection.port + 1));
  if (isLikelyTeamSpeak(connection)) checks.push(probeTeamSpeakQuery(connection));
  const results = await Promise.all(checks);
  const online = results.find((result) => result.state === "online");
  if (online) return online;
  if (isLikelyTeamSpeak(connection)) {
    return { state: "unknown", detail: "Der TeamSpeak-Voice-Port antwortet nicht auf allgemeine Abfragen und ServerQuery ist nicht erreichbar.", checkedAt: new Date().toISOString() };
  }
  const tcpResult = results[0];
  return tcpResult.state === "offline"
    ? tcpResult
    : { state: "unknown", detail: "Der Server konnte mit den verfügbaren TCP- und UDP-Abfragen nicht eindeutig geprüft werden.", checkedAt: new Date().toISOString() };
}

async function refreshGameStatuses() {
  if (availabilityRefresh) return availabilityRefresh;
  availabilityRefresh = (async () => {
    const servers = await getServers();
    const activeIds = new Set(servers.map((server) => server.id));
    await Promise.all(servers.map(async (server) => {
      if (!server.connection) {
        availabilityByServer.set(server.id, { state: "unknown", checkedAt: null, detail: "Keine Spielserver-Adresse hinterlegt." });
        return;
      }
      availabilityByServer.set(server.id, { state: "checking", checkedAt: new Date().toISOString(), detail: "Spielserver wird geprüft." });
      availabilityByServer.set(server.id, await probeGameConnection(server.connection));
    }));
    for (const id of availabilityByServer.keys()) {
      if (!activeIds.has(id)) availabilityByServer.delete(id);
    }
  })();
  try {
    return await availabilityRefresh;
  } finally {
    availabilityRefresh = null;
  }
}

function triggerGameStatusRefresh() {
  void refreshGameStatuses().catch((error) => console.error("Spielserver-Status konnte nicht aktualisiert werden:", error));
}

async function getSettings() {
  const settings = await readJson(settingsFile, {});
  return {
    defaultRefreshIntervalSeconds: normalizeRefreshInterval(settings?.defaultRefreshIntervalSeconds),
    siteTitle: normalizeSiteTitle(settings?.siteTitle)
  };
}

function settingsFromInput(input, fallback) {
  return {
    defaultRefreshIntervalSeconds: input?.defaultRefreshIntervalSeconds === undefined
      ? fallback.defaultRefreshIntervalSeconds
      : refreshIntervalFromInput(input.defaultRefreshIntervalSeconds),
    siteTitle: input?.siteTitle === undefined
      ? fallback.siteTitle
      : siteTitleFromInput(input.siteTitle, fallback.siteTitle)
  };
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
  if (await readJson(settingsFile, null) === null) await writeJson(settingsFile, { defaultRefreshIntervalSeconds, siteTitle: defaultSiteTitle });
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

  if (request.method === "GET" && path === "/api/statuses") {
    const servers = (await getServers()).filter((server) => server.visibility !== "hidden");
    return sendJson(response, 200, {
      statuses: servers.map((server) => ({ id: server.id, availability: availabilityFor(server) }))
    });
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
    return sendJson(response, 200, { servers: (await getServers()).map(adminServer) });
  }

  if (request.method === "GET" && path === "/api/admins") {
    return sendJson(response, 200, { admins: (await getAdmins()).map(publicAdmin) });
  }

  if (request.method === "GET" && path === "/api/settings") {
    return sendJson(response, 200, await getSettings());
  }

  if (request.method === "GET" && path === "/api/activity-log") {
    return sendJson(response, 200, { entries: (await getActivityLog()).slice(0, 5) });
  }

  if (request.method === "GET" && path === "/api/activity-log/download") {
    const entries = await getActivityLog();
    return sendText(response, 200, activityLogText(entries), { "Content-Disposition": "attachment; filename=amp-community-aenderungsprotokoll.txt" });
  }

  if (request.method === "GET" && path === "/api/export") {
    return sendJson(response, 200, { version: 4, exportedAt: new Date().toISOString(), settings: await getSettings(), servers: (await getServers()).map(adminServer) }, { "Content-Disposition": "attachment; filename=amp-community-backup.json" });
  }

  if (request.method === "POST" && path === "/api/settings") {
    const body = await requestBody(request, 8_192);
    const previous = await getSettings();
    const settings = settingsFromInput(body, previous);
    await writeJson(settingsFile, settings);
    if (previous.siteTitle !== settings.siteTitle || previous.defaultRefreshIntervalSeconds !== settings.defaultRefreshIntervalSeconds) {
      await addActivityLog(session.username, "Seiteneinstellungen geändert", `Webseitenname: ${settings.siteTitle}; Aktualisierung: ${settings.defaultRefreshIntervalSeconds} Sekunden`);
    }
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
    await addActivityLog(session.username, "Server hinzugefügt", server.name);
    triggerGameStatusRefresh();
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
    const saved = await saveServers(ordered);
    await addActivityLog(session.username, "Serverreihenfolge geändert", `${saved.length} Server sortiert`);
    return sendJson(response, 200, { servers: saved.map(publicServer) });
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
      ? settingsFromInput(body.settings, await getSettings())
      : await getSettings();
    const saved = await saveServers(imported);
    await writeJson(settingsFile, settings);
    await addActivityLog(session.username, "Sicherung importiert", `${saved.length} Server übernommen`);
    triggerGameStatusRefresh();
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
    await addActivityLog(session.username, "Administratorkonto hinzugefügt", username);
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
    await addActivityLog(session.username, "Server bearbeitet", updated.name);
    triggerGameStatusRefresh();
    return sendJson(response, 200, { server: publicServer(updated) });
  }

  if (serverMatch && request.method === "DELETE") {
    const servers = await getServers();
    const removed = servers.find((server) => server.id === serverMatch[1]);
    const nextServers = servers.filter((server) => server.id !== serverMatch[1]);
    if (nextServers.length === servers.length) return sendError(response, 404, "Server nicht gefunden.");
    await saveServers(nextServers);
    await addActivityLog(session.username, "Server entfernt", removed.name);
    availabilityByServer.delete(serverMatch[1]);
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
    await addActivityLog(session.username, "Administratorkonto entfernt", username);
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
await getActivityLog();
triggerGameStatusRefresh();
const gameStatusTimer = setInterval(triggerGameStatusRefresh, gameStatusIntervalMs);
gameStatusTimer.unref?.();
const activityLogTimer = setInterval(() => {
  getActivityLog().catch((error) => console.error("Änderungsprotokoll konnte nicht bereinigt werden:", error));
}, activityLogCleanupIntervalMs);
activityLogTimer.unref?.();

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
