import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { randomBytes, scryptSync } from "node:crypto";

const dataDirectory = resolve("data");
const adminsFile = resolve(dataDirectory, "admins.json");
const legacyAdminFile = resolve(dataDirectory, "admin.json");

function validateUsername(value) {
  return typeof value === "string" && /^[a-zA-Z0-9_.-]{3,32}$/.test(value);
}

function passwordHash(password) {
  const salt = randomBytes(16).toString("base64url");
  const hash = scryptSync(password, salt, 64).toString("base64url");
  return { salt, hash };
}

async function askPassword(question) {
  if (!input.isTTY) throw new Error("Für die sichere Passworteingabe wird ein Terminal benötigt.");

  return new Promise((resolvePassword, rejectPassword) => {
    let password = "";
    let finished = false;

    const finish = () => {
      if (finished) return;
      finished = true;
      input.setRawMode(false);
      input.pause();
      input.removeListener("data", onData);
      output.write("\n");
      resolvePassword(password);
    };

    const onData = (chunk) => {
      const characters = chunk.toString("utf8");
      for (const character of characters) {
        if (character === "\u0003") {
          rejectPassword(new Error("Abgebrochen."));
          return;
        }
        if (character === "\r" || character === "\n") {
          finish();
          return;
        }
        if (character === "\u007f" || character === "\b") {
          password = password.slice(0, -1);
          continue;
        }
        password += character;
      }
    };

    output.write(question);
    input.setRawMode(true);
    input.resume();
    input.on("data", onData);
  });
}

async function hasExistingAdmin() {
  try {
    const records = JSON.parse(await readFile(adminsFile, "utf8"));
    if (Array.isArray(records) && records.some((record) => record && record.username && record.hash && record.salt)) return true;
  } catch {
    // Die neue Mehrbenutzer-Datei existiert beim ersten Start noch nicht.
  }
  try {
    const record = JSON.parse(await readFile(legacyAdminFile, "utf8"));
    return Boolean(record && record.username && record.hash && record.salt);
  } catch {
    return false;
  }
}

async function main() {
  if (await hasExistingAdmin()) {
    throw new Error("Es gibt bereits ein Administratorkonto. Es wurde nichts geändert.");
  }

  const readline = createInterface({ input, output });
  const suppliedUsername = process.argv[2]?.trim();
  const username = suppliedUsername || (await readline.question("Admin-Benutzername: ")).trim();
  readline.close();

  if (!validateUsername(username)) {
    throw new Error("Der Benutzername muss 3–32 Zeichen lang sein und darf nur Buchstaben, Zahlen, Punkt, Bindestrich oder Unterstrich enthalten.");
  }

  const password = await askPassword("Passwort (mindestens 12 Zeichen): ");
  const confirmation = await askPassword("Passwort wiederholen: ");
  if (password.length < 12) throw new Error("Das Passwort muss mindestens 12 Zeichen lang sein.");
  if (password !== confirmation) throw new Error("Die Passwörter stimmen nicht überein.");

  const { salt, hash } = passwordHash(password);
  await mkdir(dirname(adminsFile), { recursive: true });
  await writeFile(adminsFile, JSON.stringify([{ username, salt, hash, createdAt: new Date().toISOString() }], null, 2), { mode: 0o600, flag: "wx" });
  console.log(`Administratorkonto „${username}“ wurde erstellt.`);
}

main().catch((error) => {
  console.error(`Fehler: ${error.message}`);
  process.exitCode = 1;
});
