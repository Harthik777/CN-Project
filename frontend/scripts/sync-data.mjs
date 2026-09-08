import { readFile, writeFile, mkdir, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const frontendDirectory = path.resolve(scriptDirectory, "..");
const projectDirectory = path.resolve(frontendDirectory, "..");
const source = path.join(projectDirectory, "assets", "dashboard_data.json");
const destinationDirectory = path.join(frontendDirectory, "src", "data");
const destination = path.join(destinationDirectory, "dashboard-data.json");

await stat(source);
await mkdir(destinationDirectory, { recursive: true });
const bytes = await readFile(source);
const payload = JSON.parse(bytes.toString("utf8"));
payload.snapshot_sha256 = createHash("sha256").update(bytes).digest("hex");
await writeFile(destination, JSON.stringify(payload));
console.log(`[frontend] synced ${path.relative(projectDirectory, source)}`);
