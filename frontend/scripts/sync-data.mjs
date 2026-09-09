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

const packetDirectory = path.join(projectDirectory, "artifacts", "packet_flow");
const browserModel = await readFile(path.join(packetDirectory, "browser_model.json"));
const sample = await readFile(path.join(packetDirectory, "sample_capture.pcap"));
const model = JSON.parse(browserModel);
if (createHash("sha256").update(sample).digest("hex") !== model.sample_sha256) throw new Error("Bundled capture does not match browser model manifest");
await writeFile(path.join(destinationDirectory, "browser-model.json"), browserModel);
await writeFile(path.join(destinationDirectory, "sample-capture.json"), JSON.stringify({base64: sample.toString("base64")}));
