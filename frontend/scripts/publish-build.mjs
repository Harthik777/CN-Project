import { copyFile, stat, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const frontendDirectory = path.resolve(scriptDirectory, "..");
const projectDirectory = path.resolve(frontendDirectory, "..");
const source = path.join(frontendDirectory, "dist", "index.html");
const destinations = [
  path.join(projectDirectory, "assets", "soc_console.html"),
  path.join(projectDirectory, "assets", "SentinelUEBA-SOC-Console.html"),
  path.join(projectDirectory, "assets", "SentinelUEBA-React-Console.html"),
];

await stat(source);
for (const destination of destinations) {
  await copyFile(source, destination);
  console.log(`[frontend] published ${path.relative(projectDirectory, destination)}`);
}
const buildId = createHash("sha256").update(await readFile(source)).digest("hex").slice(0,16);
const worker = (await readFile(path.join(scriptDirectory,"service-worker.js"),"utf8")).replace("__BUILD_ID__",buildId);
await writeFile(path.join(frontendDirectory,"dist","sw.js"),worker);
await writeFile(path.join(projectDirectory,"assets","sw.js"),worker);
