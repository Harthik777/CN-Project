import type { ViewName } from "./types";

// Older shared #live links open the bundled replay in the standalone demo.
export function resolveView(hash: string, serverEnabled: boolean): ViewName {
  const name = hash.replace(/^#/, "");
  if (name === "live") return serverEnabled ? "live" : "alerts";
  return ["alerts", "topology", "evaluation", "packets"].includes(name) ? name as ViewName : "packets";
}
