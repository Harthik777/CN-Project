/** One bounded transport for both consoles. Writes are never retried automatically. */
export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) { super(message); this.status = status; }
}
export class ConnectionError extends Error {}
export type Credential = { session_id: string; token: string };
export async function apiRequest<T>(base: string, path: string, options: {
  credential?: Credential | null; body?: BodyInit; contentType?: string; timeoutMs?: number; attempts?: number;
} = {}): Promise<T> {
  const write = options.body !== undefined;
  const attempts = write ? 1 : Math.min(2, options.attempts ?? 2);
  for (let attempt = 0; attempt < attempts; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? (write ? 60000 : 8000));
    try {
      const response = await fetch(`${base}${path}`, {
        method: write ? "POST" : "GET", body: options.body, signal: controller.signal, cache: "no-store",
        headers: { ...(write ? { "Content-Type": options.contentType || "application/json" } : {}),
          ...(options.credential ? { Authorization: `Bearer ${options.credential.token}` } : {}) },
      });
      if (!response.ok && [502, 503, 504].includes(response.status)) {
        throw new ConnectionError("The server is temporarily unavailable. Browser packet analysis and the bundled replay are available. Refresh server state before retrying a submission.");
      }
      if (!response.headers.get("content-type")?.includes("application/json")) {
        throw new ConnectionError("The server has not returned an API response. It may be starting up. Browser packet analysis and the bundled replay are available.");
      }
      const data = await response.json();
      if (!response.ok) throw new ApiError(response.status,
        `${response.status}: ${typeof data.detail === "string" ? data.detail : "Request rejected"}`);
      return data as T;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      const failure = error instanceof ConnectionError ? error : new ConnectionError(
        "Cannot reach the server. Your last displayed results remain available. Use browser packet analysis or the bundled replay, and refresh server state before retrying a submission.");
      if (attempt + 1 === attempts) throw failure;
    } finally { clearTimeout(timer); }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new ConnectionError("The server is unavailable.");
}
