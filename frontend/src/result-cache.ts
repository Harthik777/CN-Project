/** Keep one bounded, expiring browser copy per console. Never store capture bytes or bearer tokens here. */
export type CachedResult<T> = { version: 1; saved_at: string; source: string; data: T };
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_AGE = 7 * 24 * 60 * 60 * 1000;
export function readResult<T>(key: string, validate: (data: unknown) => data is T): CachedResult<T> | null {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    if (new Blob([raw]).size > MAX_BYTES) { localStorage.removeItem(key); return null; }
    const item = JSON.parse(raw);
    const age = Date.now() - Date.parse(item.saved_at);
    if (item.version !== 1 || !Number.isFinite(age) || age < 0 || age > MAX_AGE || typeof item.source !== "string" || !validate(item.data)) {
      localStorage.removeItem(key); return null;
    }
    return item;
  } catch { return null; }
}
export function saveResult<T>(key: string, data: T, source: string): CachedResult<T> | null {
  const result: CachedResult<T> = { version: 1, saved_at: new Date().toISOString(), source, data };
  try {
    const text = JSON.stringify(result);
    if (new Blob([text]).size > MAX_BYTES) { localStorage.removeItem(key); return null; }
    localStorage.setItem(key, text);
    return result;
  } catch { return null; }
}
export function clearResult(key: string) { try { localStorage.removeItem(key); } catch { /* Storage is optional. */ } }
