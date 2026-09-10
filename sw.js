/* BUILD_ID is filled from the HTML hash during the build. Only the public application shell is cached. */
const ROOT = new URL(self.registration.scope);
const PREFIX = `sentinel-shell:${ROOT.href}:`;
const CACHE = `${PREFIX}919b198f59db9f3a`;
async function shell() {
  const response = await fetch(ROOT.href,{cache:"reload"});
  if (!response.ok || !response.headers.get("content-type")?.includes("text/html")) throw new Error("Application shell unavailable");
  await (await caches.open(CACHE)).put(ROOT.href,response.clone());
  return response;
}
self.addEventListener("install",event => event.waitUntil(shell().then(() => self.skipWaiting())));
self.addEventListener("activate",event => event.waitUntil((async () => {
  for (const name of await caches.keys()) if (name.startsWith(PREFIX) && name !== CACHE) await caches.delete(name);
  await self.clients.claim();
})()));
self.addEventListener("fetch",event => {
  const url = new URL(event.request.url);
  // API calls, uploads, external requests and session data are never intercepted or cached.
  if (event.request.method !== "GET" || event.request.mode !== "navigate" || url.origin !== ROOT.origin ||
      ![ROOT.pathname,`${ROOT.pathname}index.html`].includes(url.pathname)) return;
  const fresh = shell();
  event.waitUntil(fresh.then(() => {},() => {}));
  event.respondWith((async () => {
    const saved = await (await caches.open(CACHE)).match(ROOT.href);
    if (!saved) return fresh;
    // A working cached shell appears within 2 seconds even if the network hangs.
    let timer;
    try { return await Promise.race([fresh.catch(() => saved),new Promise(resolve => {timer=setTimeout(() => resolve(saved),2000);})]); }
    finally { clearTimeout(timer); }
  })());
});
