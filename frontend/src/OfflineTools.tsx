import { useEffect, useState } from "react";

export default function OfflineTools() {
  const isFile = window.location.protocol === "file:";
  const [status,setStatus] = useState(isFile ? "Offline file open · browser packet analysis ready" : "Preparing offline page…");
  const [downloading,setDownloading] = useState(false);
  useEffect(() => {
    if (isFile) return;
    let active = true;
    if (!("serviceWorker" in navigator)) { setStatus("Offline caching unavailable · download a copy for your presentation"); return; }
    const root = new URL("./",window.location.href);
    void navigator.serviceWorker.register(new URL("sw.js",root),{scope:root.pathname,updateViaCache:"none"})
      .then(() => navigator.serviceWorker.ready)
      .then(async () => {
        const saved = await caches.match(root.href);
        if (active) setStatus(saved ? "Offline page saved on this device" : "Download an offline copy for your presentation");
      }).catch(() => { if (active) setStatus("Offline caching unavailable · download a copy for your presentation"); });
    return () => { active = false; };
  },[isFile]);
  async function download() {
    setDownloading(true);
    try {
      const root = new URL("./",window.location.href);
      let response: Response | undefined;
      try { response = await caches.match(root.href); } catch { /* Cache access is optional. */ }
      response ||= await fetch(root,{signal:AbortSignal.timeout(15000)});
      if (!response.ok || !response.headers.get("content-type")?.includes("text/html")) throw new Error();
      const blob = await response.blob(), url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href=url; a.download="SentinelUEBA-Offline.html"; a.click();
      setTimeout(() => URL.revokeObjectURL(url),1000);
      setStatus("Offline HTML downloaded · open it to analyze PCAP files without hosting");
    } catch { setStatus("Download could not complete. Retry when this page is reachable."); }
    finally { setDownloading(false); }
  }
  return <div className="offline-tools"><span role="status">{import.meta.env.VITE_ENABLE_SERVER !== "true" && <strong>Standalone demo · </strong>}{status}</span><div>
    {!isFile && <button disabled={downloading} onClick={() => void download()}>{downloading ? "Preparing download…" : "Download offline HTML"}</button>}
    {window.location.hostname !== "harthik777.github.io" && !isFile && <a href="https://harthik777.github.io/CN-Project/#packets">Independent demo page ↗</a>}
  </div></div>;
}
