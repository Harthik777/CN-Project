# Demonstration resilience

Use **https://harthik777.github.io/CN-Project/#packets** as the primary project link. The public application runs without a backend: fresh packet inference, stored access-log replay, local reviews, topology and model audit. The build rejects cloud API routes and Render URLs, and its content-security policy restricts connection requests to the page's own origin for offline-shell caching.

Six [recorded CTU excerpts](REAL_DATA.md) and the synthetic teaching capture are stored with the application; packet features and model scores are computed when you run one. Server modes are absent from the public build. Access-log views use bundled, precomputed synthetic results and do not compute new UEBA predictions. Old `#live` links open this replay. Recorded captures do not change the model's synthetic training provenance; the app separately shows its poor transfer to normal DNS.

## What happens during an outage

| Operation | Behavior |
|---|---|
| Analyze sample or a new PCAP | Parse headers, build flows and score the exported trained forest locally. No server is required. |
| Packet analysis | No capture upload or API calls. Results and exports are computed on the device. |
| Access-log replay and reviews | Inspect stored results, change filters/policies, save a local disposition and export decisions. No cloud session. |
| Topology | Explore the 3D graph or connection table. Rendering failures switch to the table. |
| Reload while the host is unreachable | After a successful visit and service-worker installation, use the cached application shell. A hung navigation falls back within two seconds. |
| Completely disconnected presentation | Open the downloaded self-contained HTML; packet analysis, the embedded sample, exports and benchmark replay work without installation. |
| Render outage or expired session | No effect on public-demo interactions. Its cloud controls and API routes are excluded at build time. |

## Data and model integrity

`scripts/export_browser_model.py` exports numeric decision trees from the existing trusted Isolation Forest. It never retrains the model or accepts uploaded model files. `frontend/src/packet-engine.ts` implements the Python PCAP parser and feature schema, including TCP acknowledgement matching, IPv6 extension handling, fragment accounting, limits and float32 conversion before tree traversal. Both implementations use the same reference model ID and threshold.

The latest report per console is cached in localStorage for at most seven days, with a 2 MiB size bound per report. Browser result copies contain output data and header metadata, not packet payloads or bearer tokens. Existing session credentials remain in their separate origin-scoped connection storage. Each console has an explicit clear control. Storage can be blocked, cleared or evicted; export important evidence to a file. Reports retain their original model identity across application updates.

The service worker caches only the public application HTML with its embedded model, sample and assets. It never intercepts API requests or stores authorization headers, writes or API responses. Cache names are scoped to this application path; updates remove only obsolete caches from that scope. Offline caching requires an initial successful visit. The downloadable HTML is a separate presentation fallback, not a second backend.

## Verification

```powershell
python scripts/export_browser_model.py --check
python scripts/verify_browser_packets.py
python -m unittest discover -s tests -v
cd frontend
npm test
npm run build
```

The differential check compares **136 captures**: 107 accepted, 29 rejected; **1,244 flows** with matching flags and a maximum measured score difference of **1.1102230246251565e-16**. It includes six recorded CTU excerpts, the 36 training/validation/test captures, the separate sample, endian/timestamp variants, IPv6, VLAN/raw/cooked links, malformed lengths, sequence wraparound, partial handshakes, flow limits and deterministic byte mutations. This establishes implementation parity, not real-world detection accuracy.

Six JavaScript resilience tests cover standalone deep links, safe GET retry in the separate server client, no automatic POST retry, non-retryable HTTP errors, aborts/startup HTML, corrupt/expired/unavailable browser storage, and service-worker outage recovery with API exclusion. The Python suite has **71 tests**, including public-capture provenance/redaction checks, API health uptime, compressed HTML delivery and service-worker response headers. `scripts/verify_standalone_demo.py` checks the public HTML and matching offline worker without contacting Render.

Browser outage exercise: start a local production build/API, save a packet report and score 120 synthetic access events; stop the server; reload the page; confirm the 120-event copy is read-only and exportable; analyze a separately generated PCAP entirely locally; export it and reload again. The additional capture has SHA-256 `1b75d0142efe76e2a41aefb8c77d8ff966d42935e7c6f5851b4c242685ece2d7`, 378 packets, 32 flows, 22 handshakes and 9 flagged flows, matching Python.

## Remaining boundary

New visitors need to load the page once or receive the offline HTML. Browser storage may be blocked or evicted, so export important evidence. The standalone demo has no remote inference or cloud SQL persistence. Those features remain in the separate backend implementation for local/API experiments; enable them explicitly with `VITE_ENABLE_SERVER=true` when building its frontend. No paid service or keep-alive automation was added. This design removes the Render dependency, not every possible browser or internet failure.
