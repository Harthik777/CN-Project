# Demonstration resilience

Use **https://harthik777.github.io/CN-Project/#packets** as the primary project link. Render remains the optional packet SQL backend and the required access-log inference backend. This release adds actual browser packet inference, not prerecorded results presented as live inference.

## What happens during an outage

| Operation | Behavior |
|---|---|
| Analyze sample or a new PCAP | Parse headers, build flows and score the exported trained forest locally. No server is required. |
| Automatic analysis mode | Display the browser result first; probe the API for up to four seconds. If reachable and the model identity matches, upload to an isolated session, save to SQL and read back. |
| Browser only mode | No capture upload or API calls for analysis. |
| Lost response during a server write | Keep the local result. Display that the save is unconfirmed and offer explicit server refresh. Never automatically repeat a POST. |
| Reload while the host is unreachable | After a successful visit and service-worker installation, use the cached application shell. A hung navigation falls back within two seconds. |
| Completely disconnected presentation | Open the downloaded self-contained HTML; packet analysis, the embedded sample, exports and benchmark replay work without installation. |
| Access-log inference outage | Keep the latest browser copy read-only and exportable; disable server writes and link to packet analysis and the bundled synthetic replay. New access-log ML predictions still need Render. |
| Expired/restarted cloud session | Preserve the browser copy. Do not claim it is still saved on the server. |

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

The differential check compares **130 captures**: 101 accepted, 29 rejected; **1,050 flows** with matching flags and a maximum measured score difference of **1.1102230246251565e-16**. It includes the 36 training/validation/test captures, the separate sample, endian/timestamp variants, IPv6, VLAN/raw/cooked links, malformed lengths, sequence wraparound, partial handshakes, flow limits and deterministic byte mutations. This establishes implementation parity, not real-world detection accuracy.

Five JavaScript resilience tests cover safe GET retry, no automatic POST retry, non-retryable HTTP errors, aborts/startup HTML, corrupt/expired/unavailable browser storage, and service-worker outage recovery with API exclusion. The Python suite has **67 tests**, including API health uptime, compressed HTML delivery and service-worker response headers.

Browser outage exercise: start a local production build/API, save a packet report and score 120 synthetic access events; stop the server; reload the page; confirm the 120-event copy is read-only and exportable; analyze a separately generated PCAP entirely locally; export it and reload again. The additional capture has SHA-256 `1b75d0142efe76e2a41aefb8c77d8ff966d42935e7c6f5851b4c242685ece2d7`, 378 packets, 32 flows, 22 handshakes and 9 flagged flows, matching Python.

## Remaining boundary

This does not promise universal uptime, fix an ISP/hosting route, or add an always-on second API. Render Free still sleeps and uses temporary storage. New visitors need to load the page once or receive the offline HTML. Live access-log inference and cloud SQL persistence remain unavailable while Render is unreachable. No paid service or keep-alive automation was added.
