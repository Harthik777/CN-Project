# SentinelUEBA React SOC Console

The default build is a standalone browser demo. PCAP parsing and Isolation Forest scoring run locally; access-log views consume stored synthetic results in `assets/dashboard_data.json`. It makes no backend requests.

The application includes four investigation surfaces:

- A risk-ranked alert workspace with explainability and analyst disposition.
- Fresh browser PCAP analysis with bundled CTU captures, a teaching sample, local file selection, header evidence and exports.
- An interactive 3D entity-resource topology derived from the synthetic benchmark alerts.
- A model-assurance view for operating points, channel metrics, and evidence
  boundaries.

## Development

```powershell
npm ci
npm run dev
```

## Verification and production build

```powershell
npm run check
npm run build
```

The build writes `dist/index.html` as a self-contained offline artifact. It has
all React, Three.js, charting, styles, icons, and dashboard data embedded in one
file, so it can be opened directly without Node.js, a server, or internet
access. The build rejects cloud API routes or Render URLs in this artifact and includes a same-origin connection policy. Old `#live` links open the stored replay. The topology includes a connection table for devices without working 3D graphics.

For the separate backend application, explicitly set `VITE_ENABLE_SERVER=true` at build time. Set `VITE_API_BASE` only for a separate API origin; Docker enables server controls and uses the same origin. See [backend setup](../docs/BACKEND.md). Do not use the server-enabled artifact for the standalone Pages deployment.
