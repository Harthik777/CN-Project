# SentinelUEBA React SOC Console

This React frontend includes a live API investigation view and a synthetic benchmark replay. The live view submits raw events to the Python backend; benchmark views consume `assets/dashboard_data.json`.

The application includes four investigation surfaces:

- A risk-ranked alert workspace with explainability and analyst disposition.
- Live ingestion, actual saved-model inference, raw evidence and server-side feedback audit.
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
access. Live inference requires a running API. Set `VITE_API_BASE` at build time for a separate API origin, or serve the HTML from the backend and open `/#live`. See [backend setup](../docs/BACKEND.md).
