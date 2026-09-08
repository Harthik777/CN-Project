# SentinelUEBA React SOC Console

This is the product-grade frontend for the SentinelUEBA Honeywell submission.
The model pipeline remains Python; the console consumes the generated
`assets/dashboard_data.json` evidence bundle.

The application includes three connected investigation surfaces:

- A risk-ranked alert workspace with explainability and analyst disposition.
- A full-bleed interactive 3D entity-resource topology derived from real alerts.
- A model-assurance view for operating points, channel metrics, and evidence
  boundaries.

## Development

```powershell
npm install
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
access.
