# Public demo deployment

## Connected backend preview — 9 September 2026

- Verified [source build and all 41 tests on Linux](https://github.com/Harthik777/CN-Project/actions/runs/34265825462), source commit `ed76058f4acac6fde52d909c0abd91fc3e060e0b`.
- Verified [Pages deployment](https://github.com/Harthik777/CN-Project/actions/runs/34265708624), artifact commit `f6743289aeab459658ae72494727b325a855e812`.
- Anonymous Pages GET returned HTTP 200 with 5,321,741 bytes, exactly matching the local final build; SHA-256 `863968899f84f359aa517a7becf683e6adeab8b568c32bbff1e3952dbb11d346`.
- Frontend: [SentinelUEBA](https://harthik777.github.io/CN-Project/).
- Temporary backend: [Live API](https://bacteria-believe-arnold-rogers.trycloudflare.com/api/health) and [API documentation](https://bacteria-believe-arnold-rogers.trycloudflare.com/docs).
- The API process and Cloudflare quick tunnel run on the project host computer. This is a public preview, not permanent remote hosting; the computer and both processes must remain online. A restarted tunnel can receive a different URL.
- Backend state is on the host's SQLite database under `output/service/`, with 24-hour demo sessions. Local process restart was verified without loss of events or feedback.
- Permanent Python hosting requires a working provider connection. Both available Hugging Face environment credentials returned HTTP 401. No paid hosting plan was purchased.

The public HTTP smoke test ingested and scored 168 events, verified duplicate replay, rejected unauthenticated reads and malformed input, and saved/read two audit revisions with idempotent retries. All 48 staged campaign events and 56 baseline events were flagged under top 2%. These are demonstration results, not held-out benchmark claims. Server scoring took approximately 1.24 seconds for the baseline and 3.18 seconds for the campaign append (including replayed history); the full HTTP verification took 12.37 seconds. Measurements describe one demo run, not a load benchmark.

Local verification passed all 41 tests. The actual-model test compares uninterrupted, chunked and restarted scoring. The browser saved an analyst review, then recovered 168 events and the review after a real API process restart. The final frontend type-check and production build passed. Source and tests are in the `codex/full-stack` branch; Pages serves the built artifact from `codex/public-demo`.

To run a new preview, start the API as described in [BACKEND.md](BACKEND.md), then run `cloudflared tunnel --url http://127.0.0.1:7860`. To connect a separately hosted frontend, rebuild it with `VITE_API_BASE` set to the current HTTPS API origin and republish the built HTML. The quick tunnel tool is [intended for development and testing](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/).

## Initial static deployment record

Verified on 9 September 2026 (Asia/Calcutta).

- Public HTTPS URL: [SentinelUEBA](https://harthik777.github.io/CN-Project/).
- Repository: [Harthik777/CN-Project](https://github.com/Harthik777/CN-Project).
- Deployment branch: `codex/public-demo`, served from `/` using GitHub Pages.
- Published commit: `d400268a36e4da6633d3474363069122f5accb51`.
- Successful [GitHub Pages workflow](https://github.com/Harthik777/CN-Project/actions/runs/34263234773).
- Public files: `index.html`, `.nojekyll`, `LICENSE`, `README.md`.

## Verification

An anonymous HTTPS GET returned HTTP 200 with `text/html; charset=utf-8`. The response contained 5,301,843 bytes and matched the local `assets/SentinelUEBA-React-Console.html` build exactly.

SHA-256: `81d2463cd1ad8bad56a7388ca3243e162bf0a88b728dbcbef948a719ddf98395`.

The public browser loaded the synthetic replay dashboard. Switching from top 2% to top 1% changed the displayed policy metrics from 73.7% precision / 99.3% attack recall / 3,097 alerts to 100.0% / 46.7% / 1,074 alerts. The policy was restored to top 2%. Topology displayed 41 principal/resource nodes and 40 links, with threshold 0.004. Model audit loaded the evaluation and operating-point tables. No browser console errors were captured during these checks.

## Scope

This is a static synthetic replay demo. Scores and evidence are bundled into the website. Analyst decisions are stored in the visitor's browser and can be exported for the separate Python import workflow. Live ingestion, inference, model retraining and server-side feedback are not deployed.

Original attribution to Induj Gupta and the MIT license are preserved. Python source and model artifacts remain in the local project workspace. The successful Pages workflow verifies deployment; the local source test workflow has not run on GitHub.

## Updating this deployment

Use Node 22.12+ (Node 24 was used for this deployment). Rebuild and validate the frontend from `frontend/` with `npm ci` and `npm run build`. Copy the resulting `assets/SentinelUEBA-React-Console.html` to `output/public-site/index.html`, then commit and push within that separate checkout to `origin codex/public-demo`. The deployment checkout is ignored by the parent workspace.

Wait for the Pages workflow to succeed, compare the public HTML to the new build, and repeat browser checks before recording a replacement commit and hash here.
