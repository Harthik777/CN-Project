# Public demo deployment

## Academic/networking update — 9 September 2026

- Source commit: `055e38aa0088d06f48d97bb359b14e97413866b9`; [CI passed](https://github.com/Harthik777/CN-Project/actions/runs/34269569143), including all 41 Python tests, a two-trial HTTP socket experiment with eleven correctness checks, and the frontend production build. The workflow retains its network-lab evidence artifact.
- Render automatically deployed that commit after CI passed: deployment `dep-dag666btqb8s73advhgg` reported **Live**, with a duration of 1m18s. The plan remains Free. [Deployment record](https://dashboard.render.com/web/srv-dag5n9fqj5pc73931i8g/deploys/dep-dag666btqb8s73advhgg).
- The public Render HTML includes the network evidence display, lab link and unavailable-session recovery. Verified size: 5,323,330 bytes; SHA-256 `2a9a5b102b5b5d49ca317b8fc0c5a5738262c472e4e4f6b02b99d403aeb9ef56`.
- Pages artifact commit `97e2cd412844caeaab3e54ea0eb2a2743ccd78e9` [deployed successfully](https://github.com/Harthik777/CN-Project/actions/runs/34269583726). The public HTML matches the tested build exactly: 5,323,331 bytes; SHA-256 `a1f73f41b2d7e9990ab055d2dee308d91f5e3d04817d314997ef3340827d42d9`.
- The temporary local experiment server was stopped before checking the final public build. Render health remained `ok` with the unchanged model/source identity below. The browser correctly explained that a previous cloud session had disappeared after deployment and offered a new session.
- [RESULTS.md](RESULTS.md) publishes the nine-trial local and nine-trial Render networking experiments. [ACADEMIC_REPORT.md](ACADEMIC_REPORT.md) and [PORTFOLIO.md](PORTFOLIO.md) document the current coursework and résumé presentation.

The records below preserve the initial deployments and older artifact hashes.

## Current deployment: Render — 9 September 2026

- Full app: [SentinelUEBA on Render](https://sentinelueba-harthik.onrender.com/#live).
- API: [health](https://sentinelueba-harthik.onrender.com/api/health) and [interactive documentation](https://sentinelueba-harthik.onrender.com/docs).
- Alternate frontend: [GitHub Pages](https://harthik777.github.io/CN-Project/), built with the Render API origin.
- Render service: `sentinelueba-harthik`, ID `srv-dag5n9fqj5pc73931i8g`, Singapore, Docker, Free plan (512 MB RAM, 0.1 CPU).
- Successful first deployment: `dep-dag5n9vqj5pc73931j60`, source commit `a7ae81b99286e40b02cb8e4573bcfce604df1c69`. [Render deployment dashboard](https://dashboard.render.com/web/srv-dag5n9fqj5pc73931i8g/deploys/dep-dag5n9vqj5pc73931j60).
- [GitHub verification passed](https://github.com/Harthik777/CN-Project/actions/runs/34266386830). Render also built the multi-stage Docker image successfully and reported the service live.
- Health check: `/api/health`. The UI was configured to auto-deploy after CI checks pass. The Docker build serves its own frontend with same-origin API requests and contains no temporary tunnel address.

The [GitHub Pages update](https://github.com/Harthik777/CN-Project/actions/runs/34267029879) also succeeded at artifact commit `409e83dbab2aa40bba18033c98d064837d0f3f55`. Its public HTML matched the tested build exactly: 5,321,726 bytes, SHA-256 `6e5786e4f15b8cc9c5ed05853a19d6a6024b06cc89e3d1d0a794333e3cadaafc`. The final artifact contains the Render API origin and no temporary tunnel URL.

Browser verification on the Render app created a session, scored the 120-event baseline and 48-event campaign, saved an analyst disposition, and recovered all 168 events plus the saved review after a reload. The old local API and Cloudflare tunnel were then stopped. Render's health endpoint still returned HTTP 200 and the browser still retrieved its saved cloud session; the GitHub Pages frontend also connected to Render. The deployment therefore no longer depends on a running local backend.

The public HTTP smoke test against Render scored 168 events, skipped duplicate replay, rejected unauthenticated reads and malformed input, and saved/read two review revisions with idempotent retries. All 48 campaign events and 56 baseline events were flagged at top 2%; these are demo outcomes, not a new held-out evaluation. The baseline request spent 6.47 seconds scoring; the campaign append spent 11.42 seconds, including historical replay. The full smoke check took 23.61 seconds. These timings are a single functional test on the free instance, not a throughput benchmark.

The Render app returned HTTP 200 with 5,321,725 HTML bytes and SHA-256 `ce16a48da53c7822c87d7d6651382695f8006344373ab73ebb88dd756fa31f75`. The health endpoint returned model/source identity `91f67dfe56ef23644bd7aa12cc1e917e6faa844a7cbeedf1c536ace57086504e`, matching the verified model bundle and scoring source.

This deployment does not depend on the developer's computer. It has a stable public Render URL, but it is not an always-on paid service. [Render Free sleeps after inactivity and does not support persistent disks](https://render.com/docs/free). Sessions on its temporary filesystem may disappear on sleep, restart or redeployment; the app displays this and provides evidence export. No paid plan was purchased. A durable disk or external database remains a separate upgrade.

## Historical temporary backend preview — superseded by Render

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
