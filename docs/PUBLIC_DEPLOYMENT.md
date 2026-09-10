# Public demo deployment

## Standalone presentation release: 10 September 2026

The [v4.3.0 release](https://github.com/Harthik777/CN-Project/releases/tag/v4.3.0) removes the Render dependency from the public frontend. Packet parsing and inference, stored access-log replay, local analyst dispositions, topology and model audit all run in the browser. The standalone build excludes cloud API routes and server-save controls. Old `#live` links open the stored replay; access-log predictions there are explicitly precomputed.

- Source commit `7b8772ab2d76a59b1ca94d11d44fd6b24f8d9082` passed [source CI](https://github.com/Harthik777/CN-Project/actions/runs/34470263145): 71 Python tests, 6 JavaScript tests, frontend type checking/build, 136-capture/1,244-flow parity and the networking labs. The original standalone change also passed [CI](https://github.com/Harthik777/CN-Project/actions/runs/34469863802).
- The production build rejects Render URLs, API health/session routes and cloud-only controls in the generated artifact. It embeds all required runtime assets and sets `connect-src 'self'` for its own offline-shell caching. A separate build with `VITE_ENABLE_SERVER=true` was also verified; the Docker backend explicitly uses that mode. Render was not redeployed for this frontend release.
- Offline HTML: **6,760,480 bytes**, SHA-256 `45f4f5edf0cd3ca819a2903b28df0a5dd74c68684c37bd51550abaf3bdc7c10d`. GitHub's uploaded release asset digest matches the local artifact. [Download the presentation file](https://github.com/Harthik777/CN-Project/releases/download/v4.3.0/SentinelUEBA-Offline.html).
- Browser verification covered the legacy link redirect, all four views, real-DNS analysis (200 packets, 54 flows, 51 flags), local analyst review save/reload, topology table and investigation navigation, and model audit. With the local host stopped, the cached page reloaded and analyzed another real excerpt (200 packets, 14 flows, 1 matched handshake). The final cached build also analyzed the synthetic sample after the host was stopped: 378 packets, 32 flows, 22 handshakes and 11 flags.
- The automated browser did not deliver a file from the original programmatic export button. Exports now use explicit data links and include a copyable JSON report. Browser inspection verified that the JSON link and visible copy agree, the capture hash matches the selected CTU excerpt, and the CSV contains 14 corresponding flow rows. No new downloaded file was observed in that browser session, so its file-save behavior is not claimed as verified. The earlier restriction on direct `file:` navigation also remains; cached-page offline behavior was verified.

The Pages artifact commit is `09dba20099eb769f15d8bbb54457a7b41d60f47e`. Attempt 1 of the [publishing run](https://github.com/Harthik777/CN-Project/actions/runs/34470262202) passed its build, then timed out after ten minutes in GitHub's `updating_pages` phase. **Attempt 2 succeeded** after retrying the failed publishing job. The earlier Pages attempt for the intermediate artifact was cancelled when the final artifact superseded it.

The [local HTTP artifact check](experiments/standalone-local-4.3.0.json) and [independent public verification](https://github.com/Harthik777/CN-Project/actions/runs/34471572546) passed. The [public evidence](experiments/public-standalone-4.3.0.json) confirms exact HTML bytes, matching offline worker, same-origin connection policy, embedded runtime assets and absence of backend routes. This workflow contacts only Pages. Public browser verification computed a fresh DNS result (200 packets, 54 flows, 51 flags), verified its JSON export data, opened the stored access-log replay and recorded no console errors. Offline use requires a successful initial visit or a saved presentation file; browser storage can be evicted. Model training and real-data limitations are unchanged.

## Recorded datasets release: 10 September 2026

The [primary Pages packet lab](https://harthik777.github.io/CN-Project/#packets) now bundles six payload-redacted excerpts from CTU Normal 4 and CTU-13 scenario 7: **1,200 recorded packets and 194 extracted flows**. Browser-only analysis remains the default, with source attribution, SHA-256 provenance, selected PCAP downloads and report exports embedded in the page. See [dataset preparation and results](REAL_DATA.md).

- Source commit `a80db5206ac1b7bc0380af9203c9da6ce11ad9a3` passed [source CI](https://github.com/Harthik777/CN-Project/actions/runs/34459692083): 71 Python tests, 5 JavaScript resilience tests, frontend production build, network labs, and browser/Python agreement across 136 captures and 1,244 flows. Flags matched; maximum score difference was `1.1102230246251565e-16`. Raw [parity evidence](experiments/browser-parity-real-data.json) is retained.
- Pages artifact commit `89d4d33422dd2f4a28fce2d36916c19126089359` [deployed successfully](https://github.com/Harthik777/CN-Project/actions/runs/34459698081). Its public HTML exactly matches the packaged artifact: 6,778,774 bytes, SHA-256 `919b198f59db9f3ab744f236b9de118d6ce44b03543a93b5c8e77196c1c07fa2`.
- Render automatically deployed the tested source commit after CI passed. Deployment `dep-dah7b88u01pc73cia4o0` reported **Live**, duration 3m21s, on the existing Free service. [Deployment record](https://dashboard.render.com/web/srv-dag5n9fqj5pc73931i8g/deploys/dep-dah7b88u01pc73cia4o0). The public API returns **4.2.0** with the unchanged model identities. Render's HTML is 6,778,692 bytes, SHA-256 `25288fbe2e26bfb3c3fbefc1306b09c45a9d8e29be234b311c8ef98e810800e5`.
- [Independent public verification passed](https://github.com/Harthik777/CN-Project/actions/runs/34460167225): API version and model identity, all 15 existing packet HTTP checks, both published frontends, offline workers, Pages upload CORS, and upload/scoring/saved-report readback for **all six real excerpts**. Raw [packet evidence](experiments/packet-render-4.2.0.json), [frontend and real-capture evidence](experiments/public-frontend-4.2.0.json), and [health response](experiments/public-health-4.2.0.json) are retained.
- Public browser verification analyzed the default normal-DNS excerpt without upload: 200 packets, 54 flows and 51 flags. No browser console errors were recorded. Local browser checks confirmed that changing the dataset selector does not relabel an existing report, and that exported JSON provenance and the downloaded PCAP hash match the analyzed dataset.
- In a local host-stop exercise, the cached page reloaded successfully and analyzed a different recorded excerpt while its host was stopped: 200 packets, 1 flow and 1 flag from the CTU-13 midpoint. This verifies cached-page recovery and fresh local computation, not guaranteed browser-storage retention.
- [Offline release v4.2.0](https://github.com/Harthik777/CN-Project/releases/tag/v4.2.0) includes the same datasets. GitHub's published HTML asset digest matches the packaged SHA-256 above. Direct `file:` navigation remains unverified in the automated browser environment, which blocked that navigation in the earlier offline release check.

The model was **not retrained**. It flags 153 of 159 normal DNS flows, exposing poor transfer from synthetic training. Botnet-host context does not establish a per-flow attack label, and no real-data accuracy, precision or recall is claimed. A direct Render request from the development computer still timed out during this release, while the independent public checks passed. The default packet demo avoids that backend dependency; optional cloud writes still require a reachable Render service.

## Browser-only default: 10 September 2026

The [primary Pages demo](https://harthik777.github.io/CN-Project/#packets) now starts in **Browser only: no upload** mode on every page load. The existing synthetic PCAP and trained model are bundled in the page; parsing and scoring happen on the device. A direct link opens the stored synthetic access-log benchmark replay, explicitly identified as precomputed output. Real PCAPs can also be analyzed in the browser within the documented limits; the model still has synthetic training/evaluation provenance.

- Source commit `ebf0aef7e49dafe5fa48ad6d200be9918676345c`; [source verification](https://github.com/Harthik777/CN-Project/actions/runs/34398324644).
- Pages commit `162aba5bbfcb876acfa8b3c2125e058c6814a5c1`; [deployment passed](https://github.com/Harthik777/CN-Project/actions/runs/34398330435). Anonymous HTTPS download matched the built artifact exactly: 6,127,472 bytes, SHA-256 `3fbeb0e7cc8032b451cb6c6fc01b6f540fa1f1ae27a529ca39845bba6bac0658`.
- Browser verification confirmed the default after a public-page reload and computed fresh sample results without upload: 378 packets, 32 flows, 22 matching handshakes and 11 flags. The stored replay link opened successfully in the local production build; public browser console errors were absent. Frontend production build and five resilience tests passed locally.
- [Offline HTML release v4.1.1](https://github.com/Harthik777/CN-Project/releases/tag/v4.1.1) includes the new default. Render's API remains version 4.1.0; no backend change or redeployment was needed for this presentation update.

At the follow-up check, Render's dashboard marked the last deployment Live, while a direct health request from the development computer timed out. No failed Render deployment was visible in the inspected history. The earlier failed GitHub public-verification run remains historical; it was followed by the successful v4.1.0 verification below. The Pages demonstration no longer attempts that connection by default.

## Dependability release: 10 September 2026

**Primary demo:** [SentinelUEBA Packet analysis on GitHub Pages](https://harthik777.github.io/CN-Project/#packets). **Presentation download:** [v4.1.0 release and offline HTML](https://github.com/Harthik777/CN-Project/releases/tag/v4.1.0).

Packet parsing, flow extraction and trained Isolation Forest scoring now run in the browser before any optional server request. The application caches its public page for offline reload, retains clearly labeled result copies, offers a self-contained HTML download, and bounds network waits without automatically repeating writes. See [DEPENDABILITY.md](DEPENDABILITY.md) for behavior, retention and remaining limits.

- Source commit `bcc4f9cdb2603a8b770189ea8800dde4c967e3c1` passed [source CI](https://github.com/Harthik777/CN-Project/actions/runs/34394090370): 67 Python tests, 5 JavaScript resilience tests, frontend build, network labs, and Python/browser comparisons over 130 captures and 1,050 flows. Flags matched; maximum measured score difference was `1.1102230246251565e-16`.
- Render deployment `dep-dagr3pafngtc73aueee0` reported **Deploy succeeded | Live** on the existing Free service. [Deployment record](https://dashboard.render.com/web/srv-dag5n9fqj5pc73931i8g/deploys/dep-dagr3pafngtc73aueee0). The public API returns **4.1.0**, health uptime and the unchanged model identities. Its HTML is 6,126,905 bytes, SHA-256 `e11bb53953970b115744a3d7657a180a801ccd654c5c3954f07520f545c0f19b`.
- Pages artifact commit `f809be4ed0a4da543721d3005c5c7293f46bad17` [deployed successfully](https://github.com/Harthik777/CN-Project/actions/runs/34394096803). Its 6,126,987-byte HTML matches the packaged download exactly; SHA-256 `2b1505d1e3d2794029453ec126f12f1b028c7db039f89541b7266d4771c6fb7e`.
- [Independent public verification passed](https://github.com/Harthik777/CN-Project/actions/runs/34394826305): expected API version and model identity, all 15 packet HTTP checks, both published frontends, offline workers and Pages upload CORS. Raw [packet evidence](experiments/packet-render-4.1.0.json), [frontend evidence](experiments/public-frontend-4.1.0.json) and [health response](experiments/public-health-4.1.0.json) are retained.
- A real local server-stop exercise verified offline page reload, a retained 120-event read-only access-log result, and analysis/export/reload of a different uploaded PCAP with 378 packets, 32 flows and 9 flags matching Python. The final download was retrieved from the page cache with the host stopped. The automated browser environment blocked direct `file:` navigation, so direct opening of the downloaded HTML was not browser-verified there.
- Public browser verification on Pages displayed the local result immediately, then confirmed SQL save and readback from Render 4.1.0. The public sample has 378 packets, 32 flows, 22 matched handshakes and 11 flags.

The first public verification attempt ran before source CI completed and timed out waiting for 4.1.0 while Render still served 4.0.0. Render had not started an automatic deployment. After confirming source CI passed, the tested commit was deployed manually and the public verification above passed. For future releases, wait for source CI and Render deployment before dispatching the public verification workflow. A post-deployment check should not be started while the provider is still waiting for commit checks. Render's [deployment documentation](https://render.com/docs/deploys#integrating-with-ci) states that this mode waits for all checks. Documentation-only evidence commits use `[skip render]` to avoid an unnecessary service restart.

No paid hosting, second backend, keep-alive automation or local-server dependency was added. New access-log inference and cloud SQL writes still require Render; browser packet analysis remains usable during a backend outage. Offline page caching requires an initial successful visit, and browser storage can be evicted. These checks establish demonstrated recovery behavior, not guaranteed uptime or operational detection accuracy.

## Packet analysis release: 9 September 2026

**Public packet lab:** [Open SentinelUEBA Packet analysis](https://sentinelueba-harthik.onrender.com/#packets). The default hosted view now opens Packet analysis; the original access-log console remains at `#live`.

- Implementation commit `22c8131` was merged with the newer GitHub presentation edits in release commit `cb9aff23cf094e7c10f2f360aa1508cb4a843c5c`. [Release CI passed](https://github.com/Harthik777/CN-Project/actions/runs/34305492797): 66 Python tests, frontend production build, the original HTTP socket lab and the new 15-check packet HTTP lab.
- Render serves API version **4.0.0**, with flow-model/extractor identity `98feff1193f3da62619ea86de2d20e2bfbd1a952a3b344743eafa789ace14677`. The original UEBA model/source identity remains `91f67dfe56ef23644bd7aa12cc1e917e6faa844a7cbeedf1c536ace57086504e`.
- [Independent public release verification passed](https://github.com/Harthik777/CN-Project/actions/runs/34305800529). It waited for the expected model identity, uploaded the public sample to Render, independently decoded the same bytes with dpkt, compared packet/flow/header statistics, verified saved results and idempotent retries, rejected cross-session access and invalid/conflicting uploads, and checked both frontend artifacts and the Pages upload CORS preflight. All 15 packet HTTP checks passed. The raw [Render packet evidence](experiments/packet-render.json) and [frontend evidence](experiments/packet-public-frontend.json) are retained.
- Render's public HTML is **5,340,150 bytes**, SHA-256 `26ba102116befd7f6bf39339ed10074c8d49d00c9265255fe169088bade44a04`, with the new packet-analysis controls present.
- Pages artifact commit `85243274e96c8d66efa6352d56e0a5fad01e5d40` [deployed successfully](https://github.com/Harthik777/CN-Project/actions/runs/34305509839). Its **5,340,232-byte** public HTML matches the packaged release build exactly; SHA-256 `b05da3b3523c62a4e18c05e5dca3f9655d01ce3addd644e4b6319dda8c3447be`.
- Local browser verification exercised the sample button, actual file-chooser upload, a matching TCP handshake, saved-report reload and both exports. The exported CSV and JSON each contain 32 flows representing 378 packets, without session credentials. Browser console errors were absent. The public sample has 22 matching handshakes and 157,599 IP bytes.

Direct connections from the development computer to Render (including Render's dashboard) timed out during release verification. The public service was therefore checked from GitHub's hosted runner, which successfully reached it over verified HTTPS. No local-network, DNS or firewall settings were changed. A Render dashboard deployment ID was not retrieved for this release; the recorded public API/model identity and HTTP/frontend evidence establish what is serving.

The existing Free service and temporary-storage constraints remain. The packet module adds no paid service, active sniffing or local-computer dependency. The model is evaluated only on generated captures; the [packet lab](PACKET_LAB.md) records that limitation and the supported capture formats.

## Harthik's ML/Data Engineering presentation — 9 September 2026

The public application now identifies **Harthik M V — Aspiring Machine Learning Engineer / Data Engineer** in the page title, project badge and live introduction. The README, academic report and portfolio pack describe Harthik's modified project, with separate ML Engineer and Data Engineer résumé versions. Inspiration and retained components remain documented in the provenance record and original MIT notice.

- Source commit `3e075bc39edfff1f42668b8a0af0af4e51c9f0dd` passed [frontend, Python and HTTP integration CI](https://github.com/Harthik777/CN-Project/actions/runs/34270390053).
- Render deployment `dep-dag6a6ijnfac73dau31g` succeeded in 1m33s on the Free plan. The public HTML contains the new identity and the API returns `ok` with unchanged model/source identity. Verified HTML: 5,323,824 bytes; SHA-256 `fee17619c10ee370ee41a76c158d2d5c5d05e7f246bbcdcd0c651f9c55798089`.
- Pages artifact `3ef2798208ed7ed4068aaa0e126c5c6367892ab6` [deployed successfully](https://github.com/Harthik777/CN-Project/actions/runs/34270422278). Public HTML matches the local build exactly: 5,323,825 bytes; SHA-256 `83ab4289816fa0eb073e8592ab3b9722e1385c4d3fff9450c7d319c71bb4c4b0`.

This update changes the project presentation and documentation; the measured inference implementation and benchmark artifacts are retained.

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
