# Course presentation and résumé pack

## Project title and pitch

**SentinelUEBA — Reliable Network-Access Monitoring over HTTP**

“A computer-networks and security project that transports access events to an explainable monitoring API. It handles retries, ordering and isolated analyst reviews, and includes reproducible batching experiments. I extended an attributed UEBA baseline into a free public demonstration with tested delivery behaviour.”

Use the first person only for work you understand, contributed to and can explain. The original submission and model training credit Induj Gupta; current extensions used coding-assistant support. Follow your course's disclosure requirements.

## Five-minute assessment demo

| Time | Show | Explain |
|---|---|---|
| 0:00–0:40 | [Public app](https://sentinelueba-harthik.onrender.com/#live), architecture diagram | Client, HTTPS endpoint, application server and SQLite; the problem of repeat submissions |
| 0:40–1:40 | Create a session; score baseline then campaign | Raw logs travel to the API; saved models compute scores; the session is isolated |
| 1:40–2:20 | Inspect event 167, “Network access evidence” | One source IP, twelve accounts, high failure ratio; fields and rolling windows behind the explanation |
| 2:20–3:00 | Submit the campaign again; save a review; refresh | Duplicate events are skipped; review history is fetched from the server; exporting preserves a copy |
| 3:00–4:10 | [Network experiment results](RESULTS.md) and one raw JSON trial | Equal input, batch size versus request count, client versus server timing, trade-off from prefix replay |
| 4:10–5:00 | [Contribution record](PROVENANCE.md), CI run, model audit | What was reused, what was added, synthetic evaluation limits and free-hosting behaviour |

Wake the service before presenting. Prepare a saved experiment report and the local demo as backups. Do not make a long benchmark run part of a five-minute demonstration.

## Résumé bullets

Choose two or three bullets that reflect your actual participation:

- Extended an attributed UEBA prototype into a publicly deployed React/FastAPI application with HTTPS ingestion, isolated sessions, model inference and a SQLite analyst-review audit.
- Implemented transactional event delivery with duplicate suppression, conflict detection and chronological replay; verified batch/restart equivalence and failure behaviour through automated tests and HTTP integration experiments.
- Designed reproducible HTTP batching experiments on a fixed 168-event workload, recording client/server timings and validating consistent outputs across local and free cloud deployments.

Technology line: **Python, FastAPI, React, TypeScript, HTTP/HTTPS, SQLite, Docker, GitHub Actions**. Describe the supplied PyTorch/LightGBM models as integrated components unless you personally trained or modified them.

Keep the public demo and repository links on the résumé. Avoid “99% real-world accuracy,” “built the entire AI pipeline,” “exactly-once distributed processing,” “production-ready,” “zero packet loss” or a throughput figure extrapolated from this small replay experiment. None is established by the current evidence.

## Viva preparation

| Question | Answer to understand and demonstrate |
|---|---|
| Why is this a computer-networks project? | It implements and measures an HTTP client/server monitoring system, including application delivery, transport boundaries, network access security and per-IP behaviour. The models provide the security workload. |
| If TCP is reliable, why deduplicate? | A client can be uncertain whether a transaction committed before it retries. Transport reliability within a connection does not assign transaction IDs or suppress a second application request. |
| Is POST idempotent? | Not automatically. This API explicitly deduplicates event/review submissions using IDs and content. Creating a session does not have that guarantee. |
| Why reject late events? | Earlier outputs already represent a committed chronology. Accepting older input could change historical features and explanations. Starting a new ordered replay makes that change explicit. |
| Why does batch size change processing time? | Each append replays its stored prefix. Smaller batches require both more requests and more repeated inference, while exposing intermediate results sooner. |
| Can you call the timing difference network latency? | No. It includes uninstrumented service, commit, transfer and proxy work. We report the two measured timers separately. |
| What happens after a restart? | On retained local disk the service reloads raw events and reconstructs model state by replay. The free cloud host may replace temporary disk, so that persistence guarantee is not available there. |
| How are users isolated? | A random bearer capability is required for each session; only its hash is stored. This is demo capability access, not an identity or roles system. |
| Does CORS secure the API? | CORS controls browser access across origins. The bearer capability authorizes session operations; a non-browser client is not stopped by CORS. |
| Are the IP addresses actual captured traffic? | No. They are synthetic access-log fields. Actual HTTP(S) requests transport those records to the backend during the network experiment. |
| What does 100% precision mean here? | At one frozen threshold on the supplied synthetic benchmark, no returned alerts are false positives, but more than half the attacks are missed. It is not general real-world accuracy. |
| What did you build versus reuse? | Show the contribution matrix, relevant commits and tests. Credit the supplied generator, model pipeline, trained artifacts and original evaluation. |

## Submission contents

Use [ACADEMIC_REPORT.md](ACADEMIC_REPORT.md) as the current report, [NETWORK_LAB.md](NETWORK_LAB.md) as the lab manual, [RESULTS.md](RESULTS.md) and its JSON files as experimental evidence, and [BACKEND.md](BACKEND.md) for installation. Include the current source revision, CI link, public demo URL and [LICENSE](../LICENSE). The original submitted report/deck remain attributed baseline references; they predate the live service.

Add your course, team details and required formatting only after checking the actual rubric. Rehearse explaining the store transaction and one network experiment without relying on the slides or dashboard text.
