# Harthik M V — ML and Data Engineering Portfolio

**Aspiring Machine Learning Engineer / Data Engineer**

Project: [SentinelUEBA packet analysis](https://sentinelueba-harthik.onrender.com/#packets) · [GitHub](https://github.com/Harthik777/CN-Project)

## Packet-to-flow résumé entry

**SentinelUEBA: Network Flow Analytics and ML Anomaly Detection**

- Built and deployed a Dockerized FastAPI and React application that parses IPv4/IPv6 TCP/UDP captures into bidirectional flows, validates TCP handshake evidence and serves anomaly scores from 13 flow features.
- Trained an Isolation Forest on 480 benign flows, selected a threshold on 192 validation flows and evaluated 256 flows from separate synthetic captures, obtaining 83.12% precision and a 6.77% benign false-positive rate.
- Engineered a Python and SQLite packet-to-flow pipeline with capture SHA-256 lineage, typed SQL flow records, transactional ingestion, idempotent retries and CSV/JSON exports.
- Verified the application with 66 automated tests and a 15-check packet HTTP harness that compares headers, lengths and flow counts with an independent decoder; integrated verification into GitHub Actions.

Use the explicit synthetic qualifier on the ML metrics. The separate four-component pretrained UEBA pipeline and measured 61.4% cloud replay reduction remain useful additional talking points; their workload and attribution details appear below. The packet module is the stronger lead for a combined core-CN and ML/data-engineering résumé entry.

## Project title and pitch

**SentinelUEBA — ML-Powered Network Access Analytics**

“My modified SentinelUEBA project turns network packet captures into structured TCP/UDP flows and ML anomaly evidence. I built header parsing and handshake inspection, trained and evaluated a separate flow model on reproducible synthetic captures, and deployed the pipeline with transactional SQL storage and a public React demo. The project also serves pretrained access-log models and measures HTTP delivery reliability. It connects core Computer Networks concepts with my ML and data engineering interests.”

Short profile: “Aspiring Machine Learning Engineer / Data Engineer interested in turning event data and trained models into reliable, explainable applications.”

Inspiration and retained code/model components are acknowledged in [PROVENANCE.md](PROVENANCE.md), alongside the modifications and coding-assistant support. The project title and résumé bullets below focus on the implemented engineering work.

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

## Machine Learning Engineer résumé version

- Integrated PyTorch autoencoder/GRU models, Isolation Forest and LightGBM into a FastAPI inference service with causal features, risk scores and investigation explanations.
- Developed a React model-investigation workflow with policy thresholds, per-IP context and server-side analyst feedback; deployed the application using Docker and Render.
- Verified inference consistency across batch boundaries and local restart, with 41 automated tests and reproducible HTTP experiments covering 18 local/cloud timing trials.

Skills demonstrated: **Python, PyTorch, scikit-learn, LightGBM, feature computation, inference serving, evaluation, FastAPI, Docker**. The retained models are integrated pretrained components; the published benchmark is separate from the new service experiments.

## Data Engineer résumé version

- Built a validated event-ingestion workflow with UTC normalization, chronological replay, duplicate suppression and conflict detection, backed by transactional SQLite storage.
- Implemented isolated event histories and an append-only analyst-review audit with idempotent requests, versioned model/source identity and exportable evidence.
- Designed fixed-workload batching experiments across local and public-cloud APIs; all eleven delivery checks passed in each environment, with identical outputs across nine trials per environment.

Skills demonstrated: **Python, SQL/SQLite, data validation, event ordering, idempotency, transactional storage, HTTP APIs, reproducibility, GitHub Actions**. The current implementation uses bounded chronological replay and a single worker; it does not claim a distributed streaming engine.

Use two or three bullets for the target role and include the live demo and repository links. Keep synthetic model metrics, measured service timings and implemented features distinct.

## Interview walkthrough by role

| Target | Start with | Explain in code | Evidence |
|---|---|---|---|
| ML Engineer | Raw event → causal features → model scores → explanation | `src/inference.py`, `backend/app.py`, fixed policy thresholds and model/source identity | Real-model replay/restart regression, model audit and live scoring |
| Data Engineer | Validated request → ordered event log → transaction → replay | `backend/schemas.py`, `backend/store.py`, duplicate/conflict rules and review history | Rejected batches leave state unchanged; retries avoid extra writes |
| CN course assessment | HTTP client/server flow and per-IP behaviour | Protocol responses, session access and batching | [Network lab](NETWORK_LAB.md) and [measured results](RESULTS.md) |

## Viva preparation

| Question | Answer to understand and demonstrate |
|---|---|
| How does the model reach the application? | FastAPI loads saved models once, validates events, computes features and scores, and returns stored outputs to the React client. |
| How do you prevent future information from entering a prediction? | Feature and sequence construction use the available chronological prefix. Tests append future events and check that earlier features and compared outputs stay consistent. |
| What is your data-quality boundary? | The API rejects invalid fields, missing timezone offsets and extra target/score fields before writing. Event IDs and chronological rules provide additional integrity checks. |
| What is reproducible about the experiment? | Each trial uses the same input hash, model/source identity and policy, starts a fresh session and records the harness hash plus request measurements. |
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
| What did you modify, and what inspired it? | Explain the inference API, event/review pipeline, live UI, deployment and experiments in this project. The provenance record identifies the inspiration and retained baseline code/models. |

## Submission contents

Use [ACADEMIC_REPORT.md](ACADEMIC_REPORT.md) as Harthik's current project report, [NETWORK_LAB.md](NETWORK_LAB.md) as the lab manual, [RESULTS.md](RESULTS.md) and its JSON files as experimental evidence, and [BACKEND.md](BACKEND.md) for installation. Include the current source revision, CI link, public demo URL and [LICENSE](../LICENSE). Historical baseline documents remain in `original_submission/`; they predate the modified live application.

Add your course, team details and required formatting only after checking the actual rubric. Rehearse explaining the store transaction and one network experiment without relying on the slides or dashboard text.
