# SentinelUEBA: ML-Powered Network Access Analytics

**Modified project by Harthik M V** · Aspiring Machine Learning Engineer / Data Engineer

Computer Networks course project · ML inference and reliable event processing · September 2026

[Public demonstration](https://sentinelueba-harthik.onrender.com/#live) · [Source](https://github.com/Harthik777/CN-Project) · [Experiment results](RESULTS.md)

## Abstract

SentinelUEBA is Harthik M V's modified project combining machine learning inference and reliable event processing for network-access analytics. A React client sends validated event batches over HTTPS to a FastAPI service. The backend computes causal behavioural features, executes saved models, stores results in SQLite, and exposes source-IP evidence for investigation. The ML engineering focus is model integration, explainable serving and reproducibility; the data engineering focus is validation, chronology, duplicate handling and transactional audit history. As a Computer Networks course project, it evaluates application-level reliability and HTTP batching on identical workloads. The system is publicly deployed on a free hosting tier, with an offline benchmark console and a local API for rehearsals. Synthetic-data evaluation and temporary cloud storage bound its claims.

## 1. Problem and objectives

An access-monitoring client can lose track of a response, repeat a submission, send events out of order or mix invalid and valid records. The server must avoid duplicate effects, preserve an understandable chronology and prevent one visitor from reading another visitor's results. It must also expose useful evidence rather than only an unexplained anomaly score.

The course objectives are to implement and evaluate: (1) a documented HTTP client/server protocol; (2) reliable application delivery with explicit failure behaviour; (3) chronological state and network-behaviour features; (4) isolated analyst review history; and (5) measured batching trade-offs on a deployed service. The model pipeline supplies a realistic computation workload and security use case.

## 2. Scope and contribution

**Harthik M V's project modifications** include the HTTP inference API, transactional event/review storage, session capabilities, live React integration, feedback validation, deployment, regression checks and networking experiments. Together these connect the ML computation to a tested data-processing and investigation workflow. Development used coding-assistant support.

The project was inspired by **Induj Gupta's SentinelUEBA work**. The current repository also retains its MIT-licensed generator and model-pipeline components, pretrained models and original evaluation artifacts. The benchmark metrics describe those retained artifacts; the HTTP experiments measure the modified application. See the [source and contribution record](PROVENANCE.md) for the component-level distinction. No new model-training run is claimed in this report.

## 3. System design

The [network laboratory](NETWORK_LAB.md#architecture-and-protocol) contains component and message-sequence diagrams. The public endpoint serves the application and API on the same origin. A GitHub Pages frontend also connects to the API using a configured CORS origin. Render terminates public HTTPS and runs a single Docker API worker. SQLite stores sessions, raw events, scored outputs and review revisions.

The event schema includes timestamp, principal, source IP, protocol, accessed resource, authentication outcome, bytes and contextual device/geographic fields. IP addresses are validated; timestamps require offsets and are canonicalized to UTC. Labels and precomputed risk scores are rejected. These fields describe submitted synthetic access records, not traffic automatically collected from the browser.

Network evidence includes the number of accounts observed at an IP in the last hour, the IP's failure ratio and its five-minute activity. These windows include the current event and preceding events. Entity profiles and other causal features provide historical context. The saved autoencoder, Isolation Forest, GRU and LightGBM components feed the existing risk strategy and explanations. A fixed policy threshold determines the alert flag.

## 4. Delivery and security decisions

An event's key is its session and event ID. Repeating identical content returns a duplicate count without another write. Reusing the ID with different content returns HTTP 409. A new event older than the committed chronology also returns 409; a reversed batch or invalid field returns 422. The server validates the whole request before writes and commits event outputs transactionally.

For each append, the backend rebuilds causal state from the stored chronological prefix. This avoids persisting opaque mutable model state, makes local restart behaviour testable, and preserves batch-boundary equivalence for the tested channels. Repeated prefix work limits performance, so each session is capped at 1,000 events, with up to 250 per request. This is a bounded replay system.

The server returns a random session capability once and stores its hash. Subsequent reads, ingests and reviews require that bearer token. The frontend scopes its stored credential to the API origin and excludes it from exported evidence. Requests using another session's token fail. This provides isolated demo sessions; it does not implement institutional identity, user roles or account recovery.

Reviews have independent request IDs. Retrying a review is deduplicated; changing its content under the same key conflicts; a fresh key appends a revision. Reviews are read back from the server and do not trigger model retraining. Request-body, rate, session-capacity and lifetime limits constrain the free demonstration.

## 5. Experimental method

The networking experiment uses 120 baseline events and a 48-event staged credential-stuffing campaign. The same serialized input hash, model/source identity and policy apply to every trial. Three repetitions at batch sizes 42, 84 and 168 each start a fresh session. Trial order rotates, requests are sequential, and an initial full replay provides warm-up and reference outputs. JSON reports preserve measurements and implementation identity without session credentials.

The dependent measures are total ingestion request time, total reported server work, request count and JSON body bytes. Client time includes computation and HTTP transfer. Server timing covers inference and insert calls, but not the transaction commit. Therefore, their difference is not a network-only latency measurement. A larger batch changes both the number of network requests and the amount of repeated prefix computation; this confound is part of the documented replay architecture.

Correctness checks compare exact event IDs, labels and flags plus seven numeric channels at `1e-6` tolerance. Separate protocol exercises verify retries, conflict responses, chronology rejection, atomic validation, capability isolation and revision readback. They simulate an ignored application acknowledgement, not actual packet loss. The repository's real-model regression additionally reopens SQLite between batches.

## 6. Results and discussion

The current [results record](RESULTS.md) contains measured local and public-cloud outcomes and links to every raw trial. Consult it for numerical timings rather than copying a timing from an old demo session. The GitHub Actions workflow also checks the protocol through a real loopback HTTP connection and retains its evidence artifact.

In the live demonstration under the top-2% policy, the saved model flags 48 of 48 staged campaign events and 56 of 120 intended-baseline events. This is a functional scenario outcome with substantial baseline alerts; it is not held-out precision or evidence of universal attack detection.

The original supplied synthetic test contains 115,360 events, including 2,300 labelled attacks. At the fixed top-1% validation threshold it produces 1,074 true positives and no false positives, but only 46.7% attack recall. At top 2% it produces 2,284 true positives and 813 false positives, giving 73.7% precision and 99.3% recall. These illustrate the operational precision/recall trade-off. Threshold names are validation budgets; the realized test alert rates differ. These results belong to the attributed baseline, and the same-generator seed studies do not establish independent real-world generalization.

## 7. Deployment and reproducibility

The project runs on Render Free and does not require the developer's computer to keep serving its public URL. Docker builds the frontend and launches one API worker. GitHub Actions validates the Python suite, the HTTP experiment and the TypeScript production build. A separate branch publishes the alternative Pages frontend. [BACKEND.md](BACKEND.md) documents the commands, environment settings and API contract; [PUBLIC_DEPLOYMENT.md](PUBLIC_DEPLOYMENT.md) records deployment evidence.

The free service may sleep while idle and uses temporary disk. The stable URL does not imply durable session data. Export evidence for assessment and keep the locally runnable API and self-contained benchmark console available. No paid service is required for the documented workflow.

## 8. Limitations and future work

The principal limitations are synthetic telemetry, reused pretrained models, repeated prefix computation, small single-client timing samples, capability-based rather than institutional authentication, and ephemeral hosted state. The system does not currently capture packets, evaluate routing, inject real transport loss or demonstrate sustained high-volume ingestion.

The strongest future experiments would use an independently labelled network-access dataset with frozen thresholds, compare incremental state against the replay reference, and introduce controlled connection failures through a local test proxy. A packet-capture requirement can be addressed by the optional local Wireshark exercise. These additions should follow the course rubric rather than expand the project without a measurable question.

## References and supporting material

- [HTTP semantics, RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html), especially methods and idempotency.
- [TCP, RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html), reliable byte-stream service.
- [Render Free documentation](https://render.com/docs/free), hosting behaviour and limits.
- [Source attribution](PROVENANCE.md), [network laboratory](NETWORK_LAB.md), [measured results](RESULTS.md), [presentation and résumé pack](PORTFOLIO.md).
