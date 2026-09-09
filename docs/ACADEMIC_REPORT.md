# SentinelUEBA: ML-Powered Network Access Analytics

**Modified project by Harthik M V** · Aspiring Machine Learning Engineer / Data Engineer

Computer Networks course project · Packet-to-flow ML and reliable event processing · September 2026

[Packet demonstration](https://sentinelueba-harthik.onrender.com/#packets) · [Access-log demonstration](https://sentinelueba-harthik.onrender.com/#live) · [Source](https://github.com/Harthik777/CN-Project) · [Experiment results](RESULTS.md)

## Abstract

SentinelUEBA is Harthik M V's modified project combining packet-level network analysis, machine learning and reliable data processing. Its PCAP pipeline decodes IPv4/IPv6 TCP/UDP headers, aggregates bidirectional flows and verifies matching TCP handshake evidence. Thirteen flow features feed a separately trained Isolation Forest; capture hashes, typed flow records and model identities are persisted transactionally in SQLite. A second pipeline serves pretrained UEBA models on validated chronological access logs. A React client connects both pipelines to FastAPI over HTTPS. Evaluation includes capture-disjoint synthetic model tests, independent packet decoding and application-level HTTP reliability experiments. The system is publicly deployed on a free hosting tier. Synthetic evaluation, bounded capture support and temporary cloud storage limit its claims.

## Packet-level CN extension

The [packet lab](PACKET_LAB.md) is the primary technical specification and viva guide for the core CN component. It covers PCAP record validation, network/transport header parsing, five-tuple grouping, sequence acknowledgements, timing definitions, skipped-packet accounting and unsupported cases. The implementation also adds SQL capture/flow tables, idempotent file ingestion, model versioning and exports.

The public sample contains 378 packets, 32 flows and 22 matching TCP handshakes. A separate synthetic flow model was trained on 480 benign flows, thresholded on 192 validation flows and evaluated on 256 flows from different captures. The test confusion matrix is TP=64, FP=13, TN=179, FN=0, with precision 83.12% and benign false-positive rate 6.77%. These are generated-pattern results, not real-traffic attack-detection accuracy. The packaged sample uses a further seed and is excluded from all three model splits. Tests regenerate the held-out captures and reproduce the confusion matrix without refitting.

There are 66 automated tests across the project, including 25 packet-parser, flow-model and capture-API tests. The packet HTTP lab adds 15 checks including independent dpkt agreement and saved-result consistency. The earlier access-log experiments below retain their original scope and timings.

## 1. Problem and objectives

An access-monitoring client can lose track of a response, repeat a submission, send events out of order or mix invalid and valid records. The server must avoid duplicate effects, preserve an understandable chronology and prevent one visitor from reading another visitor's results. It must also expose useful evidence rather than only an unexplained anomaly score.

The course objectives are to implement and evaluate: (1) a documented HTTP client/server protocol; (2) reliable application delivery with explicit failure behaviour; (3) chronological state and network-behaviour features; (4) isolated analyst review history; and (5) measured batching trade-offs on a deployed service. The model pipeline supplies a realistic computation workload and security use case.

## 2. Scope and contribution

**Harthik M V's project modifications** include the HTTP inference API, transactional event/review storage, session capabilities, live React integration, feedback validation, deployment, regression checks and networking experiments. Together these connect the ML computation to a tested data-processing and investigation workflow. Development used coding-assistant support.

The project was inspired by **Induj Gupta's SentinelUEBA work**. The current repository retains its MIT-licensed access-log generator and model-pipeline components, pretrained UEBA models and original evaluation artifacts. Those access-log benchmark metrics describe the retained artifacts. The packet parser, generated PCAP corpus, flow-model training and flow evaluation are new work in this modified project. See the [source and contribution record](PROVENANCE.md) for the component-level distinction.

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
