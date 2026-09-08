# Measured networking results

**Both local and Render experiments passed.** Each environment completed nine trials and eleven application-delivery correctness checks. The 168-event input, policy and model/source identity were fixed. Within each environment, every trial matched its full-replay reference on event IDs, labels, flags and all seven compared numeric channels; the maximum observed numeric difference was zero.

Recorded on **9 September 2026 IST** (8 September UTC). These are small, sequential, warmed replay experiments, not production capacity or tail-latency benchmarks.

## Batching results

All times below are seconds. Each cell reports the median of three independent fresh-session trials; client ranges are minimum–maximum. Client totals cover ingestion requests only, excluding warm-up, session creation, snapshot reads and correctness exercises.

| Environment | Events / batch | POSTs / replay | Client median | Client range | Server work median |
|---|---:|---:|---:|---:|---:|
| Windows local, loopback HTTP | 42 | 4 | 7.359 | 7.327–8.787 | 7.259 |
| Windows local, loopback HTTP | 84 | 2 | 4.766 | 4.163–4.858 | 4.686 |
| Windows local, loopback HTTP | 168 | 1 | 3.148 | 3.079–3.749 | 3.127 |
| Render Free, public HTTPS | 42 | 4 | 30.244 | 30.176–30.377 | 29.605 |
| Render Free, public HTTPS | 84 | 2 | 18.142 | 17.965–18.211 | 17.768 |
| Render Free, public HTTPS | 168 | 1 | 11.663 | 11.586–12.083 | 11.381 |

The one-batch Render median was about 61% lower than the four-batch median. This is an observation about the existing replay design: fewer requests also reduce repeated model computation from 420 to 168 event evaluations. It is not a measurement of TCP optimization, and fewer intermediate responses are available with a large batch. Most observed completion time is covered by the server-work timer. The local and Render machines have different compute environments, so their timing difference cannot be attributed solely to internet transport.

Total serialized request bodies were 65,162 bytes at batch size 42, 65,138 at 84, and 65,126 at 168. The payload stays almost constant because every trial sends the same events; this excludes HTTP headers and transport overhead. No network RTT, packet-loss, peak-throughput or p95 claim is made. See the [measurement definitions](NETWORK_LAB.md#measurement-definitions).

## Correctness outcomes

| Exercise | Local | Render | Observation |
|---|---|---|---|
| Batch-boundary equivalence | Pass | Pass | Nine trials match their environment's full-replay reference |
| Ignored acknowledgement followed by retry | Pass | Pass | Zero new events, 168 duplicates; stored outputs unchanged |
| Conflicting event ID | Pass | Pass | HTTP 409 |
| Late event with a new ID | Pass | Pass | HTTP 409 |
| Reversed new-event batch | Pass | Pass | HTTP 422 |
| Rejection atomicity | Pass | Pass | Stored event outputs unchanged after all invalid submissions |
| Missing session token | Pass | Pass | HTTP 401 |
| Cross-session access | Pass | Pass | HTTP 401; fresh session contains no other visitor's events |
| Repeated review request | Pass | Pass | Duplicate acknowledged without an extra audit record |
| Conflicting review request ID | Pass | Pass | HTTP 409 |
| Review history readback | Pass | Pass | Exactly two ordered revisions retained |

The acknowledgement exercise deliberately ignores a successful application response before resending. It does not inject packet loss. Local restart/replay equivalence is covered separately by the real-model regression test. The full Python suite passed **41 tests**, with no skips, during this update. The frontend production build passed TypeScript checking. Browser verification also covered the displayed IP context and recovery from an unavailable prior session.

The demonstration flagged 56 of 120 intended-baseline events and all 48 staged campaign events in both environments. These are synthetic scenario outcomes with many baseline alerts, not held-out detection precision. The original attributed synthetic benchmark is documented separately in the [academic report](ACADEMIC_REPORT.md#6-results-and-discussion).

## Evidence and reproduction

| Evidence | Readable report | Raw measurements |
|---|---|---|
| Local: 19:25:44–19:26:37 UTC | [Local report](experiments/network-local.md) | [Local JSON](experiments/network-local.json) |
| Render: 19:26:39–19:30:00 UTC | [Render report](experiments/network-render.md) | [Render JSON](experiments/network-render.json) |

- Input SHA-256: `a5fce92b55ed9191e39ded4355ff1d5b37bd709e7b5c28289c521e22d82f0387`.
- Model/source identity: `91f67dfe56ef23644bd7aa12cc1e917e6faa844a7cbeedf1c536ace57086504e`.
- Executed harness SHA-256: `336ffb565e608f0c7f1a77426008017fabefbe5c81358791e32f08ca4af79c95`.
- The reports identify the pre-extension checkout revision; the then-uncommitted harness is identified by its content hash. This update changes client presentation, experiment tooling and documentation, while retaining the measured inference implementation and trained artifacts.

The published JSON contains 42 POST requests per environment, plus GET requests, and no session tokens. Follow [NETWORK_LAB.md](NETWORK_LAB.md#reproduce-locally-at-no-hosting-cost) to rerun. GitHub Actions additionally executes a shorter two-trial experiment against a real loopback HTTP server and uploads evidence for each workflow run. The deployed service remains on Render Free; its storage and idle behaviour are documented in [PUBLIC_DEPLOYMENT.md](PUBLIC_DEPLOYMENT.md).
