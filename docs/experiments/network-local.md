# HTTP networking experiment

Status: **passed**. Target: http://127.0.0.1:7860

Recorded: 2026-09-08T19:25:44.293072+00:00. Model/source identity: `91f67dfe56ef23644bd7aa12cc1e917e6faa844a7cbeedf1c536ace57086504e`.

| Batch size | Repetitions | POSTs / trial | Client total ms, median (min–max) | Server work ms, median | Request body bytes, median |
|---:|---:|---:|---:|---:|---:|
| 42 | 3 | 4 | 7359.0 (7326.7–8787.1) | 7259.2 | 65162 |
| 84 | 3 | 2 | 4766.2 (4163.1–4857.6) | 4686.2 | 65138 |
| 168 | 3 | 1 | 3148.1 (3078.7–3748.8) | 3127.1 | 65126 |

All trials replay the same synthetic events into fresh sessions, using sequential requests and one reusable HTTP/1.1 client.
Client time includes HTTP and service work. Server work is the API's scoring_ms timer (inference plus inserts, excluding transaction commit).
Body bytes exclude headers, TLS and TCP/IP framing. The difference between timers is not pure network RTT.
Warm-up is recorded separately; these small samples do not estimate service capacity or tail latency.

## Correctness observations

- batch_equivalence: All 9 trials agree with full replay on IDs, labels, flags and seven numeric channels.
- acknowledgement_ignored_then_retried: 0 inserts, 168 duplicates; stored outputs unchanged.
- conflicting_event_id: HTTP 409.
- late_event: HTTP 409; a new ID does not bypass chronological ordering.
- reversed_batch: HTTP 422.
- rejections_are_atomic: All committed outputs unchanged after conflict, late, reversed and invalid requests.
- missing_token: HTTP 401.
- session_isolation: Other session token receives HTTP 401; its own session is empty.
- review_retry: Duplicate acknowledged without another audit row.
- conflicting_review_key: HTTP 409.
- audit_readback: Exactly two revisions retained after duplicate and conflicting requests.

Full measurements and methodology: [network-local.json](network-local.json).
