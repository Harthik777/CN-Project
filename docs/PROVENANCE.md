# Project ownership, inspiration and contribution record

**Current project owner: Harthik M V**

**Portfolio focus: Aspiring Machine Learning Engineer / Data Engineer**

This repository is Harthik's modified SentinelUEBA project. Its engineering focus is turning network-access events and saved models into a deployed inference and investigation application, with validated event processing, transactional audit history and reproducible experiments. It also supports Computer Networks coursework.

## Inspiration and retained components

Induj Gupta's SentinelUEBA work provided inspiration for this project. The repository also retains source components, pretrained model files and evaluation artifacts from that MIT-licensed baseline. The current application, modifications and experiments are recorded separately below. The original copyright/license notice remains in [LICENSE](../LICENSE).

The baseline archive `SentinelUEBA_Honeywell_Submission (2).zip` was supplied on 8 September 2026. Its traceability record is:

- Archive SHA-256: `9f163be6d526ed217433c20d1ca03a6b1615ee0b259c6e65be7806089339a199`.
- The baseline README, report, deck and MIT license credit **Induj Gupta**. That attribution applies to the retained baseline materials.
- All 85 file hashes listed in the supplied submission manifest matched at inspection. All listed run-manifest source and artifact hashes also matched the supplied source.
- The archive contains a duplicate nested submission: 86 nested files match their outer counterparts. This working copy uses the outer runnable project and omits Python bytecode caches.
- `artifacts/run_manifest.json` records the original training run. Its source hashes describe that baseline, not the edited workspace. Original evaluation evidence and documents are preserved in `docs/original_submission/`.
- Original trained weights, evaluation metrics and scored replay are retained. They are separate from the new HTTP experiments; no new training run or independently reproduced cross-seed evaluation is claimed.

## Modifications in Harthik's project

| Component | Attribution / scope |
|---|---|
| Original generator, feature/model pipeline, trained artifacts and baseline evaluation | Retained MIT-licensed baseline components from Induj Gupta's submission |
| ML application: saved-model serving, isolated inference sessions, live React investigation and feedback integration | Modifications in Harthik's project, developed with coding-assistant support |
| Data workflow: strict API schemas, canonical timestamps, transactional events/reviews, duplicate and conflict handling | Modifications in Harthik's project, developed with coding-assistant support |
| Docker/Render deployment, GitHub Actions and regression verification | Modifications in Harthik's project, developed with coding-assistant support |
| HTTP experiments, network evidence display, current academic report and ML/DE portfolio presentation | Modifications in Harthik's project; measurements produced by executing the published harness |
| PCAP parser, flow feature extraction, TCP handshake evidence, packet UI and transactional capture/flow tables | New extension in Harthik's modified project, developed with coding-assistant support |
| Packet-flow Isolation Forest, generated PCAP sample and capture-disjoint evaluation | Newly trained with `scripts/train_flow_model.py`; separate from the retained pretrained UEBA artifacts |
| Independent packet decoding and HTTP checks | `scripts/packet_lab.py` compares the server with dpkt 1.9.8; no dpkt code is copied into the parser |

The experiment JSON records its input hash, model/source identity, checkout revision and harness hash. Results describe the specified environment and workload. Coding-assistant support was used for implementation, testing, documentation and deployment of the current modifications.

- Imported a usable project layout into the previously empty workspace.
- Fixed the ES2021 TypeScript incompatibility caused by `Array.at`.
- Documented the Node requirement and added a CI workflow for tests/builds.
- Displayed selected-policy recall beside precision; set the console's initial policy to top 2%; identified the data as synthetic replay.
- Replaced unverified benign-outcome wording with investigation guidance and renamed the arithmetic mean of channel scores accurately.
- Added snapshot-scoped browser decisions, export, strict Python import, duplicate protection and preview mode.
- Preserved historical Python feedback records; the latest decision governs training overrides.
- Added regression tests for audit history, import idempotency, snapshot mismatch and validation before writes.
- Rewrote the quick start and documented remaining validation work.

The project is published under Harthik's GitHub account, with source on `codex/full-stack`, a Pages artifact on `codex/public-demo`, and a public Render service. The [backend contract](BACKEND.md), [deployment record](PUBLIC_DEPLOYMENT.md) and [ML/DE portfolio pack](PORTFOLIO.md) describe the current modified application. The retained baseline artifacts remain available for reproducibility and acknowledgement.
