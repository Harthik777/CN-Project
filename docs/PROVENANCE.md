# Source and contribution record

The user supplied `SentinelUEBA_Honeywell_Submission (2).zip` for assessment and improvement on 8 September 2026.

- Archive SHA-256: `9f163be6d526ed217433c20d1ca03a6b1615ee0b259c6e65be7806089339a199`.
- Original README, report, deck and MIT license credit **Induj Gupta**. No authorship has been reassigned.
- All 85 file hashes listed in the supplied submission manifest matched at inspection. All listed run-manifest source and artifact hashes also matched the supplied source.
- The archive contains a duplicate nested submission: 86 nested files match their outer counterparts. This working copy uses the outer runnable project and omits Python bytecode caches.
- `artifacts/run_manifest.json` records the original training run. Its source hashes describe that baseline, not the edited workspace. Original evaluation evidence and documents are preserved in `docs/original_submission/`.
- Original trained weights, evaluation metrics and scored replay are retained. This review does not claim a new training experiment or independently reproduced cross-seed evaluation.

## Local changes during this review

| Component | Attribution / scope |
|---|---|
| Original generator, features, model pipeline, trained artifacts, original report and evaluation | Supplied Induj Gupta MIT-licensed submission; not newly trained by this extension |
| React usability and evidence/feedback changes | Current project extension with coding-assistant support |
| FastAPI protocol, capability sessions, SQLite event/review transactions, live integration and public deployment | Current project extension with coding-assistant support |
| HTTP networking experiments, CI socket integration, network evidence display, current academic and portfolio documentation | Current project extension with coding-assistant support; measurements produced by executing the published harness |

The experiment JSON records its input hash, model/source identity, checkout revision and harness hash. Results belong to the specified environment and workload. Neither generated documentation nor a deployed demo establishes individual mastery; personal contribution statements must reflect the student's actual work and understanding.

- Imported a usable project layout into the previously empty workspace.
- Fixed the ES2021 TypeScript incompatibility caused by `Array.at`.
- Documented the Node requirement and added a CI workflow for tests/builds.
- Displayed selected-policy recall beside precision; set the console's initial policy to top 2%; identified the data as synthetic replay.
- Replaced unverified benign-outcome wording with investigation guidance and renamed the arithmetic mean of channel scores accurately.
- Added snapshot-scoped browser decisions, export, strict Python import, duplicate protection and preview mode.
- Preserved historical Python feedback records; the latest decision governs training overrides.
- Added regression tests for audit history, import idempotency, snapshot mismatch and validation before writes.
- Rewrote the quick start and documented remaining validation work.

The working source, authored with assistance in this review, must be distinguished from the original submission in any academic report or résumé. Present the parts and decisions you understand and can explain. The GitHub repository supplied by the user was empty at the initial inspection. After the user explicitly requested a public URL, the built synthetic replay console and its MIT attribution were published on the `codex/public-demo` branch. A subsequent request for a connected backend adds the FastAPI service, bounded event-log replay, capability-isolated sessions, transactional feedback audit, HTTP smoke test and live React view. These extensions are separate from the original model training. See the [backend contract](BACKEND.md) and [deployment record](PUBLIC_DEPLOYMENT.md).
