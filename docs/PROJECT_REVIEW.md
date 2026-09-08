# Internship and academic project review

Reviewed 8 September 2026 against the supplied archive, source code, recorded evidence and running demo. The linked GitHub repository was empty at inspection.

## Assessment

**A strong portfolio foundation, roughly 7/10 in its submitted state on my qualitative rubric.** The project has enough depth for serious interview discussion: causal features, multiple modelling approaches, operational thresholds, explanations, drift handling and a usable investigation console. It is substantially more developed than a notebook-only classifier.

The path to an exceptional project is stronger independent evidence and a reliable end-to-end system. More model names or a more elaborate graph would not resolve the current weaknesses. This rating is an assessment, not an external benchmark or a prediction of internship selection.

| Area | Assessment |
|---|---|
| Technical substance | Strong implementation breadth and causal feature design; selected strategy is mostly classifier-led |
| Demo | Useful alert investigation and topology; recorded replay rather than live ingestion |
| Evaluation | Chronological protocol and fixed thresholds are good; mostly evidence from one synthetic generator |
| Reproducibility | Artifacts and hashes are supplied; original quick-start/build defects required fixes |
| Research novelty | Practical integration is clear; a novel detection contribution remains to be demonstrated |
| Resume value | Good when the author's personal contributions and experimental boundaries are explicit |

## Verified evidence

Recomputing from `data/scored_events.parquet` reproduced PR-AUC **0.994323** and ROC-AUC **0.999422** on **115,360 held-out events**, including **2,300 attack events**.

| Policy | TP | FP | Precision | Recall |
|---|---:|---:|---:|---:|
| Top 1% threshold | 1,074 | 0 | 100.0% | 46.7% |
| Top 2% threshold | 2,284 | 813 | 73.7% | 99.3% |

At top 1%, detected attacks by family are brute force 883/1,588, credential stuffing 152/361, lateral movement 31/154, exfiltration 8/161, device spoofing 0/28 and impossible travel 0/8. At top 2%, these become 1,588/1,588, 361/361, 151/154, 148/161, 28/28 and 8/8 respectively.

This is a meaningful policy trade-off. The original top-1% headline emphasises a clean queue while sacrificing substantial coverage. Top 2% is a useful demo default, with the added workload shown openly. Its realised alert rate is 2.68%, not exactly 2%.

## Material gaps in the supplied project

1. **Independent generalisation is unproven.** Five unseen seeds still use the same generator. The SPEDIA probe's PR-AUC is 0.0176 against a severity proxy with 0.02095 positive prevalence. This does not demonstrate real-attack detection; it also does not establish why the detector missed the proxy positives. LANL has a harness but no executed result. A real, independently labelled benchmark is the most valuable academic upgrade.

2. **Streaming operation is incomplete.** `src/inference.py:score` constructs new feature, sequence and drift state for each replay. Splitting one stream into independent calls can change results. There is no persistent ingestion service, checkpoint/restart contract or documented late-event policy. The reported 19,539 events/s is a component batch benchmark, excluding feature replay and parts of orchestration/explanations/I/O; it is not a measured end-to-end streaming throughput.

3. **Poisoning protection is narrower than the report suggests.** `src/drift.py` protects its score-history updates using rules. `src/features.py` still updates entity and role byte/hour/resource/fingerprint profiles after every event. This does not demonstrate protection of all adaptive feature baselines. Add targeted adversarial tests before making a broad anti-poisoning claim.

4. **Feedback is a prototype workflow.** The original browser wrote only localStorage, despite promising availability to training. The original Python function removed earlier decisions for an event. These were corrected locally with export/import and preserved history. The training pipeline still needs a rolling-window design before held-out analyst decisions become useful future training data; it also needs distinct model/dataset identity and concurrent storage for a service.

5. **Explanation claims exceeded what was computed.** A rule threshold change does not prove the model or full system would classify an event as benign. Local code now calls these investigation guidance, and the UI stops calling an average of heterogeneous channel scores “consensus.” Verified counterfactual explanations would require constrained feature changes and rescoring.

6. **Handoff and authorship need care.** Several original quick-start paths and `build_submission.py` were absent; the frontend used `Array.at` with an ES2021 library target; the ZIP contained a full nested duplicate. Original documents and license credit Induj Gupta. Preserve that credit and document actual personal contributions.

## Highest-value next milestones

### 1. A complete replay service and network-data demonstration

Add one documented real telemetry adapter, explicit schema validation, a stateful scoring service and a browser connection to that service. Support checkpoint/restart and duplicate event handling. Keep a offline replay fallback for interviews.

**Acceptance:** one documented command starts the demo; the same chronological stream produces equivalent results uninterrupted, in chunks and after restart; malformed events receive clear errors; a staged attack appears with raw supporting evidence. Measure end-to-end p50/p95 latency and throughput on a named machine. These service and load-test milestones are not implemented in this review.

For a computer-networks course, explain where each observed field comes from, how the collector handles transport/ordering, and the difference between network metadata and identity logs. Currently the project's centre of gravity is security analytics and ML.

### 2. A rigorous generalisation experiment

Freeze model selection and thresholds before the final evaluation. Evaluate parameter-shifted campaigns, benign changes such as shared IPs/device replacement, and a held-out attack family. Run an appropriately labelled public authentication benchmark where available. Report the limitations when the available labels are only proxies.

**Acceptance:** publish dataset provenance and splits, simple rules-only/classifier-only/unsupervised baselines, per-family recall, uncertainty and false alerts per day. Compare with the simpler champion using the same analyst workload. Do not tune on the final test set. The original report already identifies much of this missing work.

### 3. Incident quality and an interview-ready handoff

Group repeated events into incidents and measure time to first detection, incident recall and analyst workload. Evaluate whether the additional grouping or detector improves results over a simple baseline. Publish the repository, a short demo recording, architecture and a contribution log after reviewing attribution.

**Acceptance:** demonstrate one attack investigation end to end; explain a false positive; show successful CI from a fresh checkout; explain every major design decision and what failed. Use the accompanying [demo script](DEMO_SCRIPT.md).

## Changes delivered locally

The workspace now has a runnable source layout, corrected README/quick start, explicit replay labels, policy-specific recall, coverage default, honest explanation labels, browser decision export, snapshot-checked Python import, append-only feedback records, latest-decision overrides, regression tests and a GitHub Actions workflow. Original metrics/models remain baseline evidence; no new model-training claim is made. See [provenance](PROVENANCE.md).

Python verification passed **28 tests with zero skips** after installing missing dependencies. The saved-model inference smoke test processed **25,000 raw events**. The frontend successfully type-checked and built with Node 24 after correcting the ES2021 incompatibility and reinstalling optional native dependencies with the correct Node/npm runtime. The new CI configuration has not run on GitHub.

With scikit-learn 1.8.0, all 25,000 predicted labels matched the supplied inference sample. Maximum absolute risk-score difference was approximately `1.715e-8` risk points; this is numerical agreement, not a bit-for-bit or original-environment reproduction. Validation used Python 3.11.9, NumPy 2.2.4, pandas 2.3.2, LightGBM 4.6.0, PyTorch 2.13.0+cpu and PyArrow 23.0.1. Only missing packages were installed into a local ignored dependency directory; a clean-environment CI run remains to be performed after publication.

The browser save survived a reload. The visible JSON export was imported to a temporary audit CSV: preview found one new decision, apply wrote one, and repeating apply skipped it. The embedded browser did not emit a download event, so the console also exposes copyable JSON as a portable fallback. Production feedback was not modified during verification.

Do not call this production-ready or a proven novel detector yet. It can be a credible internship portfolio project when its working demo, your contributions and the evaluation boundaries are presented accurately.

## Public demo deployment

The user's subsequent request to publish a public URL has been completed: [Open SentinelUEBA](https://harthik777.github.io/CN-Project/). GitHub Pages successfully built and deployed the static console. An anonymous HTTPS request returned HTTP 200 and exactly the locally tested HTML bytes. Public browser checks covered policy switching, topology and Model audit, with no captured browser console errors. This deployment does not implement the live inference service or server-side feedback milestones above. Full details are in the [deployment record](PUBLIC_DEPLOYMENT.md).
