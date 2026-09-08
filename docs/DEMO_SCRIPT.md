# Three-minute internship demo

## Connected backend demonstration

Open **Live inference**, create a session, select **Score baseline**, then **Score attack campaign**. Inspect event 167: the model reports credential stuffing with evidence of twelve accounts sharing a source with a high failure rate. Save a disposition, refresh server state, and show the retained review history. Export the evidence JSON. Explain that these are new server-computed scores for synthetic inputs, and that the coverage policy also flags baseline false positives. The API currently uses bounded event-log replay, not a high-throughput stream processor. Hosting status and availability are in [PUBLIC_DEPLOYMENT.md](PUBLIC_DEPLOYMENT.md).

The original three-minute benchmark demonstration follows.

## 0:00-0:25 — State the problem and boundary

“This project ranks suspicious identity and device access events for a security analyst. The demo uses a synthetic chronological replay; the Python CLI also scores raw events using saved models.”

Open `assets/SentinelUEBA-React-Console.html`. Point out **Synthetic replay** and the selected policy. Explain recorded authorship and your own extensions where relevant.

## 0:25-1:05 — Explain the operating trade-off

The initial top-2% policy shows 3,097 alerts, 73.7% precision and 99.3% attack recall. Switch to top 1%: 1,074 alerts, 100% precision, 46.7% recall. Explain that thresholds were fixed on validation and that the high-precision policy misses both impossible travel and device spoofing in this test.

Return to top 2%. This demonstrates an operational decision, not just a headline metric.

## 1:05-1:50 — Investigate one case

Search for `U0186`, open an exfiltration event, and show its resource, time, risk trace and model channels. Explain that feature attributions and rule evidence help investigation; neither proves an event malicious or benign. Different channel scores are not independent votes.

Show Topology and select a principal to return to its underlying alert. Explain that the graph visualises connections; it does not implement graph-based detection.

## 1:50-2:15 — Record the decision

Add an investigation note and save a disposition. Show Export decisions. The JSON is also displayed for browsers that suppress downloads. Explain the separate preview/import step, preserved CSV history, and why a button does not instantly retrain the model. Use `--feedback-path output/demo_feedback.csv` for rehearsal imports so demo decisions do not affect training.

## 2:15-3:00 — Defend the evidence

Open Model audit. Explain chronological splitting, purge gaps, validation-fitted thresholds and why PR-AUC is useful for rare attacks. State the two main limitations: same-generator synthetic evaluation and no successful independent real-attack benchmark yet.

Finish with the actual next experiment: a held-out attack family or campaign shift, with frozen thresholds and per-family/incident recall. Have the test output and CLI replay ready as technical backup.

## Interview questions to prepare

- Why did the simpler classifier-led strategy win?
- Which features require historical state, and what happens after a restart?
- Why can perfect precision coexist with low recall?
- Why are the SPEDIA proxy labels insufficient to establish real-attack accuracy?
- Why are profile-poisoning protection and counterfactual claims still limited?
- What did you personally implement, how did you test it, and what failed during development?

## Résumé wording

Use [Harthik's ML and Data Engineering portfolio pack](PORTFOLIO.md) for the current project pitch, separate résumé versions for each role, and the five-minute walkthrough. It centres the inference application, reliable event pipeline, deployment and experiments. Inspiration and retained components are documented in [PROVENANCE.md](PROVENANCE.md).
