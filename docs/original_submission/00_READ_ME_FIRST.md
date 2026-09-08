# SentinelUEBA - Honeywell Submission

Candidate: Induj Gupta
Institute: Manipal Institute of Technology, Bengaluru
Problem: Honeywell Campus Connect 2026 - Problem 4
Title: AI-Powered Behavioural Anomaly Detection for Cybersecurity

## Review order

1. `01_REQUIRED_PRESENTATION/SentinelUEBA_Honeywell_Required_Presentation.pptx`
2. `02_TECHNICAL_REPORT/SentinelUEBA_Technical_Report.pdf`
3. `03_OFFLINE_DEMO/SentinelUEBA_SOC_Console.html`
4. `04_RUNNABLE_PROJECT/`
5. `05_EVALUATION_EVIDENCE/`

## Fast verification

From `04_RUNNABLE_PROJECT`:

```powershell
python -m unittest discover -s tests -v
python -m src.inference `
  --input data/access_logs_sample.csv `
  --output data/inference_sample.parquet `
  --policy top_1pct
streamlit run dashboard/app.py
```

To rebuild the product frontend:

```powershell
cd frontend
npm ci
npm run build
```

The packaged tests run 25/25 with zero skips. The prebuilt React console requires
no installation, server, or internet connection.

## Evidence boundary

Primary labelled results are synthetic prototype evidence, not production
guarantees. The SPEDIA result is a chronological negative-control probe using a
rule-severity proxy. The LANL red-team harness is included but not executed
because the source dataset is access-gated and approximately 11 GB.

`SUBMISSION_MANIFEST.json` contains SHA-256 checksums for every included file.
