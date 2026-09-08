# Quick start

1. For the connected demo, follow [backend setup](docs/BACKEND.md) and open `http://127.0.0.1:7860/#live`. For the offline benchmark, open `assets/SentinelUEBA-React-Console.html` in a modern browser.
2. Follow [Harthik's ML/data engineering pitch and demo](docs/PORTFOLIO.md).
3. Read [the current academic report](docs/ACADEMIC_REPORT.md) and [measured experiment results](docs/RESULTS.md).
4. Use [README.md](README.md) for Python setup, tests, inference, frontend rebuild and feedback import.

The original technical report is at `docs/original_submission/02_TECHNICAL_REPORT/SentinelUEBA_Technical_Report.pdf`. It describes the supplied baseline and predates the current local improvements.

The offline console shows precomputed synthetic events. The CLI and live API run actual saved-model inference. The API provides bounded chronological replay with recoverable event history and server-side analyst feedback; permanent hosting status is recorded in [the deployment record](docs/PUBLIC_DEPLOYMENT.md).
