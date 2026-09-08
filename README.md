# SentinelUEBA public demo

This branch hosts the SentinelUEBA investigation frontend on GitHub Pages.

Open the [public demo](https://harthik777.github.io/CN-Project/). The Live inference view submits synthetic raw events to a FastAPI backend, displays newly computed model scores, and stores analyst reviews in a server-side SQLite audit. The backend currently uses a temporary public tunnel from the project host computer and is available only while that computer and service stay online. Permanent backend hosting still needs a valid provider connection. The original Alerts, Topology and Model audit views remain a bundled synthetic benchmark replay.

Original code and submission: Induj Gupta, MIT license (see LICENSE). The current demo includes interface and feedback workflow improvements.

This deployment branch contains the built website, its license and this explanation. Source, tests, Dockerfile and deployment details are in the [codex/full-stack branch](https://github.com/Harthik777/CN-Project/tree/codex/full-stack). Analyst feedback does not automatically retrain the model.
