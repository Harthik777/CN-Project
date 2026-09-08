# SentinelUEBA public demo

This branch hosts the SentinelUEBA investigation frontend on GitHub Pages.

Open the [public demo](https://harthik777.github.io/CN-Project/) or the [complete app on Render](https://sentinelueba-harthik.onrender.com/#live). The Live inference view submits synthetic raw events to the Render-hosted FastAPI backend, displays newly computed model scores, and stores analyst reviews in a server-side SQLite audit. Hosting is independent of the developer's computer. The free Render instance can sleep when idle, and demo sessions on temporary disk can be lost on sleep/restart/redeployment; export evidence before leaving. The original Alerts, Topology and Model audit views remain a bundled synthetic benchmark replay.

Original code and submission: Induj Gupta, MIT license (see LICENSE). The current demo includes interface and feedback workflow improvements.

This deployment branch contains the built website, its license and this explanation. Source, tests, Dockerfile and deployment details are in the [codex/full-stack branch](https://github.com/Harthik777/CN-Project/tree/codex/full-stack). Analyst feedback does not automatically retrain the model.
