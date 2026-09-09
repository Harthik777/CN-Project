"""Inference on packaged flow-model artifacts, never on uploaded model files."""
import hashlib
import json
from pathlib import Path

from backend.packets import FEATURE_NAMES, extract_flows, flow_features

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts" / "packet_flow"


class FlowScorer:
    def __init__(self):
        import joblib
        self.metadata = json.loads((ARTIFACTS / "flow_model.json").read_text(encoding="utf-8"))
        model_file = ARTIFACTS / "flow_model.joblib"
        if hashlib.sha256(model_file.read_bytes()).hexdigest() != self.metadata["artifact_sha256"]:
            raise RuntimeError("Flow model artifact hash does not match its manifest")
        if self.metadata["features"] != FEATURE_NAMES:
            raise RuntimeError("Flow model feature schema does not match the extractor")
        if hashlib.sha256((ROOT / "backend" / "packets.py").read_bytes()).hexdigest() != self.metadata["extractor_sha256"]:
            raise RuntimeError("Flow extractor changed; reproduce and evaluate the flow model before serving")
        self.model = joblib.load(model_file)
        digest = hashlib.sha256()
        for path in (model_file, ARTIFACTS / "flow_model.json", ROOT / "backend" / "packets.py", Path(__file__)):
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
        self.model_id = digest.hexdigest()

    def __call__(self, data):
        result = extract_flows(data)
        scores = -self.model.score_samples([flow_features(row) for row in result["flows"]])
        for row, score in zip(result["flows"], scores):
            row.update(anomaly_score=float(score), is_alert=bool(score > self.metadata["threshold"]),
                       features=dict(zip(FEATURE_NAMES, flow_features(row))))
        result["model"] = {k: self.metadata[k] for k in ("version", "model", "training_scope", "feature_count", "train_flows",
                            "validation_flows", "test_flows", "threshold", "threshold_selection", "test_metrics")}
        result["model"]["model_id"] = self.model_id
        result["summary"]["flagged_flows"] = sum(row["is_alert"] for row in result["flows"])
        result["limitations"] = ["Scores measure deviation from a synthetic baseline; they are not attack probabilities.",
            "No payload storage, TLS decryption, TCP stream reassembly, or IP fragment reassembly.",
            "Absent handshakes can reflect partial captures; repeated sequence ranges can reflect duplicate capture.",
            "IP bytes exclude link headers; timing comes from capture timestamps at one observation point.",
            "Flow features summarize the uploaded capture; this is offline analysis, not causal live packet detection."]
        return result
