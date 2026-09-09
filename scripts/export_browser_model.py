"""Export the trusted Isolation Forest as numeric trees for offline browser inference.

No training, network access, executable model code, or uploaded model files.
The Python scorer remains the reference implementation used by parity checks.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from backend.flow_model import ARTIFACTS, FlowScorer
from sklearn.ensemble._iforest import _average_path_length


def export():
    scorer = FlowScorer()
    model = scorer.model
    trees = []
    for estimator, features in zip(model.estimators_, model.estimators_features_):
        tree = estimator.tree_
        depths = tree.compute_node_depths() - 1
        adjustment = _average_path_length(tree.n_node_samples)
        trees.append([[int(tree.children_left[i]), int(tree.children_right[i]),
                       int(features[tree.feature[i]]) if tree.children_left[i] != -1 else -1,
                       float(tree.threshold[i]), float(depths[i] + adjustment[i])]
                      for i in range(tree.node_count)])
    reference = scorer((ARTIFACTS / "sample_capture.pcap").read_bytes())
    return {"schema": 1, "features": scorer.metadata["features"],
            "normalizer": float(len(trees) * _average_path_length([model.max_samples_])[0]),
            "trees": trees, "model": reference["model"], "limitations": reference["limitations"],
            "sample_sha256": scorer.metadata["sample_sha256"],
            "artifact_sha256": scorer.metadata["artifact_sha256"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = ARTIFACTS / "browser_model.json"
    encoded = json.dumps(export(), separators=(",", ":"), allow_nan=False) + "\n"
    if args.check:
        assert target.read_text(encoding="utf-8") == encoded, "Browser forest must be re-exported"
        print("Browser forest matches the trusted Python model")
    else:
        target.write_text(encoded, encoding="utf-8", newline="\n")
        print(f"Exported {target.name}: {len(encoded)} bytes")
