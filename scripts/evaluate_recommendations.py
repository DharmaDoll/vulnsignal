"""Prepare a blinded review or score a completed review against an independent watchlist."""
import argparse
import gzip
import json
import random
from datetime import datetime
from pathlib import Path

PROMPT = ("指定期間について、締切までに公表された情報から読むべき脆弱性を"
          "最大5件選んでください。各件のID、選定理由、根拠の出典を返してください。")


def prepare(artifact, simple, baseline, seed):
    report = artifact["report"]
    methods = {"rules": report["overall"], "baseline": baseline, "fixed_prompt": simple}
    # Judge each ID once, including IDs selected by multiple methods.
    candidates = sorted({v for ids in methods.values() for v in ids})
    random.Random(seed).shuffle(candidates)
    return {"period_start": artifact["period_start"], "cutoff": artifact["snapshot"]["cutoff"],
            "reviews": [{"vuln_id": v, "worth_reading": None, "source_supported": None} for v in candidates],
            "independent_watchlist": []}, methods


def score(ballot, methods):
    labels = {row["vuln_id"]: row["worth_reading"] for row in ballot["reviews"]}
    reference_times = {row["vuln_id"]: row["first_published_at"] for row in ballot["independent_watchlist"]
                       if isinstance(row, dict)}
    relevant = set(reference_times) | {v for v in ballot["independent_watchlist"] if isinstance(v, str)}
    unsupported = {row["vuln_id"] for row in ballot["reviews"] if row.get("source_supported") is False}

    result = {}
    for name, identifiers in methods.items():
        ids = set(identifiers)
        if any(type(labels.get(v)) is not bool for v in ids):
            raise ValueError("every selected item requires a boolean review")
        result[name] = {"published": len(ids), "worth_reading": sum(labels[v] for v in ids),
                        "precision": sum(labels[v] for v in ids) / len(ids) if ids else None,
                        "missed": sorted(relevant - ids), "unsupported": sorted(ids & unsupported),
                        "hours_from_publication_at_cutoff": {
                            v: round((datetime.fromisoformat(ballot["cutoff"]) -
                                      datetime.fromisoformat(reference_times[v])).total_seconds() / 3600, 2)
                            for v in sorted(ids & reference_times.keys())
                        }}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    prompt = actions.add_parser("prompt")
    prompt.add_argument("snapshot", type=Path)
    make = actions.add_parser("prepare")
    make.add_argument("snapshot", type=Path)
    make.add_argument("--simple-result", type=Path, required=True, help="JSON array of IDs from the fixed prompt")
    make.add_argument("--baseline", type=Path, help="JSON array of IDs when baseline is not archived")
    make.add_argument("--output-dir", type=Path, required=True)
    evaluate = actions.add_parser("score")
    evaluate.add_argument("ballot", type=Path)
    evaluate.add_argument("methods", type=Path)
    args = parser.parse_args()
    if args.action == "score":
        print(json.dumps(score(json.loads(args.ballot.read_text()), json.loads(args.methods.read_text())), indent=2))
        return
    with gzip.open(args.snapshot, "rt") as saved:
        artifact = json.load(saved)
    if args.action == "prompt":
        print(PROMPT)
        print(json.dumps({"start": artifact["period_start"], "cutoff": artifact["snapshot"]["cutoff"],
                          "timezone": artifact["timezone"], "period": artifact["period"]}, ensure_ascii=False))
        return
    if args.baseline:
        baseline = json.loads(args.baseline.read_text())
    elif "baseline" in artifact:
        baseline = [item["vuln_id"] for item in artifact["baseline"]["watch_now"]][:artifact["limit"]]
    else:
        parser.error("provide --baseline from the same decision cutoff")
    simple = json.loads(args.simple_result.read_text())
    for ids in (baseline, simple):
        if not isinstance(ids, list) or not all(isinstance(v, str) for v in ids):
            parser.error("comparison results must be JSON arrays of vulnerability IDs")
    ballot, methods = prepare(artifact, simple, baseline, artifact["snapshot"]["cutoff"])
    args.output_dir.mkdir(parents=True, exist_ok=False)
    for name, data in (("ballot", ballot), ("methods", methods)):
        (args.output_dir / f"{name}.json").write_text(json.dumps(data, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
