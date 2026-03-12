#!/usr/bin/env python3
"""
Re-score saved agent outputs with the current scorer and update an existing
benchmark_report.json (scores, field_scores, aggregate main/total score).

When using -R, expects results_dir to be under project_root/results/
(e.g. results/pe_qwen_qwen3-coder-plus). Ground truth directory is then
inferred (ground_truths_pe for PE, ground_truths for ELF) from task_ids
in the report.

Usage:
  python scripts/rescore_report.py \\
    --ground-truth ground_truths_pe/ \\
    --agent-outputs results/pe_qwen_qwen3-coder-plus/agent_outputs/ \\
    --report results/pe_qwen_qwen3-coder-plus/benchmark_report.json

Or from project root with defaults for a given run:
  python scripts/rescore_report.py -R results/pe_qwen_qwen3-coder-plus
"""

import argparse
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Re-score agent outputs and update benchmark_report.json")
    parser.add_argument("--ground-truth", "-G", required=False, help="Ground truth JSON directory (e.g. ground_truths_pe/)")
    parser.add_argument("--agent-outputs", "-A", required=False, help="Agent output JSON directory")
    parser.add_argument("--report", "-r", required=False, help="Path to benchmark_report.json to update in place")
    parser.add_argument("-R", "--results-dir", help="Results directory (e.g. results/pe_qwen_qwen3-coder-plus); uses -G ground_truths_pe, -A <dir>/agent_outputs, -r <dir>/benchmark_report.json")
    args = parser.parse_args()

    if args.results_dir:
        root = Path(args.results_dir).resolve()
        if not root.is_dir():
            print(f"Error: not a directory: {root}", file=sys.stderr)
            sys.exit(1)
        # PE vs ELF: detect by presence of pe_level in agent_outputs or report
        report_path = root / "benchmark_report.json"
        if not report_path.exists():
            print(f"Error: no benchmark_report.json in {root}", file=sys.stderr)
            sys.exit(1)
        agent_dir = root / "agent_outputs"
        if not agent_dir.exists():
            print(f"Error: no agent_outputs in {root}", file=sys.stderr)
            sys.exit(1)
        with open(report_path) as f:
            data = json.load(f)
        task_ids = [m["task_id"] for m in data.get("task_metrics", [])]
        if task_ids and task_ids[0].startswith("pe_"):
            gt_dir = root.parent.parent / "ground_truths_pe"  # project_root/ground_truths_pe
        else:
            gt_dir = root.parent.parent / "ground_truths"
        gt_dir = gt_dir.resolve()
        if not gt_dir.is_dir():
            print(f"Error: ground truth dir not found: {gt_dir}", file=sys.stderr)
            sys.exit(1)
        ground_truth_dir = gt_dir
        agent_outputs_dir = agent_dir
        report_file = report_path
    else:
        if not args.ground_truth or not args.agent_outputs or not args.report:
            parser.error("Provide either -R RESULTS_DIR or -G, -A, and -r")
            return
        ground_truth_dir = Path(args.ground_truth)
        agent_outputs_dir = Path(args.agent_outputs)
        report_file = Path(args.report)

    project_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(project_root))

    from scorer import score_batch

    results = score_batch(str(ground_truth_dir), str(agent_outputs_dir))
    if not results:
        print("No score results; check that agent_outputs and ground_truth filenames match.", file=sys.stderr)
        sys.exit(1)

    by_sample = {r["sample"]: r for r in results}

    with open(report_file) as f:
        report = json.load(f)

    # Update task_metrics
    for m in report.get("task_metrics", []):
        sid = m["task_id"]
        if sid not in by_sample:
            continue
        s = by_sample[sid]
        m["score"] = s["final_score"]
        m["field_scores"] = s["field_scores"]
        m["hallucinated_techniques"] = s.get("hallucinated_techniques", [])
        m["missing_techniques"] = s.get("missing_techniques", [])
        m["hallucination_count"] = len(s.get("hallucinated_techniques", []))

    # Update score_results
    for i, r in enumerate(report.get("score_results", [])):
        sid = r.get("sample")
        if sid not in by_sample:
            continue
        s = by_sample[sid]
        report["score_results"][i] = {
            "tier": s.get("tier", "standard"),
            "field_scores": s["field_scores"],
            "hallucinated_techniques": s.get("hallucinated_techniques", []),
            "missing_techniques": s.get("missing_techniques", []),
            "hallucination_penalty": s.get("hallucination_penalty", 0),
            "weighted_score": s.get("weighted_score", 0),
            "final_score": s["final_score"],
            "sample": sid,
        }

    # Recompute aggregate scores
    standard = [r for r in results if r.get("tier") == "standard"]
    bonus = [r for r in results if r.get("tier") == "bonus"]
    main_score = sum(r["final_score"] for r in standard) / len(standard) if standard else 0.0
    bonus_score = bonus[0]["final_score"] if bonus else 0.0
    total_score = main_score + bonus_score

    if "aggregate_metrics" in report:
        report["aggregate_metrics"]["main_score"] = round(main_score, 4)
        report["aggregate_metrics"]["bonus_score"] = round(bonus_score, 4)
        report["aggregate_metrics"]["total_score"] = round(total_score, 4)
        if standard:
            report["aggregate_metrics"]["avg_hallucination_rate"] = round(
                sum(len(r.get("hallucinated_techniques", [])) for r in standard) / len(standard), 4
            )

    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Updated {report_file}")
    print(f"  main_score:  {main_score:.4f}")
    print(f"  bonus_score: {bonus_score:.4f}")
    print(f"  total_score: {total_score:.4f}")


if __name__ == "__main__":
    main()
