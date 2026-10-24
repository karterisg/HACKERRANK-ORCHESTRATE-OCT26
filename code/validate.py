#!/usr/bin/env python3
"""
Validates our output against sample_output.csv.
Run: python code/validate.py
"""
import csv, json
from pathlib import Path

REPO = Path(__file__).parent.parent
SAMPLE_REQUESTS = REPO / "dataset" / "sample_deletion_requests.csv"
SAMPLE_OUTPUT   = REPO / "dataset" / "sample_output.csv"
OUR_OUTPUT      = REPO / "output.csv"

def load(path):
    with open(path, encoding="utf-8-sig") as f:
        return {r["case_id"]: r for r in csv.DictReader(f)}

def main():
    sample  = load(SAMPLE_OUTPUT)
    ours    = load(OUR_OUTPUT)

    # Only compare cases that exist in sample_output
    sample_ids = set(sample.keys()) & set(ours.keys())
    if not sample_ids:
        print("No overlapping case_ids found. Make sure output.csv was generated.")
        return

    total = len(sample_ids)
    status_correct = 0
    step_details = []

    for cid in sorted(sample_ids, key=lambda x: int(x.replace("case_",""))):
        exp = sample[cid]
        got = ours[cid]

        exp_status = exp["deletion_status"]
        got_status = got["deletion_status"]
        status_ok  = exp_status == got_status

        if status_ok: status_correct += 1

        try: exp_steps = json.loads(exp["steps_json"])
        except: exp_steps = []
        try: got_steps = json.loads(got["steps_json"])
        except: got_steps = []

        # Step-level comparison
        exp_set = {(s["phase"],s["system_id"],s["resource_id"],s["operation"],s["state"]) for s in exp_steps}
        got_set = {(s["phase"],s["system_id"],s["resource_id"],s["operation"],s["state"]) for s in got_steps}
        matched = exp_set & got_set
        step_precision = len(matched)/len(got_set) if got_set else (1.0 if not exp_set else 0.0)
        step_recall    = len(matched)/len(exp_set) if exp_set else (1.0 if not got_set else 0.0)

        mark = "✓" if status_ok else "✗"
        if not status_ok or step_recall < 1.0:
            step_details.append((cid, exp_status, got_status, status_ok, step_recall, step_precision,
                                  exp_set - got_set, got_set - exp_set))
        print(f"{mark} {cid}: expected={exp_status:12s} got={got_status:12s} | steps recall={step_recall:.0%} precision={step_precision:.0%}")

    print()
    print(f"=== STATUS ACCURACY: {status_correct}/{total} = {status_correct/total:.1%} ===")

    if step_details:
        print("\n--- MISMATCHES / MISSING STEPS ---")
        for cid, exp_s, got_s, ok, recall, prec, missing, extra in step_details:
            if not ok:
                print(f"\n{cid}: expected {exp_s}, got {got_s}")
            if missing:
                print(f"  MISSING steps ({cid}):")
                for s in sorted(missing): print(f"    {s}")
            if extra:
                print(f"  EXTRA steps ({cid}):")
                for s in sorted(extra): print(f"    {s}")

if __name__ == "__main__":
    main()
