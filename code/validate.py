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

        mark = "OK" if status_ok else "FAIL"
        if not status_ok or step_recall < 1.0:
            step_details.append((cid, exp_status, got_status, status_ok, step_recall, step_precision,
                                  exp_set - got_set, got_set - exp_set))
        print(f"{mark} {cid}: expected={exp_status:12s} got={got_status:12s} | steps recall={step_recall:.0%} precision={step_precision:.0%}")

    # Aggregate step metrics
    all_exp, all_got, all_matched = 0, 0, 0
    f1_sum = 0.0
    for cid in sorted(sample_ids):
        exp = sample[cid]; got = ours[cid]
        try: es = json.loads(exp["steps_json"])
        except: es = []
        try: gs = json.loads(got["steps_json"])
        except: gs = []
        exp_set = {(s["phase"],s["system_id"],s["resource_id"],s["operation"],s["state"]) for s in es}
        got_set = {(s["phase"],s["system_id"],s["resource_id"],s["operation"],s["state"]) for s in gs}
        matched = exp_set & got_set
        all_exp += len(exp_set); all_got += len(got_set); all_matched += len(matched)
        p = len(matched)/len(got_set) if got_set else (1.0 if not exp_set else 0.0)
        r = len(matched)/len(exp_set) if exp_set else (1.0 if not got_set else 0.0)
        f1_sum += (2*p*r/(p+r)) if (p+r) > 0 else 0.0

    macro_p = all_matched/all_got if all_got else 1.0
    macro_r = all_matched/all_exp if all_exp else 1.0
    avg_f1  = f1_sum / total

    # Exact sequence matching
    exact_seq = 0
    for cid in sorted(sample_ids):
        exp = sample[cid]; got = ours[cid]
        try: es = json.loads(exp["steps_json"])
        except: es = []
        try: gs = json.loads(got["steps_json"])
        except: gs = []
        def norm(steps):
            return [(s["phase"],s["system_id"],s["resource_id"],s["operation"],s["state"]) for s in steps]
        if norm(es) == norm(gs): exact_seq += 1

    print()
    print(f"=== STATUS ACCURACY: {status_correct}/{total} = {status_correct/total:.1%} ===")
    print(f"=== Exact sequence: {exact_seq}/{total} = {exact_seq/total:.1%} ===")
    print(f"=== Step precision: {macro_p:.1%}  recall: {macro_r:.1%}  avg-F1: {avg_f1:.1%} ===")

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
