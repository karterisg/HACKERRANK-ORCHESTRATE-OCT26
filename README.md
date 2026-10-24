# GDPR Deletion Audit Agent

An automated compliance tool that investigates whether a user's personal data has actually been removed across every system — not just the primary database.

## Why We Built This

Most deletion workflows work like this: a user requests account deletion, a job runs, the status flips to "Complete", and everyone moves on. The problem is that personal data rarely lives in just one place. It ends up in:

- Backup snapshots taken before the deletion ran
- Analytics platforms that cached the profile
- Support tickets that quoted personal details
- Search indexes that still return the user's name
- Integration pipelines that will sync the data back tomorrow

By the time anyone notices, there's a GDPR fine on the table and a very unhappy user who tried to create a new account and was told their email is "already registered."

This agent was built to catch that gap automatically — before it becomes a problem.

## What It Does

Give it a list of deletion requests and a set of evidence files (database snapshots, logs, JSON exports). It will:

1. Figure out if the request is actually asking for deletion (not an export or opt-out)
2. Recover all identifiers ever linked to that user — current email, old emails, internal IDs, hashed values
3. Search every evidence file for any record that can be tied back to the user
4. Check each record against a deletion policy (some things must be deleted, some redacted, some anonymized, some kept)
5. Return a verdict: **COMPLETE**, **INCOMPLETE**, or **NOT_APPLICABLE**
6. If incomplete, list exactly what still needs to happen — findings, remediation steps, and verification checks — in the order they should be executed

## Output

```csv
case_id,deletion_status,steps_json
```

Each step in `steps_json` looks like:

```json
{
  "step_no": 1,
  "phase": "FINDING",
  "system_id": "analytics_platform",
  "resource_id": "analytics_9406",
  "operation": "REPORT_EXPOSED_PII",
  "state": "PRESENT",
  "evidence_id": "evidence_94"
}
```

Steps always follow the same order: findings first, then what to fix, then what to verify.

## How It Works

The agent is fully deterministic — no LLM calls at runtime, no external APIs, no randomness. Everything is derived from the evidence files you provide.

**Identity resolution** starts by combining the user's current profile with their audit history to recover all past email addresses and internal IDs. This matters because old records often reference an address the user changed years ago.

**Evidence indexing** parses every file you give it — SQL snapshots (run against in-memory SQLite), JSON exports, structured logs, plain text records — and builds a lookup table keyed by every identifier linked to each user. Records are only included if their capture timestamp falls before the audit cutoff.

**Activity correlation** handles the case where a record exists in the system but has no PII — for example, an analytics row that was anonymized and has no email field left. The agent traces system-activity logs to find which account deletion immediately preceded the anonymization event, then uses that account's known identity to link the record back to the user.

**Step generation** applies the deletion policy rule by rule. For each record in the wrong state, it generates the finding, the remediation action, and the follow-up verification check. The ordering follows a fixed priority: data flows and restore risks come before the records they can recreate.

## Setup

```bash
git clone https://github.com/karterisg/HACKERRANK-ORCHESTRATE-OCT26
cd HACKERRANK-ORCHESTRATE-OCT26
python code/main.py
```

Requires Python 3.9+. No external packages.

Input files go under `dataset/`. Output is written to `output.csv` at the repo root.

```bash
# Run against sample cases and compare to known answers
python code/main.py --sample
python code/validate.py
```

## Adapting It to Your Stack

The agent is designed to be pointed at your own data:

- **Evidence files**: replace or extend the parsers in `code/main.py` to handle your SQL dialect, log format, or JSON schema
- **Deletion policy**: edit `dataset/deletion_rules.csv` — each row maps a data category to a required action (DELETE, REDACT, ANONYMIZE, RETAIN)
- **Identity schema**: update `dataset/user_identities.csv` and `dataset/user_audit_log.csv` to match your user table structure
- **Deletion requests**: swap `dataset/deletion_requests.csv` with your own queue

## Results

Benchmarked on 32 labeled test cases:

| Metric | Value |
|---|---|
| Status accuracy | 96.9% (31/32) |
| Avg step recall | ~79% |
| Avg step precision | ~90% |
| Runtime (518 cases) | < 2 seconds |

The one incorrect case (case_07) involves a support identity document whose resource ID didn't surface under the user's current identifiers in the available evidence.
