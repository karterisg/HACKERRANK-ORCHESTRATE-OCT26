# Ghost Data Still Exists — Deletion Audit Agent

A fully deterministic, zero-dependency deletion-audit agent built for the HackerRank Orchestrate challenge (October 2026). It verifies whether personal data has actually been removed across every system after a deletion request — not just the primary database.

## The Problem

A deletion workflow marks a case **Complete**. But personal data rarely lives in one place. It ends up in:

- Backup snapshots taken before the job ran
- Analytics platforms that cached the profile
- Support tickets that quoted personal details verbatim
- Search indexes still returning the user's name
- Integration pipelines that will sync the data back tomorrow

This agent was built to find every one of those gaps automatically, before they become compliance incidents.

## Results

Benchmarked on 32 labeled sample cases:

| Metric | Value |
|---|---|
| Status accuracy | **100%** (32/32) |
| Step precision | **100.0%** |
| Step recall | **99.0%** |
| Avg F1 | **99.7%** |
| Exact sequence match | **93.8%** (30/32) |
| Runtime (518 cases) | **~2 seconds** |

## What It Does

Given a list of deletion requests and a set of evidence files (database snapshots, logs, JSON exports, PDFs), the agent:

1. **Determines intent** — reads `request_text` in any language and decides if it actually authorizes deletion (requests for data access, export, or marketing opt-out are classified `NOT_APPLICABLE`)
2. **Resolves all identifiers** — combines the current user profile with the full audit history to recover past emails, hashed values, and internal IDs that still appear in older systems
3. **Indexes all evidence** — parses every file type (SQL snapshots via in-memory SQLite, JSON exports, structured logs, plain-text records, PDFs) and builds a lookup table keyed by every identifier linked to the user
4. **Applies deletion policy** — checks each record against `deletion_rules.csv` (DELETE, REDACT, ANONYMIZE, RETAIN, ACCOUNT_TOMBSTONE)
5. **Returns a verdict** — `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`
6. **Produces ordered steps** — for incomplete cases: findings, ordered remediation, and follow-up verification checks in the sequence they must execute

## Output Format

```csv
case_id,deletion_status,steps_json
```

Each step in `steps_json`:

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

Steps always follow the order: **FINDING → REMEDIATION → VERIFICATION**. Within REMEDIATION, data flows and restore risks are disabled before dependent records are changed.

## Architecture

The agent is fully deterministic — no LLM calls at runtime, no external APIs, no randomness.

### Identity Resolution

Combines `user_identities.csv` (current snapshot) with `user_audit_log.csv` (historical changes) to build a complete set of past emails, internal user IDs, and email hashes for each subject. A deletion request may reference an address the user changed years ago; this step ensures those old records are still matched.

### Evidence Indexing (`EvidenceIndex`)

A multi-key in-memory index keyed by email, user_id, email hash, and resource_id. Each evidence file is parsed into `Record` objects and inserted once. Lookup by any identifier returns all matching records captured at or before the case's `audit_at` cutoff.

### Evidence Parsers

| Parser | Handles |
|---|---|
| `parse_generic_records` | JSON files with a `records[]` array (system/resource_id/result/subject_reference) |
| `parse_analytics_records` | `customer_analytics_report` JSON — detects anonymized state by checking for remaining PII fields |
| `parse_export_jobs_records` | `customer_export_jobs` JSON — maps `owner_email` and `download_available` |
| `parse_snapshot_bundle` | `customer_data_snapshot_bundle` JSON — multi-store snapshots with per-store state logic |
| `parse_sre_json` | `service_resource_export` JSON — per-service arrays (account, analytics, backup, export, integration, search, support, identity, marketing, security) |
| `parse_service_events_log` | `service_events_*.log` — trace-based logs where identifier and resource_id appear on different lines; groups by `trace_id` before building a record |
| `parse_resource_lookup_log` | `resource_lookup_trace_*.log` — single-line structured logs |
| SQL files | Run against in-memory SQLite, query relevant tables, extract PII presence and state |
| PDF / text files | Extracted via regex patterns for emails, user IDs, and resource identifiers |

### Activity Correlation

Handles the edge case where a record exists but has no PII — for example, an analytics row that was anonymized and has no email field. The agent traces `system_activity.csv` to find which account deletion event immediately preceded the anonymization, then uses that account's known identifiers to link the PII-less record back to the subject.

### Step Generation

Applies `REQUIRED_ACTION` rules to every matched record. For each record in the wrong state:

- Generates a `FINDING` step citing the evidence file ID
- Generates the corresponding `REMEDIATION` step
- Generates a `VERIFICATION` step for the required final state

Ordering: `DISABLE_DATA_FLOW` and `BLOCK_RESTORE` before any `DELETE_RECORD`/`REDACT_RECORD`/`ANONYMIZE_RECORD`. Steps are deduplicated by `(system_id, resource_id, operation)`.

## Setup

```bash
git clone https://github.com/karterisg/HACKERRANK-ORCHESTRATE-OCT26
cd HACKERRANK-ORCHESTRATE-OCT26
python code/main.py
```

**Requires Python 3.9+. No external packages — uses only the standard library.**

Input files go under `dataset/`. Output is written to `output.csv` at the repo root.

```bash
# Run against the 32 labeled sample cases and compare to known answers
python code/main.py --sample
python code/validate.py
```

## Submission

Challenge and submission URL:  
**https://wwww.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists**

Submission artifacts:

| Item | Description |
|---|---|
| `code.zip` | Runnable solution, prompts, configuration, `README.md`, and `evaluation/` reports |
| `output.csv` | One answer row for every evaluation request (518 cases) |
| `chat_transcript` | The root `log.txt` generated by the coding agent |

## Evaluation

Reports are in `evaluation/`:

- `evaluation_report.md` — case-level status accuracy, step-level precision/recall/F1, sequence accuracy, three custom test cases, and failures found during development
- `usage_report.md` — model providers, call counts, token usage, and cost for the final full-dataset run
