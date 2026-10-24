# GDPR Deletion Audit Agent

An AI-powered compliance checker that verifies whether a user's personal data has been truly and completely deleted across all systems of an organization.

## The Problem

When a user submits a deletion request ("right to be forgotten"), internal workflows often report it as **"Complete"** — while personal data silently persists in secondary databases, support attachments, search indexes, analytics exports, logs, archives, and backups. Active synchronization jobs can even recreate data that was deleted from the primary source.

This agent investigates the actual state of the data, not the reported status, and produces evidence-backed findings.

## What It Does

For each deletion request, the agent:

1. **Determines intent** — checks whether the request actually authorizes deletion (vs. a data export, opt-out, or correction request)
2. **Resolves identity** — recovers all current and historical identifiers (emails, user IDs, hashes) for the subject
3. **Searches all evidence** — scans SQL snapshots, JSON exports, logs, support records, and analytics files for any remaining personal data
4. **Applies deletion policy** — determines the required treatment for each record (delete, redact, anonymize, or retain)
5. **Produces a verdict** — `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`
6. **Generates ordered remediation steps** — findings, remediation actions, and verification checks with cited evidence

## Output Format

```csv
case_id,deletion_status,steps_json
```

Each step includes:

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

Phases: `FINDING` → `REMEDIATION` → `VERIFICATION`

## Requirements

- Python 3.9+ (standard library only, no external packages)

## Setup

```bash
git clone <this-repo>
cd <this-repo>
# Place your dataset files under dataset/
python code/main.py
# Output written to output.csv
```

## Running

```bash
# Full run (all cases)
python code/main.py

# Sample/test run (validates against known answers)
python code/main.py --sample

# Validate against sample answers
python code/validate.py
```

## Architecture

| Component | Description |
|---|---|
| `build_identity()` | Resolves current + historical emails and user IDs from identity and audit-log CSVs |
| `build_index()` | Parses all evidence files (SQL, JSON, logs, text) into a searchable index keyed by email/user ID |
| `EvidenceIndex` | Fast lookup by email, user ID, email hash, or resource ID; respects `captured_at ≤ audit_at` |
| `build_activity_account_map()` | Links non-account resources to their account via system-activity batch correlation |
| `build_analytics_user_map()` | Links anonymized analytics records (no PII) to users via batch proximity |
| `is_deletion()` | Multilingual classifier (EN/ES/FR/DE/JA/…) that detects genuine deletion intent |
| `generate_steps()` | Applies deletion rules and produces ordered FINDING/REMEDIATION/VERIFICATION steps |

## Adapting to Your Systems

To use this agent for your own GDPR compliance auditing:

1. **Replace evidence files** with your own SQL dumps, JSON exports, and logs under `dataset/evidence/`
2. **Update `deletion_rules.csv`** with your organization's data-retention and deletion policy
3. **Update `user_identities.csv`** and `user_audit_log.csv` with your user identity schema
4. **Adjust parsers** in `code/main.py` for your specific file formats

## Performance (on benchmark cases)

- Status accuracy: **96.9%** (31/32 sample cases correct)
- Average step recall: **~79%**
- Average step precision: **~90%**
- Runtime: **< 2 seconds** for 518 cases

## Built For

[HackerRank Orchestrate — Ghost Data Still Exists (October 2026)](https://wwww.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists)
