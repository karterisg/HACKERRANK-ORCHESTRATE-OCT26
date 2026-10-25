# Ghost Data Still Exists — Deletion Audit Agent

A hybrid deletion-audit agent built for the HackerRank Orchestrate challenge (October 2026). Built entirely with **Claude Code** (Claude Opus + Sonnet 4.6) and powered at runtime by **Groq** (qwen/qwen3.8-27b) for intent classification and evidence parsing. It verifies whether personal data has actually been removed across every system after a deletion request — not just the primary database. Deletion policy is loaded dynamically from `deletion_rules.csv`, and active sync flows that could recreate deleted data are detected automatically from the activity stream.

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
| Full dataset (518 cases) | COMPLETE=205, INCOMPLETE=303, NOT_APPLICABLE=10 |
| Runtime (518 cases) | **~20 min** (Groq rate-limit retries) |

## What It Does

Given a list of deletion requests and a set of evidence files (database snapshots, logs, JSON exports, PDFs), the agent:

1. **Classifies intent via LLM** — sends `request_text` to a Groq-hosted LLM (qwen/qwen3.8-27b) to determine if the request authorizes deletion in any language. Requests for data access, export, or marketing opt-out are classified `NOT_APPLICABLE`. Falls back to heuristic keyword matching if the API is unavailable.
2. **Resolves all identifiers** — combines the current user profile with the full audit history to recover past emails, hashed values, and internal IDs that still appear in older systems
3. **Indexes all evidence** — parses every file type (SQL snapshots via in-memory SQLite, JSON exports, structured logs, plain-text records, PDFs) and builds a lookup table keyed by every identifier linked to the user
4. **Applies deletion policy** — loads `deletion_rules.csv` at startup and checks each record against the dynamic policy table (DELETE, REDACT, ANONYMIZE, RETAIN, ACCOUNT_TOMBSTONE)
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

The agent uses a two-layer design: an LLM for intent classification, and a deterministic rule engine for everything else.

### LLM Layer — Intent Classification + Evidence Parsing (Groq)

Each case's `request_text` is sent to **qwen/qwen3.8-27b** via the Groq API with a system prompt that distinguishes deletion requests from access, export, and opt-out requests. The model handles multilingual input reliably. One API call per case (518 total for intent). If the API is unavailable, the agent falls back to regex-based heuristic classification automatically.

Evidence files (JSON, log, PDF formats) are also sent to Groq as primary parser, extracting records in a structured JSON format. The deterministic parsers run in parallel as fallback, so accuracy is maintained even under API rate limits.

### Deterministic Layer — Evidence Analysis

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
pip install groq python-dotenv
```

Create a `.env` file at the repo root with your Groq API key (free at `console.groq.com`, no credit card required):

```
GROQ_API_KEY=<your_key>
```

**Requires Python 3.9+.**

Input files go under `dataset/`. Output is written to `output.csv` at the repo root.

```bash
# Run all 518 cases
python code/main.py

# Run against the 32 labeled sample cases and compare to known answers
python code/main.py --sample
python code/validate.py
```

## How We Built It

### Claude Code — The Development Agent

The entire codebase was built using **[Claude Code](https://claude.com/claude-code)**, Anthropic's AI coding agent, running **Claude Opus** and **Claude Sonnet 4.6** throughout the development session.

Claude Code was used for every stage of development:

- **Architecture design** — deciding on the two-layer approach (LLM intent + deterministic evidence analysis), the `EvidenceIndex` data structure, and the multi-parser dispatch system
- **Evidence parsers** — writing and iterating on all 7 parsers (generic JSON, analytics reports, export jobs, snapshot bundles, service resource exports, service event logs, SQL snapshots) by reading real evidence files and adjusting to their structure
- **Identity resolution** — building the logic that joins `user_identities.csv` with `user_audit_log.csv` to recover all historical emails, user IDs, and hashes for each subject
- **Activity correlation** — solving the hard case of PII-less records (anonymized rows with no email) by tracing `system_activity.csv` to link them back to the right subject
- **Step generation and ordering** — implementing the FINDING → REMEDIATION → VERIFICATION pipeline with the correct dependency ordering (DISABLE_DATA_FLOW before DELETE, etc.)
- **Validation and debugging** — running `validate.py` after each iteration to measure precision, recall, F1, and exact sequence match against the 32 labeled sample cases

Total development token usage: ~2,000,000 input tokens + ~155,000 output tokens across all sessions (claude-sonnet-4-6).

### Groq — Runtime LLM Inference

For the final submission, **Groq** (free tier) was added to handle intent classification at runtime — the one step where a pure rule-based approach is weakest, especially for non-English or unusual request phrasing.

For each of the 518 cases, the agent sends the `request_text` to **qwen/qwen3.8-27b** via the Groq API with a system prompt that classifies the request as `DELETION` or `NOT_APPLICABLE`. The model handles multilingual requests reliably and returns a single token answer.

| Metric | Value |
|---|---|
| API calls (full run) | 518 |
| Model | qwen/qwen3.8-27b via Groq |
| Input tokens | 78,306 |
| Output tokens | 2,082 |
| Total tokens | 80,388 |
| Cost | $0.00 (Groq free tier) |
| Runtime | ~20 min (includes rate-limit retries) |

If the Groq API is unavailable, the agent falls back automatically to regex-based heuristic classification — so the pipeline never fails hard.

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
