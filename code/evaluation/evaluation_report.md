# Evaluation Report — Ghost Data Still Exists

## 1. Case-Level Deletion-Status Accuracy (Sample Cases)

Evaluated against the 32 sample cases in `dataset/sample_output.csv`:

| Metric | Value |
|---|---|
| Status correct | 32 / 32 |
| Status accuracy | **100.0%** |

All 32 sample cases produce the correct `deletion_status` (COMPLETE, INCOMPLETE, or NOT_APPLICABLE).

## 2. Step-Level and Field-Level Accuracy (Sample Cases)

Step comparison uses the 5-tuple `(phase, system_id, resource_id, operation, state)` as a set (order-independent).

| Case | Status ✓/✗ | Recall | Precision |
|---|---|---|---|
| case_01 | COMPLETE ✓ | 100% | 100% |
| case_02 | COMPLETE ✓ | 100% | 100% |
| case_03 | COMPLETE ✓ | 100% | 100% |
| case_04 | COMPLETE ✓ | 100% | 100% |
| case_05 | INCOMPLETE ✓ | 100% | 100% |
| case_06 | INCOMPLETE ✓ | 100% | 100% |
| case_07 | NOT_APPLICABLE ✓ | 100% | 100% |
| case_08 | INCOMPLETE ✓ | 100% | 100% |
| case_09 | INCOMPLETE ✓ | 100% | 100% |
| case_10 | INCOMPLETE ✓ | 100% | 100% |
| case_11 | INCOMPLETE ✓ | 100% | 100% |
| case_12 | INCOMPLETE ✓ | 100% | 100% |
| case_13 | INCOMPLETE ✓ | 100% | 100% |
| case_14 | INCOMPLETE ✓ | 100% | 100% |
| case_15 | INCOMPLETE ✓ | 100% | 100% |
| case_16 | INCOMPLETE ✓ | 100% | 100% |
| case_17 | INCOMPLETE ✓ | 100% | 100% |
| case_18 | INCOMPLETE ✓ | 93% | 100% |
| case_19 | INCOMPLETE ✓ | 100% | 100% |
| case_20 | INCOMPLETE ✓ | 88% | 100% |
| case_21 | COMPLETE ✓ | 100% | 100% |
| case_22 | INCOMPLETE ✓ | 100% | 100% |
| case_23 | INCOMPLETE ✓ | 100% | 100% |
| case_24 | INCOMPLETE ✓ | 100% | 100% |
| case_25 | COMPLETE ✓ | 100% | 100% |
| case_26 | COMPLETE ✓ | 100% | 100% |
| case_27 | COMPLETE ✓ | 100% | 100% |
| case_28 | COMPLETE ✓ | 100% | 100% |
| case_29 | INCOMPLETE ✓ | 100% | 100% |
| case_30 | INCOMPLETE ✓ | 100% | 100% |
| case_31 | COMPLETE ✓ | 100% | 100% |
| case_32 | INCOMPLETE ✓ | 100% | 100% |

**Aggregate step precision**: 100.0%  
**Aggregate step recall**: 99.0%  
**Average per-case F1**: 99.7%

## 3. Sequence Accuracy

Steps within each case are ordered by:
1. Phase order: FINDING → REMEDIATION → VERIFICATION
2. Within FINDING: operation order (REPORT_REMAINING_RECORD, REPORT_EXPOSED_PII, REPORT_ACTIVE_DATA_FLOW, REPORT_RESTORE_RISK), then by `sys_rank(system_id)`, then `resource_id`
3. Within REMEDIATION: operation order (DISABLE_DATA_FLOW, BLOCK_RESTORE, DELETE_RECORD, REDACT_RECORD, ANONYMIZE_RECORD) respecting upstream-before-downstream dependency
4. Within VERIFICATION: operation order (VERIFY_RECORD_ABSENT, VERIFY_RECORD_PRESENT, VERIFY_RECORD_REDACTED, VERIFY_RECORD_ANONYMIZED, VERIFY_DATA_FLOW_DISABLED, VERIFY_RESTORE_BLOCKED), then `sys_rank`, then `resource_id`

**Exact sequence match**: 30 / 32 = **93.8%**

Cases with sequence mismatch: case_18, case_20 (both due to missing security_service audit steps — see §4.1 below).

## 4. Known Step-Recall Failures

### 4.1 Missing Audit Record IDs for Cases 18 and 20

`audit_record_6645` (case_18, user_50) and `audit_record_5569` (case_20, user_48) appear in the expected output but are not referenced in any participant-visible evidence file or `system_activity.csv`. An exhaustive search across all log files, SQL snapshots, JSON records, and system activity found:

- No security_service event in `system_activity.csv` for user_48 or user_50
- No trace-id or subject_ref linking these users to any audit_record in any log file
- No SQL table containing `user_48` or `user_50` (2-digit) in any participant-accessible database

All other users' audit records are locatable through trace_id correlation in log files (e.g., `audit_record_4902 → subject_ref=user_61` via `structured_service_events_eu_west_20260918.log`). The absence of these two records is assessed as a dataset generation gap.

## 5. Additional Evaluation Cases

The following three cases were constructed by hand from the dataset's own systems, identity schema, and policy rules to test specific edge conditions not guaranteed to appear in the 32 sample cases. Each includes a full input row and the expected output steps.

---

### Custom Case A — Non-English Deletion Request (NOT_APPLICABLE vs DELETION)

**Input**

| Field | Value |
|---|---|
| case_id | custom_001 |
| email | test.user@example.com |
| requested_at | 2026-09-01T09:00:00Z |
| reported_status | COMPLETE |
| reported_at | 2026-09-01T12:00:00Z |
| audit_at | 2026-09-02T00:00:00Z |
| request_text | "Παρακαλώ στείλτε μου όλα τα δεδομένα που έχετε για εμένα — θέλω να δω τι έχετε αποθηκεύσει." |

**Expected output**

```
deletion_status: NOT_APPLICABLE
steps_json: []
```

**Rationale**: The Greek text requests a copy of stored data (data subject access request), not deletion. The intent classifier must distinguish DSAR from right-to-erasure even when the language is not English. A false positive here would mark a non-deletion request as COMPLETE and bypass the full audit.

**What it tests**: Multilingual intent classification. A purely keyword-based classifier that lacks Greek vocabulary defaults to NOT_APPLICABLE (safe) but may misfire for other languages. The Groq LLM call handles this correctly.

---

### Custom Case B — Reported COMPLETE but Active Sync Flow Remains

**Input**

| Field | Value |
|---|---|
| case_id | custom_002 |
| email | sync.victim@northstarshop.com |
| requested_at | 2026-08-15T10:00:00Z |
| reported_status | COMPLETE |
| reported_at | 2026-08-16T08:00:00Z |
| audit_at | 2026-08-20T00:00:00Z |

**Synthetic evidence state at audit_at**

- `account_service` → account record: ABSENT (deleted 2026-08-15)
- `analytics_platform` → analytics profile: ABSENT (anonymized 2026-08-15)
- `integration_service` → data_flow record: PRESENT, `sync_active=true`, `target=marketing_platform`
- `system_activity.csv` → SYNC_RECORD event for same resource_id on 2026-08-18 (after DELETE_RECORD on 2026-08-15)

**Expected output**

```
deletion_status: INCOMPLETE
steps_json: [
  {"step_no":1,"phase":"FINDING","system_id":"integration_service",
   "resource_id":"data_flow_sync_001","operation":"REPORT_ACTIVE_DATA_FLOW",
   "state":"ACTIVE","evidence_id":"evidence_sync_001"},
  {"step_no":2,"phase":"REMEDIATION","system_id":"integration_service",
   "resource_id":"data_flow_sync_001","operation":"DISABLE_DATA_FLOW",
   "state":"DISABLED","evidence_id":""},
  {"step_no":3,"phase":"VERIFICATION","system_id":"account_service",
   "resource_id":"account_sync_001","operation":"VERIFY_RECORD_ABSENT",
   "state":"ABSENT","evidence_id":""},
  {"step_no":4,"phase":"VERIFICATION","system_id":"integration_service",
   "resource_id":"data_flow_sync_001","operation":"VERIFY_DATA_FLOW_DISABLED",
   "state":"DISABLED","evidence_id":""}
]
```

**Rationale**: The workflow reported COMPLETE because the primary account was deleted. But an active integration continues to sync the user's email to a marketing platform. The sync-after-deletion detector (`find_post_deletion_syncs`) must flag this as REPORT_ACTIVE_DATA_FLOW and place DISABLE_DATA_FLOW first in remediation.

**What it tests**: Sync-after-deletion detection. The agent must cross-reference `system_activity.csv` timestamps — not just check the evidence files' current state.

---

### Custom Case C — Support Record Requires REDACT Not DELETE

**Input**

| Field | Value |
|---|---|
| case_id | custom_003 |
| email | redact.me@example.com |
| requested_at | 2026-09-10T14:00:00Z |
| reported_status | PARTIALLY_COMPLETE |
| reported_at | 2026-09-11T09:00:00Z |
| audit_at | 2026-09-12T00:00:00Z |
| request_text | "I want my account deleted under GDPR Article 17." |

**Synthetic evidence state at audit_at**

- `account_service` → account record: ABSENT ✓
- `support_platform` → support ticket `support_redact_001`: PRESENT, contains `name="Alice Redact"`, `email="redact.me@example.com"` in ticket body (policy: REDACT)
- `security_service` → audit log `audit_redact_001`: PRESENT (policy: RETAIN)

**Expected output**

```
deletion_status: INCOMPLETE
steps_json: [
  {"step_no":1,"phase":"FINDING","system_id":"support_platform",
   "resource_id":"support_redact_001","operation":"REPORT_EXPOSED_PII",
   "state":"PRESENT","evidence_id":"evidence_redact_001"},
  {"step_no":2,"phase":"REMEDIATION","system_id":"support_platform",
   "resource_id":"support_redact_001","operation":"REDACT_RECORD",
   "state":"REDACTED","evidence_id":""},
  {"step_no":3,"phase":"VERIFICATION","system_id":"account_service",
   "resource_id":"account_redact_001","operation":"VERIFY_RECORD_ABSENT",
   "state":"ABSENT","evidence_id":""},
  {"step_no":4,"phase":"VERIFICATION","system_id":"support_platform",
   "resource_id":"support_redact_001","operation":"VERIFY_RECORD_REDACTED",
   "state":"REDACTED","evidence_id":""},
  {"step_no":5,"phase":"VERIFICATION","system_id":"security_service",
   "resource_id":"audit_redact_001","operation":"VERIFY_RECORD_PRESENT",
   "state":"PRESENT","evidence_id":"evidence_audit_redact_001"}
]
```

**Rationale**: Policy requires `REDACT` for support records (not DELETE) and `RETAIN` for security audit logs. The agent must not delete what policy says to keep, and must not skip records that need redaction. A DELETE operation on support_redact_001 would be wrong; RETAIN on audit_redact_001 is correct and must appear as VERIFY_RECORD_PRESENT.

**What it tests**: Correct policy application from `deletion_rules.csv` — the distinction between DELETE, REDACT, and RETAIN actions for different data categories.

---

## 6. Failures Found and Improvements Made

| Iteration | Issue | Fix | Impact |
|---|---|---|---|
| v1 | `build_activity_account_map` assigned accounts after resources (wrong ordering) | `aseq < oseq` (preceding-only) + gap-based RANK vs PROXIMITY algorithm | Fixed case ordering for 12+ cases |
| v2 | Analytics records with existing PII links were overwritten by proximity heuristic | Added guard `if rec.emails or rec.user_ids: continue` before proximity link | Fixed case_27 status regression |
| v3 | `build_analytics_user_map` gap/rank algorithm missed batches with mixed known/unknown users | KEY DISCOVERY: when any KNOWN user appears between two UNKNOWN users → use RANK; else PROXIMITY | Fixed cases 26, 27, 28, 31 analytics |
| v4 | Absent accounts (COMPLETE cases) not found when user was deleted before evidence window | Added multi-path account discovery: evidence index → SQL absent check → time-proximity | Fixed cases 01–04, 21, 25 |
| v5 | Duplicate `VERIFY_RECORD_ABSENT` for account_006 in case_06 | Added `known_accts` check to include already-added verifications before `res2acct` fallback | Fixed case_06 exact sequence |
| v6 | `_find_absent_account_from_sql` inferred account IDs using naming convention without verification | Added per-table convention check: all existing rows must follow `account_`+`user_id[5:]` pattern | Prevents false positives on full 518-case set |
| v7 | Status detection: `request_text` in non-English (Greek, Japanese, etc.) was misclassified | Replaced regex keyword matching with Groq LLM (qwen/qwen3.8-27b) intent classifier | Correct multilingual NOT_APPLICABLE classification |
| v8 | Tombstone accounts with anonymized analytics companion records | `build_tombstone_forward_analytics` precomputes tombstone→analytics mapping for COMPLETE cases | Added analytics verification steps for cases 03, 21, 25, 26, 27, 28, 31 |
| v9 | `deletion_rules.csv` was not loaded at runtime — policy was fully hardcoded | Added `_load_required_actions_from_csv()`, called at startup in `main()` | Agent now data-driven; policy changes require only CSV update |
| v10 | Evidence parsing relied solely on hardcoded format parsers | Added `_parse_file_with_groq()` as LLM-first parser for JSON/log/PDF formats; deterministic parsers run as fallback | Handles unexpected or loosely structured evidence files |
| v11 | No detection of sync/index events that re-created data after deletion | Added `find_post_deletion_syncs()`: scans `system_activity.csv` for SYNC_RECORD/INDEX_RECORD after DELETE_RECORD for same resource | Flags active data flows that can recreate deleted data |

## 7. Full Dataset Summary

Run on all 518 evaluation cases (`dataset/deletion_requests.csv`) using the final submitted agent (Groq LLM for intent + evidence, deterministic rule engine for policy and step generation):

| Result | Count |
|---|---|
| COMPLETE | 205 |
| INCOMPLETE | 303 |
| NOT_APPLICABLE | 10 |
| **Total** | **518** |

**Groq API usage (intent classification + evidence parsing):**

| Metric | Value |
|---|---|
| Total Groq calls | 518+ (intent) + evidence parsing calls |
| Input tokens | ~78,306 (intent) |
| Output tokens | ~2,082 (intent) |
| Runtime | ~20 min (includes Groq rate-limit retries) |
| Cost | $0.00 (Groq free tier) |
