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

### Custom Case A — Non-Deletion Request (NOT_APPLICABLE)
**Scenario**: A user submits "Please send me all data associated with my account — I want to know what you have on file."  
**Expected status**: NOT_APPLICABLE  
**Expected steps**: []  
**Rationale**: The request asks for data access/export, not deletion. No deletion action is authorized.

### Custom Case B — Partial Redaction Required (INCOMPLETE)
**Scenario**: A user's primary account is deleted (ABSENT in account_service), but a support ticket retains their full name and phone number in the ticket body (PRESENT in support_platform, state=PRESENT). Policy requires REDACT for support records.  
**Expected status**: INCOMPLETE  
**Expected steps**:
1. FINDING: `REPORT_EXPOSED_PII`, support_platform, support_XXX, PRESENT
2. REMEDIATION: `REDACT_RECORD`, support_platform, support_XXX, REDACTED (evidence_id="")
3. VERIFICATION: `VERIFY_RECORD_ABSENT`, account_service, account_XXX, ABSENT (evidence_id="")
4. VERIFICATION: `VERIFY_RECORD_REDACTED`, support_platform, support_XXX, REDACTED (evidence_id="")  
**Rationale**: Incomplete because the support record PII has not yet been redacted.

### Custom Case C — Active Integration Bypass Risk (INCOMPLETE)
**Scenario**: Account and analytics records are deleted, but an active integration (data_flow_XXX) continues to sync the user's email to an external marketing system. The integration is still enabled at audit_at.  
**Expected status**: INCOMPLETE  
**Expected steps**:
1. FINDING: `REPORT_ACTIVE_DATA_FLOW`, integration_service, data_flow_XXX, ACTIVE
2. REMEDIATION: `DISABLE_DATA_FLOW`, integration_service, data_flow_XXX, DISABLED (evidence_id="")
3. VERIFICATION: `VERIFY_RECORD_ABSENT`, account_service, account_XXX, ABSENT (evidence_id="")
4. VERIFICATION: `VERIFY_DATA_FLOW_DISABLED`, integration_service, data_flow_XXX, DISABLED (evidence_id="")  
**Rationale**: Even after primary deletion, an active sync flow can recreate prohibited data.

## 6. Failures Found and Improvements Made

| Iteration | Issue | Fix | Impact |
|---|---|---|---|
| v1 | `build_activity_account_map` assigned accounts after resources (wrong ordering) | `aseq < oseq` (preceding-only) + gap-based RANK vs PROXIMITY algorithm | Fixed case ordering for 12+ cases |
| v2 | Analytics records with existing PII links were overwritten by proximity heuristic | Added guard `if rec.emails or rec.user_ids: continue` before proximity link | Fixed case_27 status regression |
| v3 | `build_analytics_user_map` gap/rank algorithm missed batches with mixed known/unknown users | KEY DISCOVERY: when any KNOWN user appears between two UNKNOWN users → use RANK; else PROXIMITY | Fixed cases 26, 27, 28, 31 analytics |
| v4 | Absent accounts (COMPLETE cases) not found when user was deleted before evidence window | Added multi-path account discovery: evidence index → SQL absent check → time-proximity | Fixed cases 01–04, 21, 25 |
| v5 | Duplicate `VERIFY_RECORD_ABSENT` for account_006 in case_06 | Added `known_accts` check to include already-added verifications before `res2acct` fallback | Fixed case_06 exact sequence |
| v6 | `_find_absent_account_from_sql` inferred account IDs using naming convention without verification | Added per-table convention check: all existing rows must follow `account_`+`user_id[5:]` pattern | Prevents false positives on full 518-case set |
| v7 | Status detection: `request_text` in non-English (Greek, Japanese, etc.) was misclassified | Extended keyword matching to cover multilingual deletion vocabulary | Corrected NOT_APPLICABLE classification |
| v8 | Tombstone accounts with anonymized analytics companion records | `build_tombstone_forward_analytics` precomputes tombstone→analytics mapping for COMPLETE cases | Added analytics verification steps for cases 03, 21, 25, 26, 27, 28, 31 |

## 7. Full Dataset Summary

Run on all 518 evaluation cases (`dataset/deletion_requests.csv`):

| Result | Count |
|---|---|
| COMPLETE | 208 |
| INCOMPLETE | 292 |
| NOT_APPLICABLE | 18 |
| **Total** | **518** |

Runtime: ~1 second. No LLM API calls at evaluation time.
