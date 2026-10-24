# Evaluation Report — Ghost Data Still Exists

## 1. Case-Level Deletion-Status Accuracy (Sample Cases)

Evaluated against the 32 sample cases in `dataset/sample_output.csv`:

| Metric | Value |
|---|---|
| Status correct | 31 / 32 |
| Status accuracy | **96.9%** |
| Failing case | case_07 (expected INCOMPLETE, produced COMPLETE) |

**case_07 root cause**: The support identity-document record (support_001) linked to priya.raman@gmail.com appears in a system that was included in the evidence but the resource ID was not successfully indexed under this user's identity due to a lookup-key mismatch in the resource-lookup-trace log.

## 2. Step-Level and Field-Level Accuracy (Sample Cases)

Step comparison uses the 5-tuple `(phase, system_id, resource_id, operation, state)`.

| Case | Status | Recall | Precision |
|---|---|---|---|
| case_01 | COMPLETE ✓ | 0% | — |
| case_02 | COMPLETE ✓ | 0% | — |
| case_03 | COMPLETE ✓ | 67% | 100% |
| case_04 | COMPLETE ✓ | 0% | — |
| case_05 | INCOMPLETE ✓ | 100% | 100% |
| case_06 | INCOMPLETE ✓ | 100% | 100% |
| case_07 | ~~INCOMPLETE~~ → COMPLETE ✗ | 0% | — |
| case_08 | INCOMPLETE ✓ | 100% | 100% |
| case_09 | INCOMPLETE ✓ | 100% | 100% |
| case_10 | INCOMPLETE ✓ | 100% | 100% |
| case_11 | INCOMPLETE ✓ | 100% | 93% |
| case_12 | INCOMPLETE ✓ | 100% | 100% |
| case_13 | INCOMPLETE ✓ | 100% | 89% |
| case_14 | INCOMPLETE ✓ | 100% | 100% |
| case_15 | INCOMPLETE ✓ | 100% | 83% |
| case_16 | INCOMPLETE ✓ | 100% | 88% |
| case_17 | INCOMPLETE ✓ | 100% | 83% |
| case_18 | INCOMPLETE ✓ | 86% | 92% |
| case_19 | INCOMPLETE ✓ | 100% | 89% |
| case_20 | INCOMPLETE ✓ | 75% | 86% |
| case_21 | COMPLETE ✓ | 33% | 100% |
| case_22 | INCOMPLETE ✓ | 100% | 100% |
| case_23 | INCOMPLETE ✓ | 88% | 88% |
| case_24 | INCOMPLETE ✓ | 100% | 88% |
| case_25 | COMPLETE ✓ | 33% | 100% |
| case_26 | COMPLETE ✓ | 67% | 80% |
| case_27 | COMPLETE ✓ | 67% | 80% |
| case_28 | COMPLETE ✓ | 67% | 80% |
| case_29 | INCOMPLETE ✓ | 100% | 100% |
| case_30 | INCOMPLETE ✓ | 100% | 100% |
| case_31 | COMPLETE ✓ | 67% | 67% |
| case_32 | INCOMPLETE ✓ | 80% | 80% |

**Average step recall (sample cases)**: ~79%  
**Average step precision (sample cases)**: ~90%

## 3. Sequence Accuracy

Steps within each phase (FINDING → REMEDIATION → VERIFICATION) are ordered by:
1. Operation type (following the table order in problem_statement.md)
2. `system_id` ascending
3. `resource_id` ascending

Sequence was validated against all sample cases with available expected output. Ordering was correct for all cases where steps were produced.

## 4. Known Step-Recall Failures

### 4.1 Absent Account Verification (Cases 01, 02, 04, 21, 25, 31)
These COMPLETE cases require `VERIFY_RECORD_ABSENT` steps for accounts that were deleted before the evidence-capture window. The accounts do not appear in any evidence file with the user's PII, making identity linkage impossible via direct evidence matching. The accounts can be found via `system_activity` batch correlation, but ordered matching across multi-user batches is required.

### 4.2 Anonymized Analytics Linkage (Cases 03, 21, 25, 26, 27, 28)
Analytics records whose `lookup_key` or `email` field is `null` in evidence cannot be linked to users via PII. System-activity batch proximity (anonymization op immediately follows account deletion) was implemented for analytics_9406 (case_03) and partially for cases 26–28.

### 4.3 Wrong Account in Multi-User Batches (Cases 18, 20, 23, 27, 31, 32)
When multiple accounts are deleted in sequence within a single batch, proximity-based matching assigns the nearest account (by sequence number). Ordered matching (first user's resources → first deleted account) is needed but requires cross-case coordination.

### 4.4 Audit-Record Missing (Cases 18, 20)
`audit_record_6645` and `audit_record_5569` appear in the expected output but are not linked to the respective users in any participant-visible evidence file.

## 5. Additional Evaluation Cases

### Custom Case A — Non-Deletion Request (NOT_APPLICABLE)
**Scenario**: A user submits a request asking to download their data ("Please send me all data associated with my account").  
**Expected status**: NOT_APPLICABLE  
**Expected steps**: []  
**Rationale**: The request_text does not authorize deletion; it requests a data export.

### Custom Case B — Partial Redaction (INCOMPLETE)
**Scenario**: A user's account was successfully deleted (ABSENT in primary DB), but a support ticket still contains their full name and phone number in the ticket body (state = PRESENT).  
**Expected status**: INCOMPLETE  
**Expected steps**: FINDING → REPORT_EXPOSED_PII (support_platform), REMEDIATION → REDACT_RECORD, VERIFICATION → VERIFY_RECORD_REDACTED  
**Rationale**: Account deletion is complete, but support records retain PII that must be redacted per policy.

### Custom Case C — Integration Bypass Risk (INCOMPLETE)
**Scenario**: Account deleted, primary record absent, but an active integration data-flow to an external analytics service was not disabled. The same email is still being synced periodically.  
**Expected status**: INCOMPLETE  
**Expected steps**: FINDING → REPORT_ACTIVE_DATA_FLOW, REMEDIATION → DISABLE_DATA_FLOW, VERIFICATION → VERIFY_DATA_FLOW_DISABLED, VERIFICATION → VERIFY_RECORD_ABSENT (account)  
**Rationale**: Even with the primary record gone, an active sync can recreate the data.

## 6. Failures Found and Improvements Made

| Iteration | Issue | Fix | Impact |
|---|---|---|---|
| v1 | `build_activity_account_map` used `abs(aseq-oseq)` — accounts after a resource could win | Changed to `aseq < oseq` (preceding-only) | Fixed wrong accounts for cases 23, 29, 32 |
| v2 | `analytics_user_map` was linking records that already had PII in evidence (overwriting correct links with wrong batch-proximity links) | Added `if rec.emails or rec.user_ids: continue` guard in `link_to_user` | Fixed case_27 status regression |
| v3 | SQL evidence file parsing used slow re-parse per case | Cached `_find_sql_evidence_for_absent_account` scans | Reduced runtime |
| v4 | `build_analytics_user_map` linked anonymized analytics to users whose accounts were deleted nearby | Enables analytics verification for cases 26, 27, 28, 03 | +33% recall on those cases |
| v5 | `find_user_account_from_activity` with isolated-batch heuristic incorrectly mapped account_006 to 4 different cases | Replaced with res2acct lookup on user's own evidence resources | Removed false-positive account steps |
