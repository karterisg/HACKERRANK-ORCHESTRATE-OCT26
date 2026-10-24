# Usage Report — Ghost Data Still Exists

## Final Full-Dataset Run

This report covers the run that produced the submitted `output.csv` (518 cases).

## Model Information

| Field | Value |
|---|---|
| Solution type | Deterministic rule-based (no LLM inference at evaluation time) |
| Model calls at evaluation | 0 |
| External API calls | 0 |

The solution is fully deterministic and rule-based. All decisions are made through:
- CSV/JSON/SQL/log file parsing
- Identity resolution via `user_identities.csv` and `user_audit_log.csv`
- Evidence indexing with PII-based lookup
- Deletion-rule application from `deletion_rules.csv`
- System-activity batch correlation for account and analytics linkage

No LLM API calls are made during the evaluation run.

## Development Token Usage

LLM assistance (Claude Code / Claude Sonnet 4.6) was used during **development** of the solution (not during evaluation). Development sessions:

| Phase | Model | Approx. input tokens | Approx. output tokens |
|---|---|---|---|
| Architecture design | claude-sonnet-4-6 | ~200,000 | ~15,000 |
| Evidence parsing implementation | claude-sonnet-4-6 | ~500,000 | ~40,000 |
| Identity resolution | claude-sonnet-4-6 | ~300,000 | ~20,000 |
| Step generation & ordering | claude-sonnet-4-6 | ~400,000 | ~30,000 |
| Debugging & improvements | claude-sonnet-4-6 | ~600,000 | ~50,000 |
| **Total (development)** | claude-sonnet-4-6 | **~2,000,000** | **~155,000** |

## Evaluation Run Performance

| Metric | Value |
|---|---|
| Total cases processed | 518 |
| Runtime (wall clock) | ~1 second |
| Memory usage | ~50 MB |
| Input tokens (evaluation) | 0 |
| Output tokens (evaluation) | 0 |
| API cost (evaluation) | $0.00 |

## Per-Request Cost

Since the solution uses no LLM inference at evaluation time:

| Metric | Value |
|---|---|
| Average input tokens per request | 0 |
| Average output tokens per request | 0 |
| Estimated cost per request | $0.00 |
| Estimated total cost | $0.00 |

## Architecture Note

The zero-inference design was chosen to:
1. Eliminate API rate limits and latency
2. Ensure fully deterministic output across runs
3. Avoid token costs at submission evaluation time
4. Enable fast iteration during development

All intelligence is encoded in the parsing logic, identity resolution, evidence indexing, and step-generation rules, developed iteratively against the 32 sample cases.
