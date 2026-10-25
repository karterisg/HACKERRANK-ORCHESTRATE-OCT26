# Usage Report — Ghost Data Still Exists

## Final Full-Dataset Run

This report covers the run that produced the submitted `output.csv` (518 cases).

## Model Information

| Field | Value |
|---|---|
| Solution type | Hybrid: Groq LLM for intent classification + deterministic rules for evidence analysis |
| LLM provider | Groq |
| Model (intent classification) | qwen/qwen3.8-27b |
| Model calls at evaluation | 518 |
| Total input tokens | 78,306 |
| Total output tokens | 2,082 |
| Total tokens | 80,388 |
| Average input tokens per request | 151 |
| Average output tokens per request | 4 |
| Estimated cost per request | ~$0.000 (Groq free tier) |
| Estimated total cost | ~$0.00 (Groq free tier) |

## Architecture

The agent uses a two-layer approach:

1. **LLM layer (Groq — qwen/qwen3.8-27b)**: classifies `request_text` to determine whether the person is requesting deletion, or something else (access, export, opt-out). One API call per case.
2. **Deterministic layer**: evidence parsing, identity resolution, policy application, and step generation — all rule-based with no LLM calls.

This design provides:
- Robust multilingual intent detection via LLM
- Fully auditable, reproducible evidence analysis via rules
- Graceful fallback to heuristic classification if the API is unavailable

## Evaluation Run Performance

| Metric | Value |
|---|---|
| Total cases processed | 518 |
| Runtime (wall clock) | ~20 minutes (includes Groq rate-limit retries) |
| LLM calls | 518 |
| Input tokens | 78,306 |
| Output tokens | 2,082 |
| Total tokens | 80,388 |
| Estimated total cost | ~$0.00 (Groq free tier) |

## Per-Request Breakdown

| Metric | Value |
|---|---|
| Average input tokens per request | ~151 |
| Average output tokens per request | ~4 |
| Average total tokens per request | ~155 |
| Estimated cost per request | ~$0.000 |

## Development Token Usage

Claude Code (claude-sonnet-4-6) was used during development to build and iterate on the solution:

| Phase | Model | Approx. input tokens | Approx. output tokens |
|---|---|---|---|
| Architecture design | claude-sonnet-4-6 | ~200,000 | ~15,000 |
| Evidence parsing implementation | claude-sonnet-4-6 | ~500,000 | ~40,000 |
| Identity resolution | claude-sonnet-4-6 | ~300,000 | ~20,000 |
| Step generation & ordering | claude-sonnet-4-6 | ~400,000 | ~30,000 |
| Debugging & improvements | claude-sonnet-4-6 | ~600,000 | ~50,000 |
| **Total (development)** | claude-sonnet-4-6 | **~2,000,000** | **~155,000** |
