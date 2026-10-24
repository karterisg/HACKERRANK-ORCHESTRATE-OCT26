#!/usr/bin/env python3
"""
Deletion Audit Agent — Ghost Data Still Exists
HackerRank Orchestrate Challenge, October 2026
"""

import os, csv, json, re, sys, sqlite3, logging, time
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional, Dict, List, Tuple, Any

REPO_ROOT = Path(__file__).parent.parent
DATASET_DIR = REPO_ROOT / "dataset"
EVIDENCE_DIR = DATASET_DIR / "evidence"
OUTPUT_FILE = REPO_ROOT / "output.csv"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def parse_dt(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None

def norm_email(e: str) -> str:
    return e.strip().lower() if e else ""

def load_csv_rows(path: Path) -> List[Dict[str, str]]:
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))

# ─────────────────────────────────────────────────────────────────────────────
# Evidence Record
# ─────────────────────────────────────────────────────────────────────────────

class Record:
    __slots__ = ("file_id","captured_at","system_id","resource_id","state","emails","user_ids","extra")
    def __init__(self, file_id, captured_at, system_id, resource_id, state,
                 emails=None, user_ids=None, extra=None):
        self.file_id = file_id
        self.captured_at = captured_at
        self.system_id = system_id
        self.resource_id = resource_id
        self.state = state
        self.emails = [norm_email(e) for e in (emails or []) if e]
        self.user_ids = [u for u in (user_ids or []) if u]
        self.extra = extra or {}

class EvidenceIndex:
    def __init__(self):
        self._by_email: Dict[str, List[Record]] = defaultdict(list)
        self._by_user_id: Dict[str, List[Record]] = defaultdict(list)
        self.file_meta: Dict[str, Dict] = {}

    def add(self, rec: Record):
        for e in rec.emails:
            self._by_email[e].append(rec)
        for u in rec.user_ids:
            self._by_user_id[u].append(rec)

    def find(self, emails: List[str], user_ids: List[str],
             audit_at: Optional[datetime]) -> List[Record]:
        seen = set()
        results = []
        cands = []
        for e in emails:
            cands.extend(self._by_email.get(norm_email(e), []))
        for u in user_ids:
            cands.extend(self._by_user_id.get(u, []))
        for rec in cands:
            key = (rec.file_id, rec.resource_id)
            if key in seen:
                continue
            seen.add(key)
            if audit_at is None or rec.captured_at <= audit_at:
                results.append(rec)
        return results

# ─────────────────────────────────────────────────────────────────────────────
# Evidence Parsers
# ─────────────────────────────────────────────────────────────────────────────

def _jload(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log.debug("JSON parse fail %s: %s", path.name, e)
        return None


def parse_handover_txt(file_id, captured_at, path, index: EvidenceIndex):
    """Parse customer_account_handover_*.txt format:
    - timestamp | system_id | resource_id | data_category | status | identifier
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        # Status mapping
        STATUS_MAP = {
            "NOT_FOUND": "ABSENT",
            "FOUND": "PRESENT",
            "IDENTIFIABLE": "PRESENT",  # PII exposed
            "ANONYMIZED": "ANONYMIZED",
            "ACTIVE": "ACTIVE",
            "DISABLED": "DISABLED",
            "BLOCKED": "BLOCKED",
            "REDACTED": "REDACTED",
        }
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("- "):
                continue
            parts = [p.strip() for p in line[2:].split("|")]
            if len(parts) < 6:
                continue
            ts, sys_id, rid, category, status_raw, identifier = parts[:6]
            state = STATUS_MAP.get(status_raw.upper(), "PRESENT")
            emails = []
            user_ids = []
            identifier = identifier.strip()
            if "@" in identifier:
                emails.append(identifier)
            elif identifier.startswith("user_"):
                user_ids.append(identifier)
            elif identifier != "no direct identifier":
                # Could be user_id or other
                if re.match(r"user_\d+", identifier):
                    user_ids.append(identifier)
                else:
                    emails.append(identifier)

            rec = Record(file_id, captured_at, sys_id.strip(), rid.strip(),
                         state, emails=emails, user_ids=user_ids,
                         extra={"raw_status": status_raw, "category": category})
            index.add(rec)
    except Exception as e:
        log.warning("Handover parse fail %s: %s", path.name, e)


def parse_resource_lookup_log(file_id, captured_at, path, index: EvidenceIndex):
    """Parse resource_lookup_trace_*.log files."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()

        # Index by trace_id to get paired debug+info lines
        trace_pairs: Dict[str, Dict] = {}
        for line in lines:
            if "event=" not in line:
                continue
            tid_m = re.search(r"trace_id=(\S+)", line)
            if not tid_m:
                continue
            tid = tid_m.group(1)
            if tid not in trace_pairs:
                trace_pairs[tid] = {}

            # Extract fields
            for key in ["service", "resource_id", "enabled", "restore_allowed",
                        "customer_email", "customer_reference", "lookup_key",
                        "requester_email", "email", "http_status", "rows",
                        "last_delivery_status", "connector_name", "result",
                        "subject_reference", "event_code"]:
                m = re.search(rf"\b{key}=([^\s]+)", line)
                if m:
                    trace_pairs[tid][key] = m.group(1)

        for tid, fields in trace_pairs.items():
            rid = fields.get("resource_id")
            if not rid:
                continue

            # Get system_id
            sys_id = fields.get("service", "")
            if not sys_id or sys_id not in {
                "account_service", "search_service", "analytics_platform",
                "support_platform", "export_service", "integration_service",
                "backup_service", "security_service", "identity_service",
                "marketing_platform"
            }:
                continue

            # Collect identifiers
            emails = []
            user_ids = []
            for k in ["lookup_key", "customer_email", "email", "requester_email"]:
                v = fields.get(k, "")
                if v and "@" in v and v != "null":
                    emails.append(v)
            for k in ["customer_reference", "subject_reference"]:
                v = fields.get(k, "")
                if v and v != "null" and v.startswith("user_"):
                    user_ids.append(v)

            if not emails and not user_ids:
                continue

            # Determine state
            http_status = fields.get("http_status", "")
            rows = fields.get("rows", "")
            enabled = fields.get("enabled", "")
            restore_allowed = fields.get("restore_allowed", "")
            result = fields.get("result", "")

            if http_status == "404" or rows == "0":
                state = "ABSENT"
            elif enabled == "false" or fields.get("last_delivery_status") == "stopped":
                state = "DISABLED"
            elif restore_allowed == "false":
                state = "BLOCKED"
            elif enabled == "true":
                state = "ACTIVE"
            elif restore_allowed == "true":
                state = "ACTIVE"
            elif result == "hit":
                state = "PRESENT"
            elif sys_id == "analytics_platform":
                # Check if any PII fields are set
                has_pii = any(f in str(fields) for f in ["email=", "phone="])
                state = "PRESENT" if has_pii else "ANONYMIZED"
            else:
                state = "PRESENT"

            # For security_service, always PRESENT
            if sys_id == "security_service":
                state = "PRESENT"

            rec = Record(file_id, captured_at, sys_id, rid, state,
                         emails=emails, user_ids=user_ids, extra=fields)
            index.add(rec)
    except Exception as e:
        log.warning("Log parse fail %s: %s", path.name, e)


def parse_service_events_log(file_id, captured_at, path, index: EvidenceIndex):
    """Parse service_events_*.log and similar operational logs."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            # Look for lines with resource_id and an identifier
            rid_m = re.search(r"resource_id=([a-zA-Z_][a-zA-Z0-9_]*)", line)
            if not rid_m:
                continue
            rid = rid_m.group(1)

            emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", line)
            user_ids = re.findall(r"\buser_\d+\b", line)

            if not (emails or user_ids):
                continue

            sys_m = re.search(r"service=([a-zA-Z_]+)", line)
            sys_id = sys_m.group(1) if sys_m else "unknown"

            state = "PRESENT"
            if "deleted" in line.lower() or "absent" in line.lower():
                state = "ABSENT"
            elif "anonymized" in line.lower():
                state = "ANONYMIZED"
            elif "redacted" in line.lower():
                state = "REDACTED"

            rec = Record(file_id, captured_at, sys_id, rid, state,
                         emails=list(set(emails)), user_ids=list(set(user_ids)))
            index.add(rec)
    except Exception as e:
        log.debug("Service events log parse fail %s: %s", path.name, e)


def parse_service_resource_export_json(file_id, captured_at, path, index: EvidenceIndex):
    """Parse service_resource_export_*.json files."""
    data = _jload(path)
    if not data or "service_exports" not in data:
        return
    exports = data["service_exports"]

    # account_service
    for e in exports.get("account_service", {}).get("profile_lookups", []):
        rid = e.get("resource_id"); status = e.get("status_code", 0)
        profile = e.get("profile") or {}
        emails = [v for k, v in profile.items() if k == "email" and v]
        user_ids = [v for k, v in profile.items() if k == "customer_reference" and v]
        state = "ABSENT" if status == 404 else "PRESENT"
        if rid:
            index.add(Record(file_id, captured_at, "account_service", rid, state,
                             emails=emails, user_ids=user_ids))

    # analytics_platform
    for e in exports.get("analytics_platform", {}).get("profiles", []):
        rid = e.get("resource_id")
        emails = [v for k, v in e.items() if k == "email" and v]
        user_ids = [v for k, v in e.items() if k == "customer_reference" and v]
        has_pii = any(e.get(k) for k in ["email", "phone", "email_hash"])
        state = "PRESENT" if has_pii else "ANONYMIZED"
        if rid:
            index.add(Record(file_id, captured_at, "analytics_platform", rid, state,
                             emails=emails, user_ids=user_ids))

    # backup_service
    for e in exports.get("backup_service", {}).get("restore_entries", []):
        rid = e.get("resource_id")
        emails = [v for k, v in e.items() if k == "customer_email" and v]
        user_ids = [v for k, v in e.items() if k == "customer_reference" and v]
        state = "ACTIVE" if e.get("restore_allowed") else "BLOCKED"
        if rid:
            index.add(Record(file_id, captured_at, "backup_service", rid, state,
                             emails=emails, user_ids=user_ids))

    # export_service
    for e in exports.get("export_service", {}).get("exports", []):
        rid = e.get("resource_id")
        emails = [v for k, v in e.items() if k in ["owner_email"] and v]
        user_ids = [v for k, v in e.items() if k == "customer_reference" and v]
        if rid and (emails or user_ids):
            index.add(Record(file_id, captured_at, "export_service", rid, "PRESENT",
                             emails=emails, user_ids=user_ids))

    # integration_service
    for e in exports.get("integration_service", {}).get("connectors", []):
        rid = e.get("resource_id")
        emails = [v for k, v in e.items() if k == "customer_email" and v]
        user_ids = [v for k, v in e.items() if k == "customer_reference" and v]
        state = "ACTIVE" if e.get("enabled") else "DISABLED"
        if rid and (emails or user_ids):
            index.add(Record(file_id, captured_at, "integration_service", rid, state,
                             emails=emails, user_ids=user_ids,
                             extra={"connector_name": e.get("connector_name")}))

    # search_service
    for e in exports.get("search_service", {}).get("index_queries", []):
        rid = e.get("resource_id")
        hits = e.get("hits", {})
        docs = hits.get("documents", [])
        emails = [d.get("email") for d in docs if d.get("email")]
        user_ids = [d.get("customer_reference") for d in docs if d.get("customer_reference")]
        state = "PRESENT" if hits.get("total", 0) > 0 else "ABSENT"
        if rid and (emails or user_ids):
            index.add(Record(file_id, captured_at, "search_service", rid, state,
                             emails=emails, user_ids=user_ids))

    # support_platform
    for e in exports.get("support_platform", {}).get("tickets", []):
        rid = e.get("resource_id")
        emails = [v for k, v in e.items() if k == "requester_email" and v]
        user_ids = [v for k, v in e.items() if k == "customer_reference" and v]
        has_pii = any(e.get(k) for k in ["requester_email", "requester_name", "requester_phone"])
        state = "PRESENT" if has_pii else "REDACTED"
        if rid and (emails or user_ids):
            index.add(Record(file_id, captured_at, "support_platform", rid, state,
                             emails=emails, user_ids=user_ids))

    # identity_service
    for e in exports.get("identity_service", {}).get("tombstones", []):
        rid = e.get("resource_id")
        emails = [v for k, v in e.items() if k == "email" and v]
        user_ids = [v for k, v in e.items() if k in ["user_id", "customer_reference"] and v]
        has_pii = any(e.get(k) for k in ["email", "full_name", "phone"])
        state = "PRESENT" if has_pii else "REDACTED"
        if rid and (emails or user_ids):
            index.add(Record(file_id, captured_at, "identity_service", rid, state,
                             emails=emails, user_ids=user_ids))

    # marketing_platform
    for e in exports.get("marketing_platform", {}).get("profiles", []):
        rid = e.get("resource_id")
        emails = [v for k, v in e.items() if k in ["email", "customer_email"] and v]
        user_ids = [v for k, v in e.items() if k == "customer_reference" and v]
        if rid and (emails or user_ids):
            index.add(Record(file_id, captured_at, "marketing_platform", rid, "PRESENT",
                             emails=emails, user_ids=user_ids))


def parse_snapshot_bundle_json(file_id, captured_at, path, index: EvidenceIndex):
    data = _jload(path)
    if not data:
        return
    for snap in data.get("snapshots", []):
        store = snap.get("data_store", "")
        for r in snap.get("records", []):
            rid = r.get("resource_id")
            if not rid:
                continue
            emails = [v for k, v in r.items()
                      if k in ["email","requester_email","owner_email","customer_email"] and v]
            user_ids = [v for k, v in r.items()
                        if k in ["customer_reference","user_id"] and v]
            if not (emails or user_ids):
                continue
            account_status = r.get("account_status", "")
            state = "ABSENT" if account_status in ("DELETED",) else "PRESENT"
            index.add(Record(file_id, captured_at, store or "unknown", rid, state,
                             emails=emails, user_ids=user_ids, extra=r))


def parse_security_audit_json(file_id, captured_at, path, index: EvidenceIndex):
    data = _jload(path)
    if not data:
        return
    for r in data.get("records", []):
        rid = r.get("resource_id")
        subject = r.get("subject_reference", "")
        if not rid:
            continue
        emails = [subject] if "@" in subject else []
        user_ids = [subject] if subject.startswith("user_") else []
        result = r.get("result", "FOUND")
        state = "PRESENT" if result == "FOUND" else "ABSENT"
        index.add(Record(file_id, captured_at, "security_service", rid, state,
                         emails=emails, user_ids=user_ids, extra=r))


def parse_analytics_json(file_id, captured_at, path, index: EvidenceIndex):
    data = _jload(path)
    if not data:
        return
    for r in data.get("profiles", []):
        rid = r.get("resource_id")
        if not rid:
            continue
        emails = [r.get("email")] if r.get("email") else []
        user_ids = [v for k, v in r.items() if k in ["user_id","customer_reference"] and v]
        has_pii = any(r.get(k) for k in ["email","phone","email_hash"])
        state = "PRESENT" if has_pii else "ANONYMIZED"
        if emails or user_ids:
            index.add(Record(file_id, captured_at, "analytics_platform", rid, state,
                             emails=emails, user_ids=user_ids))


def parse_export_jobs_json(file_id, captured_at, path, index: EvidenceIndex):
    data = _jload(path)
    if not data:
        return
    for job in data.get("jobs", []):
        rid = job.get("resource_id")
        if not rid:
            continue
        emails = [v for k, v in job.items() if k in ["owner_email","requester_email"] and v]
        user_ids = [v for k, v in job.items() if k in ["customer_reference","user_id"] and v]
        status = job.get("status", "")
        state = "ABSENT" if status in ("DELETED","EXPIRED") else "PRESENT"
        if emails or user_ids:
            index.add(Record(file_id, captured_at, "export_service", rid, state,
                             emails=emails, user_ids=user_ids))


def parse_connector_json(file_id, captured_at, path, index: EvidenceIndex):
    data = _jload(path)
    if not data:
        return
    for conn in data.get("connectors", []):
        rid = conn.get("resource_id")
        if not rid:
            continue
        emails = [v for k, v in conn.items() if k == "customer_email" and v]
        user_ids = [v for k, v in conn.items() if k == "customer_reference" and v]
        state = "ACTIVE" if conn.get("enabled") else "DISABLED"
        if emails or user_ids:
            index.add(Record(file_id, captured_at, "integration_service", rid, state,
                             emails=emails, user_ids=user_ids,
                             extra={"connector_name": conn.get("connector_name")}))


def parse_export_manifest_json(file_id, captured_at, path, index: EvidenceIndex):
    data = _jload(path)
    if not data:
        return
    for e in data.get("exports", []):
        rid = e.get("resource_id")
        emails = [v for k, v in e.items() if k == "owner_email" and v]
        user_ids = [v for k, v in e.items() if k == "customer_reference" and v]
        if rid and (emails or user_ids):
            index.add(Record(file_id, captured_at, "export_service", rid, "PRESENT",
                             emails=emails, user_ids=user_ids))


def parse_generic_json(file_id, captured_at, path, index: EvidenceIndex):
    """Scan JSON for any resource_id + email combinations."""
    data = _jload(path)
    if not data:
        return

    def scan(obj, sys_hint="unknown"):
        if isinstance(obj, dict):
            rid = obj.get("resource_id")
            if rid:
                emails = [v for k, v in obj.items()
                          if k in ["email","customer_email","owner_email","requester_email"] and v and "@" in str(v)]
                user_ids = [v for k, v in obj.items()
                            if k in ["user_id","customer_reference","subject_reference"] and v]
                if emails or user_ids:
                    sys_id = sys_hint if sys_hint != "unknown" else "unknown"
                    for keyword, sid in [("account",  "account_service"),
                                         ("search",   "search_service"),
                                         ("analytics","analytics_platform"),
                                         ("support",  "support_platform"),
                                         ("export",   "export_service"),
                                         ("data_flow","integration_service"),
                                         ("backup",   "backup_service"),
                                         ("audit_record","security_service"),
                                         ("tombstone","identity_service"),
                                         ("marketing","marketing_platform")]:
                        if keyword in rid.lower():
                            sys_id = sid
                            break
                    state = "PRESENT"
                    index.add(Record(file_id, captured_at, sys_id, rid, state,
                                     emails=emails, user_ids=user_ids))
            for v in obj.values():
                if isinstance(v, (dict, list)):
                    scan(v, sys_hint)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    scan(item, sys_hint)
    scan(data)


def parse_sql_inventory(file_id, captured_at, path, index: EvidenceIndex):
    try:
        sql = path.read_text(encoding="utf-8")
        conn = sqlite3.connect(":memory:")
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.executescript(sql)

        TABLE_SYSTEM = {
            "customer_profiles": "account_service",
            "customer_search_documents": "search_service",
            "customer_analytics_profiles": "analytics_platform",
            "support_records": "support_platform",
            "customer_exports": "export_service",
            "connector_subscriptions": "integration_service",
            "backup_restore_entries": "backup_service",
            "security_audit_records": "security_service",
        }

        for tbl, sys_id in TABLE_SYSTEM.items():
            try:
                rows = conn.execute(f"SELECT * FROM {tbl}").fetchall()
                desc = [d[0] for d in conn.execute(f"PRAGMA table_info({tbl})").fetchall()]
                desc_names = [d[1] for d in conn.execute(f"PRAGMA table_info({tbl})").fetchall()]
                rows = conn.execute(f"SELECT * FROM {tbl}").fetchall()
                cols = [r[1] for r in conn.execute(f"PRAGMA table_info({tbl})")]
                rows = conn.execute(f"SELECT * FROM {tbl}").fetchall()
                for row in rows:
                    r = dict(zip(cols, row))
                    rid = r.get("resource_id")
                    if not rid:
                        continue
                    emails = [v for k, v in r.items()
                              if k in ["email","requester_email","owner_email","customer_email"] and v and "@" in str(v)]
                    user_ids = [v for k, v in r.items()
                                if k in ["customer_reference","user_id","subject_reference"] and v
                                and "@" not in str(v)]
                    if not (emails or user_ids):
                        continue
                    # Determine state
                    if tbl == "backup_restore_entries":
                        state = "ACTIVE" if r.get("restore_allowed") == 1 else "BLOCKED"
                    elif tbl == "connector_subscriptions":
                        state = "ACTIVE" if r.get("enabled") == 1 else "DISABLED"
                    elif tbl == "security_audit_records":
                        state = "PRESENT"
                    elif r.get("account_status") in ("DELETED",):
                        state = "ABSENT"
                    else:
                        state = "PRESENT"
                    index.add(Record(file_id, captured_at, sys_id, rid, state,
                                     emails=emails, user_ids=user_ids, extra=r))
            except Exception:
                pass
        conn.close()
    except Exception as e:
        log.warning("SQL inventory parse fail %s: %s", path.name, e)


def parse_sql_read_replica(file_id, captured_at, path, index: EvidenceIndex):
    try:
        sql = path.read_text(encoding="utf-8")
        conn = sqlite3.connect(":memory:")
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.executescript(sql)
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for tbl in tables:
            if tbl in ("snapshot_scope",):
                continue
            try:
                cols = [r[1] for r in conn.execute(f"PRAGMA table_info({tbl})")]
                rows = conn.execute(f"SELECT * FROM {tbl}").fetchall()
                for row in rows:
                    r = dict(zip(cols, row))
                    rid = r.get("resource_id")
                    if not rid:
                        continue
                    # Handle JSON-encoded record
                    record_json_str = r.get("record_json", "")
                    if record_json_str:
                        try:
                            rj = json.loads(record_json_str)
                            emails = [rj.get(k) for k in ["email","requester_email"] if rj.get(k)]
                            user_ids = [rj.get(k) for k in ["user_id","customer_reference"] if rj.get(k)]
                            origin = r.get("origin_system", "unknown")
                            if emails or user_ids:
                                state = "PRESENT"
                                if not any(rj.get(k) for k in ["email","phone","email_hash"]) and origin == "analytics_platform":
                                    state = "ANONYMIZED"
                                index.add(Record(file_id, captured_at, origin, rid, state,
                                                 emails=emails, user_ids=user_ids, extra=rj))
                        except Exception:
                            pass
                    else:
                        emails = [v for k, v in r.items()
                                  if k in ["email","requester_email"] and v and "@" in str(v)]
                        user_ids = [v for k, v in r.items()
                                    if k in ["user_id","customer_reference"] and v and "@" not in str(v)]
                        if emails or user_ids:
                            origin = r.get("origin_system", "unknown")
                            index.add(Record(file_id, captured_at, origin, rid, "PRESENT",
                                             emails=emails, user_ids=user_ids, extra=r))
            except Exception:
                pass
        conn.close()
    except Exception as e:
        log.warning("SQL replica parse fail %s: %s", path.name, e)


def parse_sql_generic(file_id, captured_at, path, index: EvidenceIndex):
    try:
        sql = path.read_text(encoding="utf-8")
        conn = sqlite3.connect(":memory:")
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.executescript(sql)
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for tbl in tables:
            if tbl in ("snapshot_scope",):
                continue
            try:
                cols = [r[1] for r in conn.execute(f"PRAGMA table_info({tbl})")]
                rows = conn.execute(f"SELECT * FROM {tbl}").fetchall()
                for row in rows:
                    r = dict(zip(cols, row))
                    rid = r.get("resource_id")
                    if not rid:
                        continue
                    emails = [v for k, v in r.items()
                              if k in ["email","user_email","requester_email","owner_email","customer_email"] and v and "@" in str(v)]
                    user_ids = [v for k, v in r.items()
                                if k in ["user_id","customer_reference","subject_reference"] and v and "@" not in str(v)]
                    if not (emails or user_ids):
                        continue
                    # Infer system from rid prefix
                    sys_id = "unknown"
                    for keyword, sid in [("account","account_service"),("search","search_service"),
                                         ("analytics","analytics_platform"),("support","support_platform"),
                                         ("export","export_service"),("data_flow","integration_service"),
                                         ("backup","backup_service"),("audit_record","security_service"),
                                         ("tombstone","identity_service"),("marketing","marketing_platform")]:
                        if keyword in rid.lower():
                            sys_id = sid
                            break
                    state = "PRESENT"
                    if r.get("restore_allowed") == 0:
                        state = "BLOCKED"
                    elif r.get("restore_allowed") == 1:
                        state = "ACTIVE"
                    elif r.get("enabled") == 0:
                        state = "DISABLED"
                    elif r.get("enabled") == 1:
                        state = "ACTIVE"
                    index.add(Record(file_id, captured_at, sys_id, rid, state,
                                     emails=emails, user_ids=user_ids, extra=r))
            except Exception:
                pass
        conn.close()
    except Exception as e:
        log.warning("SQL generic parse fail %s: %s", path.name, e)


# ─────────────────────────────────────────────────────────────────────────────
# Build Evidence Index
# ─────────────────────────────────────────────────────────────────────────────

def build_evidence_index(evidence_csv: Path) -> EvidenceIndex:
    index = EvidenceIndex()
    rows = load_csv_rows(evidence_csv)
    log.info("Indexing %d evidence files...", len(rows))
    for row in rows:
        file_id = row["file_id"]
        rel_path = row["file_path"]
        captured_at = parse_dt(row["captured_at"])
        path = DATASET_DIR / rel_path
        if not path.exists():
            continue
        index.file_meta[file_id] = {"path": str(path), "captured_at": captured_at}
        fname = path.name.lower()
        suffix = path.suffix.lower()
        try:
            if suffix == ".txt":
                parse_handover_txt(file_id, captured_at, path, index)
            elif suffix == ".json":
                if "service_resource_export" in fname:
                    parse_service_resource_export_json(file_id, captured_at, path, index)
                elif "snapshot_bundle" in fname:
                    parse_snapshot_bundle_json(file_id, captured_at, path, index)
                elif "security_audit" in fname or "audit_ledger" in fname:
                    parse_security_audit_json(file_id, captured_at, path, index)
                elif "analytics_report" in fname:
                    parse_analytics_json(file_id, captured_at, path, index)
                elif "export_jobs" in fname:
                    parse_export_jobs_json(file_id, captured_at, path, index)
                elif "connector" in fname:
                    parse_connector_json(file_id, captured_at, path, index)
                elif "export_manifest" in fname:
                    parse_export_manifest_json(file_id, captured_at, path, index)
                else:
                    parse_generic_json(file_id, captured_at, path, index)
            elif suffix == ".sql":
                if "inventory" in fname:
                    parse_sql_inventory(file_id, captured_at, path, index)
                elif "read_replica" in fname:
                    parse_sql_read_replica(file_id, captured_at, path, index)
                else:
                    parse_sql_generic(file_id, captured_at, path, index)
            elif suffix == ".log":
                if "resource_lookup_trace" in fname:
                    parse_resource_lookup_log(file_id, captured_at, path, index)
                else:
                    parse_service_events_log(file_id, captured_at, path, index)
        except Exception as e:
            log.warning("Error indexing %s: %s", file_id, e)

    total = sum(len(v) for v in index._by_email.values())
    log.info("Index: %d email entries, %d user_id entries",
             len(index._by_email), len(index._by_user_id))
    return index


# ─────────────────────────────────────────────────────────────────────────────
# Identity Resolution
# ─────────────────────────────────────────────────────────────────────────────

def build_identity_maps(user_identities, user_audit_log):
    email_to_user: Dict[str, Dict] = {}
    user_id_to_emails: Dict[str, List[str]] = defaultdict(list)

    for u in user_identities:
        e = norm_email(u.get("email", ""))
        uid = u.get("user_id", "")
        if e:
            email_to_user[e] = u
        if uid and e:
            if e not in user_id_to_emails[uid]:
                user_id_to_emails[uid].append(e)

    for entry in user_audit_log:
        uid = entry.get("user_id", "")
        field = entry.get("field_name", "")
        if field != "email":
            continue
        for val in [entry.get("old_value", ""), entry.get("new_value", "")]:
            e = norm_email(val)
            if e and e not in user_id_to_emails[uid]:
                user_id_to_emails[uid].append(e)
            if e and e not in email_to_user:
                # Link old email to the user
                for ce in user_id_to_emails[uid]:
                    if ce in email_to_user:
                        email_to_user[e] = email_to_user[ce]
                        break

    return email_to_user, user_id_to_emails


def resolve_identity(request_email, email_to_user, user_id_to_emails):
    norm = norm_email(request_email)
    user = email_to_user.get(norm)
    if user:
        uid = user.get("user_id", "")
        all_emails = list(user_id_to_emails.get(uid, [norm]))
        return uid, list(set(all_emails + [norm]))
    for uid, emails in user_id_to_emails.items():
        if norm in [norm_email(e) for e in emails]:
            return uid, list(set(emails + [norm]))
    return None, [norm]


# ─────────────────────────────────────────────────────────────────────────────
# Deletion Request Classifier
# ─────────────────────────────────────────────────────────────────────────────

DELETION_PATTERNS = [
    r"\bdelete\b", r"\bdeletion\b", r"\berase\b", r"\berasure\b",
    r"\bremove\b.*\b(account|data|profile|personal)\b",
    r"\b(account|data|profile)\b.*\bremove\b",
    r"\bclose.*account\b", r"\baccount.*clos",
    r"\bpermanent", r"\bright to be forgotten\b",
    r"\bwipe\b.*\bdata\b", r"\bdelete.*profile\b",
    r"\berased\b", r"\blöschen\b", r"\bsuppression\b",
    r"supprim", r"\beffacer\b",  # French
    r"\bborrar\b", r"\beliminar\b",  # Spanish
    r"\b削除\b",  # Japanese
    r"\blösch",  # German
]

NON_DELETION_PATTERNS = [
    r"^(?!.*(?:delete|erase|remove.*account|close.*account|deletion|erasure)).*(?:export|download|copy of|access to|access my data|data access|request.{0,20}copy)\b",
    r"^(?!.*(?:delete|erase|remove|close)).*\bunsubscribe\b",
    r"^(?!.*(?:delete|erase|remove|close)).*\bopt.?out\b.*\bmarket",
    r"^(?!.*(?:delete|erase|remove|close)).*\bcorrect\b",
]

def is_deletion_request(text: str) -> bool:
    if not text:
        return False
    tl = text.lower()
    for p in DELETION_PATTERNS:
        if re.search(p, tl):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# System Activity
# ─────────────────────────────────────────────────────────────────────────────

def load_system_activity(path: Path) -> List[Dict]:
    return load_csv_rows(path)


def filter_activity_for_case(activities: List[Dict], resource_ids: set,
                              requested_at: Optional[datetime],
                              audit_at: Optional[datetime]) -> List[Dict]:
    """Return activity records relevant to this case (by resource_id or timing)."""
    relevant = []
    for act in activities:
        rid = act.get("resource_id", "")
        et = parse_dt(act.get("event_time", ""))
        if not et:
            continue
        # Filter by time window
        if audit_at and et > audit_at:
            continue
        if rid in resource_ids:
            relevant.append(act)
    return relevant


def get_deletion_activities(activities: List[Dict],
                             requested_at: Optional[datetime],
                             audit_at: Optional[datetime]) -> List[Dict]:
    """Get deletion-related activities in the time window."""
    deletion_types = {"DELETE_RECORD", "ANONYMIZE_RECORD", "REDACT_RECORD",
                      "BLOCK_RESTORE", "DISABLE_DATA_FLOW"}
    results = []
    for act in activities:
        et = parse_dt(act.get("event_time", ""))
        if not et:
            continue
        if requested_at and et < requested_at:
            continue
        if audit_at and et > audit_at:
            continue
        if act.get("event_type") in deletion_types:
            results.append(act)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Claude Integration
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a privacy deletion audit agent for Northstar Shop. Analyze evidence and produce structured JSON audit steps.

=== DELETION RULES ===
system_id -> required_action:
- account_service (USER_PROFILE): DELETE -> state=ABSENT
- search_service (SEARCH_INDEX_ENTRY): DELETE -> state=ABSENT
- analytics_platform (ANALYTICS_PROFILE): ANONYMIZE -> state=ANONYMIZED (null identifiers)
- support_platform (SUPPORT_MESSAGE): REDACT if shared context, DELETE if subject-only -> state=REDACTED or ABSENT
- export_service (USER_EXPORT): DELETE -> state=ABSENT
- marketing_platform (MARKETING_PROFILE): DELETE -> state=ABSENT
- integration_service data flows: DISABLE_DATA_FLOW -> state=DISABLED (then DELETE)
- backup_service (BACKUP_ARCHIVE): RETAIN but BLOCK restore -> state=BLOCKED
- security_service (SECURITY_AUDIT_LOG): RETAIN -> state=PRESENT (never delete)
- identity_service (ACCOUNT_TOMBSTONE): REDACT (keep user_id, remove name/email/phone) -> state=REDACTED

=== STEP FORMAT ===
{"step_no":1,"phase":"FINDING","system_id":"account_service","resource_id":"account_001","operation":"REPORT_REMAINING_RECORD","state":"PRESENT","evidence_id":"evidence_54"}

=== PHASES AND OPERATIONS ===
FINDING: REPORT_REMAINING_RECORD, REPORT_EXPOSED_PII, REPORT_ACTIVE_DATA_FLOW, REPORT_RESTORE_RISK
REMEDIATION: DISABLE_DATA_FLOW, BLOCK_RESTORE, DELETE_RECORD, REDACT_RECORD, ANONYMIZE_RECORD
VERIFICATION: VERIFY_RECORD_ABSENT, VERIFY_RECORD_PRESENT, VERIFY_RECORD_REDACTED, VERIFY_RECORD_ANONYMIZED, VERIFY_DATA_FLOW_DISABLED, VERIFY_RESTORE_BLOCKED

=== ORDERING RULES ===
Phase order: FINDING → REMEDIATION → VERIFICATION
Within FINDING: operation order as listed above, then system_id asc, then resource_id asc
Within REMEDIATION: DISABLE_DATA_FLOW and BLOCK_RESTORE before DELETE/REDACT/ANONYMIZE
Within VERIFICATION: operation order as listed above, then system_id asc, then resource_id asc

=== DECISION RULES ===
1. NOT_APPLICABLE: request_text does NOT authorize deletion → return []
   - Access, export, correction, marketing opt-out are NOT deletion
2. INCOMPLETE: records still present that should be absent/anonymized/redacted, OR active data flows/restore risks
3. COMPLETE: all required treatments verified by evidence, no remaining issues

=== EVIDENCE RULES ===
- COMPLETE case: EVERY step cites an evidence_id (file_id from evidence)
- INCOMPLETE FINDING steps: cite evidence_id proving the problem
- INCOMPLETE REMEDIATION steps: evidence_id=""
- INCOMPLETE post-remediation VERIFICATION steps: evidence_id=""
- ONLY cite evidence captured at or before audit_at

=== MANDATORY STEPS ===
For any deletion case with evidence:
- Always VERIFY_RECORD_ABSENT for account_service (the account profile)
- Always VERIFY_RECORD_PRESENT for security_service audit record (must be retained)
- For each anonymized analytics record: VERIFY_RECORD_ANONYMIZED
- For each redacted support record: VERIFY_RECORD_REDACTED
- For each disabled data flow: VERIFY_DATA_FLOW_DISABLED
- For each blocked backup: VERIFY_RESTORE_BLOCKED

=== EVIDENCE STATE MEANINGS ===
- ABSENT/NOT_FOUND/404: record deleted → VERIFY_RECORD_ABSENT
- PRESENT/FOUND/IDENTIFIABLE: record still has PII → REPORT_REMAINING_RECORD or REPORT_EXPOSED_PII
- ANONYMIZED: PII removed → VERIFY_RECORD_ANONYMIZED
- REDACTED: identifiers removed → VERIFY_RECORD_REDACTED
- ACTIVE (data flow): still running → REPORT_ACTIVE_DATA_FLOW
- DISABLED: stopped → VERIFY_DATA_FLOW_DISABLED
- ACTIVE (backup): restore possible → REPORT_RESTORE_RISK
- BLOCKED: restore prevented → VERIFY_RESTORE_BLOCKED

Return ONLY valid JSON:
{"deletion_status":"COMPLETE"|"INCOMPLETE"|"NOT_APPLICABLE","steps":[...]}"""


def format_records_for_prompt(records: List[Record]) -> str:
    if not records:
        return "None found in evidence."
    lines = []
    by_sys = defaultdict(list)
    for r in records:
        by_sys[r.system_id].append(r)
    for sys_id in sorted(by_sys.keys()):
        lines.append(f"[{sys_id}]")
        for r in sorted(by_sys[sys_id], key=lambda x: (x.resource_id, str(x.captured_at))):
            dt = r.captured_at.strftime("%Y-%m-%dT%H:%M:%SZ") if r.captured_at else "?"
            extra = ""
            if sys_id == "integration_service" and r.extra.get("connector_name"):
                extra = f" ({r.extra['connector_name']})"
            lines.append(f"  {r.resource_id}: state={r.state}{extra} | evidence={r.file_id} | captured={dt}")
    return "\n".join(lines)


def call_claude(client, case: Dict, user_id: Optional[str],
                all_emails: List[str], records: List[Record],
                is_deletion: bool, deletion_activities: List[Dict],
                usage_tracker: List) -> Dict:
    from anthropic import Anthropic

    if not is_deletion:
        return {"deletion_status": "NOT_APPLICABLE", "steps": []}

    records_text = format_records_for_prompt(records)

    # Format relevant activities
    act_lines = []
    for act in deletion_activities[:30]:
        act_lines.append(
            f"  {act['event_time']} | {act['event_type']} | {act.get('source_system','')} → "
            f"{act.get('target_system','')} | {act['resource_id']} | {act.get('reported_result','')} | "
            f"{act.get('details','')[:80]}"
        )
    activities_text = "\n".join(act_lines) if act_lines else "None"

    user_prompt = f"""=== CASE ===
case_id: {case['case_id']}
email: {case['email']}
requested_at: {case['requested_at']}
reported_status: {case['reported_status']}
audit_at: {case['audit_at']}
request_text: {case['request_text']}

=== USER IDENTITY ===
user_id: {user_id or 'NOT FOUND'}
all known emails: {', '.join(all_emails)}

=== EVIDENCE RECORDS (captured ≤ audit_at) ===
{records_text}

=== DELETION-RELATED SYSTEM ACTIVITY (between request and audit_at) ===
{activities_text}

Analyze this case and produce the JSON output."""

    for attempt in range(3):
        try:
            resp = client.messages.create(
                model="claude-opus-4-5",
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}]
            )
            usage_tracker.append({
                "input_tokens": resp.usage.input_tokens,
                "output_tokens": resp.usage.output_tokens
            })
            content = resp.content[0].text.strip()
            content = re.sub(r"^```[a-z]*\n?", "", content)
            content = re.sub(r"\n?```$", "", content)
            result = json.loads(content)
            return result
        except json.JSONDecodeError as e:
            log.warning("Case %s: JSON parse error attempt %d: %s",
                        case["case_id"], attempt + 1, e)
            if attempt == 2:
                return {"deletion_status": "INCOMPLETE", "steps": []}
        except Exception as e:
            log.warning("Case %s: API error attempt %d: %s",
                        case["case_id"], attempt + 1, e)
            if attempt < 2:
                time.sleep(5 * (attempt + 1))
            else:
                return {"deletion_status": "INCOMPLETE", "steps": []}
    return {"deletion_status": "INCOMPLETE", "steps": []}


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    from anthropic import Anthropic

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        env_path = REPO_ROOT / ".env"
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                if line.startswith("ANTHROPIC_API_KEY="):
                    api_key = line.split("=", 1)[1].strip().strip('"\'')
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not set. Set it as env var or in .env file.")
        sys.exit(1)

    client = Anthropic(api_key=api_key)

    log.info("Loading dataset files...")
    deletion_requests = load_csv_rows(DATASET_DIR / "deletion_requests.csv")
    user_identities = load_csv_rows(DATASET_DIR / "user_identities.csv")
    user_audit_log = load_csv_rows(DATASET_DIR / "user_audit_log.csv")
    activities = load_system_activity(DATASET_DIR / "system_activity.csv")

    log.info("Building identity maps...")
    email_to_user, user_id_to_emails = build_identity_maps(user_identities, user_audit_log)

    log.info("Building evidence index...")
    index = build_evidence_index(DATASET_DIR / "evidence_files.csv")

    usage_tracker: List[Dict] = []
    results = []
    total = len(deletion_requests)

    log.info("Processing %d deletion requests...", total)
    for i, case in enumerate(deletion_requests):
        case_id = case["case_id"]
        log.info("[%d/%d] %s (%s)", i + 1, total, case_id, case.get("email", ""))

        is_deletion = is_deletion_request(case.get("request_text", ""))
        if not is_deletion:
            results.append({"case_id": case_id, "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"})
            continue

        user_id, all_emails = resolve_identity(case.get("email", ""), email_to_user, user_id_to_emails)
        user_ids = [user_id] if user_id else []
        audit_at = parse_dt(case.get("audit_at", ""))
        requested_at = parse_dt(case.get("requested_at", ""))

        # Find evidence records
        records = index.find(all_emails, user_ids, audit_at)

        # Find known resource_ids from evidence
        known_rids = {r.resource_id for r in records}

        # Find relevant activities
        deletion_acts = get_deletion_activities(activities, requested_at, audit_at)
        relevant_acts = filter_activity_for_case(activities, known_rids, requested_at, audit_at)
        # Combine, dedup
        all_act_ids = {a["activity_id"] for a in deletion_acts}
        for a in relevant_acts:
            if a["activity_id"] not in all_act_ids:
                deletion_acts.append(a)
                all_act_ids.add(a["activity_id"])

        result = call_claude(client, case, user_id, all_emails, records,
                             is_deletion, deletion_acts[:40], usage_tracker)

        deletion_status = result.get("deletion_status", "INCOMPLETE")
        steps = result.get("steps", [])
        for j, step in enumerate(steps):
            step["step_no"] = j + 1

        results.append({
            "case_id": case_id,
            "deletion_status": deletion_status,
            "steps_json": json.dumps(steps, separators=(",", ":"))
        })

        # Small rate limit pause
        if (i + 1) % 10 == 0:
            time.sleep(1)

    # Sort by case_id number
    results.sort(key=lambda r: int(re.search(r"\d+", r["case_id"]).group()) if re.search(r"\d+", r["case_id"]) else 0)

    log.info("Writing %s...", OUTPUT_FILE)
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(results)

    # Usage summary
    if usage_tracker:
        total_in = sum(u["input_tokens"] for u in usage_tracker)
        total_out = sum(u["output_tokens"] for u in usage_tracker)
        n_calls = len(usage_tracker)
        log.info("API usage: %d calls, %d input tokens, %d output tokens",
                 n_calls, total_in, total_out)
        log.info("Avg per case: %.0f input, %.0f output tokens",
                 total_in / n_calls, total_out / n_calls)
        # Estimate cost: claude-opus-4-5 pricing (approximate)
        cost_in = total_in / 1_000_000 * 15.0
        cost_out = total_out / 1_000_000 * 75.0
        log.info("Estimated cost: $%.2f (input) + $%.2f (output) = $%.2f",
                 cost_in, cost_out, cost_in + cost_out)

        # Write usage report
        usage_report = REPO_ROOT / "code" / "evaluation" / "usage_report.md"
        usage_report.parent.mkdir(exist_ok=True)
        with open(usage_report, "w") as f:
            f.write(f"""# Usage Report — Ghost Data Still Exists

## Final Full-Dataset Run

- **Model provider:** Anthropic
- **Model name:** claude-opus-4-5
- **Total model calls:** {n_calls}
- **Total input tokens:** {total_in:,}
- **Total output tokens:** {total_out:,}
- **Average input tokens per request:** {total_in // n_calls:,}
- **Average output tokens per request:** {total_out // n_calls:,}
- **Estimated total cost:** ${cost_in + cost_out:.2f}
- **Estimated cost per request:** ${(cost_in + cost_out) / n_calls:.4f}

## Notes

Single model (claude-opus-4-5) used for all cases.
Evidence indexing was done programmatically (no API tokens consumed).
""")
        log.info("Usage report written to %s", usage_report)

    log.info("Done. %d rows written.", len(results))


if __name__ == "__main__":
    main()
