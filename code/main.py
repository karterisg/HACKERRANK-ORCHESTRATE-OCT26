#!/usr/bin/env python3
"""
Deletion Audit Agent — Ghost Data Still Exists
HackerRank Orchestrate Challenge, October 2026
Rule-based deterministic agent — no external API required.
"""

import csv, json, re, sqlite3, logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Optional, Dict, List, Tuple

REPO_ROOT   = Path(__file__).parent.parent
DATASET_DIR = REPO_ROOT / "dataset"
OUTPUT_FILE = REPO_ROOT / "output.csv"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Policy tables
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_CATEGORY = {
    "account_service":     "USER_PROFILE",
    "search_service":      "SEARCH_INDEX_ENTRY",
    "analytics_platform":  "ANALYTICS_PROFILE",
    "support_platform":    "SUPPORT_MESSAGE",
    "export_service":      "USER_EXPORT",
    "integration_service": "INTEGRATION_FLOW",
    "backup_service":      "BACKUP_ARCHIVE",
    "security_service":    "SECURITY_AUDIT_LOG",
    "identity_service":    "ACCOUNT_TOMBSTONE",
    "marketing_platform":  "MARKETING_PROFILE",
}

REQUIRED_ACTION = {
    "USER_PROFILE":        "DELETE",
    "SECONDARY_IDENTIFIER":"DELETE",
    "SEARCH_INDEX_ENTRY":  "DELETE",
    "CACHE_ENTRY":         "DELETE",
    "SUPPORT_MESSAGE":     "REDACT",
    "SUPPORT_ATTACHMENT":  "DELETE",
    "SUPPORT_RECORD":      "DELETE",   # default when record_type unknown
    "ANALYTICS_PROFILE":   "ANONYMIZE",
    "PRODUCT_TELEMETRY":   "ANONYMIZE",
    "USER_EXPORT":         "DELETE",
    "MARKETING_PROFILE":   "DELETE",
    "EMAIL_DELIVERY_LOG":  "REDACT",
    "SECURITY_AUDIT_LOG":  "RETAIN",
    "LEGAL_HOLD_RECORD":   "RETAIN",
    "BACKUP_ARCHIVE":      "RETAIN",
    "ACCOUNT_TOMBSTONE":   "REDACT",
    "INTEGRATION_FLOW":    "DISABLE",
}

SYSTEM_ORDER = [
    "account_service","analytics_platform","backup_service",
    "export_service","identity_service","integration_service",
    "marketing_platform","search_service","security_service",
    "support_platform","unknown",
]

OP_ORDER = {
    "FINDING":      {"REPORT_REMAINING_RECORD":0,"REPORT_EXPOSED_PII":1,"REPORT_ACTIVE_DATA_FLOW":2,"REPORT_RESTORE_RISK":3},
    "REMEDIATION":  {"DISABLE_DATA_FLOW":0,"BLOCK_RESTORE":1,"DELETE_RECORD":2,"REDACT_RECORD":3,"ANONYMIZE_RECORD":4},
    "VERIFICATION": {"VERIFY_RECORD_ABSENT":0,"VERIFY_RECORD_PRESENT":1,"VERIFY_RECORD_REDACTED":2,"VERIFY_RECORD_ANONYMIZED":3,"VERIFY_DATA_FLOW_DISABLED":4,"VERIFY_RESTORE_BLOCKED":5},
}

# result field → state
RESULT_TO_STATE = {
    "NOT_FOUND":   "ABSENT",
    "FOUND":       "PRESENT",
    "IDENTIFIABLE":"PRESENT",
    "ANONYMIZED":  "ANONYMIZED",
    "REDACTED":    "REDACTED",
    "ACTIVE":      "ACTIVE",
    "DISABLED":    "DISABLED",
    "BLOCKED":     "BLOCKED",
}

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def parse_dt(s):
    if not s: return None
    try: return datetime.fromisoformat(s.replace("Z","+00:00"))
    except: return None

def norm(e): return e.strip().lower() if e else ""

def load_csv(path):
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))

def sys_rank(s):
    try: return SYSTEM_ORDER.index(s)
    except: return len(SYSTEM_ORDER)

def _jload(path):
    try:
        with open(path, encoding="utf-8") as f: return json.load(f)
    except: return None

def _is_email(s): return s and "@" in s
def _is_uid(s):   return s and bool(re.match(r"user_\d+", s))

# ─────────────────────────────────────────────────────────────────────────────
# Evidence Record & Index
# ─────────────────────────────────────────────────────────────────────────────

class Record:
    __slots__ = ("file_id","captured_at","system_id","resource_id","state","emails","user_ids","extra")
    def __init__(self, file_id, captured_at, system_id, resource_id, state,
                 emails=None, user_ids=None, extra=None):
        self.file_id=file_id; self.captured_at=captured_at
        self.system_id=system_id; self.resource_id=resource_id; self.state=state
        self.emails=[norm(e) for e in (emails or []) if e and _is_email(e)]
        self.user_ids=[u for u in (user_ids or []) if u and _is_uid(u)]
        self.extra=extra or {}

class EvidenceIndex:
    def __init__(self):
        self._email: Dict[str,List[Record]] = defaultdict(list)
        self._uid:   Dict[str,List[Record]] = defaultdict(list)
        self._hash:  Dict[str,List[Record]] = defaultdict(list)  # email_hash → records
        self._rid:   Dict[str,List[Record]] = defaultdict(list)  # resource_id → records

    def add(self, rec, hashes=None):
        for e in rec.emails:   self._email[e].append(rec)
        for u in rec.user_ids: self._uid[u].append(rec)
        for h in (hashes or []):
            if h: self._hash[h].append(rec)
        self._rid[rec.resource_id].append(rec)

    def link_to_user(self, resource_id: str, emails: List[str], user_ids: List[str]):
        """Re-index existing records for resource_id under additional email/uid keys.
        Only links records that have NO existing PII (email/uid) — never overwrites known links."""
        for rec in self._rid.get(resource_id, []):
            if rec.emails or rec.user_ids:
                continue  # already has PII-based link — don't overwrite with batch heuristic
            for e in [norm(x) for x in emails if x and _is_email(x)]:
                if rec not in self._email[e]: self._email[e].append(rec)
            for u in [x for x in user_ids if x and _is_uid(x)]:
                if rec not in self._uid[u]: self._uid[u].append(rec)

    def find(self, emails, user_ids, audit_at, hashes=None):
        seen, results, cands = set(), [], []
        for e in emails:    cands.extend(self._email.get(norm(e),[]))
        for u in user_ids:  cands.extend(self._uid.get(u,[]))
        for h in (hashes or []):
            cands.extend(self._hash.get(h,[]))
        for rec in cands:
            key = (rec.file_id, rec.resource_id)
            if key in seen: continue
            seen.add(key)
            # Security records are always retained; include regardless of captured_at
            if (audit_at is None or rec.captured_at is None or
                    rec.captured_at <= audit_at or rec.system_id == "security_service"):
                results.append(rec)
        return results

# ─────────────────────────────────────────────────────────────────────────────
# Generic Records Parser (handles most JSON evidence files)
# Format: {"records": [{"system": ..., "resource_id": ..., "result": ..., "subject_reference": ...}]}
# ─────────────────────────────────────────────────────────────────────────────

def parse_generic_records(fid, cat, data, idx):
    """Parse any JSON file whose top-level 'records' array contains
    system/resource_id/result/subject_reference rows."""
    for r in data.get("records", []):
        rid    = r.get("resource_id")
        sys_id = r.get("system", "unknown")
        subj   = r.get("subject_reference", "") or ""
        result = r.get("result", "")
        state  = RESULT_TO_STATE.get(result, "PRESENT") if result else "PRESENT"
        if not rid: continue
        emails   = [subj] if _is_email(subj) else []
        user_ids = [subj] if _is_uid(subj) else []
        if not (emails or user_ids): continue
        idx.add(Record(fid, cat, sys_id, rid, state, emails=emails, user_ids=user_ids))


def parse_export_jobs_records(fid, cat, data, idx):
    """Parse customer_export_jobs JSON: records with owner_email, download_available."""
    for r in data.get("records", []):
        rid   = r.get("resource_id")
        email = r.get("owner_email", "")
        subj  = r.get("customer_reference", "")
        if not rid or not (email or subj): continue
        avail = r.get("download_available", True)
        state = "PRESENT" if avail else "ABSENT"
        idx.add(Record(fid, cat, "export_service", rid, state,
                       emails=[email] if email else [],
                       user_ids=[subj] if _is_uid(subj) else []))


def parse_analytics_records(fid, cat, data, idx):
    """Parse customer_analytics_report JSON: records with user_id/email/email_hash."""
    for r in data.get("records", []):
        rid    = r.get("resource_id")
        email  = r.get("email", "") or ""
        uid    = r.get("user_id", "") or ""
        ehash  = r.get("email_hash", "") or ""
        if not rid: continue
        has_pii = any(r.get(k) for k in ["email","phone","email_hash"])
        state   = "PRESENT" if has_pii else "ANONYMIZED"
        emails   = [email] if _is_email(email) else []
        user_ids = [uid]   if _is_uid(uid) else []
        if not (emails or user_ids or ehash): continue
        idx.add(Record(fid, cat, "analytics_platform", rid, state,
                       emails=emails, user_ids=user_ids), hashes=[ehash] if ehash else None)


def parse_snapshot_bundle(fid, cat, data, idx):
    """Parse customer_data_snapshot_bundle JSON."""
    for snap in data.get("snapshots", []):
        store = snap.get("data_store", "unknown")
        for r in snap.get("records", []):
            rid  = r.get("resource_id")
            if not rid: continue
            subj = r.get("subject_reference", "") or ""
            emails   = [subj]      if _is_email(subj) else []
            user_ids = [subj]      if _is_uid(subj) else []
            # Also check direct email field
            direct_email = r.get("email", "") or ""
            if _is_email(direct_email) and direct_email not in emails:
                emails.append(direct_email)
            if not (emails or user_ids): continue
            # State: for identity_service, check if PII fields are present
            if store == "identity_service":
                has_pii = any(r.get(k) for k in ["email","name","phone","email_hash"])
                state   = "PRESENT" if has_pii else "REDACTED"
            elif store == "security_service":
                state = "PRESENT"  # always retain
            elif r.get("account_status") == "DELETED":
                state = "ABSENT"
            else:
                has_pii = any(r.get(k) for k in ["email","name","phone","email_hash"])
                state   = "PRESENT" if has_pii else "REDACTED"
            idx.add(Record(fid, cat, store, rid, state, emails=emails, user_ids=user_ids, extra=r))


def parse_sre_json(fid, cat, data, idx):
    """Parse service_resource_export JSON."""
    ex = data.get("service_exports", {})

    for e in ex.get("account_service", {}).get("profile_lookups", []):
        rid=e.get("resource_id"); p=e.get("profile") or {}
        emails=[v for k,v in p.items() if k=="email" and v]
        uids=[v for k,v in p.items() if k=="customer_reference" and v]
        if rid: idx.add(Record(fid,cat,"account_service",rid,
                               "ABSENT" if e.get("status_code")==404 else "PRESENT",
                               emails=emails,user_ids=uids))

    for e in ex.get("analytics_platform", {}).get("profiles", []):
        rid=e.get("resource_id")
        emails=[v for k,v in e.items() if k in ["email"] and v]
        uids=[v for k,v in e.items() if k=="customer_reference" and v]
        pii=any(e.get(k) for k in ["email","phone","email_hash"])
        if rid and (emails or uids):
            idx.add(Record(fid,cat,"analytics_platform",rid,"PRESENT" if pii else "ANONYMIZED",
                           emails=emails,user_ids=uids))

    for e in ex.get("backup_service", {}).get("restore_entries", []):
        rid=e.get("resource_id")
        emails=[v for k,v in e.items() if k=="customer_email" and v]
        uids=[v for k,v in e.items() if k=="customer_reference" and v]
        if rid and (emails or uids):
            idx.add(Record(fid,cat,"backup_service",rid,
                           "ACTIVE" if e.get("restore_allowed") else "BLOCKED",
                           emails=emails,user_ids=uids))

    for e in ex.get("export_service", {}).get("exports", []):
        rid=e.get("resource_id")
        emails=[v for k,v in e.items() if k=="owner_email" and v]
        uids=[v for k,v in e.items() if k=="customer_reference" and v]
        if rid and (emails or uids):
            idx.add(Record(fid,cat,"export_service",rid,"PRESENT",emails=emails,user_ids=uids))

    for e in ex.get("integration_service", {}).get("connectors", []):
        rid=e.get("resource_id")
        emails=[v for k,v in e.items() if k=="customer_email" and v]
        uids=[v for k,v in e.items() if k=="customer_reference" and v]
        if rid and (emails or uids):
            idx.add(Record(fid,cat,"integration_service",rid,
                           "ACTIVE" if e.get("enabled") else "DISABLED",
                           emails=emails,user_ids=uids))

    for e in ex.get("search_service", {}).get("index_queries", []):
        rid=e.get("resource_id"); hits=e.get("hits",{})
        docs=hits.get("documents",[])
        emails=[d.get("email") for d in docs if d.get("email")]
        uids=[d.get("customer_reference") for d in docs if d.get("customer_reference")]
        if rid and (emails or uids):
            idx.add(Record(fid,cat,"search_service",rid,
                           "PRESENT" if hits.get("total",0)>0 else "ABSENT",
                           emails=emails,user_ids=uids))

    for e in ex.get("support_platform", {}).get("tickets", []):
        rid=e.get("resource_id")
        emails=[v for k,v in e.items() if k=="requester_email" and v]
        uids=[v for k,v in e.items() if k=="customer_reference" and v]
        pii=any(e.get(k) for k in ["requester_email","requester_name","requester_phone"])
        if rid and (emails or uids):
            idx.add(Record(fid,cat,"support_platform",rid,"PRESENT" if pii else "REDACTED",
                           emails=emails,user_ids=uids))

    for e in ex.get("identity_service", {}).get("tombstones", []):
        rid=e.get("resource_id")
        emails=[v for k,v in e.items() if k=="email" and v]
        uids=[v for k,v in e.items() if k in ["user_id","customer_reference"] and v]
        pii=any(e.get(k) for k in ["email","full_name","phone"])
        if rid and (emails or uids):
            idx.add(Record(fid,cat,"identity_service",rid,"PRESENT" if pii else "REDACTED",
                           emails=emails,user_ids=uids))

    for e in ex.get("marketing_platform", {}).get("profiles", []):
        rid=e.get("resource_id")
        emails=[v for k,v in e.items() if k in ["email","customer_email"] and v]
        uids=[v for k,v in e.items() if k=="customer_reference" and v]
        if rid and (emails or uids):
            idx.add(Record(fid,cat,"marketing_platform",rid,"PRESENT",emails=emails,user_ids=uids))

    for e in ex.get("security_service", {}).get("audit_records", []):
        rid=e.get("resource_id")
        uids=[v for k,v in e.items() if k=="subject_reference" and v and _is_uid(v)]
        if rid and uids:
            idx.add(Record(fid,cat,"security_service",rid,"PRESENT",user_ids=uids))


def parse_service_events_log(fid, cat, path, idx, hash_to_emails: Dict[str,str]):
    """Parse service_events_*.log grouped by trace_id.

    Key insight: identifier keys (lookup_key, subject_key, etc.) and resource_id
    appear on DIFFERENT lines within the same trace. We must collect ALL fields
    from ALL lines of a trace before building a Record.
    """
    VALID_SYSTEMS = {
        "account_service","search_service","analytics_platform","support_platform",
        "export_service","integration_service","backup_service","security_service",
        "identity_service","marketing_platform","support_replica",
    }
    ID_KEYS = ["lookup_key","subject_key","correlation_key","match_key",
               "requester_email","customer_email","email","subject_ref","subject_reference"]
    try:
        pairs: Dict[str,Dict] = {}
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            # Every useful line has a trace_id; skip lines that don't
            tid_m = re.search(r"\btrace_id=([^\s]+)", line)
            if not tid_m: continue
            # Parse timestamp from line prefix (before any space/field)
            ts_m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)", line)
            line_ts = parse_dt(ts_m.group(1)) if ts_m else None
            tid = tid_m.group(1)
            if tid not in pairs: pairs[tid] = {}
            p = pairs[tid]
            if line_ts and (p.get("ts") is None or line_ts < p["ts"]): p["ts"] = line_ts

            # Service: take first occurrence
            srv_m = re.search(r"\bservice=([a-zA-Z_][a-zA-Z0-9_]*)", line)
            if srv_m and "service" not in p:
                sys_id = srv_m.group(1)
                if sys_id in VALID_SYSTEMS:
                    p["service"] = sys_id

            # resource_id: take first occurrence (it appears on completion lines)
            rid_m = re.search(r"\bresource_id=([a-zA-Z_][a-zA-Z0-9_]*)", line)
            if rid_m and "resource_id" not in p:
                p["resource_id"] = rid_m.group(1)

            # Identifier keys — may appear on start/lookup lines (no resource_id yet)
            for k in ID_KEYS:
                m = re.search(rf'\b{k}="?([^"\s]+)"?', line)
                if not m: continue
                val = m.group(1).strip('"')
                if _is_email(val):
                    p.setdefault("emails", [])
                    if val not in p["emails"]: p["emails"].append(val)
                elif val in hash_to_emails:
                    p.setdefault("emails", [])
                    e = hash_to_emails[val]
                    if e not in p["emails"]: p["emails"].append(e)
                elif _is_uid(val):
                    p.setdefault("user_ids", [])
                    if val not in p["user_ids"]: p["user_ids"].append(val)

            # State signals — collect the most informative one we see across all lines
            http  = re.search(r"\bhttp_status=(\d+)", line)
            rows  = re.search(r"\brows=(\d+)", line)
            enab  = re.search(r"\benabled=(true|false)", line)
            rest  = re.search(r"\brestore_allowed=(true|false)", line)
            dblk  = re.search(r"\bdeletion_block=(true|false)", line)
            elig  = re.search(r"\beligible=(true|false)", line)
            res_m = re.search(r"\bresult=(hit|miss)", line)
            pii_m = re.search(r"\bmatched_value=", line)
            mkr_m = re.search(r"\bmarker_found=(true|false)", line)
            opt_m = re.search(r"\bemail_opt_in=(true|false)", line)
            if opt_m: p["email_opt_in"] = opt_m.group(1)

            # Priority: definitive states override uncertain ones
            cur = p.get("state")
            if http and http.group(1) == "404":
                p["state"] = "ABSENT"
            elif rows and rows.group(1) == "0" and cur not in ("PRESENT","ACTIVE","DISABLED","BLOCKED","ABSENT"):
                p["state"] = "ABSENT"
            elif rows and int(rows.group(1)) > 0 and cur not in ("ABSENT",):
                p["state"] = "PRESENT"
            elif enab and cur not in ("ABSENT","PRESENT"):
                p["state"] = "ACTIVE" if enab.group(1) == "true" else "DISABLED"
            elif dblk and cur not in ("ABSENT","PRESENT","ACTIVE","DISABLED"):
                p["state"] = "BLOCKED" if dblk.group(1) == "true" else "ACTIVE"
            elif elig and elig.group(1) == "true" and cur not in ("BLOCKED",):
                p["state"] = "ACTIVE"
            elif res_m and res_m.group(1) == "hit" and cur not in ("ABSENT",):
                p["state"] = "PRESENT"
            elif pii_m and cur not in ("ABSENT",):
                p["state"] = "PRESENT"
            elif mkr_m and cur is None:
                # marker_found=true → deletion marker present → ABSENT
                # marker_found=false → no deletion marker → still PRESENT
                p["state"] = "ABSENT" if mkr_m.group(1) == "true" else "PRESENT"

        for p in pairs.values():
            rid    = p.get("resource_id")
            sys_id = p.get("service", "")
            emails = p.get("emails", [])
            uids   = p.get("user_ids", [])
            state  = p.get("state", "PRESENT")
            if not rid or sys_id not in VALID_SYSTEMS: continue
            if not (emails or uids): continue
            extra2 = {}
            if p.get("email_opt_in"): extra2["email_opt_in"] = p["email_opt_in"]
            if sys_id == "support_replica":
                sys_id = "support_platform"
                extra2["record_type"] = "SUPPORT_RECORD"  # replica records → DELETE
            ev_ts = p.get("ts", cat)
            idx.add(Record(fid, ev_ts, sys_id, rid, state, emails=emails, user_ids=uids, extra=extra2 or None))
    except Exception as e:
        log.warning("service_events log %s: %s", path.name, e)


def parse_resource_lookup_log(fid, cat, path, idx):
    """Parse resource_lookup_trace_*.log files."""
    VALID = {"account_service","search_service","analytics_platform","support_platform",
             "export_service","integration_service","backup_service","security_service",
             "identity_service","marketing_platform"}
    try:
        pairs: Dict[str,Dict] = {}
        for line in path.read_text(encoding="utf-8",errors="replace").splitlines():
            if "event=" not in line and "service=" not in line: continue
            tm = re.search(r"trace_id=(\S+)", line)
            if not tm: continue
            ts_m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)", line)
            line_ts = parse_dt(ts_m.group(1)) if ts_m else None
            tid = tm.group(1)
            if tid not in pairs: pairs[tid]={}
            if line_ts and (pairs[tid].get("ts") is None or line_ts < pairs[tid]["ts"]):
                pairs[tid]["ts"] = line_ts
            for k in ["service","resource_id","enabled","restore_allowed","customer_email",
                       "customer_reference","lookup_key","requester_email","email",
                       "http_status","rows","last_delivery_status","connector_name",
                       "result","subject_reference"]:
                m = re.search(rf"\b{k}=([^\s]+)", line)
                if m: pairs[tid][k]=m.group(1)

        for f in pairs.values():
            rid=f.get("resource_id"); sys_id=f.get("service","")
            if not rid or sys_id not in VALID: continue
            emails=[f[k] for k in ["lookup_key","customer_email","email","requester_email"]
                    if f.get(k) and "@" in f[k] and f[k]!="null"]
            uids=[f[k] for k in ["lookup_key","customer_reference","subject_reference"]
                  if f.get(k) and f[k]!="null" and _is_uid(f[k])]
            if not emails and not uids: continue
            h=f.get("http_status",""); rows=f.get("rows","")
            en=f.get("enabled",""); ra=f.get("restore_allowed","")
            cr=f.get("customer_reference","null"); em=f.get("email","null")
            # Analytics: if all identifiers are null → ANONYMIZED
            if sys_id=="analytics_platform" and cr in ("null","") and em in ("null",""):
                state="ANONYMIZED"
            elif h=="404" or rows=="0":         state="ABSENT"
            elif en=="false" or f.get("last_delivery_status")=="stopped": state="DISABLED"
            elif ra=="false":                   state="BLOCKED"
            elif en=="true" or ra=="true":      state="ACTIVE"
            elif f.get("result")=="hit":        state="PRESENT"
            else:                               state="PRESENT"
            ev_ts=f.get("ts",cat)
            idx.add(Record(fid,ev_ts,sys_id,rid,state,emails=emails,user_ids=uids,extra=f))
    except Exception as e: log.warning("lookup log %s: %s", path.name, e)


def parse_structured_events_log(fid, cat, path, idx, hash_to_emails):
    """JSON-per-line log; group by trace_id like parse_service_events_log."""
    VALID = {"account_service","search_service","analytics_platform","support_platform",
             "export_service","integration_service","backup_service","security_service",
             "identity_service","marketing_platform","support_replica"}
    ID_KEYS = ["lookup_key","subject_ref","subject_reference","customer_email","email",
               "requester_email","correlation_id"]
    pairs: Dict[str,Dict] = {}
    try:
        for line in path.read_text(encoding="utf-8",errors="replace").splitlines():
            # Line: TIMESTAMP {...json...}
            j_start = line.find("{")
            if j_start < 0: continue
            # Parse event timestamp from line prefix
            line_ts = parse_dt(line[:j_start].strip())
            try: obj = json.loads(line[j_start:])
            except: continue
            tid = obj.get("trace_id")
            if not tid: continue
            if tid not in pairs: pairs[tid] = {}
            p = pairs[tid]
            # Track earliest event timestamp for this trace
            if line_ts and (p.get("ts") is None or line_ts < p["ts"]): p["ts"] = line_ts
            if "service" not in p:
                svc = obj.get("service","") or obj.get("logger","")
                if svc in VALID: p["service"] = svc
            if "resource_id" not in p and obj.get("resource_id"):
                p["resource_id"] = obj["resource_id"]
            for k in ID_KEYS:
                val = str(obj.get(k,"")).strip()
                if not val or val == "null": continue
                if _is_email(val): p.setdefault("emails",[]).append(val)
                elif val in hash_to_emails: p.setdefault("emails",[]).append(hash_to_emails[val])
                elif _is_uid(val): p.setdefault("user_ids",[]).append(val)
            # Determine state
            rows = str(obj.get("rows",""))
            http = str(obj.get("http_status",""))
            integ = obj.get("integrity_check","")
            ev_name = obj.get("event","")
            cur = p.get("state")
            if http=="404" or rows=="0":
                p["state"] = "ABSENT"
            elif rows.isdigit() and int(rows)>0:
                if cur not in ("ABSENT",): p["state"] = "PRESENT"
            elif integ=="passed":
                if cur not in ("ABSENT",): p["state"] = "PRESENT"
        for p in pairs.values():
            rid=p.get("resource_id"); sys_id=p.get("service","")
            emails=list(dict.fromkeys(p.get("emails",[])))
            uids=list(dict.fromkeys(p.get("user_ids",[])))
            state=p.get("state","PRESENT")
            ev_ts = p.get("ts", cat)  # use event timestamp if parsed, else evidence captured_at
            if not rid or sys_id not in VALID: continue
            if sys_id == "support_replica": sys_id = "support_platform"
            if not (emails or uids): continue
            idx.add(Record(fid,ev_ts,sys_id,rid,state,emails=emails,user_ids=uids))
    except Exception as e: log.warning("struct events log %s: %s",path.name,e)


RID_SYS_MAP = {
    "support_":        "support_platform",
    "audit_record_":   "security_service",
    "account_":        "account_service",
    "analytics_":      "analytics_platform",
    "search_":         "search_service",
    "export_":         "export_service",
    "data_flow_":      "integration_service",
    "backup_":         "backup_service",
    "tombstone_":      "account_service",
}

def _rid_to_sys(rid: str) -> str:
    for prefix, sys_id in RID_SYS_MAP.items():
        if rid.startswith(prefix):
            return sys_id
    return "unknown"


def _pdf_extract_text(path) -> str:
    """Extract text from PDF using pdfplumber (handles CMap-encoded fonts).
    Falls back to raw byte scan for ASCII-visible text."""
    try:
        import pdfplumber as _plumber
        parts = []
        with _plumber.open(str(path)) as pdf:
            for page in pdf.pages:
                t = page.extract_text()
                if t: parts.append(t)
        return "\n".join(parts)
    except ImportError:
        pass
    except Exception:
        pass
    # Fallback: try to install pdfplumber silently, then retry
    try:
        import subprocess, sys
        subprocess.run([sys.executable, "-m", "pip", "install", "pdfplumber", "-q"],
                       capture_output=True, timeout=30)
        import importlib
        import pdfplumber as _plumber  # noqa
        importlib.invalidate_caches()
        parts = []
        with _plumber.open(str(path)) as pdf:
            for page in pdf.pages:
                t = page.extract_text()
                if t: parts.append(t)
        return "\n".join(parts)
    except Exception:
        pass
    # Last resort: scan raw bytes for ASCII readable strings ≥6 chars
    raw = path.read_bytes()
    strings = re.findall(rb'[ -~]{6,}', raw)
    return " ".join(s.decode('ascii', 'ignore') for s in strings)


def parse_pdf(fid, cat, path, idx):
    """Extract records from PDF documents using stdlib zlib decompression."""
    try:
        text = _pdf_extract_text(path)
    except Exception as e:
        log.warning("pdf parse %s: %s", path.name, e)
        return

    rid_pattern = re.compile(
        r'\b(support|audit_record|account|analytics|search|export|data_flow|backup|tombstone)_\d+\b'
    )
    email_pattern = re.compile(r'\b[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}\b')
    uid_pattern = re.compile(r'\buser_\d+\b')

    found_rids = list(dict.fromkeys(m.group() for m in rid_pattern.finditer(text)))
    found_emails = list(dict.fromkeys(norm(e) for e in email_pattern.findall(text) if _is_email(e)))
    found_uids = list(dict.fromkeys(uid_pattern.findall(text)))

    if not found_rids:
        return

    # Determine data_category override based on filename
    fname_lower = path.name.lower()
    extra_category = None
    if "attachment" in fname_lower:
        extra_category = "SUPPORT_ATTACHMENT"
    elif "statement" in fname_lower or "report" in fname_lower:
        extra_category = "LEGAL_HOLD_RECORD"
    elif "retention" in fname_lower or "legal" in fname_lower or "register" in fname_lower:
        extra_category = "LEGAL_HOLD_RECORD"
    elif "compliance" in fname_lower or "security" in fname_lower:
        extra_category = "SECURITY_AUDIT_LOG"

    for rid in found_rids:
        sys_id = _rid_to_sys(rid)
        extra = {"data_category": extra_category} if extra_category else {}
        idx.add(Record(fid, cat, sys_id, rid, "PRESENT",
                       emails=found_emails, user_ids=found_uids, extra=extra))


def parse_handover_txt(fid, cat, path, idx):
    STATUS_MAP = {"NOT_FOUND":"ABSENT","FOUND":"PRESENT","IDENTIFIABLE":"PRESENT",
                  "ANONYMIZED":"ANONYMIZED","ACTIVE":"ACTIVE","DISABLED":"DISABLED",
                  "BLOCKED":"BLOCKED","REDACTED":"REDACTED"}
    try:
        for line in path.read_text(encoding="utf-8",errors="replace").splitlines():
            line=line.strip()
            if not line.startswith("- "): continue
            # Format: - DATE | sys_id | resource_id | record_type | status | identifier
            parts=[p.strip() for p in line[2:].split("|")]
            if len(parts)<6: continue
            _,sys_id,rid,rec_type,status_raw,identifier=parts[:6]
            state=STATUS_MAP.get(status_raw.upper(),"PRESENT")
            emails=[identifier] if _is_email(identifier) else []
            uids=[identifier] if _is_uid(identifier) else []
            idx.add(Record(fid,cat,sys_id.strip(),rid.strip(),state,emails=emails,user_ids=uids,
                           extra={"record_type":rec_type.strip()}))
    except Exception as e: log.warning("handover %s: %s",path.name,e)


def parse_sql(fid, cat, path, idx):
    # Prefix → system: table names may have _primary/_failover_replica/_read_replica suffixes
    TABLE_PREFIX_SYS = [
        ("customer_profiles",          "account_service"),
        ("search_documents",           "search_service"),   # search_documents_primary
        ("customer_search_documents",  "search_service"),   # inventory snapshot tables
        ("customer_analytics_profiles","analytics_platform"),
        ("customer_analytics_pro",     "analytics_platform"),
        ("support_records",            "support_platform"),
        ("customer_exports",           "export_service"),
        ("connector_subscriptions",    "integration_service"),
        ("backup_restore",             "backup_service"),
        ("security_audit_records",     "security_service"),
        ("security_audit_rec",         "security_service"),
        ("customer_data",              "account_service"),  # customer_data_primary / read_replica
    ]
    def _tbl_sys(tbl):
        for pfx, sys in TABLE_PREFIX_SYS:
            if tbl.startswith(pfx): return sys
        return "unknown"

    try:
        sql=path.read_text(encoding="utf-8")
        conn=sqlite3.connect(":memory:")
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.executescript(sql)
        tables=[r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for tbl in tables:
            if tbl=="snapshot_scope": continue
            sys_id=_tbl_sys(tbl)
            try:
                cols=[r[1] for r in conn.execute(f"PRAGMA table_info({tbl})")]
                rows=conn.execute(f"SELECT * FROM {tbl}").fetchall()
            except: continue
            for row in rows:
                r=dict(zip(cols,row))
                rid=r.get("resource_id")
                if not rid: continue
                rj={}
                if r.get("record_json"):
                    try: rj=json.loads(r["record_json"])
                    except: pass
                # Flatten nested document sub-object if present
                doc=rj.get("document",{}) if isinstance(rj.get("document"),dict) else {}
                src={**r,**rj,**doc}
                origin=src.get("origin_system",sys_id) or sys_id
                emails=[v for k,v in src.items() if k in ["email","requester_email","owner_email","customer_email"] and v and _is_email(v)]
                uids=[v for k,v in src.items() if k in ["customer_reference","user_id","subject_reference"] and v and _is_uid(v)]
                if not (emails or uids): continue
                ra=src.get("restore_allowed"); en=src.get("enabled")
                coll=r.get("collection_name","")
                if   ra in (0,"0",False):  state="BLOCKED"
                elif ra in (1,"1",True):   state="ACTIVE"
                elif en in (0,"0",False):  state="DISABLED"
                elif en in (1,"1",True):   state="ACTIVE"
                elif src.get("account_status")=="DELETED": state="ABSENT"
                elif tbl in ("security_audit_records","security_audit_events") or coll=="security_audit_events":
                    state="PRESENT"
                else:
                    pii=any(src.get(k) for k in ["email","phone","email_hash"])
                    state="PRESENT" if pii or origin=="account_service" else ("ANONYMIZED" if origin=="analytics_platform" else "PRESENT")
                ex2={}
                srid=src.get("source_resource_id")
                if srid and origin=="search_service": ex2["source_resource_id"]=srid
                rt=src.get("record_type")
                if rt: ex2["record_type"]=rt
                idx.add(Record(fid,cat,origin,rid,state,emails=emails,user_ids=uids,extra=ex2 or None))
        conn.close()
    except Exception as e: log.warning("SQL %s: %s",path.name,e)


# ─────────────────────────────────────────────────────────────────────────────
# Build Index
# ─────────────────────────────────────────────────────────────────────────────

def build_index(evidence_csv, hash_to_emails: Dict[str,str]):
    idx = EvidenceIndex()
    for row in load_csv(evidence_csv):
        fid=row["file_id"]; cat=parse_dt(row["captured_at"])
        path=DATASET_DIR/row["file_path"]
        if not path.exists(): continue
        fname=path.name.lower(); suf=path.suffix.lower()
        try:
            if suf==".txt":
                parse_handover_txt(fid,cat,path,idx)
            elif suf==".json":
                data=_jload(path)
                if data is None: continue
                if "service_exports" in data:
                    parse_sre_json(fid,cat,data,idx)
                elif "snapshots" in data:
                    parse_snapshot_bundle(fid,cat,data,idx)
                elif "collection" in data and "records" in data:
                    col=data.get("collection","")
                    if "export_job" in col or "export" in fname:
                        parse_export_jobs_records(fid,cat,data,idx)
                    elif "analytics" in col or "analytics" in fname:
                        parse_analytics_records(fid,cat,data,idx)
                    else:
                        parse_generic_records(fid,cat,data,idx)
                elif "records" in data:
                    # Generic records format
                    records=data["records"]
                    if records and "system" in records[0]:
                        parse_generic_records(fid,cat,data,idx)
                    elif records and "owner_email" in records[0]:
                        parse_export_jobs_records(fid,cat,data,idx)
                    elif records and "user_id" in records[0]:
                        parse_analytics_records(fid,cat,data,idx)
                    else:
                        parse_generic_records(fid,cat,data,idx)
                else:
                    # Fallback: scan for resource_id + email
                    parse_generic_records(fid,cat,data,idx)
            elif suf==".sql":
                parse_sql(fid,cat,path,idx)
            elif suf==".log":
                if "resource_lookup_trace" in fname:
                    parse_resource_lookup_log(fid,cat,path,idx)
                elif "structured_service_events" in fname:
                    parse_structured_events_log(fid,cat,path,idx,hash_to_emails)
                else:
                    parse_service_events_log(fid,cat,path,idx,hash_to_emails)
            elif suf==".pdf":
                parse_pdf(fid,cat,path,idx)
        except Exception as e: log.warning("index %s: %s",fid,e)
    log.info("Index: %d email keys, %d uid keys, %d hash keys",
             len(idx._email), len(idx._uid), len(idx._hash))
    return idx


# ─────────────────────────────────────────────────────────────────────────────
# Identity
# ─────────────────────────────────────────────────────────────────────────────

def build_identity(identities, audit_log):
    e2u: Dict[str,Dict] = {}
    u2e: Dict[str,List[str]] = defaultdict(list)
    h2e: Dict[str,str] = {}  # email_hash → email

    for u in identities:
        e=norm(u.get("email","")); uid=u.get("user_id","")
        ehash=u.get("email_hash","")
        if e: e2u[e]=u
        if uid and e and e not in u2e[uid]: u2e[uid].append(e)
        if ehash and e: h2e[ehash]=e

    for entry in audit_log:
        uid=entry.get("user_id","")
        field=entry.get("field_name","")
        if field=="email":
            for val in [entry.get("old_value",""),entry.get("new_value","")]:
                e=norm(val)
                if not e: continue
                if e not in u2e[uid]: u2e[uid].append(e)
                if e not in e2u:
                    for ce in u2e[uid]:
                        if ce in e2u: e2u[e]=e2u[ce]; break
        elif field=="email_hash":
            for val in [entry.get("old_value",""),entry.get("new_value","")]:
                if val and val not in h2e:
                    # Try to find email for this uid
                    for ce in u2e[uid]:
                        h2e[val]=ce; break

    return e2u, u2e, h2e


def build_activity_account_map(activity_path, idx: "EvidenceIndex" = None) -> Dict[str, str]:
    """Return resource_id → account_id mapping via system_activity batch correlation.

    Uses evidence-aware ordered matching within each batch:
    1. Group events into 2-hour batches
    2. Within each batch, identify which resources belong to which user (via evidence index)
    3. Sort users by their first resource sequence → match to accounts by deletion sequence
    Falls back to proximity-based matching for resources not in the evidence index.
    """
    acts = load_csv(activity_path)
    DELETION_OPS = {"DELETE_RECORD","ANONYMIZE_RECORD","REDACT_RECORD",
                    "DISABLE_DATA_FLOW","BLOCK_RESTORE","CHECK_DATA_FLOW"}

    # Build resource→(emails,user_ids) from evidence index
    rid2user: Dict[str, Tuple[List[str],List[str]]] = {}
    if idx:
        for rid, recs in idx._rid.items():
            for rec in recs:
                if rec.emails or rec.user_ids:
                    rid2user[rid] = (rec.emails, rec.user_ids)
                    break

    # Group activities into time-based batches (2h gap = new batch)
    BATCH_GAP_SECS = 7200
    batches: List[List[Tuple]] = []  # each batch = list of (seq, event_time, resource_id, target_system, event_type)
    current_batch: List[Tuple] = []
    prev_t = None
    for i, a in enumerate(acts):
        et = a.get("event_time",""); rid = a.get("resource_id","")
        tsys = a.get("target_system",""); etype = a.get("event_type","")
        if not et: continue
        t = parse_dt(et)
        if t is None: continue
        if prev_t and (t - prev_t).total_seconds() > BATCH_GAP_SECS:
            if current_batch: batches.append(current_batch)
            current_batch = []
        current_batch.append((i, et, rid, tsys, etype))
        prev_t = t
    if current_batch: batches.append(current_batch)

    res2acct: Dict[str, str] = {}

    for batch in batches:
        # Collect account deletions and non-account resource ops in this batch
        acct_dels: List[Tuple[int,str]] = []   # (seq, account_rid)
        res_ops: List[Tuple[int,str]] = []      # (seq, resource_rid)
        for seq, et, rid, tsys, etype in batch:
            if not rid: continue
            if tsys == "account_service" and etype == "DELETE_RECORD":
                acct_dels.append((seq, rid))
            elif etype in DELETION_OPS and tsys not in ("account_service","email_delivery_service","cache_service","archive_service"):
                res_ops.append((seq, rid))
        if not acct_dels or not res_ops:
            continue
        acct_dels.sort()  # sorted by seq

        if len(acct_dels) == 1:
            # Single account: all resources → this account
            for _, orid in res_ops:
                res2acct[orid] = acct_dels[0][1]
            continue

        # Multiple accounts: use ordered matching via evidence index
        # Step 1: find the "user fingerprint" of each resource from evidence index
        # Step 2: determine the first-occurrence sequence per user fingerprint
        # Step 3: sort user fingerprints by first-occurrence seq
        # Step 4: match Nth fingerprint → Nth account

        # User fingerprint = frozenset of (emails, user_ids) — identifies a unique user
        fingerprint_first_seq: Dict[frozenset, int] = {}
        rid_to_fingerprint: Dict[str, frozenset] = {}
        for seq, orid in res_ops:
            if orid in rid2user:
                emails, uids = rid2user[orid]
                fp = frozenset(emails + uids)
                if fp:
                    rid_to_fingerprint[orid] = fp
                    if fp not in fingerprint_first_seq or seq < fingerprint_first_seq[fp]:
                        fingerprint_first_seq[fp] = seq

        if fingerprint_first_seq:
            # Sort fingerprints by first appearance → assign to accounts in order
            sorted_fps = sorted(fingerprint_first_seq.keys(), key=lambda fp: fingerprint_first_seq[fp])
            fp_to_acct: Dict[frozenset, str] = {}
            for rank, fp in enumerate(sorted_fps):
                if rank < len(acct_dels):
                    fp_to_acct[fp] = acct_dels[rank][1]
            # Assign accounts to resources via fingerprint
            for seq, orid in res_ops:
                fp = rid_to_fingerprint.get(orid)
                if fp and fp in fp_to_acct:
                    res2acct[orid] = fp_to_acct[fp]
                elif orid not in res2acct:
                    # Fallback: nearest preceding account
                    best_acct = None; best_dist = 999999
                    for aseq, arid in acct_dels:
                        if aseq >= seq: continue
                        dist = seq - aseq
                        if dist < best_dist: best_dist = dist; best_acct = arid
                    if best_acct and best_dist <= 300:
                        res2acct[orid] = best_acct
        else:
            # No indexed resources in this batch — fall back to proximity
            for seq, orid in res_ops:
                best_acct = None; best_dist = 999999
                for aseq, arid in acct_dels:
                    if aseq >= seq: continue
                    dist = seq - aseq
                    if dist < best_dist: best_dist = dist; best_acct = arid
                if best_acct and best_dist <= 300:
                    res2acct[orid] = best_acct

    return res2acct


def build_analytics_user_map(activity_path: str, idx: "EvidenceIndex") -> Dict[str, Tuple[List[str],List[str]]]:
    """Map anonymized analytics resource_id → (emails, user_ids) using system_activity batch correlation.
    For analytics records with no PII, link them to the user whose account was deleted
    immediately before the analytics anonymization in the same batch."""
    acts = load_csv(activity_path)
    # Build account_rid → (emails, user_ids) from evidence index
    acct2user: Dict[str, Tuple[List[str],List[str]]] = {}
    seen_rids: set = set()
    for recs_by_email in idx._email.values():
        for rec in recs_by_email:
            if rec.system_id == "account_service" and rec.resource_id not in seen_rids:
                seen_rids.add(rec.resource_id)
                acct2user[rec.resource_id] = (rec.emails, rec.user_ids)
    for recs_by_uid in idx._uid.values():
        for rec in recs_by_uid:
            if rec.system_id == "account_service" and rec.resource_id not in seen_rids:
                seen_rids.add(rec.resource_id)
                acct2user[rec.resource_id] = (rec.emails, rec.user_ids)

    analytics_map: Dict[str, Tuple[List[str],List[str]]] = {}
    for i, a in enumerate(acts):
        if a.get("event_type") != "ANONYMIZE_RECORD": continue
        if a.get("target_system") != "analytics_platform": continue
        rid = a.get("resource_id","")
        if not rid: continue
        day = a.get("event_time","")[:10]
        # Find nearest PRECEDING account deletion on the same day that is in the index
        best_dist, best_user = 999999, None
        for j in range(i-1, max(-1, i-300), -1):
            a2 = acts[j]
            if a2.get("event_time","")[:10] != day: break
            if a2.get("event_type") == "DELETE_RECORD" and a2.get("target_system") == "account_service":
                acct_rid = a2.get("resource_id","")
                if acct_rid in acct2user:
                    dist = i - j
                    if dist < best_dist:
                        best_dist = dist
                        best_user = acct2user[acct_rid]
        if best_user:
            analytics_map[rid] = best_user
    return analytics_map


def _find_sql_evidence_for_absent_account(acct_rid: str, audit_at, ev_rows, dataset_dir: "Path") -> Optional[str]:
    """Find the best SQL evidence file that proves acct_rid is ABSENT (not in the snapshot)."""
    import sqlite3 as _sq3
    best_fid = None; best_cat = None
    for ev_row in ev_rows:
        if ".sql" not in ev_row.get("file_path","").lower(): continue
        fcat = parse_dt(ev_row["captured_at"])
        if fcat is None: continue
        if audit_at and fcat > audit_at: continue  # captured after audit_at
        fpath = dataset_dir/ev_row["file_path"]
        if not fpath.exists(): continue
        try:
            sql_txt = fpath.read_text(encoding="utf-8", errors="replace")
            if acct_rid not in sql_txt: continue  # quick check — only parse if ID mentioned
            # If the ID IS in the SQL, it's PRESENT → skip
            conn = _sq3.connect(":memory:")
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.executescript(sql_txt)
            found = False
            for tbl in [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]:
                try:
                    r = conn.execute(f"SELECT resource_id FROM {tbl} WHERE resource_id=?", (acct_rid,)).fetchone()
                    if r: found = True; break
                except: pass
            conn.close()
            if found: return None  # account is PRESENT in this SQL — cannot confirm ABSENT
        except: continue
        # Account not found in this SQL (which is after deletion) → can confirm ABSENT
        if best_cat is None or fcat > best_cat:  # pick most recent pre-audit capture
            best_cat = fcat; best_fid = ev_row["file_id"]
    # Re-scan for files where account is absent (not in SQL text → definitely absent)
    if best_fid: return best_fid
    for ev_row in ev_rows:
        if ".sql" not in ev_row.get("file_path","").lower(): continue
        fcat = parse_dt(ev_row["captured_at"])
        if fcat is None or (audit_at and fcat > audit_at): continue
        fpath = dataset_dir/ev_row["file_path"]
        if not fpath.exists(): continue
        try:
            sql_txt = fpath.read_text(encoding="utf-8", errors="replace")
            # If account_rid not in text at all → it was definitely absent from snapshot
            if acct_rid not in sql_txt:
                tables = re.findall(r'CREATE TABLE (\w+)', sql_txt)
                has_acct_table = any(t.startswith("customer_profiles") or t.startswith("customer_data") for t in tables)
                if has_acct_table:
                    if best_cat is None or fcat > best_cat:
                        best_cat = fcat; best_fid = ev_row["file_id"]
        except: continue
    return best_fid


def find_user_account_from_activity(
        emails: List[str], user_ids: List[str], requested_at, audit_at,
        activity_path: str, idx: "EvidenceIndex"
) -> Tuple[Optional[str], Optional[object]]:
    """For a user with no account in the evidence index, try to find their account_id
    via system_activity: isolated batches where only one account was deleted."""
    if not requested_at: return None, None
    acts = load_csv(activity_path)
    # Collect account deletions in [requested_at, audit_at] window
    candidates: List[Tuple[str,str,int]] = []   # (time, account_id, seq)
    for i, a in enumerate(acts):
        et = a.get("event_time","")
        if not et: continue
        t = parse_dt(et)
        if t is None: continue
        if t < requested_at or (audit_at and t > audit_at): continue
        if a.get("target_system") == "account_service" and a.get("event_type") == "DELETE_RECORD":
            candidates.append((et, a["resource_id"], i))
    if not candidates: return None, None
    # For each candidate, check if it is in an isolated batch (only account in a 4-hour window)
    for et, acct_rid, seq in candidates:
        t0 = parse_dt(et)
        # Check for other account deletions within 4 hours
        is_isolated = True
        for et2, acct_rid2, seq2 in candidates:
            if acct_rid2 == acct_rid: continue
            t2 = parse_dt(et2)
            if t2 and abs((t2 - t0).total_seconds()) < 4 * 3600:
                is_isolated = False; break
        if is_isolated:
            # Find which SQL evidence file best proves absence (captured after deletion, before audit_at)
            return acct_rid, None
    return None, None


def resolve(email, e2u, u2e):
    n=norm(email); u=e2u.get(n)
    if u:
        uid=u.get("user_id","")
        return uid, list(set(u2e.get(uid,[n])+[n]))
    for uid,emails in u2e.items():
        if n in [norm(e) for e in emails]:
            return uid, list(set(emails+[n]))
    return None, [n]


# ─────────────────────────────────────────────────────────────────────────────
# Deletion classifier
# ─────────────────────────────────────────────────────────────────────────────

DELETION_VERBS = re.compile(
    r"\b(delete|delet\w+|erase\w*|erasure|remov\w+|clos\w+|wipe\w*|purge\w*|"
    r"löschen|supprim\w*|effacer|borrar|eliminar|cleared?|cleaned?|"
    r"gone|forgotten|handle\s+them|left\s+behind|no\s+longer|switch\s+off|"
    r"keep\s+only|tombstone|inspect\s+the\s+actual|confirm\s+\w+\s+gone)\b",
    re.IGNORECASE
)
DELETION_NOUNS = re.compile(
    r"\b(account|profile|record|data|detail|personal|identifier|information|"
    r"gdpr|right\s+to\s+be\s+forgotten|suppression|integration|backup|"
    r"analytics|search\s+result|support|export|traces?)\b",
    re.IGNORECASE
)
EXPLICIT_DELETION = re.compile(
    r"\b(deletion|erasure|right\s+to\s+be\s+forgotten|gdpr|"
    r"permanently\s+(?:remov|delet|clos)|account\s+was\s+delet\w+|"
    r"verif\w+\s+\w+\s+delet\w+)\b",
    re.IGNORECASE
)

FOREIGN_DELETION = re.compile(
    r"\b(supprimer|suppression|effacement|supprimir|eliminaci[oó]n|eliminar|borrar|"
    r"cuenta|compte|konto|l[oö]schen|widerruf|verwijder|verwijdering|"
    r"cancella|cancellazione|usunięcie|usuń|удалить|削除|삭제|حذف)\b",
    re.IGNORECASE
)

def is_deletion(text: str) -> bool:
    if not text or not text.strip(): return False
    ascii_ratio = sum(1 for c in text if ord(c) < 128) / max(len(text),1)
    if ascii_ratio < 0.6: return True  # mostly non-ASCII → foreign language deletion
    if EXPLICIT_DELETION.search(text): return True
    if FOREIGN_DELETION.search(text): return True
    return bool(DELETION_VERBS.search(text) and DELETION_NOUNS.search(text))


# ─────────────────────────────────────────────────────────────────────────────
# Step generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_steps(records: List[Record], res2acct: Dict[str,str]=None,
                   activity_path: str=None, emails: List[str]=None, user_ids: List[str]=None,
                   requested_at=None, audit_at=None, ev_rows=None, dataset_dir: "Path"=None) -> Tuple[str, List]:
    if not records:
        return "COMPLETE", []

    # Keep most recent record per (sys_id, resource_id)
    best: Dict[Tuple[str,str],Record] = {}
    for rec in records:
        key=(rec.system_id,rec.resource_id)
        old=best.get(key)
        if old is None: best[key]=rec
        elif rec.captured_at and old.captured_at and rec.captured_at>old.captured_at: best[key]=rec
        elif rec.captured_at and not old.captured_at: best[key]=rec

    findings, remediations, verifications = [], [], []
    incomplete = False

    for (sys_id,rid),rec in sorted(best.items(), key=lambda x:(sys_rank(x[0][0]),x[0][1])):
        state=rec.state; ev=rec.file_id
        # Record type from parsed evidence overrides system-level default
        rec_type = rec.extra.get("record_type") if rec.extra else None
        data_cat = rec.extra.get("data_category") if rec.extra else None  # PDF-parsed category
        email_opt_in = rec.extra.get("email_opt_in") if rec.extra else None
        if data_cat:
            action = REQUIRED_ACTION.get(data_cat, REQUIRED_ACTION.get(SYSTEM_CATEGORY.get(sys_id,""),"DELETE"))
        elif rec_type:
            action = REQUIRED_ACTION.get(rec_type, REQUIRED_ACTION.get(SYSTEM_CATEGORY.get(sys_id,""),"DELETE"))
        elif email_opt_in == "true":
            action = "DELETE"
        else:
            action=REQUIRED_ACTION.get(SYSTEM_CATEGORY.get(sys_id,""),"DELETE")

        if sys_id=="security_service":
            verifications.append({"phase":"VERIFICATION","system_id":sys_id,"resource_id":rid,"operation":"VERIFY_RECORD_PRESENT","state":"PRESENT","evidence_id":ev})

        elif sys_id=="backup_service":
            if state=="ACTIVE":
                incomplete=True
                findings.append({"phase":"FINDING","system_id":sys_id,"resource_id":rid,"operation":"REPORT_RESTORE_RISK","state":"ACTIVE","evidence_id":ev})
                remediations.append({"phase":"REMEDIATION","system_id":sys_id,"resource_id":rid,"operation":"BLOCK_RESTORE","state":"BLOCKED","evidence_id":""})
                verifications.append({"phase":"VERIFICATION","system_id":sys_id,"resource_id":rid,"operation":"VERIFY_RESTORE_BLOCKED","state":"BLOCKED","evidence_id":""})
            elif state=="BLOCKED":
                verifications.append({"phase":"VERIFICATION","system_id":sys_id,"resource_id":rid,"operation":"VERIFY_RESTORE_BLOCKED","state":"BLOCKED","evidence_id":ev})

        elif sys_id=="integration_service":
            if state=="ACTIVE":
                incomplete=True
                findings.append({"phase":"FINDING","system_id":sys_id,"resource_id":rid,"operation":"REPORT_ACTIVE_DATA_FLOW","state":"ACTIVE","evidence_id":ev})
                remediations.append({"phase":"REMEDIATION","system_id":sys_id,"resource_id":rid,"operation":"DISABLE_DATA_FLOW","state":"DISABLED","evidence_id":""})
                verifications.append({"phase":"VERIFICATION","system_id":sys_id,"resource_id":rid,"operation":"VERIFY_DATA_FLOW_DISABLED","state":"DISABLED","evidence_id":""})
            elif state=="DISABLED":
                verifications.append({"phase":"VERIFICATION","system_id":sys_id,"resource_id":rid,"operation":"VERIFY_DATA_FLOW_DISABLED","state":"DISABLED","evidence_id":ev})

        elif action=="DELETE":
            if state=="ABSENT":
                verifications.append({"phase":"VERIFICATION","system_id":sys_id,"resource_id":rid,"operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":ev})
            elif state in ("PRESENT","IDENTIFIABLE","FOUND"):
                incomplete=True
                findings.append({"phase":"FINDING","system_id":sys_id,"resource_id":rid,"operation":"REPORT_REMAINING_RECORD","state":"PRESENT","evidence_id":ev})
                remediations.append({"phase":"REMEDIATION","system_id":sys_id,"resource_id":rid,"operation":"DELETE_RECORD","state":"ABSENT","evidence_id":""})
                verifications.append({"phase":"VERIFICATION","system_id":sys_id,"resource_id":rid,"operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":""})
                # Search records link to an account; verify the account is also absent
                if sys_id=="search_service" and rec.extra and rec.extra.get("source_resource_id"):
                    acct=rec.extra["source_resource_id"]
                    if acct not in {k[1] for k in best if k[0]=="account_service"}:
                        verifications.append({"phase":"VERIFICATION","system_id":"account_service","resource_id":acct,"operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":""})

        elif action=="ANONYMIZE":
            if state=="ANONYMIZED":
                verifications.append({"phase":"VERIFICATION","system_id":sys_id,"resource_id":rid,"operation":"VERIFY_RECORD_ANONYMIZED","state":"ANONYMIZED","evidence_id":ev})
            elif state in ("PRESENT","IDENTIFIABLE"):
                incomplete=True
                findings.append({"phase":"FINDING","system_id":sys_id,"resource_id":rid,"operation":"REPORT_EXPOSED_PII","state":"PRESENT","evidence_id":ev})
                remediations.append({"phase":"REMEDIATION","system_id":sys_id,"resource_id":rid,"operation":"ANONYMIZE_RECORD","state":"ANONYMIZED","evidence_id":""})
                verifications.append({"phase":"VERIFICATION","system_id":sys_id,"resource_id":rid,"operation":"VERIFY_RECORD_ANONYMIZED","state":"ANONYMIZED","evidence_id":""})

        elif action=="REDACT":
            if state=="REDACTED":
                verifications.append({"phase":"VERIFICATION","system_id":sys_id,"resource_id":rid,"operation":"VERIFY_RECORD_REDACTED","state":"REDACTED","evidence_id":ev})
            elif state in ("PRESENT","IDENTIFIABLE"):
                incomplete=True
                findings.append({"phase":"FINDING","system_id":sys_id,"resource_id":rid,"operation":"REPORT_EXPOSED_PII","state":"PRESENT","evidence_id":ev})
                remediations.append({"phase":"REMEDIATION","system_id":sys_id,"resource_id":rid,"operation":"REDACT_RECORD","state":"REDACTED","evidence_id":""})
                verifications.append({"phase":"VERIFICATION","system_id":sys_id,"resource_id":rid,"operation":"VERIFY_RECORD_REDACTED","state":"REDACTED","evidence_id":""})
            elif state=="ABSENT":
                verifications.append({"phase":"VERIFICATION","system_id":sys_id,"resource_id":rid,"operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":ev})

    def skey(step, phase):
        return (OP_ORDER.get(phase,{}).get(step["operation"],99), sys_rank(step["system_id"]), step["resource_id"])

    # Add account_service VERIFY_RECORD_ABSENT from activity batch correlation (INCOMPLETE cases)
    if res2acct and incomplete:
        known_accts={k[1] for k in best if k[0]=="account_service"}
        for rid in list(best.keys()):
            sys_id,resource_id=rid
            acct=res2acct.get(resource_id)
            if acct and acct not in known_accts:
                verifications.append({"phase":"VERIFICATION","system_id":"account_service","resource_id":acct,"operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":""})
                known_accts.add(acct)

    # For COMPLETE cases with no account record: find account via res2acct of own resources
    if not incomplete and res2acct:
        known_accts = {k[1] for k in best if k[0]=="account_service"}
        if not known_accts:
            # Look up each of the user's evidence resources in res2acct
            for (sys_id, resource_id) in best.keys():
                acct = res2acct.get(resource_id)
                if acct:
                    # Only use if the account isn't from a completely unrelated batch
                    # (basic sanity: account must start with "account_")
                    if acct.startswith("account_") and acct not in known_accts:
                        best_fid = _find_sql_evidence_for_absent_account(acct, audit_at, ev_rows, dataset_dir) if ev_rows and dataset_dir else None
                        verifications.append({"phase":"VERIFICATION","system_id":"account_service",
                                              "resource_id":acct,"operation":"VERIFY_RECORD_ABSENT",
                                              "state":"ABSENT","evidence_id":best_fid or ""})
                        known_accts.add(acct)
                    break

    findings.sort(     key=lambda s: skey(s,"FINDING"))
    remediations.sort( key=lambda s: skey(s,"REMEDIATION"))
    verifications.sort(key=lambda s: skey(s,"VERIFICATION"))

    if incomplete:
        # Future verification steps have no evidence yet
        for v in verifications: v["evidence_id"] = ""
        all_steps = findings + remediations + verifications
        status = "INCOMPLETE"
    else:
        all_steps = verifications
        status = "COMPLETE"

    for i,s in enumerate(all_steps,1): s["step_no"]=i
    ordered=[{"step_no":s["step_no"],"phase":s["phase"],"system_id":s["system_id"],
               "resource_id":s["resource_id"],"operation":s["operation"],
               "state":s["state"],"evidence_id":s["evidence_id"]} for s in all_steps]
    return status, ordered


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    import sys
    sample_mode = "--sample" in sys.argv or (len(sys.argv) > 1 and sys.argv[1] == "sample")
    req_file = "sample_deletion_requests.csv" if sample_mode else "deletion_requests.csv"
    log.info("Loading dataset... (%s)", req_file)
    requests   = load_csv(DATASET_DIR/req_file)
    identities = load_csv(DATASET_DIR/"user_identities.csv")
    audit_log  = load_csv(DATASET_DIR/"user_audit_log.csv")

    e2u, u2e, h2e = build_identity(identities, audit_log)
    idx = build_index(DATASET_DIR/"evidence_files.csv", h2e)
    res2acct = build_activity_account_map(DATASET_DIR/"system_activity.csv", idx)
    # Link anonymized analytics records to users via system_activity batch proximity
    analytics_map = build_analytics_user_map(str(DATASET_DIR/"system_activity.csv"), idx)
    for analytics_rid, (ae, au) in analytics_map.items():
        idx.link_to_user(analytics_rid, ae, au)
    log.info("Analytics map: %d records linked to users", len(analytics_map))

    # Build SQL snapshot account sets for ABSENT verification
    # Maps: account_rid → (evidence_file_id, captured_at) for accounts confirmed ABSENT from SQL snapshots
    sql_absent_accts: Dict[str, Tuple[str, object]] = {}
    ev_rows = load_csv(DATASET_DIR/"evidence_files.csv")
    import sqlite3 as _sqlite3
    for ev_row in ev_rows:
        fid = ev_row["file_id"]; fcat = parse_dt(ev_row["captured_at"])
        fpath = DATASET_DIR/ev_row["file_path"]
        if not fpath.suffix.lower() == ".sql" or not fpath.exists(): continue
        try:
            sql_txt = fpath.read_text(encoding="utf-8", errors="replace")
            conn2 = _sqlite3.connect(":memory:")
            conn2.execute("PRAGMA foreign_keys=OFF")
            conn2.executescript(sql_txt)
            tables2 = [r[0] for r in conn2.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for tbl2 in tables2:
                if any(tbl2.startswith(p) for p in ["customer_profiles","customer_data"]):
                    try:
                        rids2 = {r[0] for r in conn2.execute(f"SELECT resource_id FROM {tbl2}")}
                        # All account_service IDs in system_activity that are NOT in this SQL → absent
                        # We'll check per-case below; just store which rids ARE present
                        for r in rids2:
                            if r and r.startswith("account_"):
                                # Mark as PRESENT in this file (so we know it's NOT absent)
                                pass
                    except: pass
            conn2.close()
        except: pass

    results=[]; na=comp=inc=0
    for i,case in enumerate(requests):
        case_id=case["case_id"]
        if not is_deletion(case.get("request_text","")):
            results.append({"case_id":case_id,"deletion_status":"NOT_APPLICABLE","steps_json":"[]"}); na+=1; continue
        audit_at=parse_dt(case.get("audit_at",""))
        requested_at=parse_dt(case.get("requested_at",""))
        uid,emails=resolve(case.get("email",""),e2u,u2e)
        uids=[uid] if uid else []
        u_hashes=[k for k,v in h2e.items() if v in [norm(e) for e in emails]]
        records=idx.find(emails,uids,audit_at,hashes=u_hashes)
        status,steps=generate_steps(records, res2acct=res2acct,
                                     activity_path=str(DATASET_DIR/"system_activity.csv"),
                                     emails=emails, user_ids=uids,
                                     requested_at=requested_at, audit_at=audit_at,
                                     ev_rows=ev_rows, dataset_dir=DATASET_DIR)
        if status=="COMPLETE": comp+=1
        else: inc+=1
        if (i+1)%50==0: log.info("[%d/%d] COMPLETE=%d INCOMPLETE=%d N/A=%d",i+1,len(requests),comp,inc,na)
        results.append({"case_id":case_id,"deletion_status":status,"steps_json":json.dumps(steps,separators=(",",":"))})

    results.sort(key=lambda r:int(re.search(r"\d+",r["case_id"]).group()))
    with open(OUTPUT_FILE,"w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=["case_id","deletion_status","steps_json"])
        w.writeheader(); w.writerows(results)
    log.info("Done. %d rows: COMPLETE=%d INCOMPLETE=%d NOT_APPLICABLE=%d",len(results),comp,inc,na)


if __name__=="__main__":
    main()
