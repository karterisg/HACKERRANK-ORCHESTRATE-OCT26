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

    def add(self, rec, hashes=None):
        for e in rec.emails:   self._email[e].append(rec)
        for u in rec.user_ids: self._uid[u].append(rec)
        for h in (hashes or []):
            if h: self._hash[h].append(rec)

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
            if audit_at is None or rec.captured_at is None or rec.captured_at <= audit_at:
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


def parse_service_events_log(fid, cat, path, idx, hash_to_emails: Dict[str,str]):
    """Parse service_events_*.log: groups lines by trace_id, extracts email+resource+state."""
    VALID_SYSTEMS = {
        "account_service","search_service","analytics_platform","support_platform",
        "export_service","integration_service","backup_service","security_service",
        "identity_service","marketing_platform","support_replica",
    }
    try:
        pairs: Dict[str,Dict] = {}
        # Also track resource→email from lines that have both
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            # Direct resource+email in same line (no trace_id needed)
            rid_m = re.search(r"\bresource_id=([a-zA-Z_][a-zA-Z0-9_]*)", line)
            srv_m = re.search(r"\bservice=([a-zA-Z_]+)", line)
            if not rid_m or not srv_m: continue
            rid    = rid_m.group(1)
            sys_id = srv_m.group(1)
            if sys_id not in VALID_SYSTEMS: continue

            # Extract trace_id
            tid_m = re.search(r"trace_id=([^\s]+)", line)
            if tid_m:
                tid = tid_m.group(1)
                if tid not in pairs: pairs[tid] = {}
                p = pairs[tid]
                p["service"] = sys_id
                p["resource_id"] = rid
                # Emails from various keys
                for k in ["lookup_key","subject_key","correlation_key","match_key"]:
                    m = re.search(rf'\b{k}="?([^"\s]+)"?', line)
                    if m:
                        val = m.group(1)
                        if _is_email(val):
                            p.setdefault("emails",[])
                            if val not in p["emails"]: p["emails"].append(val)
                        elif val in hash_to_emails:
                            p.setdefault("emails",[])
                            e = hash_to_emails[val]
                            if e not in p["emails"]: p["emails"].append(e)
                        elif _is_uid(val):
                            p.setdefault("user_ids",[])
                            if val not in p["user_ids"]: p["user_ids"].append(val)
                # State from event + attributes
                ev_m = re.search(r"\bevent=([^\s]+)", line)
                ev   = ev_m.group(1) if ev_m else ""
                http = re.search(r"\bhttp_status=(\d+)", line)
                rows = re.search(r"\brows=(\d+)", line)
                enab = re.search(r"\benabled=(true|false)", line)
                rest = re.search(r"\brestore_allowed=(true|false)", line)
                dblk = re.search(r"\bdeletion_block=(true|false)", line)
                elig = re.search(r"\beligible=(true|false)", line)
                result_m = re.search(r"\bresult=(hit|miss)", line)
                pii_m = re.search(r"\bmatched_value=", line)
                mkr_m = re.search(r"\bmarker_found=(true|false)", line)

                if http and http.group(1) == "404":
                    p["state"] = "ABSENT"
                elif rows and rows.group(1) == "0":
                    p["state"] = "ABSENT"
                elif rows and int(rows.group(1)) > 0:
                    p["state"] = "PRESENT"
                elif enab:
                    p["state"] = "ACTIVE" if enab.group(1)=="true" else "DISABLED"
                elif dblk:
                    p["state"] = "BLOCKED" if dblk.group(1)=="true" else "ACTIVE"
                elif elig and elig.group(1) == "true":
                    p["state"] = "ACTIVE"  # backup can be restored
                elif result_m and result_m.group(1) == "hit":
                    p["state"] = "PRESENT"
                elif pii_m:
                    p["state"] = "PRESENT"  # PII found in scan
                elif mkr_m:
                    # deletion_marker_check: marker_found=false means NOT deleted
                    p["state"] = "ABSENT" if mkr_m.group(1)=="true" else "PRESENT"

        for p in pairs.values():
            rid    = p.get("resource_id")
            sys_id = p.get("service","")
            emails = p.get("emails", [])
            uids   = p.get("user_ids",[])
            state  = p.get("state","PRESENT")
            if not rid or not (emails or uids): continue
            if sys_id == "support_replica": sys_id = "support_platform"
            idx.add(Record(fid, cat, sys_id, rid, state, emails=emails, user_ids=uids))
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
            tid = tm.group(1)
            if tid not in pairs: pairs[tid]={}
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
            uids=[f[k] for k in ["customer_reference","subject_reference"]
                  if f.get(k) and f[k]!="null" and _is_uid(f[k])]
            if not emails and not uids: continue
            h=f.get("http_status",""); rows=f.get("rows","")
            en=f.get("enabled",""); ra=f.get("restore_allowed","")
            if h=="404" or rows=="0":         state="ABSENT"
            elif en=="false" or f.get("last_delivery_status")=="stopped": state="DISABLED"
            elif ra=="false":                  state="BLOCKED"
            elif en=="true" or ra=="true":     state="ACTIVE"
            elif f.get("result")=="hit":       state="PRESENT"
            elif sys_id=="analytics_platform": state="ANONYMIZED"
            else:                              state="PRESENT"
            idx.add(Record(fid,cat,sys_id,rid,state,emails=emails,user_ids=uids,extra=f))
    except Exception as e: log.warning("lookup log %s: %s", path.name, e)


def parse_handover_txt(fid, cat, path, idx):
    STATUS_MAP = {"NOT_FOUND":"ABSENT","FOUND":"PRESENT","IDENTIFIABLE":"PRESENT",
                  "ANONYMIZED":"ANONYMIZED","ACTIVE":"ACTIVE","DISABLED":"DISABLED",
                  "BLOCKED":"BLOCKED","REDACTED":"REDACTED"}
    try:
        for line in path.read_text(encoding="utf-8",errors="replace").splitlines():
            line=line.strip()
            if not line.startswith("- "): continue
            parts=[p.strip() for p in line[2:].split("|")]
            if len(parts)<6: continue
            _,sys_id,rid,_,status_raw,identifier=parts[:6]
            state=STATUS_MAP.get(status_raw.upper(),"PRESENT")
            emails=[identifier] if _is_email(identifier) else []
            uids=[identifier] if _is_uid(identifier) else []
            idx.add(Record(fid,cat,sys_id.strip(),rid.strip(),state,emails=emails,user_ids=uids))
    except Exception as e: log.warning("handover %s: %s",path.name,e)


def parse_sql(fid, cat, path, idx):
    TABLE_SYS = {
        "customer_profiles":"account_service","customer_search_documents":"search_service",
        "customer_analytics_profiles":"analytics_platform","support_records":"support_platform",
        "customer_exports":"export_service","connector_subscriptions":"integration_service",
        "backup_restore_entries":"backup_service","security_audit_records":"security_service",
    }
    try:
        sql=path.read_text(encoding="utf-8")
        conn=sqlite3.connect(":memory:")
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.executescript(sql)
        tables=[r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for tbl in tables:
            if tbl=="snapshot_scope": continue
            sys_id=TABLE_SYS.get(tbl,"unknown")
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
                src={**r,**rj}
                origin=src.get("origin_system",sys_id) or sys_id
                emails=[v for k,v in src.items() if k in ["email","requester_email","owner_email","customer_email"] and v and _is_email(v)]
                uids=[v for k,v in src.items() if k in ["customer_reference","user_id","subject_reference"] and v and _is_uid(v)]
                if not (emails or uids): continue
                ra=src.get("restore_allowed"); en=src.get("enabled")
                if   ra in (0,"0",False):  state="BLOCKED"
                elif ra in (1,"1",True):   state="ACTIVE"
                elif en in (0,"0",False):  state="DISABLED"
                elif en in (1,"1",True):   state="ACTIVE"
                elif src.get("account_status")=="DELETED": state="ABSENT"
                elif tbl=="security_audit_records": state="PRESENT"
                else:
                    pii=any(src.get(k) for k in ["email","phone","email_hash"])
                    state="PRESENT" if pii or origin=="account_service" else ("ANONYMIZED" if origin=="analytics_platform" else "PRESENT")
                idx.add(Record(fid,cat,origin,rid,state,emails=emails,user_ids=uids))
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
                else:
                    parse_service_events_log(fid,cat,path,idx,hash_to_emails)
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

def generate_steps(records: List[Record]) -> Tuple[str, List]:
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

    findings.sort(     key=lambda s: skey(s,"FINDING"))
    remediations.sort( key=lambda s: skey(s,"REMEDIATION"))
    verifications.sort(key=lambda s: skey(s,"VERIFICATION"))

    if incomplete:
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
    log.info("Loading dataset...")
    requests   = load_csv(DATASET_DIR/"deletion_requests.csv")
    identities = load_csv(DATASET_DIR/"user_identities.csv")
    audit_log  = load_csv(DATASET_DIR/"user_audit_log.csv")

    e2u, u2e, h2e = build_identity(identities, audit_log)
    idx = build_index(DATASET_DIR/"evidence_files.csv", h2e)

    results=[]; na=comp=inc=0
    for i,case in enumerate(requests):
        case_id=case["case_id"]
        if not is_deletion(case.get("request_text","")):
            results.append({"case_id":case_id,"deletion_status":"NOT_APPLICABLE","steps_json":"[]"}); na+=1; continue
        audit_at=parse_dt(case.get("audit_at",""))
        uid,emails=resolve(case.get("email",""),e2u,u2e)
        uids=[uid] if uid else []
        u_hashes=[k for k,v in h2e.items() if v in [norm(e) for e in emails]]
        records=idx.find(emails,uids,audit_at,hashes=u_hashes)
        status,steps=generate_steps(records)
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
