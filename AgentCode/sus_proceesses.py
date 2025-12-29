# suspicious_children.py
import os
import time
import ctypes
import threading
from datetime import datetime, timezone
import re
import unicodedata

import wmi


from log import log_data  # your encrypted+integrity logger

log_lock = threading.Lock()

# ---------------- Rate limiter (operational robustness) ----------------
_last_err = {}  # event_key -> last monotonic time
def _rate_limited(key: str, window_s: float) -> bool:
    now = time.monotonic()
    last = _last_err.get(key, 0.0)
    if now - last >= window_s:
        _last_err[key] = now
        return False
    return True

def _log_event(event: str, Purpose: str = "proc_watch", window_s: float = 60.0, **extra):
    if not _rate_limited(event, window_s):
        payload = {"event": event, "Purpose": Purpose}
        if extra:
            payload.update(extra)
        with log_lock:
            log_data(payload)

# ---------------- Sanitization helpers ----------------
_CONTROL_CHARS = re.compile(r'[\x00-\x1F\x7F]')
def _sanitize_str(value, max_len=256):
    """Normalize (NFKC), remove control chars, trim; return None for falsy."""
    if not value:
        return None
    s = unicodedata.normalize("NFKC", str(value))
    s = _CONTROL_CHARS.sub('', s).strip()
    if not s:
        return None
    if len(s) > max_len:
        s = s[:max_len]
    return s



# ---------------- Config validation (ASVS 1.1) ----------------
def _cfg_int(name: str, default: int, lo: int, hi: int, err_window: float = 60.0) -> int:
    raw = os.environ.get(name, str(default))
    try:
        val = int(raw)
    except (TypeError, ValueError):
        _log_event("cfg_invalid_int", name=name, value=str(raw), window_s=err_window)
        return default
    if not (lo <= val <= hi):
        _log_event("cfg_out_of_range_int", name=name, value=val, lo=lo, hi=hi, window_s=err_window)
        val = max(lo, min(hi, val))
    return val

def _cfg_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "1" if default else "0").strip().lower()
    return raw in {"1","true","yes","on"}

# Tunables
PROC_ERR_RATE_WINDOW   = float(os.environ.get("PROC_ERR_RATE_WINDOW", "60.0"))
PROC_MAX_SCAN          = _cfg_int("PROC_MAX_SCAN", 10000, 100, 100000, PROC_ERR_RATE_WINDOW)
PROC_MAX_REPORTS       = _cfg_int("PROC_MAX_REPORTS", 50, 1, 1000, PROC_ERR_RATE_WINDOW)
PROC_INCLUDE_EXPLORER  = _cfg_bool("PROC_INCLUDE_EXPLORER", True)  # reduce noise from explorer.exe

# ---------------- WMI error taxonomy ----------------
_WMI_ERROR_MAP = {
    "0x80070005": "wmi_access_denied",
    "access denied": "wmi_access_denied",
    "0x8004100e": "wmi_invalid_namespace",
    "invalid namespace": "wmi_invalid_namespace",
    "0x80041002": "wmi_not_found",
    "not found": "wmi_not_found",
    "0x800706ba": "wmi_rpc_unavailable",
    "rpc server is unavailable": "wmi_rpc_unavailable",
    "0x000005b4": "wmi_timeout",
    "timed out": "wmi_timeout",
}
def _classify_wmi_error(exc: Exception) -> str:
    msg = (str(exc) or "").lower()
    for needle, code in _WMI_ERROR_MAP.items():
        if needle in msg:
            return code
    return "wmi_generic_failure"

# ---------------- Ruleset (simple heuristic) ----------------
# Parents that commonly shouldn't spawn script shells / LOLBINs
_PARENTS_OFFICE = {"winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","visio.exe"}
_PARENTS_DOCVIEW = {"acrord32.exe","acrord64.exe","mspub.exe"}
_PARENTS_SCRIPT_HOSTS = {"wscript.exe","cscript.exe"}  # if these spawn more shells

# Suspicious children often abused by attackers (not exhaustive)
_CHILD_SHELLS = {
    "powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe",
    "regsvr32.exe","bitsadmin.exe","installutil.exe","certutil.exe","wmic.exe","msbuild.exe",
    "msiexec.exe","forfiles.exe","schtasks.exe","at.exe","attrib.exe","scriptrunner.exe"
}

def _is_suspicious_pair(parent_name: str | None, child_name: str | None) -> bool:
    if not parent_name or not child_name:
        return False
    p = parent_name.lower()
    c = child_name.lower()

    if c not in _CHILD_SHELLS:
        return False

    if p in _PARENTS_OFFICE or p in _PARENTS_DOCVIEW:
        return True

    # Optional: explorer.exe can legitimately spawn many things; make optional
    if PROC_INCLUDE_EXPLORER and p == "explorer.exe":
        return True

    # Script host spawning another shell can be suspicious (living-off-the-land chains)
    if p in _PARENTS_SCRIPT_HOSTS:
        return True

    return False

# ---------------- Main API ----------------
def get_suspicious_children():
    """
    Scan current processes and emit a record for each suspicious parent->child pair based on
    simple parent/child heuristics (e.g., Office/Browser spawning PowerShell/cmd/mshta/etc.).
    Returns "response" and logs up to PROC_MAX_REPORTS findings.
    """
    # Windows-only guard
    if os.name != "nt":
        return "response"



    try:
        c = wmi.WMI()  # default namespace root\cimv2
        # Select only the columns we need to minimize cost
        procs = c.Win32_Process(  # no user input used in the query
            fields=["ProcessId","ParentProcessId","Name","ExecutablePath","CommandLine","CreationDate"]
        )
    except wmi.x_wmi as e:
        _log_event(_classify_wmi_error(e), window_s=PROC_ERR_RATE_WINDOW)
        return "response"
    except Exception:
        _log_event("wmi_generic_failure", window_s=PROC_ERR_RATE_WINDOW)
        return "response"

    # Build quick lookup: pid -> (name, exe, cmd, create)
    proc_map = {}
    count = 0
    for p in procs:
        try:
            if count >= PROC_MAX_SCAN:
                _log_event("proc_watch_max_scan_reached", max_scan=PROC_MAX_SCAN, window_s=PROC_ERR_RATE_WINDOW)
                break
            pid  = int(getattr(p, "ProcessId", 0) or 0)
            name = _sanitize_str(getattr(p, "Name", None), 64)
            exe  = _sanitize_str(getattr(p, "ExecutablePath", None), 260)
            cmd  = _sanitize_str(getattr(p, "CommandLine", None), 512)
            crt  = _sanitize_str(getattr(p, "CreationDate", None), 32)  # WMI datetime string
            proc_map[pid] = (name, exe, cmd, crt)
            count += 1
        except Exception:
            # skip malformed entries; don't spam logs
            continue

    # Evaluate parent->child relationships
    reports = 0
    for p in procs:
        if reports >= PROC_MAX_REPORTS:
            _log_event("proc_watch_max_reports_reached", max_reports=PROC_MAX_REPORTS, window_s=PROC_ERR_RATE_WINDOW)
            break
        try:
            child_pid = int(getattr(p, "ProcessId", 0) or 0)
            ppid      = int(getattr(p, "ParentProcessId", 0) or 0)
            child     = proc_map.get(child_pid, (None,None,None,None))
            parent    = proc_map.get(ppid, (None,None,None,None))

            child_name, child_exe, child_cmd, child_crt = child
            parent_name, parent_exe, parent_cmd, parent_crt = parent

            if _is_suspicious_pair(parent_name, child_name):
                payload = {
                    "Purpose": "proc_watch",
                    "Datetime": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "child": {
                        "pid": child_pid,
                        "name": child_name,
                        "exe": child_exe,
                        "cmd": child_cmd,
                        "created": child_crt,
                    },
                    "parent": {
                        "pid": ppid,
                        "name": parent_name,
                        "exe": parent_exe,
                        "cmd": parent_cmd,
                        "created": parent_crt,
                    },
                    "rule": "parent_spawned_lolbin_or_shell"
                }
                with log_lock:

                    log_data(payload)
                reports += 1
        except Exception:
            # tolerate odd/missing fields
            continue

    # If nothing suspicious, optionally emit a heartbeat at a slow rate
    '''if reports == 0:
        _log_event("proc_watch_no_findings", window_s=max(300.0, PROC_ERR_RATE_WINDOW))'''

    return "response"



