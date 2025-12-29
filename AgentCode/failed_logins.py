import os
import time
import ctypes
import threading
from datetime import datetime, timezone
import unicodedata
import re

import win32evtlog
import pywintypes

from log import log_data

log_lock = threading.Lock()

# ---------------- File location / app dir ----------------
APP_DIR = os.environ.get("APP_DIR", r"C:\ProgramData\Aegis")
try:
    os.makedirs(APP_DIR, exist_ok=True)
except Exception:
    with log_lock:
        log_data({"event": "cfg_app_dir_create_failed", "dir": APP_DIR, "Purpose": "failed_login"})

LAST_REC_FILE = os.path.join(APP_DIR, "evtlog_last_record.txt")

# ---------------- Config validation (ASVS 1.1) ----------------
def _cfg_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        val = int(raw)
    except (TypeError, ValueError):
        with log_lock:
            log_data({"event": "cfg_invalid_int", "name": name, "value": str(raw), "Purpose": "failed_login"})
        return default
    if not (lo <= val <= hi):
        with log_lock:
            log_data({
                "event": "cfg_out_of_range_int",
                "name": name,
                "value": val,
                "lo": lo,
                "hi": hi,
                "Purpose": "failed_login",
            })
        val = max(lo, min(hi, val))
    return val

# Max events to process per invocation; error log rate window (seconds)
FAILEDLOG_MAX_EVENTS      = _cfg_int("FAILEDLOG_MAX_EVENTS", 500, 1, 5000)
FAILEDLOG_ERR_RATE_WINDOW = _cfg_int("FAILEDLOG_ERR_RATE_WINDOW", 60, 5, 600)



# ---------------- Error taxonomy + rate limiting ----------------
_EVTLOG_ERROR_MAP = {
    "Access is denied": "evt_access_denied",                       # WinError 5
    "The system cannot find the file specified": "evt_not_found",  # WinError 2
    "The handle is invalid": "evt_invalid_handle",                 # WinError 6
    "The parameter is incorrect": "evt_invalid_param",             # WinError 87
    "RPC server is unavailable": "evt_rpc_unavailable",
    "Insufficient system resources": "evt_insufficient_resources",
    "Insufficient quota": "evt_insufficient_quota",
    "The data area passed to a system call is too small": "evt_buffer_too_small",
    "The event log file is corrupt": "evt_log_corrupt",
    "Not enough storage": "evt_no_storage",
    "The specified resource type cannot be found": "evt_resource_not_found",
    "The event log file is full": "evt_log_full",
    "The system cannot find the path specified": "evt_path_not_found",
}

def _classify_evtlog_error(exc: Exception) -> str:
    msg = str(exc) if exc else ""
    low = msg.lower()
    for needle, code in _EVTLOG_ERROR_MAP.items():
        if needle.lower() in low:
            return code
    return "evt_generic_failure"

_last_err = {}  # event_key -> last log monotonic time

def _rate_limited(key: str, window_s: float) -> bool:
    now = time.monotonic()
    last = _last_err.get(key, 0.0)
    if now - last >= window_s:
        _last_err[key] = now
        return False
    return True

def _log_event(event: str, **extra):
    if not _rate_limited(event, FAILEDLOG_ERR_RATE_WINDOW):
        payload = {"event": event, "Purpose": "failed_login"}
        if extra:
            payload.update(extra)
        with log_lock:
            log_data(payload)

# ---------------- Sanitization (NFKC + control char strip) ----------------
_CONTROL_CHARS = re.compile(r'[\x00-\x1F\x7F]')

def _sanitize_str(value, max_len=128):
    if not value:
        return None
    s = unicodedata.normalize("NFKC", str(value))
    s = _CONTROL_CHARS.sub('', s).strip()
    if not s:
        return None
    if len(s) > max_len:
        s = s[:max_len]
    return s

# ---------------- Heuristics to extract IP and process name ----------------
_IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

def _extract_ip(inserts):
    """
    Find the first IPv4-looking string in the inserts.
    """
    for raw in inserts:
        s = _sanitize_str(raw, max_len=64)
        if s and _IPV4_RE.match(s):
            return s
    return None

def _extract_proc_name(inserts):
    """
    Heuristic: choose something that looks like a process name or path.
    """
    for raw in inserts:
        s = _sanitize_str(raw, max_len=260)
        if not s:
            continue
        low = s.lower()
        if low.endswith(".exe") or "\\" in s:
            return s
    return None

# ---------------- Checkpointing helpers ----------------
def _load_last_record() -> int:
    try:
        with open(LAST_REC_FILE, "r", encoding="utf-8") as f:
            return int((f.read() or "0").strip())
    except Exception:
        return 0

def _save_last_record(n: int) -> None:
    try:
        with open(LAST_REC_FILE, "w", encoding="utf-8") as f:
            f.write(str(int(n)))
    except Exception:
        # Non-fatal; we'll just re-read next time
        pass

# ---------------- Main: failed logins ----------------
def get_failed_logins():
    # Windows-only
    if os.name != "nt":
        return "response"



    hand = None
    max_record_seen = 0
    processed = 0
    last_seen = _load_last_record()

    try:
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
        except pywintypes.error as e:
            _log_event(_classify_evtlog_error(e))
            return "response"

        # Read backwards; stop when we hit records we've already processed.
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        while processed < FAILEDLOG_MAX_EVENTS:
            try:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
            except pywintypes.error as e:
                _log_event(_classify_evtlog_error(e))
                break

            if not events:
                break

            for ev in events:
                rec_no = getattr(ev, "RecordNumber", 0) or 0
                if rec_no > max_record_seen:
                    max_record_seen = rec_no

                # If we've already processed up to last_seen, stop
                if last_seen and rec_no <= last_seen:
                    events = []  # force outer break
                    break

                # 4625 = failed logon
                if (ev.EventID & 0xFFFF) == 4625:
                    inserts = list(getattr(ev, "StringInserts", None) or [])

                    def safe(idx, max_len=128):
                        return _sanitize_str(inserts[idx], max_len) if idx < len(inserts) else None

                    # Use event timestamp; convert to UTC ISO-8601 Z
                    try:
                        # ev.TimeGenerated is a pywintypes.datetime (naive, local)
                        ts = ev.TimeGenerated
                        if hasattr(ts, "timestamp"):
                            ev_iso = datetime.fromtimestamp(
                                ts.timestamp(),
                                tz=timezone.utc
                            ).isoformat().replace("+00:00", "Z")
                        else:
                            ev_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                    except Exception:
                        ev_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

                    ip_addr = _extract_ip(inserts)
                    proc_name = _extract_proc_name(inserts)

                    payload = {
                        "RecordNumber": rec_no,
                        "Target Username": safe(5),
                        "Source IP Address": ip_addr or "-",
                        "Process Name": proc_name or "-",
                        "Purpose": "failed_login",
                        "Datetime": ev_iso,
                    }
                    with log_lock:
                        log_data(payload)

                    processed += 1
                    if processed >= FAILEDLOG_MAX_EVENTS:
                        break

            if not events or processed >= FAILEDLOG_MAX_EVENTS:
                break

    except pywintypes.error as e:
        _log_event(_classify_evtlog_error(e))
    except OSError:
        _log_event("evt_namespace_not_supported")
    finally:
        if hand is not None:
            try:
                win32evtlog.CloseEventLog(hand)
            except pywintypes.error:
                pass

    # Save the newest record number we observed so we resume next time
    if max_record_seen > 0:
        _save_last_record(max_record_seen)

    return "response"
