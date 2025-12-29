from log import log_data
from datetime import datetime, timezone
import wmi
import threading
import ctypes
import os
import re
import unicodedata
import time

log_lock = threading.Lock()

# ---- Config validation (ASVS 1.1) ----
def _cfg_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, val))

# Rate-limit window (seconds) for error events
AV_ERR_RATE_WINDOW = _cfg_int("AV_ERR_RATE_WINDOW", 60, 5, 600)

# ---- Rate limiter (pattern per your snippet) ----
_last_err = {}  # event_key -> last log monotonic time

def _rate_limited(key: str, window_s: float = 60.0) -> bool:
    now = time.monotonic()
    last = _last_err.get(key, 0.0)
    if now - last >= window_s:
        _last_err[key] = now
        return False   # NOT limited -> allow
    return True        # within window -> suppress

def _log_event(event: str, purpose: str = "antivirus", window_s: float = AV_ERR_RATE_WINDOW, **extra):
    if not _rate_limited(event, window_s):
        payload = {"event": event, "Purpose": purpose}
        if extra:
            payload.update(extra)
        with log_lock:
            log_data(payload)

# ---- Sanitization: control chars + Unicode normalization (NFKC) ----
_CONTROL_CHARS = re.compile(r'[\x00-\x1F\x7F]')

def _sanitize_str(value, max_len=128):
    """Normalize (NFKC), remove control chars, trim length; return None for falsy inputs."""
    if not value:
        return None
    s = unicodedata.normalize("NFKC", str(value))
    s = _CONTROL_CHARS.sub('', s).strip()
    if not s:
        return None
    if len(s) > max_len:
        s = s[:max_len]
    return s


# ---- Input validation ----
def _parse_product_state(ps):
    if not isinstance(ps, int):
        raise ValueError("productState not int")
    if ps < 0 or ps > 0xFFFFFF:
        raise ValueError("productState out of expected 24-bit range")

        # Masks (bit groups)
    product_state = ps & 0xF000  # on/off/snoozed/expired
    sig_state = ps & 0x00F0  # up-to-date vs out-of-date
    owner = ps & 0x0F00  # windows vs non-ms

    # Interpret
    real_time_on = (product_state == 0x1000)  # "On"
    snoozed = (product_state == 0x2000)
    expired = (product_state == 0x3000)

    definitions_up_to_date = (sig_state == 0x00)  # UpToDate
    is_windows_owner = (owner == 0x0100)

    # If you want a single "ok" field:
    product_ok = real_time_on and not expired


    return real_time_on, definitions_up_to_date, product_ok

# ---- Exception taxonomy ----
_WMI_ERROR_MAP = {
    "0x80070005": "wmi_access_denied",
    "Access denied": "wmi_access_denied",
    "0x8004100e": "wmi_invalid_namespace",
    "Invalid namespace": "wmi_invalid_namespace",
    "0x80041002": "wmi_not_found",
    "Not found": "wmi_not_found",
    "0x800706ba": "wmi_rpc_unavailable",
    "RPC server is unavailable": "wmi_rpc_unavailable",
    "0x000005b4": "wmi_timeout",
    "Timed out": "wmi_timeout",
}

def _classify_wmi_error(exc: Exception) -> str:
    msg = str(exc) if exc else ""
    for needle, code in _WMI_ERROR_MAP.items():
        if needle.lower() in msg.lower():
            return code
    return "wmi_generic_failure"

def check_antivirus_status():
    # ---- Windows guard ----
    if os.name != "nt":
        return "response"


    # Optional COM init for robustness if called from a thread
    _co_inited = False
    try:
        import pythoncom
        pythoncom.CoInitialize()
        _co_inited = True
    except Exception:
        pass

    try:
        c = wmi.WMI(namespace=r"root\SecurityCenter2")
        antiviruses = c.AntiVirusProduct()

        for av in antiviruses:
            try:
                ps_raw = getattr(av, "productState", None)
                rt, defs_ok, prod_ok = _parse_product_state(ps_raw)

                antivirus = {
                    "name": _sanitize_str(getattr(av, "displayName", None)),
                    "Real_time_Protection": rt,
                    "definitions": defs_ok,
                    "product": prod_ok,
                    "Purpose": "antivirus",
                    "Datetime": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                }
                with log_lock:
                    log_data(antivirus)

            except ValueError:
                _log_event("av_malformed_product_state")
            except AttributeError:
                _log_event("av_missing_attributes")

    except wmi.x_wmi as e:
        _log_event(_classify_wmi_error(e))
    except OSError:
        _log_event("wmi_namespace_not_supported")




