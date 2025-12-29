import os
import time
import ctypes
import subprocess
import threading
from datetime import datetime, timezone
from log import log_data

log_lock = threading.Lock()

# ---------------- Config validation (ASVS 1.1) ----------------
def _cfg_float(name: str, default: float, lo: float, hi: float) -> float:
    raw = os.environ.get(name, str(default))
    try:
        val = float(raw)
    except (TypeError, ValueError):
        with log_lock:
            log_data({"event": "cfg_invalid_float", "name": name, "value": str(raw), "Purpose": "firewall"})
        return default
    if not (lo <= val <= hi):
        with log_lock:
            log_data({"event": "cfg_out_of_range", "name": name, "value": val, "lo": lo, "hi": hi, "Purpose": "firewall"})
        val = max(lo, min(hi, val))
    return val

# Command timeout & error-log rate window (seconds)
FIREWALL_CMD_TIMEOUT = _cfg_float("FIREWALL_CMD_TIMEOUT", 5.0, 0.5, 60.0)
FW_ERR_RATE_WINDOW   = _cfg_float("FW_ERR_RATE_WINDOW",   60.0, 5.0, 600.0)



# ---------------- Error taxonomy + rate limiting ----------------
def _classify_subprocess_error(exc: Exception) -> str:
    if isinstance(exc, FileNotFoundError):
        return "fw_cmd_not_found"
    if isinstance(exc, subprocess.TimeoutExpired):
        return "fw_cmd_timeout"
    if isinstance(exc, subprocess.CalledProcessError):
        return "fw_cmd_failed"
    return "fw_generic_failure"

_last_err = {}  # event_key -> last log monotonic time

def _rate_limited(key: str, window_s: float) -> bool:
    now = time.monotonic()
    last = _last_err.get(key, 0.0)
    if now - last >= window_s:
        _last_err[key] = now
        return False
    return True

def _log_event(event: str, purpose: str = "firewall", window_s: float | None = None, **extra):
    """Consistent, rate-limited event logger."""
    w = FW_ERR_RATE_WINDOW if window_s is None else window_s
    if not _rate_limited(event, w):
        payload = {"event": event, "Purpose": purpose}
        if extra:
            payload.update(extra)
        with log_lock:
            log_data(payload)

# ---------------- Execution path hardening ----------------
# Resolve absolute path to netsh to avoid PATH hijacking
def _resolve_netsh_path() -> str:

    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    system32 = os.path.join(system_root, "System32")
    # If 32-bit process on 64-bit OS and you want the real 64-bit tools, try Sysnative
    is_64_os = bool(os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROGRAMFILES(X86)"))
    is_32_proc = os.environ.get("PROCESSOR_ARCHITECTURE", "").endswith("86") and not os.environ.get("PROCESSOR_ARCHITEW6432")
    if is_64_os and is_32_proc:
        sysnative = os.path.join(system_root, "Sysnative", "netsh.exe")
        if os.path.exists(sysnative):
            return sysnative
    return os.path.join(system32, "netsh.exe")

#NETSH = _resolve_netsh_path()

def get_firewall_status():
    # Configuration & Secure Defaults: Windows-only
    if os.name != "nt":
        return "response"
    NETSH = _resolve_netsh_path()


    # Helper: run fixed 'netsh' commands; treat output as untrusted and only derive booleans
    def _run(args) -> bool:
        try:
            # Hide console window for netsh to prevent flashing
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0  # SW_HIDE

            out = subprocess.check_output(
                args,
                shell=False,
                timeout=FIREWALL_CMD_TIMEOUT,
                startupinfo=si,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            # Derive boolean only; do not log raw output
            return b"ON" in (out or b"")
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            _log_event(_classify_subprocess_error(e))
            return False
        except Exception as e:
            _log_event(_classify_subprocess_error(e))
            return False

    firewall_statuses = {
        "Domain":  _run([NETSH, "advfirewall", "show", "Domain"]),
        "Private": _run([NETSH, "advfirewall", "show", "Private"]),
        "Public":  _run([NETSH, "advfirewall", "show", "Public"]),
        "Purpose": "firewall",
        "Datetime": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    with log_lock:
        log_data(firewall_statuses)

    return "response"
