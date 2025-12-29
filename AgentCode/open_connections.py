# outbound_connections.py
import os
import time
import ctypes
import subprocess
import threading
from datetime import datetime, timezone
import re


from log import log_data  # your encrypted+integrity logging

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

def _log_event(event: str, Purpose: str = "outbound", window_s: float = 60.0, **extra):
    if not _rate_limited(event, window_s):
        payload = {"event": event, "Purpose": Purpose}
        if extra:
            payload.update(extra)
        with log_lock:
            log_data(payload)





# ---------------- Execution path hardening ----------------
def _resolve_netstat_path() -> str:


    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    system32 = os.path.join(system_root, "System32")
    # Prefer Sysnative for 32-bit proc on 64-bit OS to bypass WOW64 redirection
    is_64_os = bool(os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROGRAMFILES(X86)"))
    is_32_proc = os.environ.get("PROCESSOR_ARCHITECTURE", "").endswith("86") and not os.environ.get("PROCESSOR_ARCHITEW6432")
    if is_64_os and is_32_proc:
        sysnative = os.path.join(system_root, "Sysnative", "netstat.exe")
        if os.path.exists(sysnative):
            return sysnative
    return os.path.join(system32, "netstat.exe")

#NETSTAT = _resolve_netstat_path()

# ---------------- Config validation (ASVS 1.1) — resolved at runtime ----------------
def _cfg_int(name: str, default: int, lo: int, hi: int, err_window: float) -> int:
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

def _cfg_float(name: str, default: float, lo: float, hi: float, err_window: float) -> float:
    raw = os.environ.get(name, str(default))
    try:
        val = float(raw)
    except (TypeError, ValueError):
        _log_event("cfg_invalid_float", name=name, value=str(raw), window_s=err_window)
        return default
    if not (lo <= val <= hi):
        _log_event("cfg_out_of_range_float", name=name, value=val, lo=lo, hi=hi, window_s=err_window)
        val = max(lo, min(hi, val))
    return val

def _cfg_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "1" if default else "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}

# ---------------- Parsing helpers ----------------
_SPLIT_WS = re.compile(r"\s+")
_IPV6_BRACKET = re.compile(r"^\[(.*)\]:(\d+)$")  # matches [IPv6]:port

def _extract_host_port(addr: str) -> tuple[str | None, int | None]:
    """Extract host and port from netstat address columns (IPv4 'A:B', IPv6 '[A]:B')."""
    if not addr:
        return None, None
    addr = addr.strip()
    m = _IPV6_BRACKET.match(addr)
    if m:
        host, port = m.group(1), m.group(2)
    else:
        if ":" not in addr:
            return None, None
        host, port = addr.rsplit(":", 1)
    port = port.strip()
    if port == "*" or not port.isdigit():
        return host, None
    try:
        p = int(port)
        if 0 <= p <= 65535:
            return host, p
    except Exception:
        return host, None
    return host, None

def _is_loopback(host: str) -> bool:
    if not host:
        return False
    h = host.strip().lower()
    return h in {"127.0.0.1", "0.0.0.0", "::1", "[::1]"}

# ---------------- Main ----------------
def get_outbound_connections():
    """
    Collect current outbound connections (TCP ESTABLISHED).
    Optional: include UDP entries that have a concrete remote endpoint (rare).
    Honors OUTBOUND_INCLUDE_LOOPBACK (default 0) to include/exclude loopback remotes.
    """
    # Windows-only guard
    if os.name != "nt":
        return "response"
    NETSTAT = _resolve_netstat_path()
    # Resolve config at runtime (no import-time side effects)
    ERR_WIN              = max(5.0, min(600.0, float(os.environ.get("OUTBOUND_ERR_RATE_WINDOW", "60.0"))))
    CMD_TIMEOUT          = _cfg_float("OUTBOUND_CMD_TIMEOUT", 7.0, 0.5, 60.0, ERR_WIN)
    MAX_ROWS             = _cfg_int("OUTBOUND_MAX_ROWS", 10000, 100, 100000, ERR_WIN)
    INCLUDE_UDP_ACTIVE   = _cfg_bool("OUTBOUND_INCLUDE_UDP", False)
    INCLUDE_LOOPBACK     = _cfg_bool("OUTBOUND_INCLUDE_LOOPBACK", False)



    # Run hardened netstat
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE

        out = subprocess.check_output(
            [NETSTAT, "-n", "-o", "-a"],
            shell=False,
            timeout=CMD_TIMEOUT,
            startupinfo=si,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        text = out.decode("utf-8", errors="ignore")
    except FileNotFoundError:
        _log_event("outbound_cmd_not_found", window_s=ERR_WIN)
        return "response"
    except subprocess.TimeoutExpired:
        _log_event("outbound_cmd_timeout", timeout=CMD_TIMEOUT, window_s=ERR_WIN)
        return "response"
    except subprocess.CalledProcessError:
        _log_event("outbound_cmd_failed", window_s=ERR_WIN)
        return "response"
    except Exception:
        _log_event("outbound_generic_failure", window_s=ERR_WIN)
        return "response"

    tcp_remotes: set[str] = set()
    udp_remotes: set[str] = set()
    rows_seen = 0

    for raw in text.splitlines():
        if rows_seen >= MAX_ROWS:
            _log_event("outbound_max_rows_reached", max_rows=MAX_ROWS, window_s=ERR_WIN)
            break

        line = raw.strip()
        if not line or line.startswith("Proto") or line.startswith("Active Connections"):
            continue

        parts = _SPLIT_WS.split(line)
        if not parts:
            continue

        proto = parts[0].upper()
        if proto == "TCP":
            # Columns: Proto LocalAddr ForeignAddr State PID
            if len(parts) < 5:
                continue
            state = parts[3].upper()
            if state != "ESTABLISHED":
                continue
            remote_host, remote_port = _extract_host_port(parts[2])
            if remote_host and remote_port is not None:
                if not INCLUDE_LOOPBACK and _is_loopback(remote_host):
                    continue
                tcp_remotes.add(f"{remote_host}:{remote_port}")

        elif proto == "UDP" and INCLUDE_UDP_ACTIVE:
            # Keep entries that have a concrete foreign endpoint (if present)
            if len(parts) < 4:
                continue
            remote_host, remote_port = _extract_host_port(parts[2])
            if remote_host and remote_port is not None:
                if not INCLUDE_LOOPBACK and _is_loopback(remote_host):
                    continue
                udp_remotes.add(f"{remote_host}:{remote_port}")

        rows_seen += 1

    payload = {
        "Purpose": "outbound",
        "Datetime": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tcp_established": sorted(tcp_remotes),
        "counts": {
            "tcp": len(tcp_remotes),
            "udp": len(udp_remotes) if INCLUDE_UDP_ACTIVE else 0,
        },
    }
    if INCLUDE_UDP_ACTIVE:
        payload["udp_active"] = sorted(udp_remotes)

    with log_lock:
        log_data(payload)

    return "response"
