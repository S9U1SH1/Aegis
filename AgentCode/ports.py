# ports_compact.py
import os
import time
import ctypes
import subprocess
import threading
from datetime import datetime, timezone
import re


from log import log_data

log_lock = threading.Lock()

# ---------------- Config validation (ASVS 1.1) ----------------
def _cfg_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        val = int(raw)
    except (TypeError, ValueError):
        _log_event("cfg_invalid_int", Purpose="ports", name=name, value=str(raw))
        return default
    if not (lo <= val <= hi):
        _log_event("cfg_out_of_range_int", Purpose="ports", name=name, value=val, lo=lo, hi=hi)
        val = max(lo, min(hi, val))
    return val

def _cfg_float(name: str, default: float, lo: float, hi: float) -> float:
    raw = os.environ.get(name, str(default))
    try:
        val = float(raw)
    except (TypeError, ValueError):
        _log_event("cfg_invalid_float", Purpose="ports", name=name, value=str(raw))
        return default
    if not (lo <= val <= hi):
        _log_event("cfg_out_of_range_float", Purpose="ports", name=name, value=val, lo=lo, hi=hi)
        val = max(lo, min(hi, val))
    return val

# Limits / knobs (env-configurable, range-checked)
PORTS_CMD_TIMEOUT     = _cfg_float("PORTS_CMD_TIMEOUT", 7.0, 0.5, 60.0)
PORTS_ERR_RATE_WINDOW = _cfg_float("PORTS_ERR_RATE_WINDOW", 60.0, 5.0, 600.0)
PORTS_MAX_ROWS        = _cfg_int("PORTS_MAX_ROWS", 5000, 50, 50000)
PORTS_INCLUDE_UDP     = os.environ.get("PORTS_INCLUDE_UDP", "1").strip().lower() in {"1","true","yes","on"}

# ---------------- Rate limiter (operational robustness) ----------------
_last_err = {}  # event_key -> last monotonic time
def _rate_limited(key: str, window_s: float) -> bool:
    now = time.monotonic()
    last = _last_err.get(key, 0.0)
    if now - last >= window_s:
        _last_err[key] = now
        return False
    return True

def _log_event(event: str, Purpose: str = "ports", window_s: float = PORTS_ERR_RATE_WINDOW, **extra):
    if not _rate_limited(event, window_s):
        payload = {"event": event, "Purpose": Purpose}
        if extra: payload.update(extra)
        with log_lock:
            log_data(payload)





# ---------------- Execution path hardening ----------------
def _resolve_netstat_path() -> str:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    system32 = os.path.join(system_root, "System32")
    # Prefer Sysnative when 32-bit proc on 64-bit OS to bypass WOW64 redirection
    is_64_os = bool(os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROGRAMFILES(X86)"))
    is_32_proc = os.environ.get("PROCESSOR_ARCHITECTURE","").endswith("86") and not os.environ.get("PROCESSOR_ARCHITEW6432")
    if is_64_os and is_32_proc:
        sysnative = os.path.join(system_root, "Sysnative", "netstat.exe")
        if os.path.exists(sysnative):
            return sysnative
    return os.path.join(system32, "netstat.exe")

#NETSTAT = _resolve_netstat_path()



# ---------------- Parsing helpers ----------------
_SPLIT_WS = re.compile(r"\s+")

def _extract_port(local_addr: str) -> int | None:
    """Extract numeric port from netstat local address (IPv4 'A:B' or IPv6 '[A]:B')."""
    if not local_addr:
        return None
    try:
        # netstat wraps IPv6 in [..]:port, IPv4 is host:port; rsplit handles both
        host, port = local_addr.rsplit(":", 1)
        port = port.strip()
        if port == "*" or not port.isdigit():
            return None
        p = int(port)
        if 0 <= p <= 65535:
            return p
    except Exception:
        return None
    return None

def _parse_netstat_lines(lines: list[str]) -> tuple[set[int], int, int]:
    """
    Return (unique_ports, tcp_listen_count, udp_count)
    We keep only TCP LISTENING and (optionally) UDP sockets (no state).
    """
    ports: set[int] = set()
    tcp_listen = 0
    udp_total = 0

    rows_seen = 0
    for raw in lines:
        if rows_seen >= PORTS_MAX_ROWS:
            _log_event("ports_max_rows_reached", max_rows=PORTS_MAX_ROWS)
            break

        line = raw.strip()
        if not line or line.startswith("Proto") or line.startswith("Active Connections"):
            continue

        parts = _SPLIT_WS.split(line)
        if not parts:
            continue

        proto = parts[0].upper()
        if proto not in ("TCP", "UDP"):
            continue

        try:
            if proto == "TCP":
                # TCP line: Proto LocalAddr ForeignAddr State PID
                if len(parts) < 5:
                    continue
                local, state = parts[1], parts[3]
                if state.upper() != "LISTENING":
                    continue
                p = _extract_port(local)
                if p is not None:
                    ports.add(p)
                    tcp_listen += 1
            else:  # UDP
                if not PORTS_INCLUDE_UDP:
                    continue
                # UDP line: Proto LocalAddr ForeignAddr PID  (no State)
                if len(parts) < 4:
                    continue
                local = parts[1]
                p = _extract_port(local)
                if p is not None:
                    ports.add(p)
                    udp_total += 1
        except Exception:
            # tolerant to format variants
            continue

        rows_seen += 1

    return ports, tcp_listen, udp_total

def _compress_ports_to_ranges(sorted_ports: list[int]) -> str:
    """Return '11,14-17,33' style."""
    if not sorted_ports:
        return ""
    ranges = []
    start = prev = sorted_ports[0]
    for p in sorted_ports[1:]:
        if p == prev + 1:
            prev = p
            continue
        # close current run
        ranges.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = p
    ranges.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(ranges)

# ---------------- Main ----------------
def get_open_ports():
    # Windows-only guard
    if os.name != "nt":
        return "response"

    NETSTAT = _resolve_netstat_path()
    # Run hardened netstat
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE

        out = subprocess.check_output(
            [NETSTAT, "-a", "-n", "-o"],
            shell=False,
            timeout=PORTS_CMD_TIMEOUT,
            startupinfo=si,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        text = out.decode("utf-8", errors="ignore")
    except FileNotFoundError:
        _log_event("ports_cmd_not_found")
        return "response"
    except subprocess.TimeoutExpired:
        _log_event("ports_cmd_timeout", timeout=PORTS_CMD_TIMEOUT)
        return "response"
    except subprocess.CalledProcessError:
        _log_event("ports_cmd_failed")
        return "response"
    except Exception:
        _log_event("ports_generic_failure")
        return "response"

    ports, tcp_listen_count, udp_count = _parse_netstat_lines(text.splitlines())
    ports_list = sorted(ports)
    compact = _compress_ports_to_ranges(ports_list)


    payload = {
        "Purpose": "ports",
        "Datetime": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "open_ports": ports_list,     # e.g., "11,14-17,33"
        "counts": {
            "tcp_listen": tcp_listen_count,
            "udp_total": udp_count if PORTS_INCLUDE_UDP else 0,
            "unique": len(ports_list),
        },
    }

    with log_lock:
        log_data(payload)

    return "response"


