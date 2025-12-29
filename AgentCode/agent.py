# agent.py
import os
import sys
import ctypes
import time
import subprocess
import threading
import json
import signal
import atexit

import wmi
import pythoncom
import requests
import pywintypes

from log import log_data
from antivirus import check_antivirus_status
from failed_logins import get_failed_logins
from firewall import get_firewall_status
from registrires import read_registries
from ports import get_open_ports
from open_connections import get_outbound_connections
from sus_proceesses import get_suspicious_children
from Binary_Checker import binary_check
from log import read_and_remove_first_log


# ----------------- App dir -----------------
APP_DIR = os.path.abspath(os.environ.get("APP_DIR", r"C:\ProgramData\Aegis"))


# Ensure APP_DIR exists early
try:
    os.makedirs(APP_DIR, exist_ok=True)
except Exception:
    pass


# ----------------- Global stop flag (graceful shutdown) -----------------
STOP_EVENT = threading.Event()

def _request_stop(*_args):
    STOP_EVENT.set()

# Task Scheduler / service wrapper will typically terminate the process;
# this gives threads a chance to stop cleanly.
try:
    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
except Exception:
    pass

atexit.register(_request_stop)

# Best-effort Windows console close/logoff/shutdown handling (optional, safe)
try:
    import win32api  # pywin32
    def _console_ctrl_handler(ctrl_type):
        _request_stop()
        return True
    win32api.SetConsoleCtrlHandler(_console_ctrl_handler, True)
except Exception:
    pass


# ----------------- Small helpers (rate limit + config validation) -----------------
log_lock = threading.Lock()
_last_event_time = {}

def _rate_limited(key: str, window_s: float) -> bool:
    now = time.monotonic()
    last = _last_event_time.get(key, 0.0)
    if now - last >= window_s:
        _last_event_time[key] = now
        return False
    return True

def _log_event(event: str, purpose: str, window_s: float, **extra):
    if not _rate_limited(event, window_s):
        payload = {"event": event, "Purpose": purpose}
        if extra:
            payload.update(extra)
        with log_lock:
            log_data(payload)

def _cfg_float(name: str, default: float, lo: float, hi: float) -> float:
    raw = os.environ.get(name, str(default))
    try:
        val = float(raw)
    except (TypeError, ValueError):
        _log_event("cfg_invalid_float", "agent", 60.0, name=name, value=str(raw))
        return default
    if not (lo <= val <= hi):
        _log_event("cfg_out_of_range_float", "agent", 60.0, name=name, value=val, lo=lo, hi=hi)
        val = max(lo, min(hi, val))
    return val

def _cfg_url(name: str, default: str) -> str:
    url = os.environ.get(name, default).strip()
    return url


# ----------------- Config (validated) -----------------
SUBMIT_URL = _cfg_url("SUBMIT_URL", "https://aegis-security-solutions.com/submit")

READ_LOG_TIME_DELAY          = _cfg_float("READ_LOG_TIME_DELAY",          5, 0.1, 3600.0)
CRITICAL_REG_DELAY_TIME      = _cfg_float("CRITICAL_REG_DELAY_TIME",      20.0, 0.1, 3600.0)
FIREWALL_STATUS_DELAY_TIME   = _cfg_float("FIREWALL_STATUS_DELAY_TIME",   20.0, 0.1, 3600.0)
FAILED_LOGINS_DELAY_TIME     = _cfg_float("FAILED_LOGINS_DELAY_TIME",     20.0, 0.1, 3600.0)
ANTIVIRUS_STATUS_DELAY_TIME  = _cfg_float("ANTIVIRUS_STATUS_DELAY_TIME",  20.0, 0.1, 3600.0)
PORTS_STATUS_DELAY_TIME      = _cfg_float("PORTS_STATUS_DELAY_TIME",      20.0, 0.1, 3600.0)
OUTBOUND_STATUS_DELAY_TIME   = _cfg_float("OUTBOUND_STATUS_DELAY_TIME",   20.0, 0.1, 3600.0)
SUSPROC_STATUS_DELAY_TIME    = _cfg_float("SUSPROC_STATUS_DELAY_TIME",    20.0, 0.1, 3600.0)
BINARY_CHECKER_DELAY_TIME    = _cfg_float("BINARY_CHECKER_DELAY_TIME",    180.0, 0.5, 3600.0)

AGENT_ERR_RATE_WINDOW = _cfg_float("AGENT_ERR_RATE_WINDOW", 60.0, 5.0, 600.0)


# ----------------- Looped tasks -----------------
def check_antivirus_status_looped():
    try:
        pythoncom.CoInitialize()
        while not STOP_EVENT.is_set():
            try:
                check_antivirus_status()
            except (wmi.x_wmi, OSError, AttributeError, ValueError) as e:
                _log_event("av_loop_error", "agent", AGENT_ERR_RATE_WINDOW, err=repr(e))
            STOP_EVENT.wait(ANTIVIRUS_STATUS_DELAY_TIME)
    finally:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass

def get_failed_logins_looped():
    """
    Runs like the other loops (same process/thread).
    Key fix: catch ALL exceptions so the thread never exits.
    """
    while not STOP_EVENT.is_set():
        try:
            get_failed_logins()
        except pywintypes.error as e:
            _log_event("failedlogins_pywintypes_error", "agent", AGENT_ERR_RATE_WINDOW, err=str(e))
        except PermissionError as e:
            _log_event("failedlogins_permission_error", "agent", AGENT_ERR_RATE_WINDOW, err=repr(e))
        except Exception as e:
            _log_event("failedlogins_unexpected_error", "agent", AGENT_ERR_RATE_WINDOW, err=repr(e))
        STOP_EVENT.wait(FAILED_LOGINS_DELAY_TIME)

def get_firewall_status_looped():
    while not STOP_EVENT.is_set():
        try:
            get_firewall_status()
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            _log_event("fw_loop_error", "agent", AGENT_ERR_RATE_WINDOW, err=repr(e))
        STOP_EVENT.wait(FIREWALL_STATUS_DELAY_TIME)

def read_registries_looped():
    while not STOP_EVENT.is_set():
        try:
            read_registries()
        except (OSError, ValueError, PermissionError) as e:
            _log_event("reg_loop_error", "agent", AGENT_ERR_RATE_WINDOW, err=repr(e))
        STOP_EVENT.wait(CRITICAL_REG_DELAY_TIME)

def get_open_ports_looped():
    while not STOP_EVENT.is_set():
        try:
            get_open_ports()
        except Exception as e:
            _log_event("ports_loop_error", "agent", AGENT_ERR_RATE_WINDOW, err=repr(e))
        STOP_EVENT.wait(PORTS_STATUS_DELAY_TIME)

def get_outbound_connections_looped():
    while not STOP_EVENT.is_set():
        try:
            get_outbound_connections()
        except Exception as e:
            _log_event("outbound_loop_error", "agent", AGENT_ERR_RATE_WINDOW, err=repr(e))
        STOP_EVENT.wait(OUTBOUND_STATUS_DELAY_TIME)

def get_suspicious_processes_looped():
    try:
        pythoncom.CoInitialize()
        while not STOP_EVENT.is_set():
            try:
                get_suspicious_children()
            except (wmi.x_wmi, OSError) as e:
                _log_event("susproc_loop_error", "agent", AGENT_ERR_RATE_WINDOW, err=repr(e))
            STOP_EVENT.wait(SUSPROC_STATUS_DELAY_TIME)
    finally:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass

def binary_checker_looped():
    while not STOP_EVENT.is_set():
        try:
            binary_check()
        except Exception as e:
            _log_event("binary_checker_loop_error", "agent", AGENT_ERR_RATE_WINDOW, err=repr(e))
        STOP_EVENT.wait(BINARY_CHECKER_DELAY_TIME)

def read_and_remove_first_log_looped():
    backoff = 0.0
    while not STOP_EVENT.is_set():
        ok = True
        try:
            _ = read_and_remove_first_log()
        except (json.JSONDecodeError, requests.exceptions.RequestException, OSError, PermissionError) as e:
            _log_event("sender_loop_error", "agent", AGENT_ERR_RATE_WINDOW, err=repr(e))
            ok = False

        if not ok:
            backoff = min(backoff + 0.5, 5.0)
        else:
            backoff = 0.0

        # Wait in a stop-aware way
        STOP_EVENT.wait(READ_LOG_TIME_DELAY + backoff)


# ----------------- MAIN -----------------
if __name__ == "__main__":
    # Start all loops as normal threads
    thread_av         = threading.Thread(target=check_antivirus_status_looped,     name="AVLoop",        daemon=True)
    thread_failed     = threading.Thread(target=get_failed_logins_looped,          name="FailedLogins",  daemon=True)
    thread_fw         = threading.Thread(target=get_firewall_status_looped,        name="FirewallLoop",  daemon=True)
    thread_reg        = threading.Thread(target=read_registries_looped,            name="RegistryLoop",  daemon=True)
    thread_ports      = threading.Thread(target=get_open_ports_looped,             name="PortsLoop",     daemon=True)
    thread_outbound   = threading.Thread(target=get_outbound_connections_looped,   name="OutboundLoop",  daemon=True)
    thread_susproc    = threading.Thread(target=get_suspicious_processes_looped,   name="SusProcLoop",   daemon=True)
    thread_bincheck   = threading.Thread(target=binary_checker_looped,             name="BinCheckLoop",  daemon=True)
    thread_sender     = threading.Thread(target=read_and_remove_first_log_looped,  name="SenderLoop",    daemon=True)

    thread_av.start()
    thread_failed.start()
    thread_fw.start()
    thread_reg.start()
    thread_ports.start()
    thread_outbound.start()
    thread_susproc.start()
    thread_bincheck.start()
    thread_sender.start()

    # Keep process alive until stop requested
    try:
        while not STOP_EVENT.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        _request_stop()

    # Give threads a moment to exit
    for _t in (thread_av, thread_fw, thread_reg, thread_ports, thread_outbound, thread_susproc, thread_bincheck, thread_sender):
        try:
            _t.join(timeout=5.0)
        except Exception:
            pass

