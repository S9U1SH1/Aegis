
import os
import time
import csv
import psutil
import subprocess
import concurrent.futures
import unicodedata
import re
from pathlib import Path
from typing import Dict, Optional, List

from log import log_data  # your encrypted+integrity logger

# ======= Small helpers (rate limit + sanitization + cfg validators) =======

_last_err: dict[str, float] = {}
def _rate_limited(key: str, window_s: float) -> bool:
    now = time.monotonic()
    last = _last_err.get(key, 0.0)
    if now - last >= window_s:
        _last_err[key] = now
        return False
    return True

def _log_event(event: str, window_s: float = 60.0, Purpose: str = "bintrust", **extra):
    """Rate-limited event logger (no secrets)."""
    if not _rate_limited(event, window_s):
        payload = {"event": event, "Purpose": Purpose}
        if extra:
            payload.update(extra)
        log_data(payload)

_CONTROL_CHARS = re.compile(r'[\x00-\x1F\x7F]')
def _sanitize_str(value: Optional[str], max_len: int = 256) -> Optional[str]:
    if value is None:
        return None
    s = unicodedata.normalize("NFKC", str(value))
    s = _CONTROL_CHARS.sub("", s).strip()
    if not s:
        return None
    return s[:max_len]

def _cfg_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        v = int(raw)
    except (TypeError, ValueError):
        _log_event("cfg_invalid_int", name=name, value=str(raw))
        return default
    if not (lo <= v <= hi):
        _log_event("cfg_out_of_range_int", name=name, value=v, lo=lo, hi=hi)
        v = max(lo, min(hi, v))
    return v

def _cfg_float(name: str, default: float, lo: float, hi: float) -> float:
    raw = os.environ.get(name, str(default))
    try:
        v = float(raw)
    except (TypeError, ValueError):
        _log_event("cfg_invalid_float", name=name, value=str(raw))
        return default
    if not (lo <= v <= hi):
        _log_event("cfg_out_of_range_float", name=name, value=v, lo=lo, hi=hi)
        v = max(lo, min(hi, v))
    return v

def _cfg_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "1" if default else "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


# ======= AppDir / Config (Windows guard) =======

if os.name != "nt":
    # Silent no-op on non-Windows; just log once and return when called
    def binary_check():
        _log_event("windows_only")
        return "response"
else:
    APP_DIR = Path(os.path.abspath(os.environ.get("APP_DIR", r"C:\ProgramData\Aegis")))
    SIGCHECK_NAME = os.environ.get("SIGCHECK_NAME", "sigcheck64.exe")
    TRUSTED_PATHS_NAME = os.environ.get("TRUSTED_PATHS_FILE", "trusted_paths.txt")

    SIGCHECK_PATH = APP_DIR / SIGCHECK_NAME
    TRUSTED_PATHS_FILE = APP_DIR / TRUSTED_PATHS_NAME

    # Bounded tunables
    ERR_RATE_WINDOW   = _cfg_float("PROC_TRUST_ERR_RATE_WINDOW", 60.0, 5.0, 600.0)
    SIGCHECK_TIMEOUT  = _cfg_float("SIGCHECK_TIMEOUT", 5.0, 1.0, 30.0)
    MAX_WORKERS       = _cfg_int("PROC_TRUST_MAX_WORKERS", min(8, (os.cpu_count() or 2) * 2), 1, 32)

    def _env_default(var: str, fallback: str) -> str:
        v = os.environ.get(var, fallback)
        return v if isinstance(v, str) and v.strip() else fallback

    # ======= Trusted paths loader (from APP_DIR + safe defaults) =======

    def load_trusted_paths(file_path: Path) -> List[str]:
        paths: List[str] = []
        defaults = [
            _env_default("WINDIR", r"C:\Windows"),
            _env_default("PROGRAMFILES", r"C:\Program Files"),
            _env_default("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            _env_default("PROGRAMDATA", r"C:\ProgramData"),
            #os.environ.get("APPDATA"),
            os.environ.get("LOCALAPPDATA"),
        ]
        paths.extend([p for p in defaults if p])

        if file_path.exists():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        p = line.strip()
                        if p and not p.startswith("#"):
                            paths.append(p)
            except Exception as e:
                _log_event("trusted_paths_read_failed", window_s=ERR_RATE_WINDOW, file=str(file_path), err=_sanitize_str(str(e), 160))

        norm: List[str] = []
        for p in paths:
            pl = os.path.normpath(p).lower()
            if not pl.endswith(os.sep):
                pl += os.sep
            norm.append(pl)
        return list(set(norm))

    TRUSTED_PATH_PREFIXES = load_trusted_paths(TRUSTED_PATHS_FILE)

    # Ensure sigcheck path stays inside APP_DIR (exec path hardening)
    def _path_under(parent: Path, child: Path) -> bool:
        try:
            p = parent.resolve(strict=False)
            c = child.resolve(strict=False)
            return p == c.parent or p in c.parents
        except Exception:
            return False

    if not _path_under(APP_DIR, SIGCHECK_PATH):
        _log_event("sigcheck_path_outside_appdir", path=str(SIGCHECK_PATH))

    # ======= Process enumeration =======

    def enumerate_processes() -> Dict[int, Dict]:
        procs: Dict[int, Dict] = {}
        for p in psutil.process_iter(attrs=["pid", "name", "exe", "username"]):
            info = p.info
            procs[int(info["pid"])] = {
                "name": _sanitize_str(info.get("name"), 64) or "<unknown>",
                "exe": _sanitize_str(info.get("exe"), 520),
                "username": _sanitize_str(info.get("username"), 128),
            }
        return procs

    # ======= Sigcheck wrapper (no shell; bounded timeout; sanitized) =======

    def run_sigcheck(path: Optional[str]) -> Dict[str, Optional[str]]:
        res = {
            "verified_raw": "N/A",
            "verified_status": "N/A",
            "publisher": "N/A",
            "error": None,
        }

        if not path:
            res["error"] = "no_executable_path"
            return res

        if not SIGCHECK_PATH.exists():
            res["error"] = f"sigcheck_not_found:{str(SIGCHECK_PATH)}"
            return res

        si = None
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0
        except Exception:
            si = None

        cmd = [
            str(SIGCHECK_PATH),
            "-q",
            "-nobanner",
            "-c",
            "-r",
            str(Path(path)),
        ]

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SIGCHECK_TIMEOUT,
                shell=False,
                startupinfo=si,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except FileNotFoundError:
            res["error"] = "sigcheck_not_invoked"
            return res
        except subprocess.TimeoutExpired:
            res["error"] = "sigcheck_timeout"
            return res
        except Exception as e:
            res["error"] = f"sigcheck_failed:{_sanitize_str(str(e), 160)}"
            return res

        stdout_lines = (completed.stdout or "").splitlines()
        stderr_txt = _sanitize_str((completed.stderr or "").strip(), 200)

        if stderr_txt:
            res["error"] = stderr_txt  # retain hint

        if len(stdout_lines) < 2:
            if not res["error"]:
                res["error"] = "sigcheck_parse_error"
            return res

        try:
            reader = csv.reader(stdout_lines[1:])
            fields = next(reader)
            verified_raw = _sanitize_str(fields[1] if len(fields) > 1 else None, 64) or "N/A"
            publisher    = _sanitize_str(fields[3] if len(fields) > 3 else None, 128) or "N/A"
        except Exception as e:
            res["error"] = f"sigcheck_csv_read_error:{_sanitize_str(str(e), 120)}"
            return res

        res["verified_raw"] = verified_raw
        res["publisher"] = publisher

        vr = verified_raw.lower()
        if vr == "verified":
            res["verified_status"] = "Validly Signed"
        elif vr in ("unverified", "bad signature"):
            res["verified_status"] = "Bad Signature"
        elif vr == "signature not found":
            res["verified_status"] = "Unsigned"
        elif vr == "revoked":
            res["verified_status"] = "Revoked"
        else:
            res["verified_status"] = verified_raw
        return res

    # ======= Classification =======

    def classify_process(siginfo: Dict[str, Optional[str]], exe_path: Optional[str], name: Optional[str]) -> str:
        BENIGN_KERNEL_NAMES = {"System Idle Process", "Registry", "MemCompression", "<unknown>", "System"}
        if (name or "") in BENIGN_KERNEL_NAMES:
            return "trusted"

        status = siginfo.get("verified_status")
        is_validly_signed = (status == "Validly Signed")
        is_signed_but_bad = (status in ("Bad Signature", "Revoked"))

        if is_signed_but_bad:
            return "untrusted"

        is_in_trusted_path = False
        if exe_path:
            path_low = os.path.normpath(exe_path).lower()
            if not path_low.endswith(os.sep):
                path_low += os.sep
            for prefix in TRUSTED_PATH_PREFIXES:
                if path_low.startswith(prefix):
                    is_in_trusted_path = True
                    break

        if is_validly_signed:
            return "trusted"
        if is_in_trusted_path:
            return "trusted"
        if status == "Unsigned" and not is_in_trusted_path:
            return "untrusted"
        return "sus"

    # ======= Inspect one process =======

    def inspect_process(pid: int, info: Dict) -> Dict:
        exe = info.get("exe")
        name = info.get("name")
        username = info.get("username")
        sig = run_sigcheck(exe)
        proc_class = classify_process(sig, exe, name)

        row = {
            "pid": pid,
            "name": name,
            "exe": exe,
            "username": username,
            "verified_raw": sig["verified_raw"],
            "verified_status": sig["verified_status"],
            "publisher": sig["publisher"],
            "error": sig["error"],
            "class": proc_class,
            "is_real_exe": False,
        }
        if exe:
            try:
                row["is_real_exe"] = Path(exe).exists()
            except Exception:
                pass
        return row

    # ======= Main entry (no prints; no exits; logs JSON events) =======

    def binary_check():

        # Pre-flight checks
        if not SIGCHECK_PATH.exists():
            _log_event("sigcheck_missing", path=str(SIGCHECK_PATH))
            return "response"

        if not TRUSTED_PATHS_FILE.exists():
            _log_event("trusted_paths_missing", file=str(TRUSTED_PATHS_FILE))

        # Enumerate
        procs = enumerate_processes()
        #_log_event("scan_start", total=len(procs))

        start = time.monotonic()
        results: List[Dict] = []

        max_workers = MAX_WORKERS
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                fut_to_pid = {pool.submit(inspect_process, pid, info): pid for pid, info in procs.items()}
                for fut in concurrent.futures.as_completed(fut_to_pid):
                    pid = fut_to_pid[fut]
                    try:
                        results.append(fut.result())
                    except Exception as e:
                        _log_event("inspect_process_exception", window_s=ERR_RATE_WINDOW,
                                   pid=pid, err=_sanitize_str(str(e), 160))
                        results.append({
                            "pid": pid, "name": "<error>", "exe": None, "username": None,
                            "verified_raw": None, "verified_status": None, "publisher": None,
                            "error": "exception", "class": "unreadable", "is_real_exe": False
                        })
        except Exception as e:
            _log_event("threadpool_exception", err=_sanitize_str(str(e), 160))
            return "response"

        elapsed = time.monotonic() - start

        # Buckets
        trusted    = [r for r in results if r["class"] == "trusted"]
        sus        = [r for r in results if r["class"] == "sus"]
        untrusted  = [r for r in results if r["class"] == "untrusted"]
        unreadable = [r for r in results if r["class"] == "unreadable"]

        # Per-item logs (lightweight; sanitized)
        for r in untrusted:

            log_data({
                "Purpose": "bintrust",
                "event": "proc_untrusted",
                "pid": r.get("pid"),
                "name": r.get("name"),
                "exe": r.get("exe"),
                "publisher": r.get("publisher"),
                "verified_status": r.get("verified_status"),
                "is_real_exe": r.get("is_real_exe"),
            })
        for r in sus:

            log_data({
                "Purpose": "bintrust",
                "event": "proc_suspicious",
                "pid": r.get("pid"),
                "name": r.get("name"),
                "exe": r.get("exe"),
                "publisher": r.get("publisher"),
                "verified_status": r.get("verified_status"),
                "is_real_exe": r.get("is_real_exe"),
            })
        for r in unreadable:
            _log_event("proc_unreadable", pid=r.get("pid"))

        # Summary
        '''log_data({
            "Purpose": "bintrust",
            "event": "scan_complete",
            "duration_s": round(float(elapsed), 3),
            "counts": {
                "total": len(results),
                "trusted": len(trusted),
                "suspicious": len(sus),
                "untrusted": len(untrusted),
                "unreadable": len(unreadable),
            },
        })'''

        return "response"


