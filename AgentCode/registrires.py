import os
import ctypes
import threading
import unicodedata
import re
import time
from datetime import datetime, timezone
import winreg
from log import log_data

log_lock = threading.Lock()

# ----------------- File location -----------------
APP_DIR = os.environ.get("APP_DIR", r"C:\ProgramData\Aegis")
try:
    os.makedirs(APP_DIR, exist_ok=True)
except Exception:
    with log_lock:
        log_data({"event": "cfg_app_dir_create_failed", "dir": APP_DIR, "Purpose": "registry"})

CRITICAL_REG_FILE = os.path.join(APP_DIR, "Critical_registries.txt")

# ---- Sanitization: control chars + Unicode normalization (NFKC) ----
_CONTROL_CHARS = re.compile(r'[\x00-\x1F\x7F]')

def _sanitize_str(value, max_len=256):
    # Only treat actual None as missing, not 0
    if value is None:
        return None

    s = unicodedata.normalize("NFKC", str(value))
    s = _CONTROL_CHARS.sub('', s).strip()

    # Now treat empty string as missing
    if not s:
        return None

    if len(s) > max_len:
        s = s[:max_len]
    return s

# ----------------- Rate-limited logging -----------------
_last_err = {}  # event_key -> last log time (monotonic)

def _rate_limited(key: str, window_s: float = 60.0) -> bool:
    now = time.monotonic()
    last = _last_err.get(key, 0.0)
    if now - last >= window_s:
        _last_err[key] = now
        return False   # NOT limited -> allow
    return True        # within window -> suppress

def _log_event(event: str, purpose: str = "registry", window_s: float = 60.0, **extra):
    if not _rate_limited(event, window_s):
        payload = {"event": event, "Purpose": purpose}
        if extra:
            payload.update(extra)
        with log_lock:
            log_data(payload)



# ----------------- Error taxonomy -----------------
def _classify_reg_error(exc: Exception) -> str:
    if isinstance(exc, KeyError):
        return "reg_invalid_hive"
    if isinstance(exc, FileNotFoundError):
        return "reg_key_or_value_not_found"
    if isinstance(exc, PermissionError):
        return "reg_permission_denied"
    if isinstance(exc, OSError):
        return "reg_os_error"
    return "reg_generic_failure"

# ----------------- Helpers -----------------
def _cfg_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        val = int(raw)
    except (TypeError, ValueError):
        _log_event("cfg_invalid_int", name=name, value=str(raw))
        return default
    if not (lo <= val <= hi):
        _log_event("cfg_out_of_range_int", name=name, value=val, lo=lo, hi=hi)
        val = max(lo, min(hi, val))
    return val

def _open_key_try_views(registry, path: str):
    """
    Try to open a key in preferred view first, then the alternate view.
    Preference controlled by REG_VIEW env ("64" default).
    """
    prefer_64 = os.environ.get("REG_VIEW", "64").strip() == "64"
    views = []
    if prefer_64:
        views = [winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY]
    else:
        views = [winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY]

    last_exc = None
    for v in views:
        try:
            return winreg.OpenKey(registry, path, 0, winreg.KEY_READ | v)
        except FileNotFoundError as e:
            last_exc = e
            continue
    # If both views failed with FileNotFoundError, re-raise as FileNotFoundError
    if last_exc:
        raise last_exc

# ----------------- Single registry read -----------------
def read_registry_key(hive, path, key_name):
    hive_map = {
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
        "HKEY_USERS": winreg.HKEY_USERS,
        "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
    }
    root = hive_map[hive]  # may raise KeyError
    registry = winreg.ConnectRegistry(None, root)
    key = _open_key_try_views(registry, path)  # may raise FileNotFoundError/PermissionError
    value, _ = winreg.QueryValueEx(key, key_name)  # may raise FileNotFoundError
    skey = _sanitize_str(key_name, 128)
    sval = _sanitize_str(value, 512)
    return f"{skey}: {sval}"

# ----------------- Main -----------------
def read_registries():
    if os.name != "nt":
        return "response"



    # Ensure APP_DIR is writable (light robustness)
    try:
        test_path = os.path.join(APP_DIR, ".rwtest.tmp")
        with open(test_path, "wb") as _f:
            _f.write(b".")
        os.remove(test_path)
    except Exception:
        _log_event("cfg_app_dir_not_writable", dir=APP_DIR)

    MAX_REG_LINES = _cfg_int("MAX_REG_LINES", 200, 1, 5000)

    registry_list = {}
    stats = {"lines_total": 0, "lines_used": 0, "not_found": 0, "errors": 0}
    missing_keys = []  # collect missing keys for one summary event

    # Read registry list file (safe decode)
    try:
        with open(CRITICAL_REG_FILE, "rb") as fb:
            raw = fb.read()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                _log_event("reg_file_decode_error", file=CRITICAL_REG_FILE)
                return "response"
    except FileNotFoundError:
        # Silently skip if the file isn't present (agent may create/copy it later)
        return "response"
    except PermissionError:
        _log_event("reg_file_permission_denied", file=CRITICAL_REG_FILE)
        return "response"
    except OSError:
        _log_event("reg_file_os_error", file=CRITICAL_REG_FILE)
        return "response"

    # Process lines
    for raw_line in text.splitlines():
        stats["lines_total"] += 1
        if stats["lines_used"] >= MAX_REG_LINES:
            _log_event("reg_file_max_lines_reached", max_lines=MAX_REG_LINES)
            break

        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        try:
            hive, path, key_name = [part.strip() for part in line.split(",", 2)]
        except ValueError:
            stats["errors"] += 1
            _log_event("reg_invalid_line")
            continue

        # Sanitize untrusted inputs
        hive_s     = _sanitize_str(hive, 64)
        path_s     = _sanitize_str(path, 512)
        key_name_s = _sanitize_str(key_name, 128)

        if not hive_s or not path_s or not key_name_s:
            stats["errors"] += 1
            _log_event("reg_line_sanitized_empty")
            continue

        composite_key = f"{hive_s}\\{path_s}:{key_name_s}"

        try:
            pair = read_registry_key(hive_s, path_s, key_name_s)
            kname, val = pair.split(":", 1)
            registry_list[composite_key] = (val or "").strip()
            stats["lines_used"] += 1
        except FileNotFoundError:
            # Key or value not present in *either* view -> mark once, no per-key event.
            stats["not_found"] += 1
            registry_list[composite_key] = "NOT_FOUND"
            missing_keys.append(composite_key)
        except (KeyError, PermissionError, OSError) as e:
            stats["not_found"] += 1
            registry_list[composite_key] = "NOT_FOUND"
            # Do not spam per-key error; if it's a permission issue, still emit a single classified event
            if isinstance(e, PermissionError):
                _log_event(_classify_reg_error(e))
        except Exception:
            stats["errors"] += 1
            registry_list[composite_key] = "ERROR"
            _log_event("reg_unhandled")

    # One **summary** event for all missing in this run (optional preview subset)

    # Attach purpose, stats, and timestamp
    registry_list["Purpose"]   = "registry"
    registry_list["Stats"]     = stats
    registry_list["Datetime"]  = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    with log_lock:
        log_data(registry_list)


    return "response"

