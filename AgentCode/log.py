# log_secure.py
import os
import json
import base64
import logging
import threading
import requests
import socket
from datetime import datetime, timezone

# ---------- Config ----------
APP_DIR = os.path.abspath(os.environ.get("APP_DIR", r"C:\ProgramData\Aegis"))
os.makedirs(APP_DIR, exist_ok=True)

DATA_LOG_FILE = os.path.join(APP_DIR, os.environ.get("DATA_LOG_FILE", "data_log.jsonl"))
KEY_FILE      = os.path.join(APP_DIR, os.environ.get("KEY_FILE", "key.bin"))   # DPAPI-wrapped AES key
CREDS_FILE    = os.path.join(APP_DIR, "creds.txt")                             # Encrypted JSON blob
SUBMIT_URL    = os.environ.get("SUBMIT_URL", "https://aegis-security-solutions.com/submit")

# ----- Config validation (timeouts / sizes) -----
def _cfg_float(name: str, default: float, lo: float, hi: float) -> float:
    raw = os.environ.get(name, str(default))
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, val))

def _cfg_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, val))

# Submit timeout (seconds) and maximum on-disk log size (bytes)
SUBMIT_TIMEOUT = _cfg_float("SUBMIT_TIMEOUT", 5.0, 1.0, 60.0)
# 10 MiB default; clamp to 1 MiB .. 1 GiB
MAX_LOG_BYTES  = _cfg_int("MAX_LOG_BYTES", 100 * 1024 * 1024, 1 * 1024 * 1024, 1024 * 1024 * 1024)

# ---------- Thread safety ----------
log_lock = threading.Lock()

# ---------- Optional AES-GCM (AEAD) via cryptography ----------
_AES_AVAILABLE = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _AES_AVAILABLE = True
except Exception:
    _AES_AVAILABLE = False

# ---------- Windows DPAPI helpers (for key wrapping & fallback encryption) ----------
import ctypes
import ctypes.wintypes as wt

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

def _bytes_to_blob(b: bytes) -> DATA_BLOB:
    buf = (ctypes.c_byte * len(b))(*b)
    return DATA_BLOB(len(b), buf)

def _blob_to_bytes(blob: DATA_BLOB) -> bytes:
    size = int(blob.cbData)
    ptr = ctypes.cast(blob.pbData, ctypes.POINTER(ctypes.c_ubyte))
    return bytes(bytearray(ptr[i] for i in range(size)))

def _dpapi_protect(data: bytes, entropy: bytes = b"") -> bytes:
    CryptProtectData = ctypes.windll.crypt32.CryptProtectData
    CryptProtectData.argtypes = [ctypes.POINTER(DATA_BLOB), wt.LPCWSTR, ctypes.POINTER(DATA_BLOB),
                                 wt.LPVOID, wt.LPVOID, wt.DWORD, ctypes.POINTER(DATA_BLOB)]
    CryptProtectData.restype = wt.BOOL

    in_blob = _bytes_to_blob(data)
    ent_blob = _bytes_to_blob(entropy) if entropy else None
    out_blob = DATA_BLOB()

    if not CryptProtectData(ctypes.byref(in_blob), None, ctypes.byref(ent_blob) if ent_blob else None,
                            None, None, 0, ctypes.byref(out_blob)):
        raise OSError("DPAPI protect failed")
    try:
        return _blob_to_bytes(out_blob)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)

def _dpapi_unprotect(data: bytes, entropy: bytes = b"") -> bytes:
    CryptUnprotectData = ctypes.windll.crypt32.CryptUnprotectData
    CryptUnprotectData.argtypes = [ctypes.POINTER(DATA_BLOB), ctypes.POINTER(wt.LPWSTR), ctypes.POINTER(DATA_BLOB),
                                   wt.LPVOID, wt.LPVOID, wt.DWORD, ctypes.POINTER(DATA_BLOB)]
    CryptUnprotectData.restype = wt.BOOL

    in_blob = _bytes_to_blob(data)
    ent_blob = _bytes_to_blob(entropy) if entropy else None
    out_blob = DATA_BLOB()
    if not CryptUnprotectData(ctypes.byref(in_blob), None, ctypes.byref(ent_blob) if ent_blob else None,
                              None, None, 0, ctypes.byref(out_blob)):
        raise OSError("DPAPI unprotect failed")
    try:
        return _blob_to_bytes(out_blob)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)

# ---------- Key management (persisted across restarts) ----------
_ENTROPY = b"jsonlog-key-wrap-v1"  # static associated data for DPAPI wrapping

def _set_private_mode(path: str):
    """Best-effort restrictive permissions. On Windows, real ACLs should be set by installer."""
    try:
        os.chmod(path, 0o600)  # POSIX-y hint; harmless on Windows
    except Exception:
        pass

def _ensure_file_exists_with_mode(path: str):
    if not os.path.exists(path):
        with open(path, "a", encoding="utf-8"):
            pass
        _set_private_mode(path)

def _load_or_create_key() -> bytes:
    """
    Returns a 32-byte AES key. If cryptography is unavailable, we still return a key
    (used only to tag records) but encryption will fall back to DPAPI-per-line.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            wrapped = f.read()
        return _dpapi_unprotect(wrapped, _ENTROPY)

    import secrets
    key = secrets.token_bytes(32)
    wrapped = _dpapi_protect(key, _ENTROPY)

    with open(KEY_FILE, "wb") as f:
        f.write(wrapped)
    _set_private_mode(KEY_FILE)
    return key

_AES_KEY = _load_or_create_key()

# ---------- Encryption / Decryption of a single record ----------
import secrets

def _enc_record(payload: dict) -> str:
    """
    Returns a compact line (JSON) for storage:
      AES available: {"v":1,"n":"b64","c":"b64"}  where AESGCM(key, nonce, plaintext) -> ciphertext+tag
      Fallback     : {"v":0,"d":"b64"}            DPAPI-protected bytes
    """
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    if _AES_AVAILABLE:
        aes = AESGCM(_AES_KEY)
        nonce = secrets.token_bytes(12)  # 96-bit nonce
        ct = aes.encrypt(nonce, raw, None)  # associated_data=None
        line = {"v": 1,
                "n": base64.b64encode(nonce).decode("ascii"),
                "c": base64.b64encode(ct).decode("ascii")}
        return json.dumps(line, separators=(",", ":"))
    else:
        dp = _dpapi_protect(raw, _ENTROPY)  # includes integrity
        line = {"v": 0, "d": base64.b64encode(dp).decode("ascii")}
        return json.dumps(line, separators=(",", ":"))

def _dec_record(line: str) -> dict:
    """
    Parses and decrypts a stored line, verifying integrity.
    Raises on tamper/parse errors.
    """
    obj = json.loads(line)
    v = obj.get("v")
    if v == 1 and _AES_AVAILABLE:
        nonce = base64.b64decode(obj["n"])
        ct = base64.b64decode(obj["c"])
        aes = AESGCM(_AES_KEY)
        raw = aes.decrypt(nonce, ct, None)  # integrity verified by GCM tag
        return json.loads(raw.decode("utf-8"))
    elif v == 0:
        dp = base64.b64decode(obj["d"])
        raw = _dpapi_unprotect(dp, _ENTROPY)  # integrity verified by DPAPI
        return json.loads(raw.decode("utf-8"))
    else:
        raise ValueError("Unsupported record version")

# ---------- Simple compaction when file exceeds MAX_LOG_BYTES ----------
def _compact_log_file_if_needed():
    try:
        if os.path.exists(DATA_LOG_FILE) and os.path.getsize(DATA_LOG_FILE) > MAX_LOG_BYTES:
            with open(DATA_LOG_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            if not lines:
                return
            keep = lines[len(lines) // 2 :]  # newest half
            with open(DATA_LOG_FILE, "w", encoding="utf-8") as f:
                f.writelines(keep)
            _set_private_mode(DATA_LOG_FILE)
    except Exception:
        pass

# Ensure the log file exists (so we can set permissions once)
_ensure_file_exists_with_mode(DATA_LOG_FILE)

# ---------- Device identity (added to every record) ----------
_device_cache = {}
def _device_identity():
    """Resolve once per process; robust fallbacks."""
    if _device_cache:
        return _device_cache
    try:
        name = socket.gethostname() or "unknown"
    except Exception:
        name = "unknown"
    ip = "127.0.0.1"
    try:
        # UDP connect trick (no traffic sent) to get primary outbound IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0] or ip
        finally:
            s.close()
    except Exception:
        pass
    _device_cache.update({"DeviceName": name, "DeviceIP": ip})
    return _device_cache

# ---------- Credentials loading/decryption (from CREDS_FILE) ----------
_creds_cache = None
_creds_mtime = None

def _dec_blob_obj(obj: dict) -> dict:
    """
    Decrypts an encrypted JSON object produced by setup (v=1 AES-GCM; v=0 DPAPI).
    Returns the decrypted dict (e.g., {"username": "...", "password": "..."}).
    """
    v = obj.get("v")
    if v == 1 and _AES_AVAILABLE:
        nonce = base64.b64decode(obj["n"])
        ct = base64.b64decode(obj["c"])
        raw = AESGCM(_AES_KEY).encrypt(b"\x00"*12, b"", None)  # dummy to load class (no effect)
        raw = AESGCM(_AES_KEY).decrypt(nonce, ct, None)
        return json.loads(raw.decode("utf-8"))
    elif v == 0:
        dp = base64.b64decode(obj["d"])
        raw = _dpapi_unprotect(dp, _ENTROPY)
        return json.loads(raw.decode("utf-8"))
    else:
        raise ValueError("Unsupported creds format")

def _load_creds() -> dict | None:
    """
    Loads and decrypts creds from CREDS_FILE once, caches result.
    Reloads only if mtime changes. Returns {"username": str, "password": str} or None.
    """
    global _creds_cache, _creds_mtime
    try:
        st = os.stat(CREDS_FILE)
    except FileNotFoundError:
        return None
    except Exception:
        return None

    mtime = st.st_mtime
    if _creds_cache is not None and _creds_mtime == mtime:
        return _creds_cache

    try:
        with open(CREDS_FILE, "r", encoding="utf-8") as f:
            enc_text = f.read().strip()
        obj = json.loads(enc_text)  # outer envelope produced by setup
        creds = _dec_blob_obj(obj)
        # sanity
        u = creds.get("username")
        p = creds.get("password")
        if not isinstance(u, str) or not isinstance(p, str):
            return None
        _creds_cache = {"username": u, "password": p}
        _creds_mtime = mtime
        return _creds_cache
    except Exception:
        # Do not log secrets or paths here; fail closed without creds
        return None

# ---------- Logging handler that encrypts each JSON message ----------
class EncryptedJsonFileHandler(logging.FileHandler):
    """
    Expects the log message to be a JSON string.
    Encrypts and appends one encrypted line per record to DATA_LOG_FILE.
    """
    def emit(self, record):
        try:
            msg = self.format(record)
            payload = json.loads(msg)  # must be JSON already
        except Exception:
            return

        _compact_log_file_if_needed()

        line = _enc_record(payload)
        self.stream.write(line + "\n")
        self.flush()

# ---------- Logger setup ----------
logger = logging.getLogger("json_logger")
logger.setLevel(logging.INFO)

handler = EncryptedJsonFileHandler(DATA_LOG_FILE, mode="a", encoding="utf-8")
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.handlers.clear()
logger.addHandler(handler)

# ---------- Public API ----------
def log_data(data: dict):
    """
    Accepts a dict; adds DeviceName, DeviceIP, and decrypted username/password to each record.
    Encryption + integrity happens in the handler.
    """
    dev = _device_identity()
    creds = _load_creds()  # None if missing/unreadable

    enriched = dict(data)
    enriched["DeviceName"] = dev.get("DeviceName", "unknown")
    enriched["DeviceIP"]   = dev.get("DeviceIP", "127.0.0.1")
    enriched["Datetime"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Inject creds only if available and well-formed
    if creds:
        # Field names per your request
        enriched["username"] = creds.get("username")
        enriched["password"] = creds.get("password")

    logger.info(json.dumps(enriched, separators=(",", ":"), ensure_ascii=False))

def read_and_remove_first_log():
    """
    Decrypts the first record, verifies integrity, POSTs it to SUBMIT_URL,
    and removes it from the file **only** if POST succeeded (200).
    On tamper/decrypt/parse errors, the record is skipped and removed to avoid deadlocks.
    """
    with log_lock:
        try:
            with open(DATA_LOG_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except FileNotFoundError:
            return None
        except PermissionError:
            log_data({"event": "log_file_perm_denied"})
            return None
        except OSError:
            log_data({"event": "log_file_os_error"})
            return None

        if not lines:
            return None

        first_line = lines[0].rstrip("\n")

        try:
            data = _dec_record(first_line)
        except Exception:
            try:
                with open(DATA_LOG_FILE, "w", encoding="utf-8") as f:
                    f.writelines(lines[1:])
            except Exception:
                pass
            log_data({"event": "log_record_invalid_dropped"})
            return None

    try:
        resp = requests.post(SUBMIT_URL, json=data, timeout=SUBMIT_TIMEOUT)
        ok = (resp.status_code == 200)


    except Exception as e:
        ok = False

    if ok:
        with log_lock:
            try:
                with open(DATA_LOG_FILE, "w", encoding="utf-8") as f:
                    f.writelines(lines[1:])
            except (PermissionError, OSError):
                log_data({"event": "log_truncate_failed"})
    return data if ok else None




