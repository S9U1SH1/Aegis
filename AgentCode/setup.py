# setup_agent_env.py
# Moves the full PyInstaller --onedir folder (default: ./aegis) into:
#   C:\ProgramData\Aegis\aegis\
#
# Optionally moves sigcheck64.exe into:
#   C:\ProgramData\Aegis\sigcheck64.exe
# Creates app files in:
#   C:\ProgramData\Aegis\
# Adds startup entry (HKCU Run):
#   Aegis -> "C:\ProgramData\Aegis\aegis\aegis.exe"

import json
import base64
import secrets
import shutil
from getpass import getpass
import os
import sys
import ctypes
import subprocess
import tempfile

# ---------------- OS guard ----------------
if os.name != "nt":
    print("[setup] Unsupported OS: this setup script is Windows-only.")
    sys.exit(0)

import ctypes.wintypes as wt  # after OS guard
import winreg  # noqa: F401  (kept if you use it elsewhere)

# ---------------- Trusted base for APP_DIR ----------------
SAFE_BASE_DIR = r"C:\ProgramData\Aegis"

def _normalize(p: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(p)))

def _is_unc(p: str) -> bool:
    return p.startswith("\\\\")

def _validate_or_fallback_app_dir(raw_env: str | None) -> str:
    if not raw_env:
        return SAFE_BASE_DIR
    try:
        cand = _normalize(raw_env)
        base = _normalize(SAFE_BASE_DIR)

        if _is_unc(cand):
            print(f"[setup] APP_DIR is UNC and not allowed: {raw_env!r}. Falling back to {SAFE_BASE_DIR}")
            return SAFE_BASE_DIR

        if not os.path.isabs(cand):
            print(f"[setup] APP_DIR is not absolute: {raw_env!r}. Falling back to {SAFE_BASE_DIR}")
            return SAFE_BASE_DIR

        if not (cand == base or cand.startswith(base + os.sep)):
            print(f"[setup] APP_DIR is outside allowed base: {raw_env!r}. Allowed base: {SAFE_BASE_DIR}. Falling back.")
            return SAFE_BASE_DIR

        return cand
    except Exception as e:
        print(f"[setup] APP_DIR validation error ({e}). Falling back to {SAFE_BASE_DIR}")
        return SAFE_BASE_DIR

def _script_dir() -> str:
    """
    If packaged with PyInstaller --onefile, __file__ points to _MEI temp.
    Use sys.executable directory (where the setup EXE lives) to find payloads.
    If running as .py, use the .py file directory.
    """
    try:
        if getattr(sys, "frozen", False):
            return _normalize(os.path.dirname(sys.executable))
        return _normalize(os.path.dirname(os.path.abspath(__file__)))
    except Exception:
        return _normalize(os.getcwd())

APP_DIR = _validate_or_fallback_app_dir(os.environ.get("APP_DIR"))

# ---------------- File paths (created under APP_DIR) ----------------
DATA_LOG_FILE      = os.path.join(APP_DIR, os.environ.get("DATA_LOG_FILE", "data_log.jsonl"))
KEY_FILE           = os.path.join(APP_DIR, os.environ.get("KEY_FILE", "key.bin"))
CRITICAL_REG_FILE  = os.path.join(APP_DIR, "Critical_registries.txt")
LAST_REC_FILE      = os.path.join(APP_DIR, "evtlog_last_record.txt")
CREDS_FILE         = os.path.join(APP_DIR, "creds.txt")
TRUSTED_PATHS_FILE = os.path.join(APP_DIR, os.environ.get("TRUSTED_PATHS_FILE", "trusted_paths.txt"))

# ---------------- Agent folder move ----------------
SRC_AGENT_DIR_NAME = os.environ.get("SRC_AGENT_DIR_NAME", "aegis")
DEST_AGENT_DIR     = os.path.join(APP_DIR, SRC_AGENT_DIR_NAME)
AGENT_EXE_NAME     = os.environ.get("AGENT_EXE", "aegis.exe")
AGENT_EXE          = os.path.join(DEST_AGENT_DIR, AGENT_EXE_NAME)

# ---------------- Optional sigcheck move ----------------
SRC_SIGCHECK_NAME  = os.environ.get("SRC_SIGCHECK_NAME", "sigcheck64.exe")
DEST_SIGCHECK_NAME = os.environ.get("SIGCHECK_NAME", "sigcheck64.exe")
DEST_SIGCHECK_PATH = os.path.join(APP_DIR, DEST_SIGCHECK_NAME)

# ---------------- Windows DPAPI helpers ----------------
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
    CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), wt.LPCWSTR, ctypes.POINTER(DATA_BLOB),
        wt.LPVOID, wt.LPVOID, wt.DWORD, ctypes.POINTER(DATA_BLOB)
    ]
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
    CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), ctypes.POINTER(wt.LPWSTR), ctypes.POINTER(DATA_BLOB),
        wt.LPVOID, wt.LPVOID, wt.DWORD, ctypes.POINTER(DATA_BLOB)
    ]
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

# ---------------- Permissions (chmod-only, best-effort on Windows) ----------------
def _set_private_mode(p: str):
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass

def _write_atomic(p: str, data: bytes):
    tmp = p + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    _set_private_mode(tmp)
    os.replace(tmp, p)
    _set_private_mode(p)

def _ensure_dir(p: str):
    try:
        os.makedirs(p, exist_ok=True)
        print(f"[setup] Ensured directory exists: {p}")
    except Exception as e:
        print(f"[setup] Failed to create directory {p}: {e}")

def _ensure_empty_file(p: str, desc: str):
    if os.path.exists(p):
        print(f"[setup] {desc} already exists: {p}")
        return
    try:
        with open(p, "w", encoding="utf-8"):
            pass
        _set_private_mode(p)
        print(f"[setup] Created {desc}: {p}")
    except Exception as e:
        print(f"[setup] Failed to create {desc} at {p}: {e}")

def _ensure_binary_key(p: str):
    if os.path.exists(p):
        print(f"[setup] Key file already exists: {p}")
        return
    try:
        key = secrets.token_bytes(32)
        wrapped = _dpapi_protect(key, b"jsonlog-key-wrap-v1")
        with open(p, "wb") as f:
            f.write(wrapped)
        _set_private_mode(p)
        print(f"[setup] Created key file: {p}")
    except Exception as e:
        print(f"[setup] Failed to create key file {p}: {e}")

def _unwrap_aes_key(p: str) -> bytes | None:
    try:
        with open(p, "rb") as f:
            wrapped = f.read()
        return _dpapi_unprotect(wrapped, b"jsonlog-key-wrap-v1")
    except Exception as e:
        print(f"[setup] Failed to unwrap AES key: {e}")
        return None

def _aes_available() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        return True
    except Exception:
        return False

def _encrypt_creds_with_aesgcm(aes_key: bytes, payload: dict) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    nonce = secrets.token_bytes(12)
    ct = AESGCM(aes_key).encrypt(nonce, raw, None)
    obj = {"v": 1,
           "n": base64.b64encode(nonce).decode("ascii"),
           "c": base64.b64encode(ct).decode("ascii")}
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")

def _encrypt_creds_with_dpapi(payload: dict) -> bytes:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    dp = _dpapi_protect(raw, b"jsonlog-key-wrap-v1")
    obj = {"v": 0, "d": base64.b64encode(dp).decode("ascii")}
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")

def _ensure_critical_reg_file(p: str):
    if os.path.exists(p):
        print(f"[setup] Critical registry file already exists: {p}")
        return
    registry_content = (
        "HKEY_LOCAL_MACHINE,SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State,UEFISecureBootEnabled\n"
        "HKEY_LOCAL_MACHINE,SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System,EnableLUA\n"
        "HKEY_LOCAL_MACHINE,SYSTEM\\CurrentControlSet\\Control\\Lsa,RunAsPPL\n"
        "HKEY_LOCAL_MACHINE,SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters,SMB1\n"
        "HKEY_LOCAL_MACHINE,SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp,UserAuthentication\n"
    )
    try:
        with open(p, "w", encoding="utf-8") as f:
            f.write(registry_content)
        _set_private_mode(p)
        print(f"[setup] Created critical registry file: {p}")
    except Exception as e:
        print(f"[setup] Failed to create critical registry file {p}: {e}")

def _ensure_checkpoint(p: str):
    if os.path.exists(p):
        print(f"[setup] Checkpoint already exists: {p}")
        return
    try:
        with open(p, "w", encoding="utf-8") as f:
            f.write("0\n")
        _set_private_mode(p)
        print(f"[setup] Created checkpoint (initialized to 0): {p}")
    except Exception as e:
        print(f"[setup] Failed to create checkpoint {p}: {e}")

def _prompt_yes_no(msg: str) -> bool:
    while True:
        ans = input(msg + " [y/n]: ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("Please answer 'y' or 'n'.")

def _collect_creds() -> dict:
    while True:
        username = input("Enter email: ").strip()
        password = input("Enter password: ").strip()
        confirm  = input("Confirm password: ").strip()
        if not username:
            print("Username cannot be empty.")
            continue
        if len(password) < 0:
            print("Password must be at least 8 characters.")
            continue
        if password != confirm:
            print("Passwords do not match.")
            continue
        return {"username": username, "password": password}

def _create_or_update_creds():
    exists = os.path.exists(CREDS_FILE)
    if exists:
        print(f"[setup] Credentials file already exists: {CREDS_FILE}")
        if not _prompt_yes_no("Do you want to change the stored username/password?"):
            print("[setup] Keeping existing credentials.")
            return

    creds = _collect_creds()
    aes_key = _unwrap_aes_key(KEY_FILE)
    use_aes = bool(aes_key) and _aes_available()

    try:
        enc = _encrypt_creds_with_aesgcm(aes_key, creds) if use_aes else _encrypt_creds_with_dpapi(creds)
        _write_atomic(CREDS_FILE, enc)
        print(f"[setup] Encrypted credentials written to: {CREDS_FILE}")
    except Exception as e:
        print(f"[setup] Failed to write encrypted credentials: {e}")

# ---------------- Move sigcheck64.exe (optional) ----------------
def _safe_move_sigcheck():
    base_dir = _script_dir()
    src = _normalize(os.path.join(base_dir, SRC_SIGCHECK_NAME))
    dst = _normalize(DEST_SIGCHECK_PATH)

    if _is_unc(src):
        print(f"[setup] Refusing UNC source for {SRC_SIGCHECK_NAME!r}: {src}")
        return
    if not os.path.isfile(src):
        print(f"[setup] Source file not found: {src}")
        return

    _ensure_dir(APP_DIR)

    if os.path.exists(dst):
        print(f"[setup] Destination already has {DEST_SIGCHECK_NAME}: {dst}")
        if not _prompt_yes_no("Overwrite existing sigcheck64.exe?"):
            print("[setup] Keeping existing sigcheck64.exe.")
            return
        try:
            os.remove(dst)
        except Exception as e:
            print(f"[setup] Failed to remove existing destination file {dst}: {e}")
            return

    try:
        shutil.move(src, dst)
        _set_private_mode(dst)
        print(f"[setup] Moved {SRC_SIGCHECK_NAME} -> {dst}")
    except Exception as e:
        print(f"[setup] Failed to move {SRC_SIGCHECK_NAME} to {dst}: {e}")

# ---------------- Move FULL PyInstaller --onedir folder into APP_DIR ----------------
def _safe_move_agent_folder():
    base_dir = _script_dir()
    src_dir = _normalize(os.path.join(base_dir, SRC_AGENT_DIR_NAME))
    dst_dir = _normalize(DEST_AGENT_DIR)

    if _is_unc(src_dir):
        print(f"[setup] Refusing UNC source folder: {src_dir}")
        return
    if not os.path.isdir(src_dir):
        print(f"[setup] Agent folder not found next to setup: {src_dir}")
        return

    _ensure_dir(APP_DIR)

    if os.path.exists(dst_dir):
        print(f"[setup] Destination agent folder already exists: {dst_dir}")
        if not _prompt_yes_no("Overwrite existing destination agent folder?"):
            print("[setup] Keeping existing agent folder.")
            return
        try:
            shutil.rmtree(dst_dir)
        except Exception as e:
            print(f"[setup] Failed to remove existing destination folder: {e}")
            return

    try:
        shutil.move(src_dir, dst_dir)
        print(f"[setup] Moved folder {src_dir} -> {dst_dir}")
    except Exception as e:
        print(f"[setup] Failed to move folder {src_dir} to {dst_dir}: {e}")
        return

    if os.path.isfile(AGENT_EXE):
        print(f"[setup] Agent EXE is present: {AGENT_EXE}")
    else:
        print(f"[setup] Warning: {AGENT_EXE_NAME} not found at expected location: {AGENT_EXE}")

# ---------------- Main ----------------
def ensure_app_env():
    if os.name != "nt":
        raise RuntimeError("Windows-only function.")

    def is_admin() -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    # Relaunch with UAC if needed
    # IMPORTANT: you cannot elevate in-place; Windows must start a new elevated process.
    # To avoid "CMD on top of CMD", immediately exit the non-admin instance after spawning the elevated one.
    if not is_admin():
        params = " ".join(f'"{a}"' for a in sys.argv)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        raise SystemExit(0)

    _ensure_dir(APP_DIR)
    _ensure_empty_file(DATA_LOG_FILE, "log file")
    _ensure_binary_key(KEY_FILE)
    _ensure_critical_reg_file(CRITICAL_REG_FILE)
    _ensure_checkpoint(LAST_REC_FILE)
    _ensure_empty_file(TRUSTED_PATHS_FILE, "trusted paths file")

    _safe_move_sigcheck()
    _safe_move_agent_folder()

    _create_or_update_creds()

    def create_scheduled_task():
        import os
        import sys
        import ctypes
        import subprocess
        import tempfile
        import ctypes.wintypes as wt

        if os.name != "nt":
            raise RuntimeError("Windows-only function.")

        def is_admin() -> bool:
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False

        # If not admin, re-launch current Python with UAC prompt
        if not is_admin():
            params = " ".join(f'"{a}"' for a in sys.argv)
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
            return False

        def get_current_user_ru() -> str:
            """
            Returns the current interactive user as DOMAIN\\Username (preferred).
            """
            secur32 = ctypes.WinDLL("secur32", use_last_error=True)
            GetUserNameExW = secur32.GetUserNameExW
            GetUserNameExW.argtypes = [wt.ULONG, wt.LPWSTR, ctypes.POINTER(wt.ULONG)]
            GetUserNameExW.restype = wt.BOOL

            NameSamCompatible = 2
            size = wt.ULONG(0)

            # First call to get required size
            GetUserNameExW(NameSamCompatible, None, ctypes.byref(size))
            if size.value:
                buf = ctypes.create_unicode_buffer(size.value)
                if GetUserNameExW(NameSamCompatible, buf, ctypes.byref(size)):
                    val = buf.value.strip()
                    if val:
                        return val

            # Fallback: USERDOMAIN\USERNAME
            user = os.environ.get("USERNAME")
            dom = os.environ.get("USERDOMAIN")
            if user and dom:
                return fr"{dom}\{user}"
            if user:
                return user

            raise RuntimeError("Could not determine current user.")

        ru = get_current_user_ru()

        # S4U => "Run whether user is logged on or not" + "Do not store password"
        task_xml = f"""<?xml version="1.0" encoding="UTF-16"?>
       <Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
         <Triggers>
           <LogonTrigger>
             <Enabled>true</Enabled>
           </LogonTrigger>
         </Triggers>

         <Principals>
           <Principal id="Author">
             <UserId>{ru}</UserId>
             <LogonType>S4U</LogonType>
             <RunLevel>HighestAvailable</RunLevel>
           </Principal>
         </Principals>

         <Settings>
           <!-- Power options OFF -->
           <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
           <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>

           <!-- Idle options OFF -->
           <RunOnlyIfIdle>false</RunOnlyIfIdle>
           <IdleSettings>
             <StopOnIdleEnd>false</StopOnIdleEnd>
             <RestartOnIdle>false</RestartOnIdle>
             <Duration>PT0S</Duration>
             <WaitTimeout>PT0S</WaitTimeout>
           </IdleSettings>

           <AllowStartOnDemand>true</AllowStartOnDemand>
           <StartWhenAvailable>true</StartWhenAvailable>
           <Enabled>true</Enabled>
         </Settings>

         <Actions Context="Author">
           <Exec>
             <Command>C:\\ProgramData\\Aegis\\aegis\\aegis.exe</Command>
           </Exec>
         </Actions>
       </Task>
       """

        with tempfile.NamedTemporaryFile(
                delete=False, suffix=".xml", mode="w", encoding="utf-16"
        ) as f:
            xml_file = f.name
            f.write(task_xml)

        try:
            # No /RU or /RP -> use S4U principal from XML, no password stored
            cmd = ["schtasks", "/Create", "/TN", "Aegis", "/XML", xml_file, "/F"]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                raise RuntimeError(
                    "schtasks failed.\n"
                    f"Exit code: {r.returncode}\n"
                    f"STDOUT:\n{r.stdout}\n"
                    f"STDERR:\n{r.stderr}"
                )
        finally:
            try:
                os.remove(xml_file)
            except Exception:
                pass

        return True

    # Call once
    create_scheduled_task()

    print("[setup] Environment ready.")
    return True

if __name__ == "__main__":
    ok = ensure_app_env()
    if not ok:
        raise SystemExit(0)
    input("Setup complete. Press Enter to exit...")
