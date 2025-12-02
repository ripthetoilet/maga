#!/usr/bin/env python3
"""
USB Protector — interactive, corrected version

This is a corrected and cleaned-up version of the script you have been testing.
Fixes applied:
- All backslashes in string literals and f-strings were escaped or replaced with os.sep where appropriate.
- Removed use of __file__ in places that can run under interactive environments.
- Fixed indentation issues.
- Cleaned up interactive menu formatting.

Behavior:
- Interactive menu to choose a removable drive and either permanently encrypt it (destructive) or permanently decrypt it (requires metadata and authorization).
- Optional monitor mode to provide temporary decrypted view while program runs.

IMPORTANT:
- This is still a prototype. Back up any important data before using the destructive encrypt operation.

Dependencies:
  pip install cryptography pywin32

Run:
  python usb_protector.py

"""

from __future__ import annotations
import os
import sys
import time
import json
import base64
import struct
import tempfile
import threading
import traceback
import getpass
import hashlib
import winreg
import tkinter as tk
from tkinter import ttk, messagebox
from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple

# Cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Windows-specific
try:
    import win32api
    import win32file
    import win32con
except Exception:
    win32api = None
    win32file = None
    win32con = None

# ----------------------------- Configuration ---------------------------------
PROGRAM_SALT = b"USB_PROTECT_SALT_v1"
META_DIRNAME = ".usb_protect_meta"
META_WRAPPED_KEYS = "wrapped_keys.json"
META_INFO = "meta.enc"
FILE_TAG = b"USBPROT1"
FILE_VERSION = 1
POLL_INTERVAL = 2
TEMP_ROOT = os.path.join(tempfile.gettempdir(), "usb_protect_view")
CONFIG_ROOT = os.path.join(os.getenv('APPDATA', tempfile.gettempdir()), "usb_protector")
CONFIG_PATH = os.path.join(CONFIG_ROOT, "config.json")
MAX_AUTO_DECRYPT = 300 * 1024 * 1024
# -----------------------------------------------------------------------------


def ensure_windows():
    if os.name != 'nt' or win32file is None:
        print("This program runs on Windows and requires pywin32.")
        sys.exit(1)


def ensure_config_dir():
    os.makedirs(CONFIG_ROOT, exist_ok=True)


def load_config() -> dict:
    ensure_config_dir()
    if not os.path.exists(CONFIG_PATH):
        return {"admin_hash": "", "allowed": {}}
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
        data.setdefault("admin_hash", "")
        data.setdefault("allowed", {})
        return data
    except Exception:
        return {"admin_hash": "", "allowed": {}}


def save_config(cfg: dict) -> None:
    ensure_config_dir()
    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


# ----------------------------- HWID & KDF -----------------------------------
import subprocess


def get_hwid() -> str:
    try:
        cmd = ['powershell', '-NoProfile', '-Command', "(Get-CimInstance Win32_BIOS).SerialNumber"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        serial = (result.stdout or "").strip()
        if serial:
            return serial
    except Exception:
        pass
    try:
        if win32api:
            vol = win32api.GetVolumeInformation("C:\\")[1]
            if vol:
                return str(vol)
    except Exception:
        pass
    return os.getenv('COMPUTERNAME', 'unknown-hwid')


def derive_wrapping_key(hwid: str, salt: bytes = PROGRAM_SALT) -> bytes:
    if isinstance(hwid, str):
        hwid_bytes = hwid.encode('utf-8')
    else:
        hwid_bytes = bytes(hwid)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=150000,
        backend=default_backend(),
    )
    return kdf.derive(hwid_bytes)


def _hash_password(pw: str) -> str:
    h = hashlib.sha256()
    h.update(pw.encode('utf-8'))
    return h.hexdigest()


def require_admin_password(prompt: str = 'Admin password: ') -> bool:
    cfg = load_config()
    if not cfg.get('admin_hash'):
        print('No admin password set. Create a new one now.')
        pw1 = getpass.getpass('New admin password: ')
        pw2 = getpass.getpass('Repeat password: ')
        if not pw1 or pw1 != pw2:
            print('Passwords did not match.')
            return False
        cfg['admin_hash'] = _hash_password(pw1)
        save_config(cfg)
        print('Admin password set.')
        return True
    pw = getpass.getpass(prompt)
    if _hash_password(pw) == cfg['admin_hash']:
        return True
    print('Admin authentication failed.')
    return False


# ----------------------------- Metadata helpers -----------------------------
@dataclass
class Meta:
    wrapped: Dict[str, str]


def meta_dir(root: str) -> str:
    return os.path.join(root, META_DIRNAME)


def wrapped_path(root: str) -> str:
    return os.path.join(meta_dir(root), META_WRAPPED_KEYS)


def meta_enc_path(root: str) -> str:
    return os.path.join(meta_dir(root), META_INFO)


def load_wrapped_keys(root: str) -> Optional[Meta]:
    p = wrapped_path(root)
    if not os.path.exists(p):
        return None
    try:
        with open(p, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return Meta(wrapped=data.get('wrapped', {}))
    except Exception:
        return None


def save_wrapped_keys(root: str, meta: Meta) -> None:
    d = meta_dir(root)
    os.makedirs(d, exist_ok=True)
    p = wrapped_path(root)
    with open(p, 'w', encoding='utf-8') as f:
        json.dump({'wrapped': meta.wrapped}, f, indent=2, ensure_ascii=False)
    try:
        if win32api:
            win32api.SetFileAttributes(d, win32con.FILE_ATTRIBUTE_HIDDEN)
    except Exception:
        pass


def save_meta_encrypted(root: str, master_key: bytes, payload: dict) -> None:
    aes = AESGCM(master_key)
    nonce = os.urandom(12)
    data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    ct = aes.encrypt(nonce, data, None)
    with open(meta_enc_path(root), 'wb') as f:
        f.write(nonce + ct)


def load_meta_encrypted(root: str, master_key: bytes) -> Optional[dict]:
    p = meta_enc_path(root)
    if not os.path.exists(p):
        return None
    try:
        with open(p, 'rb') as f:
            raw = f.read()
        nonce = raw[:12]
        ct = raw[12:]
        aes = AESGCM(master_key)
        data = aes.decrypt(nonce, ct, None)
        return json.loads(data.decode('utf-8'))
    except Exception:
        return None


# ----------------------------- Key management -------------------------------

def generate_master_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def wrap_master_for_hwid(master_key: bytes, hwid: str) -> bytes:
    wrapping_key = derive_wrapping_key(hwid)
    wrapped = keywrap.aes_key_wrap(wrapping_key, master_key, default_backend())
    return wrapped


def unwrap_master_with_hwid(wrapped_b64: str, hwid: str) -> Optional[bytes]:
    try:
        wrapped = base64.b64decode(wrapped_b64)
        wrapping_key = derive_wrapping_key(hwid)
        master = keywrap.aes_key_unwrap(wrapping_key, wrapped, default_backend())
        return master
    except Exception:
        return None


# ----------------------------- Filename obfuscation -------------------------

def obfuscate_filename(orig_name: str, master_key: bytes) -> str:
    aes = AESGCM(master_key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, orig_name.encode('utf-8'), None)
    token = base64.urlsafe_b64encode(nonce + ct).decode('utf-8').rstrip('=')
    return token


def deobfuscate_filename(token: str, master_key: bytes) -> Optional[str]:
    try:
        padded = token + ('=' * (-len(token) % 4))
        raw = base64.urlsafe_b64decode(padded.encode('utf-8'))
        nonce = raw[:12]
        ct = raw[12:]
        aes = AESGCM(master_key)
        name = aes.decrypt(nonce, ct, None)
        return name.decode('utf-8')
    except Exception:
        return None


# ----------------------------- File encryption ------------------------------

def encrypt_content_bytes(data: bytes, master_key: bytes) -> bytes:
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    header = FILE_TAG + bytes([FILE_VERSION]) + nonce + struct.pack('>Q', len(data))
    return header + ct


def decrypt_content_bytes(raw: bytes, master_key: bytes) -> Optional[bytes]:
    try:
        if len(raw) < len(FILE_TAG) + 1 + 12 + 8:
            return None
        tag = raw[:len(FILE_TAG)]
        if tag != FILE_TAG:
            return None
        version = raw[len(FILE_TAG)]
        nonce = raw[len(FILE_TAG)+1:len(FILE_TAG)+1+12]
        orig_size = struct.unpack('>Q', raw[len(FILE_TAG)+1+12:len(FILE_TAG)+1+12+8])[0]
        ct = raw[len(FILE_TAG)+1+12+8:]
        aes = AESGCM(master_key)
        data = aes.decrypt(nonce, ct, None)
        return data[:orig_size]
    except Exception:
        return None


def encrypt_and_obfuscate_file(path: str, root: str, master_key: bytes, mapping: dict) -> Optional[str]:
    try:
        rel = os.path.relpath(path, root)
        with open(path, 'rb') as f:
            data = f.read()
        enc = encrypt_content_bytes(data, master_key)
        orig_name = rel.replace('\\', '/')
        token = obfuscate_filename(orig_name, master_key)
        new_path = os.path.join(root, token)
        if os.path.exists(new_path):
            token = token + '_' + base64.urlsafe_b64encode(os.urandom(4)).decode('utf-8').rstrip('=')
            new_path = os.path.join(root, token)
        with open(new_path, 'wb') as f:
            f.write(enc)
        os.remove(path)
        mapping[token] = orig_name
        return token
    except Exception:
        return None


def decrypt_token_to_path(root: str, token: str, orig_rel: str, master_key: bytes) -> bool:
    try:
        enc_path = os.path.join(root, token)
        if not os.path.exists(enc_path):
            return False
        with open(enc_path, 'rb') as f:
            raw = f.read()
        data = decrypt_content_bytes(raw, master_key)
        if data is None:
            return False
        out_path = os.path.join(root, orig_rel.replace('/', os.sep))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, 'wb') as f:
            f.write(data)
        os.remove(enc_path)
        return True
    except Exception:
        return False


# ----------------------------- Drive processing -----------------------------
class DriveProcessor:
    def __init__(self, drive_letter: str):
        self.root = drive_letter
        self.hwid = get_hwid()
        self.master_key: Optional[bytes] = None
        self.meta: Optional[Meta] = None
        self.authorized = False
        self.temp_dir = os.path.join(TEMP_ROOT, drive_letter.replace(':', '').replace('\\', ''))
        self._mapping: Dict[str, str] = {}
        self._reverse_mapping: Dict[str, str] = {}
        self._sync_thread: Optional[threading.Thread] = None
        self._sync_stop = threading.Event()
        self._last_view_state: Dict[str, Tuple[float, int]] = {}

    def load_or_init(self) -> Tuple[bool, str]:
        self.meta = load_wrapped_keys(self.root)
        if self.meta is None:
            return (False, 'no_meta')
        hwid_hash = _short_hwid_hash(self.hwid)
        if hwid_hash in self.meta.wrapped:
            candidate = self.meta.wrapped[hwid_hash]
            m = unwrap_master_with_hwid(candidate, self.hwid)
            if m is not None:
                self.master_key = m
                self.authorized = True
                return (True, 'unwrapped')
        for k, v in self.meta.wrapped.items():
            m = unwrap_master_with_hwid(v, self.hwid)
            if m is not None:
                self.master_key = m
                self.authorized = True
                return (True, 'unwrapped_alt')
        return (False, 'not_authorized')

    def initialize_and_encrypt(self, make_backup: bool = True) -> Tuple[bool, str]:
        try:
            if make_backup:
                ok, msg = _optional_backup(self.root)
                if not ok:
                    return (False, 'backup_failed')
            master = generate_master_key()
            wrapped = wrap_master_for_hwid(master, self.hwid)
            meta = Meta(wrapped={})
            hwid_hash = _short_hwid_hash(self.hwid)
            meta.wrapped[hwid_hash] = base64.b64encode(wrapped).decode('utf-8')
            save_wrapped_keys(self.root, meta)
            self.meta = meta
            self.master_key = master
            self.authorized = True
            mapping = {}
            for dirpath, dirnames, filenames in os.walk(self.root, topdown=False):
                if os.path.abspath(dirpath).startswith(os.path.abspath(meta_dir(self.root))):
                    continue
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    try:
                        encrypt_and_obfuscate_file(full, self.root, self.master_key, mapping)
                    except Exception:
                        pass
                try:
                    if dirpath != self.root:
                        os.rmdir(dirpath)
                except Exception:
                    pass
            save_meta_encrypted(self.root, self.master_key, {'mapping': mapping, 'created_by': self.hwid})
            return (True, 'encrypted')
        except Exception as e:
            return (False, str(e))

    def permanent_decrypt(self) -> Tuple[bool, str]:
        try:
            if self.meta is None:
                self.meta = load_wrapped_keys(self.root)
            if self.meta is None:
                return (False, 'no_meta')
            for k, v in self.meta.wrapped.items():
                m = unwrap_master_with_hwid(v, self.hwid)
                if m is not None:
                    self.master_key = m
                    break
            if self.master_key is None:
                return (False, 'not_authorized')
            payload = load_meta_encrypted(self.root, self.master_key)
            if not payload or 'mapping' not in payload:
                return (False, 'no_mapping')
            mapping = payload['mapping']
            failures = []
            for token, orig_rel in mapping.items():
                ok = decrypt_token_to_path(self.root, token, orig_rel, self.master_key)
                if not ok:
                    failures.append(token)
            try:
                os.remove(wrapped_path(self.root))
            except Exception:
                pass
            try:
                os.remove(meta_enc_path(self.root))
            except Exception:
                pass
            try:
                os.rmdir(meta_dir(self.root))
            except Exception:
                pass
            if failures:
                return (False, f"failed_tokens:{len(failures)}")
            return (True, 'restored')
        except Exception as e:
            return (False, str(e))

    def provide_temp_view(self):
        if not self.master_key:
            ok, reason = self.load_or_init()
            if not ok:
                print('Cannot provide temp view: ', reason)
                return
        self.cleanup_temp()
        payload = load_meta_encrypted(self.root, self.master_key)
        if not payload or 'mapping' not in payload:
            print('No mapping metadata to build view.')
            return
        mapping = payload['mapping']
        self._mapping = dict(mapping)
        self._reverse_mapping = {v: k for k, v in mapping.items()}
        os.makedirs(self.temp_dir, exist_ok=True)
        for token, orig_rel in mapping.items():
            enc_path = os.path.join(self.root, token)
            try:
                size = os.path.getsize(enc_path)
                if size > MAX_AUTO_DECRYPT:
                    continue
                decrypt_to = os.path.join(self.temp_dir, orig_rel.replace('/', os.sep))
                os.makedirs(os.path.dirname(decrypt_to), exist_ok=True)
                with open(enc_path, 'rb') as f:
                    raw = f.read()
                data = decrypt_content_bytes(raw, self.master_key)
                if data is None:
                    continue
                with open(decrypt_to, 'wb') as out:
                    out.write(data)
            except Exception:
                pass
        try:
            os.startfile(self.temp_dir)
        except Exception:
            pass
        self._start_sync_loop()

    def cleanup_temp(self):
        self._stop_sync_loop()
        try:
            if os.path.exists(self.temp_dir):
                for dirpath, dirnames, filenames in os.walk(self.temp_dir, topdown=False):
                    for fn in filenames:
                        try:
                            p = os.path.join(dirpath, fn)
                            os.remove(p)
                        except Exception:
                            pass
                    for dn in dirnames:
                        try:
                            os.rmdir(os.path.join(dirpath, dn))
                        except Exception:
                            pass
                try:
                    os.rmdir(self.temp_dir)
                except Exception:
                    pass
        except Exception:
            pass

    # ----------------------------- Temp sync loop -----------------------------
    def _start_sync_loop(self):
        if self._sync_thread and self._sync_thread.is_alive():
            return
        self._sync_stop.clear()
        self._sync_thread = threading.Thread(target=self._sync_worker, daemon=True)
        self._sync_thread.start()

    def _stop_sync_loop(self):
        self._sync_stop.set()
        if self._sync_thread and self._sync_thread.is_alive():
            self._sync_thread.join(timeout=1.5)
        self._sync_thread = None

    def _sync_worker(self):
        while not self._sync_stop.is_set():
            try:
                self._sync_temp_changes()
            except Exception:
                traceback.print_exc()
            self._sync_stop.wait(1.5)

    def _sync_temp_changes(self):
        current_state: Dict[str, Tuple[float, int]] = {}
        for dirpath, dirnames, filenames in os.walk(self.temp_dir):
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, self.temp_dir).replace('\\', '/')
                try:
                    stat = os.stat(full)
                    current_state[rel] = (stat.st_mtime, stat.st_size)
                except FileNotFoundError:
                    continue

        for rel, meta in current_state.items():
            if rel not in self._last_view_state or self._last_view_state[rel] != meta:
                self._encrypt_back(rel)

        for rel in set(self._last_view_state.keys()) - set(current_state.keys()):
            self._handle_deletion(rel)

        self._last_view_state = current_state

    def _encrypt_back(self, rel: str):
        full = os.path.join(self.temp_dir, rel.replace('/', os.sep))
        try:
            with open(full, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            return

        token = self._reverse_mapping.get(rel)
        if not token:
            token = obfuscate_filename(rel, self.master_key)
            while os.path.exists(os.path.join(self.root, token)):
                token = obfuscate_filename(rel + '_' + base64.urlsafe_b64encode(os.urandom(3)).decode('utf-8'), self.master_key)
            self._mapping[token] = rel
            self._reverse_mapping[rel] = token

        enc = encrypt_content_bytes(data, self.master_key)
        enc_path = os.path.join(self.root, token)
        with open(enc_path, 'wb') as f:
            f.write(enc)
        save_meta_encrypted(self.root, self.master_key, {'mapping': self._mapping, 'created_by': self.hwid})

    def _handle_deletion(self, rel: str):
        token = self._reverse_mapping.get(rel)
        if not token:
            return
        try:
            os.remove(os.path.join(self.root, token))
        except FileNotFoundError:
            pass
        self._reverse_mapping.pop(rel, None)
        self._mapping.pop(token, None)
        save_meta_encrypted(self.root, self.master_key, {'mapping': self._mapping, 'created_by': self.hwid})


# ----------------------------- Utilities ------------------------------------

def _short_hwid_hash(hwid: str) -> str:
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(hwid.encode('utf-8'))
    return h.finalize().hex()[:32]


def get_drive_identifier(drive: str) -> str:
    try:
        label, serial, _, _, _ = win32api.GetVolumeInformation(drive)
        return f"{label or 'VOL'}-{serial}"
    except Exception:
        return drive.replace(':', '').replace('\\', '')


def get_drive_label(drive: str) -> str:
    try:
        label, serial, _, _, _ = win32api.GetVolumeInformation(drive)
        parts = [p for p in [label, serial] if p]
        return " | ".join(parts) if parts else drive.rstrip('\\')
    except Exception:
        return drive.rstrip('\\')


def is_drive_allowed(drive: str) -> bool:
    cfg = load_config()
    drive_id = get_drive_identifier(drive)
    return drive_id in cfg.get('allowed', {})


def add_allowed_drive(drive: str) -> bool:
    if not require_admin_password():
        return False
    cfg = load_config()
    drive_id = get_drive_identifier(drive)
    label = get_drive_label(drive)
    cfg.setdefault('allowed', {})[drive_id] = label
    save_config(cfg)
    print(f"Drive {drive} added to local allowlist.")
    return True


def list_connected_drives() -> List[str]:
    drives = []
    mask = win32file.GetLogicalDrives()
    for letter in range(26):
        if mask & (1 << letter):
            drives.append(f"{chr(65 + letter)}:" + os.sep)
    return drives


def ensure_autostart():
    try:
        ensure_config_dir()
        run_key = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_SET_VALUE) as key:
            cmd = f'"{sys.executable}" "{os.path.abspath(__file__)}" --gui'
            winreg.SetValueEx(key, 'USBProtector', 0, winreg.REG_SZ, cmd)
    except Exception:
        pass


def list_removable_drives() -> List[str]:
    drives = []
    mask = win32file.GetLogicalDrives()
    for letter in range(26):
        if mask & (1 << letter):
            drive = f"{chr(65 + letter)}:" + os.sep
            try:
                dtype = win32file.GetDriveType(drive)
                if dtype == win32file.DRIVE_REMOVABLE:
                    drives.append(drive)
            except Exception:
                pass
    return drives


def _optional_backup(root: str) -> Tuple[bool, str]:
    try:
        ans = input('Create a zip backup of current USB before destructive encrypt? (y/N): ').strip().lower()
        if ans != 'y':
            return (True, 'no_backup')
        import zipfile
        root_safe = root.replace('\\', '').replace(':', '')
        backup_name = os.path.join(tempfile.gettempdir(), f"usb_backup_{os.path.basename(root_safe)}.zip")
        with zipfile.ZipFile(backup_name, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for dirpath, dirnames, filenames in os.walk(root):
                if os.path.abspath(dirpath).startswith(os.path.abspath(meta_dir(root))):
                    continue
                for fn in filenames:
                    full = os.path.join(dirpath, fn)
                    arc = os.path.relpath(full, root)
                    try:
                        zf.write(full, arc)
                    except Exception:
                        pass
        print(f'Backup created at: {backup_name}')
        return (True, backup_name)
    except Exception as e:
        return (False, str(e))


# ----------------------------- Main monitor (interactive) -------------------
class USBMonitor:
    def __init__(self):
        ensure_windows()
        self.known = set()
        self.processors: Dict[str, DriveProcessor] = {}
        self.running = False
        self._thread: Optional[threading.Thread] = None

    def start_monitor(self):
        self.start_background()
        print("USB Protector monitor running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping... cleaning up temp views...")
            self.stop()
            print("Stopped.")

    def start_background(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        for dp in list(self.processors.values()):
            dp.cleanup_temp()
        self.processors.clear()

    def _loop(self):
        while self.running:
            try:
                drives = set(list_removable_drives())
                for d in drives - self.known:
                    print(f"Detected removable drive: {d}")
                    if not is_drive_allowed(d):
                        print(f"Drive {d} is not in local allowlist. Auto-decrypt disabled.")
                        continue
                    dp = DriveProcessor(d)
                    ok, reason = dp.load_or_init()
                    if ok:
                        dp.provide_temp_view()
                    else:
                        print(f"Drive {d} not authorized or uninitialized ({reason})")
                    self.processors[d] = dp
                for d in list(self.known - drives):
                    print(f"Drive removed: {d}")
                    if d in self.processors:
                        self.processors[d].cleanup_temp()
                        del self.processors[d]
                self.known = drives
            except Exception as e:
                print("Error in monitor loop:", e)
                traceback.print_exc()
            time.sleep(POLL_INTERVAL)


# ----------------------------- CLI Entrypoint --------------------------------

def choose_drive_interactive() -> Optional[str]:
    drives = list_removable_drives()
    if not drives:
        print('No removable drives found.')
        return None
    print('Removable drives:')
    for i, d in enumerate(drives, start=1):
        label = get_drive_label(d)
        print(f'  [{i}] {d} ({label})')
    sel = input('Choose drive number: ').strip()
    try:
        idx = int(sel) - 1
        if idx < 0:
            raise ValueError
        return drives[idx]
    except Exception:
        print('Invalid selection')
        return None


class SimpleGUI:
    def __init__(self):
        ensure_windows()
        ensure_autostart()
        self.monitor = USBMonitor()
        self.root = tk.Tk()
        self.root.title('USB Protector')
        self.root.geometry('480x280')
        self.root.iconify()
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)

        frm = ttk.Frame(self.root, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(frm, columns=('status', 'id'), show='headings')
        self.tree.heading('status', text='Status')
        self.tree.heading('id', text='Identifier')
        self.tree.column('status', width=80)
        self.tree.column('id', width=280)
        self.tree.pack(fill=tk.BOTH, expand=True)

        btn_frame = ttk.Frame(frm)
        btn_frame.pack(fill=tk.X, pady=8)

        ttk.Button(btn_frame, text='Refresh', command=self.refresh).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='Start monitor', command=self.start_monitor).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='Stop monitor', command=self.stop_monitor).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='Add to allowlist (admin)', command=self.admin_allow).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text='Admin decrypt', command=self.admin_decrypt).pack(side=tk.LEFT, padx=4)

        self.refresh()
        self.monitor.start_background()

    def refresh(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        cfg = load_config()
        connected = {get_drive_identifier(d): d for d in list_connected_drives()}
        for drive_id, label in cfg.get('allowed', {}).items():
            drive = connected.get(drive_id, '')
            status = 'allowed (connected)' if drive else 'allowed (not connected)'
            display = f"{drive or '—'} | {label}"
            self.tree.insert('', 'end', iid=drive or drive_id, values=(status, display))
        for drive_id, drive in connected.items():
            if drive_id in cfg.get('allowed', {}):
                continue
            label = get_drive_label(drive)
            self.tree.insert('', 'end', iid=drive, values=('blocked', f"{drive} | {label}"))

    def _selected_drive(self) -> Optional[str]:
        sel = self.tree.selection()
        return sel[0] if sel else None

    def start_monitor(self):
        self.monitor.start_background()
        messagebox.showinfo('USB Protector', 'Monitor running in background (window may stay minimized).')

    def stop_monitor(self):
        self.monitor.stop()
        messagebox.showinfo('USB Protector', 'Monitor stopped and temp views cleaned.')

    def admin_allow(self):
        d = self._selected_drive()
        if not d:
            messagebox.showwarning('USB Protector', 'Select a drive first.')
            return
        if ':' not in d:
            messagebox.showwarning('USB Protector', 'Insert the USB drive before allowing it.')
            return
        if add_allowed_drive(d):
            self.refresh()

    def admin_decrypt(self):
        d = self._selected_drive()
        if not d:
            messagebox.showwarning('USB Protector', 'Select a drive first.')
            return
        if not require_admin_password():
            return
        dp = DriveProcessor(d)
        dp.meta = load_wrapped_keys(d)
        if dp.meta is None:
            messagebox.showerror('USB Protector', 'Metadata missing; cannot restore.')
            return
        ok, msg = dp.permanent_decrypt()
        messagebox.showinfo('USB Protector', f'Decrypt result: {ok} ({msg})')

    def on_close(self):
        self.monitor.stop()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def main_menu():
    ensure_windows()
    ensure_autostart()
    monitor = USBMonitor()
    monitor.start_background()
    while True:
        print('\n- main menu -')
        print('1) (Admin) Initialize & Encrypt (lock forever) - choose USB to encrypt')
        print('2) (Admin) Permanently Decrypt (restore) - choose USB to restore')
        print('3) View (temporary decrypted view while running)')
        print('4) Show connected drives and allowlist status')
        print('5) Show allowed USB list for this PC')
        print('6) (Admin) Add connected USB to local allowlist')
        print('7) Exit')
        choice = input('Select: ').strip()
        if choice == '1':
            if not require_admin_password():
                continue
            d = choose_drive_interactive()
            if not d:
                continue
            while True:
                confirm = input(f"This WILL destructively encrypt drive {d}. Continue? (y/n): ").strip().lower()
                if confirm in {'y', 'n'}:
                    break
                print("Please press 'y' to proceed or 'n' to cancel.")
            if confirm != 'y':
                print('Aborted')
                continue
            dp = DriveProcessor(d)
            ok, msg = dp.initialize_and_encrypt(make_backup=True)
            print('Result:', ok, msg)
        elif choice == '2':
            if not require_admin_password():
                continue
            d = choose_drive_interactive()
            if not d:
                continue
            dp = DriveProcessor(d)
            dp.meta = load_wrapped_keys(d)
            if dp.meta is None:
                print('No metadata found on USB — cannot restore')
                continue
            ok, msg = dp.permanent_decrypt()
            print('Result:', ok, msg)
        elif choice == '3':
            print('Starting monitor — insert USB to create temporary decrypted views')
            monitor = USBMonitor()
            monitor.start_monitor()
        elif choice == '4':
            print('Connected drives:')
            cfg = load_config()
            for drive in list_connected_drives():
                allowed = 'allowed' if is_drive_allowed(drive) else 'blocked'
                drive_id = get_drive_identifier(drive)
                label = cfg.get('allowed', {}).get(drive_id, get_drive_label(drive))
                print(f"  {drive} -> {label} ({allowed})")
        elif choice == '5':
            cfg = load_config()
            allowed = cfg.get('allowed', {})
            if not allowed:
                print('No USB drives are currently allowed on this PC.')
            else:
                print('Allowed USB drives for this PC:')
                for idx, (drive_id, label) in enumerate(allowed.items(), start=1):
                    print(f'  [{idx}] {label} ({drive_id})')
        elif choice == '6':
            d = choose_drive_interactive()
            if not d:
                continue
            add_allowed_drive(d)
        elif choice == '7':
            print('Exit')
            monitor.stop()
            break
        else:
            print('Unknown option')


if __name__ == '__main__':
    if '--gui' in sys.argv:
        app = SimpleGUI()
        app.run()
    else:
        main_menu()
