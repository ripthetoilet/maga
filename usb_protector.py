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
MAX_AUTO_DECRYPT = 300 * 1024 * 1024
# -----------------------------------------------------------------------------


def ensure_windows():
    if os.name != 'nt' or win32file is None:
        print("This program runs on Windows and requires pywin32.")
        sys.exit(1)


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

    def cleanup_temp(self):
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


# ----------------------------- Utilities ------------------------------------

def _short_hwid_hash(hwid: str) -> str:
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(hwid.encode('utf-8'))
    return h.finalize().hex()[:32]


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

    def start_monitor(self):
        self.running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        print("USB Protector monitor running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping... cleaning up temp views...")
            self.running = False
            for dp in list(self.processors.values()):
                dp.cleanup_temp()
            print("Stopped.")

    def _loop(self):
        while self.running:
            try:
                drives = set(list_removable_drives())
                for d in drives - self.known:
                    print(f"Detected removable drive: {d}")
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
    for i, d in enumerate(drives):
        print(f'  [{i}] {d}')
    sel = input('Choose drive number: ').strip()
    try:
        idx = int(sel)
        return drives[idx]
    except Exception:
        print('Invalid selection')
        return None


def main_menu():
    ensure_windows()
    while True:
        print('\n- main menu -')
        print('1) Initialize & Encrypt (lock forever) - choose USB to encrypt')
        print('2) Permanently Decrypt (restore) - choose USB to restore')
        print('3) View (temporary decrypted view while running)')
        print('4) Exit')
        choice = input('Select: ').strip()
        if choice == '1':
            d = choose_drive_interactive()
            if not d:
                continue
            confirm = input(f"This WILL destructively encrypt drive {d}. Continue? (type 'YES' to proceed): ")
            if confirm != 'YES':
                print('Aborted')
                continue
            dp = DriveProcessor(d)
            ok, msg = dp.initialize_and_encrypt(make_backup=True)
            print('Result:', ok, msg)
        elif choice == '2':
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
            print('Exit')
            break
        else:
            print('Unknown option')


if __name__ == '__main__':
    main_menu()
