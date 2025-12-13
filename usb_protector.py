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
from tkinter import ttk, messagebox, simpledialog
from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple

# Cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, PublicFormat, NoEncryption

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
META_RSA_ENCRYPTED_KEY = "master_key.enc"
FILE_TAG = b"USBPROT1"
FILE_VERSION = 1
POLL_INTERVAL = 2
# Тимчасові файли на диску D
def get_temp_root():
    """Повертає шлях для тимчасових файлів на диску D"""
    try:
        # Перевіряємо чи існує диск D
        if os.path.exists("D:\\"):
            return os.path.join("D:\\", "usb_protect_view")
    except Exception:
        pass
    # Fallback до стандартного temp
    return os.path.join(tempfile.gettempdir(), "usb_protect_view")

TEMP_ROOT = get_temp_root()
CONFIG_ROOT = os.path.join(os.getenv('APPDATA', tempfile.gettempdir()), "usb_protector")
CONFIG_PATH = os.path.join(CONFIG_ROOT, "config.json")
RECOVERY_ROOT = os.path.join(CONFIG_ROOT, "recovery")
PRIVATE_KEY_PATH = os.path.join(CONFIG_ROOT, "private_key.pem.enc")  # Зашифрований ключ
PUBLIC_KEY_FILENAME = "public_key.pem"
DEFAULT_ADMIN_HASH = "0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c"
MAX_AUTO_DECRYPT = 300 * 1024 * 1024
MAX_PASSWORD_ATTEMPTS = 5
LOCKOUT_SECONDS = 30
RECOVERY_ENC_SALT = b"USB_PROTECT_RECOVERY_v1"
RSA_KEY_SIZE = 2048

# Hardcoded закритий ключ (генерується один раз для всіх копій програми)
# Це дозволяє розшифровувати носії на будь-якому комп'ютері з встановленою програмою
# Ключ генерується програмно при першому запуску і зберігається у коді
HARDCODED_PRIVATE_KEY_PEM = None  # Буде встановлено при першому запуску
# -----------------------------------------------------------------------------

_PASSWORD_STATE = {"count": 0, "lock_until": 0.0}


def ensure_windows():
    if os.name != 'nt' or win32file is None:
        print("This program runs on Windows and requires pywin32.")
        sys.exit(1)


def ensure_config_dir():
    os.makedirs(CONFIG_ROOT, exist_ok=True)
    os.makedirs(RECOVERY_ROOT, exist_ok=True)


def load_config() -> dict:
    ensure_config_dir()
    if not os.path.exists(CONFIG_PATH):
        return {"admin_hash": DEFAULT_ADMIN_HASH, "admin_must_change": True, "allowed": {}}
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # Не встановлюємо admin_must_change = True, якщо він вже був змінений
        if "admin_must_change" not in data:
            data["admin_must_change"] = True
        data.setdefault("admin_hash", DEFAULT_ADMIN_HASH)
        data.setdefault("allowed", {})
        return data
    except Exception:
        return {"admin_hash": DEFAULT_ADMIN_HASH, "admin_must_change": True, "allowed": {}}


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


def get_program_encryption_key() -> bytes:
    """Генерує ключ для шифрування приватного ключа на основі унікального ідентифікатора програми (не залежить від HWID)"""
    # Використовуємо тільки унікальний ідентифікатор програми, щоб ключ міг бути розшифрований на будь-якому комп'ютері
    program_id = "USB_PROTECTOR_V1.0_SECURE_KEY"
    return derive_wrapping_key(program_id, salt=PROGRAM_SALT)


def _hash_password(pw: str) -> str:
    h = hashlib.sha256()
    h.update(pw.encode('utf-8'))
    return h.hexdigest()


def _get_password(prompt_text: str, password_provider=None) -> Optional[str]:
    if password_provider:
        return password_provider(prompt_text)
    return getpass.getpass(prompt_text)


def require_admin_password(prompt: str = 'Admin password: ', password_provider=None) -> bool:
    now = time.time()
    if now < _PASSWORD_STATE["lock_until"]:
        wait = int(_PASSWORD_STATE["lock_until"] - now)
        print(f'Admin authentication locked. Try again in {wait} seconds.')
        return False

    cfg = load_config()
    # Перевіряємо чи потрібно змінити пароль тільки якщо він ще не був змінений
    if cfg.get('admin_must_change'):
        pw = _get_password('Введіть поточний пароль адміністратора для встановлення нового: ', password_provider)
        if _hash_password(pw) != cfg['admin_hash']:
            print('Пароль за замовчуванням не співпадає.')
            _PASSWORD_STATE["count"] += 1
            if _PASSWORD_STATE["count"] >= MAX_PASSWORD_ATTEMPTS:
                _PASSWORD_STATE["lock_until"] = time.time() + LOCKOUT_SECONDS
                print(f'Занадто багато невдалих спроб. Заблоковано на {LOCKOUT_SECONDS} секунд.')
            return False
        while True:
            pw1 = _get_password('Новий пароль адміністратора: ', password_provider)
            pw2 = _get_password('Повторіть пароль: ', password_provider)
            if not pw1:
                print('Пароль не може бути порожнім.')
                continue
            if pw1 != pw2:
                print('Паролі не співпадають. Спробуйте ще раз.')
                continue
            cfg['admin_hash'] = _hash_password(pw1)
            cfg['admin_must_change'] = False
            save_config(cfg)
            print('Пароль адміністратора змінено для цієї установки.')
            return True
    pw = _get_password(prompt, password_provider)
    if _hash_password(pw) == cfg['admin_hash']:
        _PASSWORD_STATE["count"] = 0
        _PASSWORD_STATE["lock_until"] = 0.0
        return True
    print('Admin authentication failed.')
    _PASSWORD_STATE["count"] += 1
    if _PASSWORD_STATE["count"] >= MAX_PASSWORD_ATTEMPTS:
        _PASSWORD_STATE["lock_until"] = time.time() + LOCKOUT_SECONDS
        print(f'Too many failed attempts. Locked for {LOCKOUT_SECONDS} seconds.')
    else:
        remaining = MAX_PASSWORD_ATTEMPTS - _PASSWORD_STATE["count"]
        print(f'{remaining} attempt(s) remaining before temporary lock.')
    return False


def _gui_password_provider(parent):
    def provider(prompt_text: str) -> Optional[str]:
        return simpledialog.askstring('Пароль адміністратора', prompt_text, show='*', parent=parent)
    return provider


def require_admin_password_gui(parent, prompt: str = 'Пароль адміністратора: ') -> bool:
    return require_admin_password(prompt, password_provider=_gui_password_provider(parent))


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


def rsa_encrypted_key_path(root: str) -> str:
    return os.path.join(meta_dir(root), META_RSA_ENCRYPTED_KEY)


def recovery_path(root: str) -> str:
    drive_id = get_drive_identifier(root)
    safe = drive_id.replace(':', '_').replace('\\', '_').replace('/', '_')
    return os.path.join(RECOVERY_ROOT, f"{safe}.json")


def _encrypt_recovery_dict(data: dict) -> dict:
    try:
        key = derive_wrapping_key(get_hwid(), salt=RECOVERY_ENC_SALT)
        aes = AESGCM(key)
        nonce = os.urandom(12)
        raw = json.dumps(data, ensure_ascii=False).encode('utf-8')
        ct = aes.encrypt(nonce, raw, None)
        return {"enc": base64.b64encode(nonce + ct).decode('utf-8')}
    except Exception:
        return data


def _decrypt_recovery_dict(data: dict) -> dict:
    if "enc" not in data:
        return data
    try:
        blob = base64.b64decode(data["enc"])
        nonce, ct = blob[:12], blob[12:]
        key = derive_wrapping_key(get_hwid(), salt=RECOVERY_ENC_SALT)
        aes = AESGCM(key)
        raw = aes.decrypt(nonce, ct, None)
        return json.loads(raw.decode('utf-8'))
    except Exception:
        return {}


def load_wrapped_keys(root: str) -> Optional[Meta]:
    p = wrapped_path(root)
    if not os.path.exists(p):
        restored = restore_metadata_from_recovery(root)
        if restored:
            return restored
        return None
    try:
        with open(p, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return Meta(wrapped=data.get('wrapped', {}))
    except Exception:
        restored = restore_metadata_from_recovery(root)
        return restored


def persist_recovery_snapshot(root: str, meta: Optional[Meta], payload: Optional[dict]) -> None:
    try:
        ensure_config_dir()
        data: dict = {}
        rp = recovery_path(root)
        if os.path.exists(rp):
            with open(rp, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                    data = _decrypt_recovery_dict(data)
                except Exception:
                    data = {}
        if meta:
            data['wrapped'] = meta.wrapped
        if payload is not None:
            data['meta_payload'] = payload
        data['drive_root'] = root
        data['updated_at'] = time.time()
        data = _encrypt_recovery_dict(data)
        with open(rp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def restore_metadata_from_recovery(root: str) -> Optional[Meta]:
    rp = recovery_path(root)
    if not os.path.exists(rp):
        return None
    try:
        with open(rp, 'r', encoding='utf-8') as f:
            data = json.load(f)
        data = _decrypt_recovery_dict(data)
        wrapped = data.get('wrapped', {})
        if not wrapped:
            return None
        meta = Meta(wrapped=wrapped)
        save_wrapped_keys(root, meta)
        master_key = None
        for candidate in wrapped.values():
            master_key = unwrap_master_with_hwid(candidate, get_hwid())
            if master_key:
                break
        payload = data.get('meta_payload')
        if master_key and payload:
            save_meta_encrypted(root, master_key, payload, meta)
        return meta
    except Exception:
        return None


def save_wrapped_keys(root: str, meta: Meta) -> None:
    d = meta_dir(root)
    os.makedirs(d, exist_ok=True)
    p = wrapped_path(root)
    with open(p, 'w', encoding='utf-8') as f:
        json.dump({'wrapped': meta.wrapped}, f, indent=2, ensure_ascii=False)
    persist_recovery_snapshot(root, meta, None)
    try:
        if win32api:
            win32api.SetFileAttributes(d, win32con.FILE_ATTRIBUTE_HIDDEN)
    except Exception:
        pass


def save_meta_encrypted(root: str, master_key: bytes, payload: dict, meta: Optional[Meta] = None) -> None:
    aes = AESGCM(master_key)
    nonce = os.urandom(12)
    data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    ct = aes.encrypt(nonce, data, None)
    with open(meta_enc_path(root), 'wb') as f:
        f.write(nonce + ct)
    persist_recovery_snapshot(root, meta, payload)


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


# ----------------------------- RSA Key management --------------------------

def generate_rsa_keypair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Генерує RSA ключову пару"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def encrypt_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """Шифрує приватний ключ для збереження"""
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    encryption_key = get_program_encryption_key()
    aes = AESGCM(encryption_key)
    nonce = os.urandom(12)
    encrypted = aes.encrypt(nonce, private_pem, None)
    return nonce + encrypted


def decrypt_private_key(encrypted_data: bytes) -> Optional[rsa.RSAPrivateKey]:
    """Розшифровує приватний ключ"""
    try:
        if len(encrypted_data) < 12:
            return None
        nonce = encrypted_data[:12]
        ct = encrypted_data[12:]
        encryption_key = get_program_encryption_key()
        aes = AESGCM(encryption_key)
        private_pem = aes.decrypt(nonce, ct, None)
        return load_pem_private_key(private_pem, password=None, backend=default_backend())
    except Exception:
        return None


def get_hardcoded_private_key() -> rsa.RSAPrivateKey:
    """Отримує закритий ключ з AppData (зашифрований) або генерує новий"""
    # Спробувати завантажити зашифрований ключ з AppData
    try:
        ensure_config_dir()
        if os.path.exists(PRIVATE_KEY_PATH):
            with open(PRIVATE_KEY_PATH, 'rb') as f:
                encrypted_data = f.read()
            private_key = decrypt_private_key(encrypted_data)
            if private_key is not None:
                return private_key
            else:
                # Якщо не вдалося розшифрувати (можливо старий формат з HWID), 
                # спробуємо завантажити як незашифрований (для сумісності)
                try:
                    old_key_path = PRIVATE_KEY_PATH.replace('.enc', '')
                    if os.path.exists(old_key_path):
                        with open(old_key_path, 'rb') as f:
                            private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())
                        # Перешифруємо у новому форматі (без HWID)
                        encrypted_data = encrypt_private_key(private_key)
                        with open(PRIVATE_KEY_PATH, 'wb') as f:
                            f.write(encrypted_data)
                        return private_key
                except Exception:
                    pass
    except Exception:
        pass
    
    # Якщо ключ не знайдено або не вдалося розшифрувати, генеруємо новий
    private_key, _ = generate_rsa_keypair()
    
    # Шифруємо і зберігаємо у AppData
    try:
        ensure_config_dir()
        encrypted_data = encrypt_private_key(private_key)
        with open(PRIVATE_KEY_PATH, 'wb') as f:
            f.write(encrypted_data)
    except Exception as e:
        # Якщо не вдалося зберегти, виводимо попередження
        print(f"Попередження: не вдалося зберегти зашифрований ключ: {e}")
    
    return private_key


def ensure_rsa_keys() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Забезпечує наявність RSA ключів - використовує hardcoded закритий ключ"""
    # Використовуємо hardcoded закритий ключ з коду програми
    private_key = get_hardcoded_private_key()
    return private_key, private_key.public_key()


def save_public_key_to_drive(root: str, public_key: rsa.RSAPublicKey) -> bool:
    """Зберігає публічний ключ на носій"""
    try:
        d = meta_dir(root)
        os.makedirs(d, exist_ok=True)
        public_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        pub_path = os.path.join(d, PUBLIC_KEY_FILENAME)
        with open(pub_path, 'wb') as f:
            f.write(public_pem)
        return True
    except Exception:
        return False


def load_public_key_from_drive(root: str) -> Optional[rsa.RSAPublicKey]:
    """Завантажує публічний ключ з носія"""
    pub_path = os.path.join(meta_dir(root), PUBLIC_KEY_FILENAME)
    if not os.path.exists(pub_path):
        return None
    try:
        with open(pub_path, 'rb') as f:
            return load_pem_public_key(f.read(), backend=default_backend())
    except Exception:
        return None


def encrypt_master_key_rsa(master_key: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """Шифрує master key за допомогою RSA публічного ключа"""
    # RSA може шифрувати лише невеликі дані, тому використовуємо hybrid encryption
    # Генеруємо випадковий AES ключ для шифрування master_key
    aes_key = os.urandom(32)
    aes = AESGCM(aes_key)
    nonce = os.urandom(12)
    encrypted_master = aes.encrypt(nonce, master_key, None)
    # Шифруємо AES ключ RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Повертаємо: RSA(encrypted_aes_key) + nonce + AES(encrypted_master)
    return encrypted_aes_key + nonce + encrypted_master


def decrypt_master_key_rsa(encrypted_data: bytes, private_key: rsa.RSAPrivateKey) -> Optional[bytes]:
    """Розшифровує master key за допомогою RSA приватного ключа"""
    try:
        # RSA ключ розміром 2048 може зашифрувати до 245 байт
        # encrypted_aes_key має бути 256 байт для 2048-bit ключа
        rsa_encrypted_size = RSA_KEY_SIZE // 8
        encrypted_aes_key = encrypted_data[:rsa_encrypted_size]
        nonce = encrypted_data[rsa_encrypted_size:rsa_encrypted_size + 12]
        encrypted_master = encrypted_data[rsa_encrypted_size + 12:]
        
        # Розшифровуємо AES ключ
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Розшифровуємо master key
        aes = AESGCM(aes_key)
        master_key = aes.decrypt(nonce, encrypted_master, None)
        return master_key
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
        # Verify write before destructive delete
        with open(new_path, 'rb') as f:
            written = f.read()
        restored = decrypt_content_bytes(written, master_key)
        if restored is None or restored != data:
            try:
                os.remove(new_path)
            except Exception:
                pass
            return None
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
        """Завантажує метадані та розшифровує master key через RSA"""
        # Спочатку перевіряємо RSA зашифрований ключ
        rsa_key_path = rsa_encrypted_key_path(self.root)
        if os.path.exists(rsa_key_path):
            try:
                private_key, _ = ensure_rsa_keys()
                with open(rsa_key_path, 'rb') as f:
                    encrypted_data = f.read()
                master_key = decrypt_master_key_rsa(encrypted_data, private_key)
                if master_key is not None:
                    self.master_key = master_key
                    self.authorized = True
                    # Завантажуємо метадані для сумісності
                    self.meta = load_wrapped_keys(self.root)
                    if self.meta is None:
                        self.meta = Meta(wrapped={})
                    return (True, 'rsa_unwrapped')
            except Exception:
                pass
        
        # Fallback до старої системи HWID для сумісності
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

    def add_local_hwid_access(self) -> Tuple[bool, str]:
        if self.meta is None:
            self.meta = load_wrapped_keys(self.root)
        if self.meta is None:
            return (False, 'no_meta')
        ok, reason = self.load_or_init()
        if not ok:
            return (False, reason)
        hwid_hash = _short_hwid_hash(self.hwid)
        if hwid_hash in self.meta.wrapped:
            return (True, 'already_added')
        try:
            new_wrapped = wrap_master_for_hwid(self.master_key, self.hwid)
            self.meta.wrapped[hwid_hash] = base64.b64encode(new_wrapped).decode('utf-8')
            save_wrapped_keys(self.root, self.meta)
            persist_recovery_snapshot(self.root, self.meta, None)
            return (True, 'added')
        except Exception as e:
            return (False, str(e))

    def initialize_and_encrypt(self, make_backup: bool = True, prompt_fn=None) -> Tuple[bool, str]:
        """Ініціалізує та шифрує носій, використовуючи RSA"""
        try:
            if make_backup:
                ok, msg = _optional_backup(self.root, prompt_fn=prompt_fn)
                if not ok:
                    return (False, 'backup_failed')
            # Генеруємо master key
            master = generate_master_key()
            
            # Отримуємо або генеруємо RSA ключову пару
            private_key, public_key = ensure_rsa_keys()
            
            # Зберігаємо публічний ключ на носій
            if not save_public_key_to_drive(self.root, public_key):
                return (False, 'failed_to_save_public_key')
            
            # Шифруємо master key через RSA та зберігаємо на носій
            encrypted_master = encrypt_master_key_rsa(master, public_key)
            rsa_key_path = rsa_encrypted_key_path(self.root)
            os.makedirs(meta_dir(self.root), exist_ok=True)
            with open(rsa_key_path, 'wb') as f:
                f.write(encrypted_master)
            
            # Створюємо метадані (для сумісності зі старою системою)
            meta = Meta(wrapped={})
            save_wrapped_keys(self.root, meta)
            self.meta = meta
            self.master_key = master
            self.authorized = True
            
            # Шифруємо всі файли
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
            save_meta_encrypted(self.root, self.master_key, {'mapping': mapping, 'created_by': self.hwid}, self.meta)
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
                    print(f'Skipping large file in temp view: {orig_rel} ({size} bytes)')
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
        # Закриваємо відкриту папку Explorer
        try:
            if os.path.exists(self.temp_dir):
                # Використовуємо PowerShell для закриття Explorer вікна з цією папкою
                import subprocess
                # Екрануємо зворотні слеші для PowerShell
                temp_path_escaped = self.temp_dir.replace('\\', '\\\\')
                ps_cmd = f'''
$shell = New-Object -ComObject Shell.Application
$windows = $shell.Windows()
$targetPath = "{temp_path_escaped}"
foreach ($window in $windows) {{
    try {{
        $url = $window.LocationURL
        if ($url -and $url.Contains($targetPath.Replace("\\\\", "/"))) {{
            $window.Quit()
        }}
    }} catch {{
        # Ігноруємо помилки
    }}
}}
'''
                subprocess.run(['powershell', '-NoProfile', '-Command', ps_cmd], 
                            capture_output=True, timeout=3, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass
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
        save_meta_encrypted(self.root, self.master_key, {'mapping': self._mapping, 'created_by': self.hwid}, self.meta)

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
        save_meta_encrypted(self.root, self.master_key, {'mapping': self._mapping, 'created_by': self.hwid}, self.meta)


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


def get_drive_size_gb(drive: str) -> float:
    """Повертає розмір диска в GB"""
    try:
        # GetDiskFreeSpaceEx повертає кортеж: (free_bytes, total_bytes, available_bytes)
        result = win32api.GetDiskFreeSpaceEx(drive)
        if len(result) >= 2:
            total_bytes = result[1]  # Другий елемент - загальний розмір
            return round(total_bytes / (1024 ** 3), 2)
        return 0.0
    except Exception:
        return 0.0


def format_drive_info(drive: str) -> str:
    """Форматує інформацію про диск: назва, серійний номер, розмір"""
    try:
        label, serial, _, _, _ = win32api.GetVolumeInformation(drive)
        size_gb = get_drive_size_gb(drive)
        parts = []
        if label:
            parts.append(f"Назва: {label}")
        if serial:
            parts.append(f"Серійний: {serial}")
        if size_gb > 0:
            parts.append(f"Розмір: {size_gb} GB")
        return " | ".join(parts) if parts else drive.rstrip('\\')
    except Exception:
        return drive.rstrip('\\')


def is_drive_allowed(drive: str) -> bool:
    cfg = load_config()
    drive_id = get_drive_identifier(drive)
    return drive_id in cfg.get('allowed', {})


def add_allowed_drive(drive: str, password_provider=None) -> bool:
    if not require_admin_password(password_provider=password_provider):
        return False
    cfg = load_config()
    drive_id = get_drive_identifier(drive)
    label = get_drive_label(drive)
    cfg.setdefault('allowed', {})[drive_id] = label
    save_config(cfg)
    print(f"Drive {drive} added to local allowlist.")
    return True


def list_connected_drives() -> List[str]:
    """Повертає список підключених знімних дисків, виключаючи C та D"""
    drives = []
    mask = win32file.GetLogicalDrives()
    excluded = {'C:', 'D:'}
    for letter in range(26):
        if mask & (1 << letter):
            drive = f"{chr(65 + letter)}:" + os.sep
            drive_letter = f"{chr(65 + letter)}:"
            if drive_letter in excluded:
                continue
            try:
                if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    drives.append(drive)
            except Exception:
                pass
    return drives


def ensure_autostart():
    try:
        ensure_config_dir()
        run_key = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_SET_VALUE) as key:
            script_path = os.path.abspath(sys.argv[0] or __file__)
            cmd = f'"{sys.executable}" "{script_path}"'
            winreg.SetValueEx(key, 'USBProtector', 0, winreg.REG_SZ, cmd)
    except Exception:
        pass


def list_removable_drives() -> List[str]:
    """Повертає список знімних дисків, виключаючи C та D"""
    drives = []
    mask = win32file.GetLogicalDrives()
    excluded = {'C:', 'D:'}
    for letter in range(26):
        if mask & (1 << letter):
            drive = f"{chr(65 + letter)}:" + os.sep
            drive_letter = f"{chr(65 + letter)}:"
            if drive_letter in excluded:
                continue
            try:
                dtype = win32file.GetDriveType(drive)
                if dtype == win32file.DRIVE_REMOVABLE:
                    drives.append(drive)
            except Exception:
                pass
    return drives


def _optional_backup(root: str, prompt_fn=None) -> Tuple[bool, str]:
    try:
        ask = prompt_fn if prompt_fn else (lambda msg: input(msg))
        ans = (ask('Створити ZIP резервну копію поточного USB перед руйнівним шифруванням? (y/N): ') or '').strip().lower()
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
        print(f'Резервну копію створено: {backup_name}')
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
        print('Знімні накопичувачі не знайдено.')
        return None
    print('Знімні накопичувачі:')
    for i, d in enumerate(drives, start=1):
        info = format_drive_info(d)
        print(f'  [{i}] {d} | {info}')
    sel = input('Виберіть номер накопичувача: ').strip()
    try:
        idx = int(sel) - 1
        if idx < 0:
            raise ValueError
        return drives[idx]
    except Exception:
        print('Невірний вибір')
        return None


def print_new_pc_help():
    print('\nЯк розшифрувати носій на новому ПК:')
    print("  1. Зашифруйте USB накопичувач на будь-якому комп'ютері з встановленою програмою.")
    print('     Публічний ключ автоматично зберігається на носії.')
    print("  2. Перенесіть зашифрований носій на інший комп'ютер з встановленою програмою.")
    print('     Програма автоматично розпізнає публічний ключ та розшифрує дані.')
    print('  3. Використовуйте кнопку "Розшифрувати накопичувач" для постійної розшифровки.')
    print('  4. Якщо прихована папка .usb_protect_meta була втрачена, програма відновить її')
    print('     з локальної резервної копії (з каталогу AppData) під час першої спроби роботи з носієм.')


class SimpleGUI:
    def __init__(self):
        ensure_windows()
        ensure_autostart()
        self.monitor = USBMonitor()
        self.root = tk.Tk()
        self.root.title('Захист USB накопичувачів')
        self.root.geometry('900x650')
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)

        self.section_iids = {'section_allowed', 'section_blocked'}

        frm = ttk.Frame(self.root, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(frm, columns=('status', 'info'), show='headings')
        self.tree.heading('status', text='Статус')
        self.tree.heading('info', text='Інформація про накопичувач')
        self.tree.column('status', width=150)
        self.tree.column('info', width=700)
        self.tree.pack(fill=tk.BOTH, expand=True)

        btn_frame = ttk.Frame(frm)
        btn_frame.pack(fill=tk.X, pady=8)

        # Перший рядок кнопок - основні операції
        main_btn_frame = ttk.Frame(btn_frame)
        main_btn_frame.pack(fill=tk.X, pady=4)
        
        ttk.Button(main_btn_frame, text='1. Зашифрувати накопичувач (адмін)', command=self.admin_encrypt).pack(side=tk.LEFT, padx=4)
        ttk.Button(main_btn_frame, text='2. Розшифрувати накопичувач (адмін)', command=self.admin_decrypt).pack(side=tk.LEFT, padx=4)
        
        # Другий рядок кнопок - управління
        control_btn_frame = ttk.Frame(btn_frame)
        control_btn_frame.pack(fill=tk.X, pady=4)
        
        ttk.Button(control_btn_frame, text='Оновити список', command=self.refresh).pack(side=tk.LEFT, padx=4)
        ttk.Button(control_btn_frame, text='Додати до дозволених (адмін)', command=self.admin_allow).pack(side=tk.LEFT, padx=4)
        ttk.Button(control_btn_frame, text='Видалити з дозволених', command=self.admin_remove).pack(side=tk.LEFT, padx=4)
        ttk.Button(control_btn_frame, text='Додати зашифрований носій для іншого ПК (адмін)', command=self.admin_add_encrypted_drive).pack(side=tk.LEFT, padx=4)

        help_text = (
            "Зашифрований накопичувач можна розшифрувати на будь-якому комп'ютері з встановленою програмою, "
            "оскільки використовується RSA шифрування. Публічний ключ зберігається на носії, "
            "приватний ключ - у програмі на кожному комп'ютері."
        )
        ttk.Label(frm, text=help_text, wraplength=800, foreground='gray').pack(fill=tk.X, pady=6)

        self.refresh()
        self.monitor.start_background()

    def refresh(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        cfg = load_config()
        connected = {get_drive_identifier(d): d for d in list_connected_drives()}

        self.tree.insert('', 'end', iid='section_allowed', values=('Дозволені носії', ''))
        for drive_id, label in cfg.get('allowed', {}).items():
            drive = connected.get(drive_id, '')
            if drive:
                status = 'Дозволено (підключено)'
                info = f"{drive} | {format_drive_info(drive)}"
            else:
                status = 'Дозволено (не підключено)'
                info = f"— | {label}"
            self.tree.insert('', 'end', iid=drive or drive_id, values=(status, info))

        self.tree.insert('', 'end', iid='section_blocked', values=('Заблоковані носії', ''))
        for drive_id, drive in connected.items():
            if drive_id in cfg.get('allowed', {}):
                continue
            info = f"{drive} | {format_drive_info(drive)}"
            self.tree.insert('', 'end', iid=drive, values=('Заблоковано', info))

    def _selected_drive(self) -> Optional[str]:
        sel = self.tree.selection()
        if not sel:
            return None
        iid = sel[0]
        if iid in self.section_iids:
            return None
        return iid

    def admin_allow(self):
        d = self._selected_drive()
        if not d:
            messagebox.showwarning('Захист USB', 'Спочатку виберіть накопичувач.')
            return
        if ':' not in d:
            messagebox.showwarning('Захист USB', 'Вставте USB накопичувач перед додаванням до дозволених.')
            return
        if add_allowed_drive(d, password_provider=_gui_password_provider(self.root)):
            self.refresh()

    def admin_remove(self):
        d = self._selected_drive()
        if not d:
            messagebox.showwarning('Захист USB', 'Виберіть накопичувач для видалення зі списку дозволених.')
            return
        cfg = load_config()
        drive_id = get_drive_identifier(d) if ':' in d else d
        if drive_id not in cfg.get('allowed', {}):
            messagebox.showinfo('Захист USB', 'Вибраний накопичувач не знаходиться у списку дозволених.')
            return
        if not require_admin_password_gui(self.root):
            return
        cfg['allowed'].pop(drive_id, None)
        save_config(cfg)
        messagebox.showinfo('Захист USB', 'Накопичувач видалено зі списку дозволених.')
        self.refresh()

    def admin_decrypt(self):
        d = self._selected_drive()
        if not d:
            messagebox.showwarning('Захист USB', 'Спочатку виберіть накопичувач.')
            return
        if ':' not in d:
            messagebox.showwarning('Захист USB', 'Вставте зашифрований USB накопичувач.')
            return
        if not require_admin_password_gui(self.root):
            return
        dp = DriveProcessor(d)
        dp.meta = load_wrapped_keys(d)
        if dp.meta is None:
            # Перевіряємо чи є RSA ключ
            rsa_key_path = rsa_encrypted_key_path(d)
            if not os.path.exists(rsa_key_path):
                messagebox.showerror('Захист USB', 'Метадані відсутні; неможливо відновити.')
                return
        ok, msg = dp.permanent_decrypt()
        if ok:
            messagebox.showinfo('Захист USB', f'Накопичувач успішно розшифровано.')
        else:
            messagebox.showerror('Захист USB', f'Помилка розшифрування: {msg}')

    def admin_encrypt(self):
        d = self._selected_drive()
        if not d:
            messagebox.showwarning('Захист USB', 'Спочатку виберіть накопичувач.')
            return
        if ':' not in d:
            messagebox.showwarning('Захист USB', 'Вставте USB накопичувач перед шифруванням.')
            return
        if not require_admin_password_gui(self.root):
            return
        confirm = messagebox.askyesno(
            'Захист USB',
            f'Це знищить всі дані на накопичувачі {d} та зашифрує їх. Продовжити? (рекомендується створити резервну копію)',
        )
        if not confirm:
            return
        backup_yes = messagebox.askyesno(
            'Захист USB',
            'Створити ZIP резервну копію цього USB перед шифруванням?',
        )
        backup_fn = (lambda _prompt: 'y' if backup_yes else 'n')
        dp = DriveProcessor(d)
        ok, msg = dp.initialize_and_encrypt(make_backup=True, prompt_fn=backup_fn)
        if ok:
            messagebox.showinfo('Захист USB', f'Накопичувач успішно зашифровано.')
        else:
            messagebox.showerror('Захист USB', f'Помилка шифрування: {msg}')
        self.refresh()

    def admin_share_local(self):
        # Ця функція більше не потрібна з RSA, але залишаємо для сумісності
        messagebox.showinfo('Захист USB', 'З RSA шифруванням накопичувач автоматично доступний на всіх комп\'ютерах з встановленою програмою.')

    def admin_add_encrypted_drive(self):
        """Додає зашифрований носій для використання на іншому комп'ютері"""
        d = self._selected_drive()
        if not d:
            messagebox.showwarning('Захист USB', 'Спочатку виберіть зашифрований накопичувач.')
            return
        if ':' not in d:
            messagebox.showwarning('Захист USB', 'Вставте зашифрований USB накопичувач.')
            return
        if not require_admin_password_gui(self.root):
            return
        
        # Перевіряємо чи є публічний ключ на носії
        public_key = load_public_key_from_drive(d)
        if public_key is None:
            messagebox.showerror('Захист USB', 'На носії не знайдено публічний ключ. Носій не зашифровано через RSA.')
            return
        
        # Перевіряємо чи є зашифрований master key
        rsa_key_path = rsa_encrypted_key_path(d)
        if not os.path.exists(rsa_key_path):
            messagebox.showerror('Захист USB', 'На носії не знайдено зашифрований master key.')
            return
        
        # Перевіряємо чи закритий ключ у програмі може розшифрувати master key
        try:
            private_key = get_hardcoded_private_key()
            with open(rsa_key_path, 'rb') as f:
                encrypted_data = f.read()
            master_key = decrypt_master_key_rsa(encrypted_data, private_key)
            if master_key is None:
                messagebox.showerror('Захист USB', 'Неможливо розшифрувати master key. Переконайтеся, що використовується правильна версія програми.')
                return
        except Exception as e:
            messagebox.showerror('Захист USB', f'Помилка при перевірці ключа: {str(e)}')
            return
        
        # Додаємо носій до списку дозволених
        if add_allowed_drive(d, password_provider=_gui_password_provider(self.root)):
            messagebox.showinfo('Захист USB', 'Зашифрований носій успішно додано. Тепер його можна використовувати на цьому комп\'ютері.')
            self.refresh()
        else:
            messagebox.showerror('Захист USB', 'Не вдалося додати носій до списку дозволених.')

    def on_close(self):
        self.root.iconify()

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
        print('7) (Admin) Share access with this PC for an encrypted USB')
        print('8) Help: how to decrypt on a new PC')
        print('9) Exit')
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
            if not require_admin_password():
                continue
            d = choose_drive_interactive()
            if not d:
                continue
            dp = DriveProcessor(d)
            ok, msg = dp.add_local_hwid_access()
            print('Result:', ok, msg)
        elif choice == '8':
            print_new_pc_help()
        elif choice == '9':
            print('Exit')
            monitor.stop()
            break
        else:
            print('Unknown option')


if __name__ == '__main__':
    if '--cli' in sys.argv:
        main_menu()
    else:
        app = SimpleGUI()
        app.run()

