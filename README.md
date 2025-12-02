# USB Protector Concept (Windows, Python)

This document summarizes the architecture implemented by `usb_protector.py` and highlights how the tool is meant to protect USB flash drives on Windows machines.

## Goals
- Automatically encrypt all content on a removable USB drive.
- Allow transparent access only on authorized PCs where the program is installed.
- Keep data encrypted by default on unknown PCs without the software.
- Start with the OS and keep resource usage minimal.

## High-level flow
1. **HWID-based key derivation**: On startup the program fetches a hardware identifier (BIOS serial fallback to volume ID or `COMPUTERNAME`) and derives a wrapping key using PBKDF2-HMAC-SHA256 with a built-in salt.
2. **Master key handling**: A random 256-bit master key encrypts drive contents. The master key is wrapped per HWID (`aes_key_wrap`) and stored in hidden metadata on the drive. Multiple authorized PCs can add their wrapped copy.
3. **Drive detection**: Using `pywin32` the app polls logical drives, filtering for removable drives. Newly detected drives are inspected for metadata; authorized drives are given a temporary decrypted view that stays in sync with the encrypted media.
4. **File encryption format**: Files are encrypted with AES-GCM. A header stores a tag, version byte, nonce, and original size. Filenames are obfuscated via AES-GCM then URL-safe Base64 so the drive surface contains only opaque tokens.
5. **Metadata**: Hidden folder `.usb_protect_meta` contains `wrapped_keys.json` (wrapped master keys indexed by HWID hash) and `meta.enc` (AES-GCM-encrypted JSON mapping of encrypted tokens to original relative paths).
6. **Operations**:
   - **Initialize & Encrypt**: Optionally zip-backs up the drive, generates a master key, wraps it for the local HWID, encrypts/obfuscates files, and writes metadata.
   - **Permanent Decrypt**: Unwraps the master key with local HWID, decrypts all files, restores original names/paths, and removes metadata.
    - **Temporary View**: For authorized drives, decrypts small files to a temp directory for on-the-fly access while the program runs. Any edits, additions, or deletions in that temp view are re-encrypted and written back to the USB automatically; cleanup occurs when drives are removed or the monitor stops.

## Running
```bash
pip install cryptography pywin32
python usb_protector.py
```

Choose from the interactive menu:
- **Initialize & Encrypt**: destructively encrypts a selected removable drive (with optional zip backup) after an explicit `y/n` confirmation.
- **Permanently Decrypt**: restores an encrypted drive when run on an authorized PC.
- **View**: starts a monitor that auto-decrypts files to a temp view for authorized drives while running, automatically opens that folder when an authorized drive is inserted, and syncs any edits back to encrypted storage.

## Deployment notes
- Convert to a Windows service or add to Startup for auto-run.
- Bundle with PyInstaller to avoid requiring a local Python install.
- Avoid storing secrets on the USB: the master key is only ever wrapped for specific HWIDs.

## Safety considerations
- Always back up important data before initialization; the encrypt step is destructive.
- Sudden removal during encryption/decryption can leave files missing; the tool attempts cleanup but cannot guarantee recovery.
- Keep the `PROGRAM_SALT` consistent across authorized installations; changing it invalidates wrapped keys.

## Changes still needed (high level)
- **Robust monitoring**: replace the polling loop with Windows WMI events (e.g., `Win32_VolumeChangeEvent`) to detect inserts/removals instantly and with lower CPU usage.
- **Copy/IO interception**: implement an on-write hook (e.g., a filesystem filter driver or a user-mode API hook) so that new files are encrypted before they ever reside unencrypted on disk.
- **Atomic metadata writes**: write `wrapped_keys.json` and `meta.enc` via temp files + `ReplaceFile`/`MoveFileEx` to avoid corruption on sudden removal or power loss.
- **Integrity checks**: add per-file HMAC or AES-GCM additional authenticated data (AAD) over the relative path to detect tampering/renames on the encrypted USB surface.
- **Allowlist of PCs**: sign and ship an allowlist of trusted HWID hashes and require a signed policy file before wrapping keys for new machines to prevent uncontrolled replication.
- **Service packaging**: provide an installable Windows Service (e.g., with `pywin32` `win32serviceutil`) plus a minimal tray UI for status, pause, and safe eject guidance.
- **Audit logging**: log encrypt/decrypt outcomes and failures to the Windows Event Log for supportability; redact filenames by logging only hashed identifiers.
- **Resilient cleanup**: harden temporary directory cleanup (handle in-use files, retries, background sweeper) and add a failsafe on next boot to remove stale temp data.
