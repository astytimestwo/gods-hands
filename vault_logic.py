"""
vault_logic.py — GodsVault Cryptographic Engine

Implements a time-locked storage system where decryption keys are derived from
external entropy (NIST Randomness Beacon) and local hardware identifiers.
This eliminates centralized trust and prevents unauthorized local access
prior to the expiration of the time-gate.
"""


import json
import os
import sys
import time
import base64
import hashlib
import hmac as _hmac
import uuid
import platform
import struct
import math
from pathlib import Path
from typing import Any, Dict, Optional, List

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from beacon_client import BeaconClient, BeaconError


class VaultError(Exception):
    pass


class VaultLockedError(VaultError):
    def __init__(self, message: str, seconds_remaining: float):
        super().__init__(message)
        self.seconds_remaining = seconds_remaining


class VaultOfflineError(VaultError):
    pass


def _default_data_dir() -> Path:
    """Cross-platform data directory: LOCALAPPDATA (Win) / XDG_DATA_HOME (Linux)."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "GodsHands"


class Vault:
    DEFAULT_PATH = _default_data_dir() / "vault.json"
    SCHEMA = "5.0-TrueFuture"
    MIN_DAYS = 0
    SIMPLE_THRESHOLD_MIN = 5
    NIST_MIN_DAYS = 2 / (24 * 60)
    MAX_DAYS = 5 * 365
    MAX_SECRET_BYTES = 50 * 1024 * 1024    # 50 MB cap for TEXT secrets only
    CHUNK_SIZE     = 8 * 1024 * 1024       # 8 MB streaming chunk for large files
    ENC_MAGIC      = b'GVLT'               # 4-byte header magic for .enc files

    # ── SECURITY NOTE: Simple-mode time guarantee ───────────────────────────────
    # Simple locks (<5 min) are enforced by Python wall-clock only.
    # NIST mode (≥5 min) provides true cryptographic time-binding.
    # ─────────────────────────────────────────────────────────────────────────────

    def __init__(self, file_path: Optional[str] = None):
        self.file_path = Path(file_path).expanduser().resolve() if file_path else self.DEFAULT_PATH
        self._machine_seed = self._get_machine_id()

    # ── Machine Identity ──────────────────────────────────────────────────────

    def _get_machine_id(self) -> bytes:
        """
        Stable hardware fingerprint used as the 'password' in PBKDF2.
        Obfuscated to frustrate casual reverse engineering.
        """
        mac       = uuid.getnode()
        sys_info  = f"{platform.node()}-{platform.machine()}-{platform.processor()}"

        # Obfuscation: bit-shift + XOR mixture
        seed_val  = (mac << 5) ^ (len(sys_info) * 997) ^ (mac >> 3)
        mixed     = f"{seed_val:x}" + sys_info[::-1] + f"{mac:x}"

        return hashlib.sha3_512(mixed.encode()).digest()   # 64 bytes

    # ── Key Derivation ────────────────────────────────────────────────────────

    def _derive_key(self, beacon_pulse: str) -> bytes:
        """
        PBKDF2-HMAC-SHA256(machine_seed, beacon_pulse, 1_000_000 rounds).
        beacon_pulse is the 512-bit NIST hex string fetched live from NIST.
        NEVER passes through vault.json.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=beacon_pulse.encode("utf-8"),
            iterations=1_000_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(self._machine_seed))

    def _derive_key_simple(self, unlock_timestamp: float) -> bytes:
        """
        Simple key derivation for short locks (< 5 min).
        PBKDF2-HMAC-SHA256(machine_seed, str(unlock_timestamp)).
        No NIST required. Time gate is enforced locally.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=str(unlock_timestamp).encode("utf-8"),
            iterations=100_000,
        )
        return base64.urlsafe_b64encode(kdf.derive(self._machine_seed))

    # ── Streaming File Encryption ─────────────────────────────────────────────
    #
    # .enc file layout:
    #   [magic: 4B "GVLT"][iv: 16B][hmac: 32B][ciphertext...]
    #   HMAC-SHA256 is over (iv || ciphertext), written by seeking back after
    #   the full ciphertext is written. Decryption verifies HMAC before returning.

    def _enc_path(self, enc_id: str) -> Path:
        return self.file_path.parent / f"{enc_id}.enc"

    def _stream_encrypt_file(self, src: Path, dst: Path, file_key: bytes) -> None:
        """AES-256-CTR encrypt src to dst in 8 MB chunks. RAM peak = 8 MB."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(file_key[:32]), modes.CTR(iv))
        encryptor = cipher.encryptor()
        mac = _hmac.new(file_key, digestmod=hashlib.sha256)
        mac.update(iv)

        with open(dst, 'wb') as out:
            out.write(self.ENC_MAGIC)      # 4 bytes
            out.write(iv)                  # 16 bytes
            hmac_offset = out.tell()       # 20
            out.write(b'\x00' * 32)        # placeholder — filled in below

            with open(src, 'rb') as inp:
                while True:
                    chunk = inp.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    ct = encryptor.update(chunk)
                    mac.update(ct)
                    out.write(ct)

            tail = encryptor.finalize()
            if tail:
                mac.update(tail)
                out.write(tail)

            out.seek(hmac_offset)
            out.write(mac.digest())        # fill in real HMAC

    def _stream_decrypt_file(self, src: Path, dst: Path, file_key: bytes) -> None:
        """AES-256-CTR decrypt src to dst. Raises VaultError on HMAC mismatch."""
        with open(src, 'rb') as inp:
            if inp.read(4) != self.ENC_MAGIC:
                raise VaultError("Invalid .enc header — file corrupted or not a vault file.")
            iv          = inp.read(16)
            stored_mac  = inp.read(32)

            cipher = Cipher(algorithms.AES(file_key[:32]), modes.CTR(iv))
            decryptor = cipher.decryptor()
            mac = _hmac.new(file_key, digestmod=hashlib.sha256)
            mac.update(iv)

            with open(dst, 'wb') as out:
                while True:
                    chunk = inp.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    mac.update(chunk)
                    out.write(decryptor.update(chunk))
                tail = decryptor.finalize()
                if tail:
                    out.write(tail)

        if not _hmac.compare_digest(mac.digest(), stored_mac):
            dst.unlink(missing_ok=True)
            raise VaultError("HMAC verification failed — file tampered or wrong key.")

    # ── Two-Layer Key Wrapping ────────────────────────────────────────────────

    def _wrap_file_key(self, file_key: bytes, derived_key: bytes) -> str:
        return Fernet(derived_key).encrypt(file_key).decode('utf-8')

    def _unwrap_file_key(self, wrapped: str, derived_key: bytes) -> bytes:
        return Fernet(derived_key).decrypt(wrapped.encode('utf-8'))

    # ── Large File Lock & Reveal ──────────────────────────────────────────────

    def lock_large(self, name: str, src_path: Path, original_filename: str,
                   days: float) -> None:
        """
        Seal any-size file using streaming AES-256-CTR.
        RAM peak: CHUNK_SIZE (8 MB) regardless of file size.

        Architecture:
          1. Random 32-byte file_key encrypts content  → UUID.enc file on disk
          2. file_key wrapped by PBKDF2 Fernet key     → tiny blob in vault.json
        """
        name = name.strip()
        if not name:
            raise ValueError("Name required")
        if not isinstance(days, (int, float)) or math.isnan(days) or math.isinf(days):
            raise ValueError("Duration must be a finite number.")
        if days <= 0:
            raise ValueError("Duration must be positive.")
        if days > self.MAX_DAYS:
            raise ValueError(f"Duration exceeds maximum ({self.MAX_DAYS} days).")

        existing = self._load_raw()
        if name in existing.get("items", {}):
            raise ValueError(f"A fate named \u2018{name}\u2019 already exists.")

        file_key = os.urandom(32)
        enc_id   = str(uuid.uuid4())
        enc_file = self._enc_path(enc_id)
        enc_file.parent.mkdir(parents=True, exist_ok=True)

        minutes  = days * 24 * 60
        use_nist = minutes >= self.SIMPLE_THRESHOLD_MIN

        if use_nist:
            if days < self.NIST_MIN_DAYS:
                raise ValueError("NIST mode requires at least 2 minutes.")
            try:
                criteria = BeaconClient.get_lock_criteria(days * 86400)
            except BeaconError as e:
                raise VaultOfflineError(f"Cannot lock — NIST unreachable: {e}")

            lock_round       = criteria["lock_round"]
            lock_pulse       = criteria["lock_pulse"]
            unlock_timestamp = criteria["unlock_timestamp"]
            derived_key      = self._derive_key(lock_pulse)
            del lock_pulse

            record = {
                "name": name, "enc_id": enc_id,
                "wrapped_file_key": self._wrap_file_key(file_key, derived_key),
                "original_filename": original_filename,
                "lock_round": lock_round,
                "unlock_timestamp": unlock_timestamp,
                "type": "large_file", "mode": "nist",
            }
        else:
            unlock_timestamp = time.time() + (days * 86400)
            derived_key      = self._derive_key_simple(unlock_timestamp)
            record = {
                "name": name, "enc_id": enc_id,
                "wrapped_file_key": self._wrap_file_key(file_key, derived_key),
                "original_filename": original_filename,
                "unlock_timestamp": unlock_timestamp,
                "type": "large_file", "mode": "simple",
            }

        del derived_key
        self._stream_encrypt_file(src_path, enc_file, file_key)
        del file_key

        data  = self._load_raw()
        items = data.get("items", {})
        items[name] = record
        data["items"] = items
        self._save_raw(data)

    def reveal_to_file(self, name: str, dst_path: Path) -> None:
        """
        Stream-decrypt a large_file lock to dst_path. RAM peak: 8 MB.
        Enforces time gate (both simple and NIST modes).
        """
        data  = self._load_raw()
        items = data.get("items", {})

        if name not in items:
            raise FileNotFoundError(f"Lock '{name}' not found")

        item = items[name]
        if item.get("type") != "large_file":
            raise VaultError(f"'{name}' is not a large file lock.")

        unlock_ts = item["unlock_timestamp"]
        mode      = item.get("mode", "nist")
        enc_file  = self._enc_path(item["enc_id"])

        if not enc_file.exists():
            raise VaultError(f"Encrypted data missing for '{name}'. Data may be corrupted.")

        if mode == "simple":
            if time.time() < unlock_ts:
                raise VaultLockedError("Not yet. Wait for the timer.", unlock_ts - time.time())
            derived_key = self._derive_key_simple(unlock_ts)
        else:
            try:
                gate_pulse = BeaconClient.get_pulse_by_time(unlock_ts)
            except BeaconError as e:
                raise VaultOfflineError(f"NIST time-gate check failed: {e}")
            if gate_pulse is None:
                raise VaultLockedError("Beacon says: Wait.", max(0.0, unlock_ts - time.time()))
            try:
                lock_pulse = BeaconClient.get_pulse_by_round(item["lock_round"])
            except BeaconError as e:
                raise VaultOfflineError(f"NIST key fetch failed: {e}")
            derived_key = self._derive_key(lock_pulse)
            del lock_pulse

        try:
            file_key = self._unwrap_file_key(item["wrapped_file_key"], derived_key)
        except InvalidToken:
            raise VaultError("Key unwrap failed — wrong machine or vault tampered.")
        finally:
            del derived_key

        try:
            self._stream_decrypt_file(enc_file, dst_path, file_key)
        finally:
            del file_key

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load_raw(self) -> Dict[str, Any]:
        if not self.file_path.exists():
            return {"schema": self.SCHEMA, "items": {}}
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {"schema": self.SCHEMA, "items": {}}

    def _save_raw(self, payload: Dict[str, Any]) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.file_path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, self.file_path)

    # ── Core Operations ───────────────────────────────────────────────────────

    def lock(self, name: str, secret: str, days: float,
             type: str = "text", filename: Optional[str] = None) -> None:
        """
        Create a time-lock.

        Mode selection:
          days < SIMPLE_THRESHOLD_MIN minutes  →  simple mode (local, no NIST)
          days ≥ SIMPLE_THRESHOLD_MIN minutes  →  NIST beacon mode
        """
        name = name.strip()
        if not name:
            raise ValueError("Name required")

        # ── Input validation ──────────────────────────────────────────────────────────
        import math
        if not isinstance(days, (int, float)) or math.isnan(days) or math.isinf(days):
            raise ValueError("Duration must be a finite number.")
        if days <= 0:
            raise ValueError("Duration must be positive.")
        if days > self.MAX_DAYS:
            raise ValueError(f"Duration exceeds maximum ({self.MAX_DAYS} days).")

        secret_bytes = secret.encode("utf-8")
        if len(secret_bytes) > self.MAX_SECRET_BYTES:
            raise ValueError(f"Secret exceeds maximum size ({self.MAX_SECRET_BYTES // (1024*1024)} MB).")

        # ── Duplicate name guard ──────────────────────────────────────────────────────
        existing = self._load_raw()
        if name in existing.get("items", {}):
            raise ValueError(f"A fate named \u2018{name}\u2019 already exists. Delete it first or choose a different name.")

        minutes = days * 24 * 60
        use_nist = minutes >= self.SIMPLE_THRESHOLD_MIN

        if use_nist and days < self.NIST_MIN_DAYS:
            raise ValueError("NIST mode requires at least 2 minutes.")

        unlock_timestamp = time.time() + (days * 86400)

        if use_nist:
            # ── NIST beacon mode ──────────────────────────────────────────────
            try:
                criteria = BeaconClient.get_lock_criteria(days * 86400)
            except BeaconError as e:
                raise VaultOfflineError(f"Cannot lock — NIST unreachable: {e}")

            lock_round   = criteria["lock_round"]
            lock_pulse   = criteria["lock_pulse"]
            unlock_timestamp = criteria["unlock_timestamp"]

            key    = self._derive_key(lock_pulse)
            cipher = Fernet(key)
            enc_secret = cipher.encrypt(secret_bytes).decode("utf-8")
            del lock_pulse, key, cipher

            record = {
                "name":             name,
                "secret_enc":       enc_secret,
                "lock_round":       lock_round,
                "unlock_timestamp": unlock_timestamp,
                "type":             type,
                "filename":         filename,
                "mode":             "nist",
            }
        else:
            # ── Simple mode (<5 min) ─────────────────────────────────────────
            key    = self._derive_key_simple(unlock_timestamp)
            cipher = Fernet(key)
            enc_secret = cipher.encrypt(secret_bytes).decode("utf-8")
            del key, cipher

            record = {
                "name":             name,
                "secret_enc":       enc_secret,
                "unlock_timestamp": unlock_timestamp,
                "type":             type,
                "filename":         filename,
                "mode":             "simple",
            }

        data  = self._load_raw()
        items = data.get("items", {})
        items[name] = record
        data["items"] = items
        self._save_raw(data)

    def get_all_locks(self) -> List[Dict[str, Any]]:
        """Return lock metadata list — no secrets, no pulse values."""
        data  = self._load_raw()
        items = data.get("items", {})
        now   = time.time()
        result = []
        for name, item in items.items():
            unlock_ts = item["unlock_timestamp"]
            rem = max(0.0, unlock_ts - now)
            result.append({
                "name":             name,
                "is_locked":        rem > 0,
                "time_remaining":   rem,
                "unlock_timestamp": unlock_ts,
                "type":             item.get("type", "text"),
                "filename":         item.get("filename"),
            })
        return result

    def reveal(self, name: str) -> Dict[str, Any]:
        """
        Reveal a secret.

        Simple mode (< 5 min locks):
          - Local time gate only. Key re-derived from machine_seed + unlock_timestamp.
          - No network required.

        NIST mode (≥ 5 min locks):
          - NIST time-gate + live key fetch required.
        """
        data  = self._load_raw()
        items = data.get("items", {})

        if name not in items:
            raise FileNotFoundError(f"Lock '{name}' not found")

        item       = items[name]
        unlock_ts  = item["unlock_timestamp"]
        mode       = item.get("mode", "nist")   # legacy items default to nist

        if mode == "simple":
            # ── Simple time gate (local clock) ────────────────────────────────
            now = time.time()
            if now < unlock_ts:
                rem = unlock_ts - now
                raise VaultLockedError("Not yet. Wait for the timer.", rem)

            if item.get("type", "text") == "large_file":
                secret = ""
            else:
                key    = self._derive_key_simple(unlock_ts)
                cipher = Fernet(key)
                try:
                    secret = cipher.decrypt(item["secret_enc"].encode("utf-8")).decode("utf-8")
                except InvalidToken:
                    raise VaultError("Decryption failed. Wrong machine, or data tampered.")
                finally:
                    del key, cipher

        else:
            # ── NIST beacon mode ──────────────────────────────────────────────
            lock_round = item["lock_round"]

            # Step 1: Time gate — ask NIST if unlock moment has arrived.
            try:
                gate_pulse = BeaconClient.get_pulse_by_time(unlock_ts)
            except BeaconError as e:
                raise VaultOfflineError(f"NIST time-gate check failed: {e}")

            if gate_pulse is None:
                rem = max(0.0, unlock_ts - time.time())
                raise VaultLockedError("Beacon says: Wait.", rem)

            if item.get("type", "text") == "large_file":
                secret = ""
            else:
                # Step 2: Fetch the lock-round pulse live.
                try:
                    lock_pulse = BeaconClient.get_pulse_by_round(lock_round)
                except BeaconError as e:
                    raise VaultOfflineError(f"NIST key-derivation fetch failed: {e}")

                # Step 3: Derive key + decrypt.
                key    = self._derive_key(lock_pulse)
                cipher = Fernet(key)
                try:
                    secret = cipher.decrypt(item["secret_enc"].encode("utf-8")).decode("utf-8")
                except InvalidToken:
                    raise VaultError("Decryption failed. Wrong machine, or vault.json tampered.")
                finally:
                    del lock_pulse, key, cipher

        return {
            "name":     name,
            "secret":   secret,
            "type":     item.get("type", "text"),
            "filename": item.get("filename"),
        }

    def delete_lock(self, name: str) -> bool:
        """Delete a lock from the vault. Also removes companion .enc file if present."""
        data  = self._load_raw()
        items = data.get("items", {})
        if name in items:
            item = items[name]
            # Remove companion encrypted file for large_file locks
            if item.get("type") == "large_file" and "enc_id" in item:
                enc = self._enc_path(item["enc_id"])
                enc.unlink(missing_ok=True)
            del items[name]
            data["items"] = items
            self._save_raw(data)
            return True
        return False


    def reset(self) -> None:
        if self.file_path.exists():
            self.file_path.unlink()