# God's Hands

### Time-Locked Cryptographic Storage System

God's Hands is a local storage system designed for absolute privacy and mathematically enforced time-locking. It utilizes external entropy sources to ensure that data remains inaccessible until a predefined timestamp has passed.

Unlike conventional time-lock mechanisms that rely on system clocks or centralized middle-ware, God's Hands binds encryption keys to the NIST Randomness Beacon. This ensures that the cryptographic variables required for decryption literally do not exist until they are broadcast by the beacon at the specified time.

> **HARDWARE BINDING:** Decryption keys are bound to firmware-level SMBIOS identifiers (OEM service tag, motherboard serial, SMBIOS UUID). OS updates do not break key access — only a motherboard replacement would. Vault integrity is protected by HMAC-SHA256.

---

## Technical Specifications

| Component | Implementation |
|-----------|---------------|
| **Ciphers** | AES-256-CTR (streaming), Fernet (envelope) |
| **Integrity** | HMAC-SHA256 (vault + .enc files) |
| **Key Derivation** | PBKDF2-HMAC-SHA256 (1M iterations NIST, 500K simple) |
| **Machine Binding** | HKDF-SHA3-512 over SMBIOS UUID + motherboard serial + OEM service tag |
| **Vault Integrity** | HMAC-SHA256 on canonical JSON (excludes `_hmac` field) |
| **Time Source** | NIST Randomness Beacon v2.0 (60s pulse interval) |
| **Rate Limiting** | 5-fail / 30s lockout per entry on reveal operations |

---

## Security Properties

**Time-Lock Enforcement:**
- **< 5 minutes:** Wall-clock only (simple mode)
- **≥ 5 minutes:** Cryptographically bound to NIST beacon pulse — mathematically impossible to derive key before unlock time

**Hardware Stability:**
- Machine ID derives from firmware-level SMBIOS identifiers, not OS-level signals
- Survives OS reinstall, driver updates, MAC address changes
- Only a motherboard replacement would break key access

**Vault Integrity:**
- Every vault load verifies HMAC-SHA256 over canonical JSON
- Tampering with timestamps or `permanent` flags is detectable
- Legacy vaults (no HMAC) load normally and get HMAC on next save

**Brute-Force Protection:**
- Per-entry rate limiting: 5 failed reveals triggers 30s lockout
- 1M PBKDF2 iterations for NIST mode, 500K for simple mode

---

## Architecture

### Time-Lock Mechanism

```
Lock time:
  1. Fetch current NIST pulse (not stored — derived at reveal time via lock_round)
  2. Derive KEK: PBKDF2(machine_seed, lock_pulse, 1M)
  3. Generate random DEK (32 bytes)
  4. Encrypt secret with Fernet(DEK), wrap DEK with KEK
  5. Store wrapped_dek + lock_round + unlock_timestamp in vault.json

Unlock time:
  1. Fetch NIST pulse for unlock timestamp (time-gate check)
  2. If pulse exists, fetch lock_round pulse and re-derive KEK
  3. Unwrap DEK, decrypt secret
```

### File Encryption (large files)

```
.enc file layout: [GVLT magic][IV][HMAC-SHA256][ciphertext...]
  - 8MB streaming chunks — RAM peak is always 8MB regardless of file size
  - Unique DEK per file, wrapped by the same KEK as text entries
  - HMAC computed over IV || ciphertext for integrity verification
```

### Machine ID Derivation

```
Firmware sources → HKDF-SHA3-512 → 64-byte machine_seed

Sources (all from SMBIOS/firmware):
  - Win32_ComputerSystemProduct.IdentifyingNumber (OEM service tag)
  - Win32_ComputerSystemProduct.UUID (SMBIOS UUID)
  - Win32_BaseBoard.SerialNumber (motherboard serial)
  - Fallback: MAC address

Salt: "GodsHands-machine-salt-v2"
Info: "GodsHands-v1-machine-seed"
```

---

## Deployment

### Prerequisites

- **Windows** or **Linux**
- Python 3.10+

### Installation

```bash
pip install -r requirements.txt
```

**Linux only** — pywebview requires GTK3:
```bash
sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1
```

### Launch

- Windows: `python app.py` or `run.bat`
- Linux: `python3 app.py` or `./run.sh`

---

## CLI Reference

```bash
# List all entries
python cli.py list

# Lock text secret
python cli.py lock <name> "<secret>" <minutes>

# Lock file (streaming encryption)
python cli.py lock-file <name> <path> <minutes>

# Unlock (text prints to stdout, files stream to Downloads)
python cli.py unlock <name>

# Delete entry
python cli.py delete <name>
```

---

## Security Model

God's Hands is designed for cryptographic self-enforcement and theft prevention.

- **Authenticated vault integrity** prevents silent tampering with timestamps
- **Hardware binding** ensures a stolen disk cannot be decrypted on another machine
- **NIST-bound key derivation** makes early reveal mathematically impossible for ≥5min locks
- **Rate limiting** deters brute-force attacks on the reveal pathway

The local security model assumes a non-compromised execution environment. As with all local-first tools, an administrator with root access to the running system can bypass any restriction — this is by design for legitimate use cases.

> "A good cryptosystem should be secure even if everything about the system, except the key, is public knowledge." — Auguste Kerckhoffs

---

## License

Dual-licensed:
1. **GPL v3** — open source, derivative works must be open-sourced
2. **Commercial** — closed-source/commercial use requires separate license

Contact for commercial licensing.