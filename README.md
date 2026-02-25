# God's Hands

### Time-Locked Cryptographic Storage System

God's Hands is a local storage system designed for absolute privacy and mathematically enforced time-locking. It utilizes external entropy sources to ensure that data remains inaccessible until a predefined timestamp has passed.

Unlike conventional time-lock mechanisms that rely on system clocks or centralized middle-ware, God's Hands binds encryption keys to the NIST Randomness Beacon. This ensures that the cryptographic variables required for decryption literally do not exist until they are broadcast by the beacon at the specified time.

> ⚠️ **DIVINE PERMANENCE:** This vault is bound to this specific hardware. If this computer dies, your secrets die with it. There is no back door.

---

## Technical Specifications

- **Ciphers:** AES-256-CTR (Streaming)
- **Integrity:** HMAC-SHA256
- **Key Derivation:** PBKDF2-HMAC-SHA256
- **Environment Binding:** SHA3-512 Hardware Fingerprinting
- **Time Source:** NIST Randomness Beacon v2.0

---

## System Architecture

### 1. Entropy-Bound Time Locking

God's Hands implements time-locking by mapping a future unlock date to a specific NIST Randomness Pulse index. The key derivation process requires the future pulse value as an input. Since the beacon has not yet broadcast the pulse for a future date, the key is mathematically unavailable until the designated time.

### 2. Streaming Authenticated Encryption

To support the storage of high-volume data (exceeding 10GB) without exceeding system memory limits, God's Hands uses a streaming cipher engine.

- Data is processed in 8MB segments.
- Integrity is verified via continuous HMAC-SHA256 calculation.
- Unique ephemeral file keys are generated and wrapped using the master key.

### 3. Hardware Isolation

Decryption capability is restricted to the host machine. The application generates a stable SHA3-512 fingerprint derived from system hardware identifiers (MAC address, CPU architecture, and Machine ID). This fingerprint serves as the cryptographic salt, ensuring the database remains inaccessible if moved to an external environment.

---

## Security Model and Threat Analysis

God's Hands is designed for cryptographic self-enforcement and theft prevention.

- **Authenticated Protection:** Mitigates risks associated with physical disk theft, database exfiltration, and unauthorized access attempts prior to the unlock threshold.
- **System Constraints:** As a local application, enforcement depends on the integrity of the execution environment. While mathematically sound, the local security model assumes the host environment is not being intentionally compromised by an administrator with the ability to modify application source code.

"A good cryptosystem should be secure even if everything about the system, except the key, is public knowledge." — Auguste Kerckhoffs

---

## Deployment

### Prerequisites

- **Windows** or **Linux**
- Python 3.10 or higher

### Installation

1. Install dependencies:
   `pip install -r requirements.txt`

2. **Linux only** — pywebview requires GTK3:

   ```bash
   sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1
   ```

3. Launch:
   - Windows: `python app.py` or `run.bat`
   - Linux: `python3 app.py` or `./run.sh`

### Operating Modes

- **Simple Mode:** Local hardware-based time-gating for durations under 5 minutes.
- **NIST Mode:** Cryptographic time-binding for durations exceeding 5 minutes. Requires network connectivity for beacon pulse retrieval during the reveal phase.

### CLI Instructions

God's Hands can be operated headlessly via the included `cli.py` engine wrapper:

- **List entries:** `python cli.py list`
- **Lock text:** `python cli.py lock <name> "<secret text>" <minutes>`
- **Lock file (Streaming):** `python cli.py lock-file <name> <file_path> <minutes>`
- **Unlock entry:** `python cli.py unlock <name>` *(Note: Files are automatically stream-decrypted directly into your Downloads folder)*
- **Delete entry:** `python cli.py delete <name>`

---

## License & Commercial Use

God's Hands is dual-licensed:

1. **Open Source (GPL v3):** Use, modify, and distribute for free, provided that all derivative works are also open-sourced under the GPL v3.
2. **Commercial License:** If you wish to use God's Hands logic or code within a closed-source/commercial product, a separate commercial license is required.

For commercial inquiries, please contact the author.
