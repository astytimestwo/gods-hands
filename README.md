# God's Hands

Time-locked cryptographic storage for local secrets and files.

God's Hands is a local vault that binds decryption to both the current machine and an unlock time. Short locks use a local wall-clock convenience mode. Longer locks use the NIST Randomness Beacon so the key material required for decryption is not available until the target time has passed.

## Security Summary

| Area | Implementation |
| --- | --- |
| Text encryption | Fernet envelope encryption |
| Large file encryption | AES-256-CTR streaming encryption |
| Integrity | HMAC-SHA256 for vault metadata and encrypted files |
| Key derivation | PBKDF2-HMAC-SHA256 |
| Machine binding | HKDF-SHA3-512 over firmware identifiers with MAC fallback |
| Time source | NIST Randomness Beacon v2.0 |
| Reveal rate limit | 5 failed attempts, then 30 second lockout |

## Time-Lock Modes

Simple mode is used for locks under five minutes. It is convenient for testing and short personal delays, but it is not a cryptographic time-lock. A user with local access can bypass it by changing local time or code.

NIST mode is used for locks of five minutes or longer. It gates reveal through the NIST Randomness Beacon and derives key material from beacon output. This means NIST availability is required to unlock NIST-mode entries.

## Project Layout

```text
.
|-- app.py                  # pywebview desktop app bridge
|-- vault_v3.html           # React/Tailwind UI loaded by pywebview
|-- vault_logic.py          # vault encryption, persistence, reveal rules
|-- beacon_client.py        # NIST beacon client and source abstraction
|-- cli.py                  # command-line interface
|-- tests/                  # pytest/unittest test suite
|-- docs/                   # planning and design notes
|-- requirements.txt        # runtime dependencies
|-- pyproject.toml          # pytest configuration
|-- CONTRIBUTING.md
|-- SECURITY.md
|-- LICENSE
```

Local-only folders such as `.venv/`, `.pytest_cache/`, `__pycache__/`, `.claude/`, `.remember/`, `.playwright-mcp/`, and `models/` are ignored and should not be published.

## Installation

Python 3.10 or newer is recommended.

```bash
python -m venv .venv
python -m pip install -r requirements.txt
```

On Linux, pywebview may also need GTK/WebKit packages:

```bash
sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1
```

## Running the App

Windows:

```bash
python app.py
```

Linux/macOS:

```bash
python3 app.py
```

You can also use the helper scripts:

```bash
run.bat
./run.sh
```

## CLI Usage

```bash
python cli.py list
python cli.py lock <name> "<secret>" <minutes>
python cli.py lock-file <name> <path> <minutes>
python cli.py unlock <name>
python cli.py delete <name>
```

## Testing

Install pytest if it is not already available:

```bash
python -m pip install pytest
```

Run the local deterministic test suite:

```bash
python -m pytest -q
```

Live NIST beacon tests are skipped by default. To run them:

```bash
RUN_LIVE_BEACON_TESTS=1 python -m pytest -q
```

## Security Warnings

Simple mode does not provide cryptographic time-lock guarantees. Use NIST mode for meaningful time-lock enforcement.

Machine binding is a theft deterrent, not a perfect hardware security boundary. If firmware identifiers are unavailable, fallback identifiers may be easier to spoof.

NIST mode depends on the NIST Randomness Beacon API. If the service is unavailable, NIST-mode entries cannot be revealed until access returns.

Do not commit vault data, encrypted payloads, keys, logs, or local models.

## License

This project is dual-licensed:

1. GPL v3 for open-source use.
2. Commercial license for closed-source or commercial use by separate agreement.
