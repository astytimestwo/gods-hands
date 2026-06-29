# Contributing

Thanks for helping improve God's Hands.

## Local Setup

```bash
python -m venv .venv
python -m pip install -r requirements.txt pytest
```

Run the automated tests:

```bash
python -m pytest -q
```

Live NIST beacon tests are disabled by default so local and CI runs stay deterministic. To include them:

```bash
RUN_LIVE_BEACON_TESTS=1 python -m pytest -q
```

## Before Opening a Pull Request

- Do not commit `vault.json`, `.enc` files, keys, logs, virtual environments, or local model files.
- Keep changes focused and include tests for behavior changes.
- Document any security-sensitive change in the pull request description.
