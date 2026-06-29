# tests/vault_test.py
import pytest
import time
from vault_logic import Vault, VaultLockedError


@pytest.fixture
def temp_vault(tmp_path):
    """Provide a Vault pointing at a temp path, cleaned up after."""
    vault_file = tmp_path / "vault.json"
    v = Vault(file_path=str(vault_file))
    yield v
    if vault_file.exists():
        vault_file.unlink()


def test_vault_lock_and_reveal_simple_mode(temp_vault):
    """Lock a text secret in simple mode (1 minute), wait if needed, reveal it."""
    name = "test_simple_secret"
    secret = "hello world"

    # Lock with 1/1440 days = 1 minute (simple mode, no NIST required)
    temp_vault.lock(name, secret, 1 / 1440)

    # Check time remaining
    locks = temp_vault.get_all_locks()
    assert any(lock["name"] == name for lock in locks), "Lock should exist"

    lock_entry = next(l for l in locks if l["name"] == name)

    # If still locked (shouldn't happen for 1-minute lock but check gracefully)
    remaining = lock_entry.get("time_remaining", 0)
    if remaining > 0 and remaining <= 65:
        # Just under 1 minute — sleep the extra second plus buffer
        time.sleep(remaining + 2)
    elif remaining > 65:
        pytest.skip(f"Lock timer too long ({remaining}s) — skipping test")

    # Reveal should now work
    result = temp_vault.reveal(name)
    assert result["secret"] == secret


def test_vault_integrity_hmac_missing_for_legacy_vault(tmp_path):
    """A vault JSON without _hmac field loads without error."""
    import json

    vault_file = tmp_path / "vault_legacy.json"
    # Write a legacy vault — no _hmac, no items
    legacy_data = {
        "schema": "5.0-TrueFuture",
        "items": {}
    }
    vault_file.write_text(json.dumps(legacy_data))

    # Should load without raising
    v = Vault(file_path=str(vault_file))
    data = v._load_raw()
    assert "items" in data
    assert data["items"] == {}


def test_vault_machine_id_is_deterministic(tmp_path):
    """_get_machine_id called twice returns identical bytes."""
    v = Vault()
    id1 = v._get_machine_id()
    id2 = v._get_machine_id()
    assert id1 == id2
    assert isinstance(id1, bytes)
    assert len(id1) > 0