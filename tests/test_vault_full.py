import unittest
import os
import shutil
import tempfile
import time
import json
import hmac as _hmac
from pathlib import Path
from unittest.mock import patch, MagicMock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from vault_logic import Vault, VaultError, VaultLockedError, VaultOfflineError, _is_garbage_identifier
from beacon_client import BeaconClient, BeaconError


class TestGodsVault(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for the vault file and enc files
        self.test_dir = Path(tempfile.mkdtemp())
        self.vault_path = self.test_dir / "test_vault.json"
        self.vault = Vault(file_path=str(self.vault_path))

    def tearDown(self):
        # Clean up the temporary directory
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_garbage_identifier_filtering(self):
        # Test the helper directly
        self.assertTrue(_is_garbage_identifier("FFFFFFFF"))
        self.assertTrue(_is_garbage_identifier("0000000000"))
        self.assertTrue(_is_garbage_identifier("None"))
        self.assertTrue(_is_garbage_identifier("Default string"))
        self.assertTrue(_is_garbage_identifier("To Be Filled By O.E.M."))
        self.assertTrue(_is_garbage_identifier("unknown"))
        self.assertTrue(_is_garbage_identifier("00000000-0000-0000-0000-000000000000"))
        self.assertTrue(_is_garbage_identifier("   "))
        self.assertTrue(_is_garbage_identifier("0000"))  # repeating chars
        self.assertTrue(_is_garbage_identifier("11111111"))  # repeating chars
        self.assertFalse(_is_garbage_identifier("12345ABCDE")) # valid serial

    def test_simple_mode_roundtrip(self):
        name = "simple_secret"
        secret = "hello_world_simple"
        # Lock for 0.00001 days (~0.86 seconds)
        days = 0.00001
        
        self.vault.lock(name, secret, days)
        
        # Immediate decrypt should fail because time hasn't passed
        with self.assertRaises(VaultLockedError):
            self.vault.reveal(name)
            
        # Mock time.time to be in the future
        future_time = time.time() + (days * 86400) + 1
        with patch('time.time', return_value=future_time):
            result = self.vault.reveal(name)
            self.assertEqual(result["secret"], secret)

    def test_large_file_roundtrip_and_tamper(self):
        # Create a dummy source file
        src_path = self.test_dir / "source.txt"
        content = b"This is a large file content to be encrypted!" * 100
        src_path.write_bytes(content)
        
        name = "file_secret"
        days = 0.00001
        
        # Lock large file
        self.vault.lock_large(name, src_path, src_path.name, days)
        
        # Verify .enc file was created
        enc_id = self.vault._load_raw()["items"][name]["enc_id"]
        enc_file = self.vault._enc_path(enc_id)
        self.assertTrue(enc_file.exists())
        
        # Immediate decrypt should fail
        dst_path = self.test_dir / "output.txt"
        with self.assertRaises(VaultLockedError):
            self.vault.reveal_to_file(name, dst_path)
            
        # Mock time to future
        future_time = time.time() + (days * 86400) + 1
        with patch('time.time', return_value=future_time):
            # Reveal success
            self.vault.reveal_to_file(name, dst_path)
            self.assertTrue(dst_path.exists())
            self.assertEqual(dst_path.read_bytes(), content)
            
            # Remove output to test tamper
            dst_path.unlink()
            
            # Tamper with the encrypted file (flip last byte)
            enc_bytes = bytearray(enc_file.read_bytes())
            enc_bytes[-1] ^= 0xFF
            enc_file.write_bytes(bytes(enc_bytes))
            
            # Decrypt should fail with VaultError (HMAC verification fails)
            with self.assertRaises(VaultError):
                self.vault.reveal_to_file(name, dst_path)
                
            # Verify no partial plaintext file remains
            self.assertFalse(dst_path.exists())
            self.assertFalse(dst_path.with_name(dst_path.name + ".tmp").exists())

    def test_vault_hmac_tamper_detection(self):
        name = "tamper_test"
        secret = "super_secret"
        days = 0.00001
        
        self.vault.lock(name, secret, days)
        
        # Load raw data and alter it manually back to vault.json without updating _hmac
        with open(self.vault_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # Tamper with the item's timestamp manually
        data["items"][name]["unlock_timestamp"] -= 1000
        with open(self.vault_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            
        # Initializing a new Vault instance and loading should fail due to HMAC mismatch
        with self.assertRaises(VaultError) as ctx:
            v2 = Vault(file_path=str(self.vault_path))
            v2.reveal(name)
        self.assertIn("integrity check failed", str(ctx.exception))

    def test_machine_binding_fails_on_different_machine(self):
        name = "machine_secret"
        secret = "only_on_this_machine"
        days = 0.00001
        
        self.vault.lock(name, secret, days)
        
        # Mock different machine ID
        future_time = time.time() + (days * 86400) + 1
        with patch('time.time', return_value=future_time):
            # Same machine should work
            result = self.vault.reveal(name)
            self.assertEqual(result["secret"], secret)
            
            # Now simulate a different machine by patching _get_machine_id
            with patch.object(Vault, '_get_machine_id', return_value=b"different_machine_seed_123456"):
                # Initializing a vault or loading should raise VaultError on integrity check
                with self.assertRaises(VaultError):
                    v2 = Vault(file_path=str(self.vault_path))
                    v2.reveal(name)

    @patch('beacon_client.requests')
    def test_nist_mode_roundtrip(self, mock_requests):
        # 1000000000.0 is 2001-09-09T01:46:40.000Z
        # 1000000864.0 is 2001-09-09T02:01:04.000Z
        start_time = 1000000000.0

        # Mock responses
        mock_last_resp = MagicMock()
        mock_last_resp.status_code = 200
        mock_last_resp.json.return_value = {
            "pulse": {
                "pulseIndex": 123456,
                "outputValue": "a" * 128, # 512-bit hex
                "timeStamp": "2001-09-09T01:46:40.000Z"
            }
        }
        
        mock_time_resp = MagicMock()
        mock_time_resp.status_code = 200
        mock_time_resp.json.return_value = {
            "pulse": {
                "pulseIndex": 123461,
                "outputValue": "b" * 128,
                "timeStamp": "2001-09-09T02:01:04.000Z"
            }
        }
        
        mock_round_resp = MagicMock()
        mock_round_resp.status_code = 200
        mock_round_resp.json.return_value = {
            "pulse": {
                "pulseIndex": 123456,
                "outputValue": "a" * 128,
                "timeStamp": "2001-09-09T01:46:40.000Z"
            }
        }
        
        def mock_get(url, *args, **kwargs):
            if "/last" in url:
                return mock_last_resp
            elif "/time/" in url:
                return mock_time_resp
            elif "/pulse/" in url:
                return mock_round_resp
            raise ValueError(f"Unexpected URL: {url}")
            
        mock_requests.get = mock_get
        
        # NIST mode: lock for 0.01 days (~14.4 minutes, which is >= 5 min simple threshold)
        name = "nist_secret"
        secret = "hello_nist"
        days = 0.01
        
        # Lock item with mocked time
        with patch('time.time', return_value=start_time):
            self.vault.lock(name, secret, days)
        
        # Ensure it is locked in NIST mode
        raw_data = self.vault._load_raw()
        self.assertEqual(raw_data["items"][name]["mode"], "nist")
        self.assertEqual(raw_data["items"][name]["lock_round"], 123456)
        
        # Case A: Locked. NIST get_pulse_by_time returns 404 (None)
        mock_404_resp = MagicMock()
        mock_404_resp.status_code = 404
        
        def mock_get_locked(url, *args, **kwargs):
            if "/last" in url:
                return mock_last_resp
            elif "/time/" in url:
                return mock_404_resp
            elif "/pulse/" in url:
                return mock_round_resp
            raise ValueError(f"Unexpected URL: {url}")
            
        mock_requests.get = mock_get_locked
        with patch('time.time', return_value=start_time + 854):
            with self.assertRaises(VaultLockedError):
                self.vault.reveal(name)
            
        # Case B: Unlocked. NIST get_pulse_by_time returns valid pulse
        mock_requests.get = mock_get
        with patch('time.time', return_value=start_time + 865):
            result = self.vault.reveal(name)
            self.assertEqual(result["secret"], secret)

    def test_backward_compatibility_unfiltered_smbios(self):
        # Generate the HKDF seeds
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.backends import default_backend
        
        # unfiltered has VM placeholder, filtered has it removed
        identifiers_unfiltered = [b"To Be Filled By O.E.M.", b"mac_bytes"]
        identifiers_filtered = [b"mac_bytes"]
        
        def get_hkdf_seed(ids):
            combined = b"|".join(ids) + b"hostname" + b"machine-proc"
            return HKDF(
                algorithm=_hashes.SHA3_512(),
                length=64,
                salt=b"GodsHands-machine-salt-v2",
                info=b"GodsHands-v1-machine-seed",
                backend=default_backend()
            ).derive(combined)
            
        seed_unfiltered = get_hkdf_seed(identifiers_unfiltered)
        seed_filtered = get_hkdf_seed(identifiers_filtered)
        
        def mock_get_machine_id(reject_garbage=True):
            return seed_filtered if reject_garbage else seed_unfiltered
            
        unfiltered_integrity_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"GodsHands-vault-integrity-v1",
            info=b"vault-integrity",
        ).derive(seed_unfiltered)
        
        vault_payload = {
            "schema": Vault.SCHEMA,
            "items": {
                "compat_secret": {
                    "name": "compat_secret",
                    "secret_enc": "...",
                    "unlock_timestamp": time.time() + 100,
                    "mode": "simple"
                }
            }
        }
        
        canonical = json.dumps(vault_payload, sort_keys=True, separators=(',', ':'))
        stored_hmac = _hmac.new(unfiltered_integrity_key, canonical.encode('utf-8'), 'sha256').hexdigest()
        vault_payload["_hmac"] = stored_hmac
        
        with open(self.vault_path, "w", encoding="utf-8") as f:
            json.dump(vault_payload, f, indent=2)
            
        with patch.object(Vault, '_get_machine_id', side_effect=mock_get_machine_id):
            v = Vault(file_path=str(self.vault_path))
            loaded = v._load_raw()
            self.assertIn("compat_secret", loaded["items"])
            self.assertEqual(v._machine_seed, seed_unfiltered)


if __name__ == '__main__':
    unittest.main()
