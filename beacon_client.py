"""
beacon_client.py

Client for NIST Randomness Beacon.
Provides "Future Randomness" to mathematically gate time-locked vaults.

KEY DESIGN PROPERTY:
  Pulse VALUES are never cached locally — always fetched live from NIST.
  This means:  offline + code-modification = cannot decrypt.
  You MUST reach NIST to derive the key.
"""

import time
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple

try:
    import requests
except ImportError:
    requests = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BeaconError(Exception):
    pass


class BeaconClient:
    """
    NIST Randomness Beacon v2.0 client.

    Pulse interval: 60 seconds.
    timeStamp format: ISO 8601 string, e.g. "2026-02-19T17:47:00.000Z"
    """

    NIST_URL = "https://beacon.nist.gov/beacon/2.0/pulse"
    PULSE_INTERVAL = 60        # seconds between NIST pulses
    _TIMEOUT = 7
    _RETRIES = 3

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_ts(ts_str: str) -> float:
        """Parse NIST ISO timestamp string → POSIX float (UTC)."""
        dt = datetime.fromisoformat(ts_str.strip().rstrip("Z"))
        return dt.replace(tzinfo=timezone.utc).timestamp()

    @classmethod
    def _get(cls, url: str) -> dict:
        """GET with retries. Raises BeaconError on failure."""
        if requests is None:
            raise BeaconError("requests library not installed")
        last_err = None
        for attempt in range(cls._RETRIES):
            try:
                resp = requests.get(url, timeout=cls._TIMEOUT)
                resp.raise_for_status()
                return resp.json()
            except Exception as e:
                last_err = e
                if attempt < cls._RETRIES - 1:
                    time.sleep(1)
        raise BeaconError(f"NIST unreachable after {cls._RETRIES} attempts: {last_err}")

    # ── public API ────────────────────────────────────────────────────────────

    @classmethod
    def get_latest_pulse(cls) -> dict:
        """Fetch the most-recently published pulse. Raises BeaconError on failure."""
        return cls._get(f"{cls.NIST_URL}/last")

    @classmethod
    def get_pulse_by_round(cls, round_index: int) -> str:
        """
        Fetch the outputValue for a specific NIST round index.
        Round indices are always in the past, so this should always succeed.
        Raises BeaconError on failure.
        """
        data = cls._get(f"https://beacon.nist.gov/beacon/2.0/chain/2/pulse/{round_index}")
        return data["pulse"]["outputValue"]  # 512-bit hex string

    @classmethod
    def get_pulse_by_time(cls, timestamp: float) -> Optional[str]:
        """
        Fetch the outputValue for a specific POSIX timestamp.

        Returns:
          str   — hex outputValue if that moment has passed (unlocked).
          None  — if the timestamp is still in the future (locked).

        Raises BeaconError on genuine network/API failure.
        """
        if requests is None:
            raise BeaconError("requests library not installed")

        ts_ms    = int(timestamp * 1000)
        url      = f"{cls.NIST_URL}/time/{ts_ms}"
        last_err = None

        for attempt in range(cls._RETRIES):
            try:
                resp = requests.get(url, timeout=cls._TIMEOUT)

                # NIST returns 404 when no pulse exists yet for a future timestamp.
                if resp.status_code == 404:
                    return None

                resp.raise_for_status()
                data = resp.json()
                break

            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 404:
                    return None
                last_err = e
                if attempt < cls._RETRIES - 1:
                    time.sleep(1)
            except Exception as e:
                last_err = e
                if attempt < cls._RETRIES - 1:
                    time.sleep(1)
        else:
            raise BeaconError(f"NIST unreachable after {cls._RETRIES} attempts: {last_err}")

        pulse_ts = cls._parse_ts(data["pulse"]["timeStamp"])
        now_utc  = time.time()

        # Guard: NIST returned a pulse implausibly ahead of wall-clock.
        if pulse_ts > now_utc + cls.PULSE_INTERVAL:
            logger.warning("NIST pulse timestamp is ahead of wall-clock — treating as locked.")
            return None

        # Core check: the closest pulse NIST gave us must be within one interval
        # of the target time to count as "arrived."
        if pulse_ts < timestamp - cls.PULSE_INTERVAL:
            return None

        return data["pulse"]["outputValue"]

    @classmethod
    def get_lock_criteria(cls, duration_seconds: float) -> dict:
        """
        Returns metadata for creating a new time-lock entry.
        Fetches current pulse live — value NOT stored in vault.
        Returns round INDEX only (used to fetch pulse at decrypt time).
        Raises BeaconError if NIST unreachable.
        """
        latest     = cls.get_latest_pulse()
        now        = time.time()
        unlock_ts  = now + duration_seconds
        lock_round = latest["pulse"]["pulseIndex"]     # int — stored in vault.json

        # lock_pulse_value is used for key derivation RIGHT NOW during lock()
        # but is NOT persisted — it must be re-fetched via lock_round at reveal time.
        lock_pulse = latest["pulse"]["outputValue"]    # 512-bit hex — ephemeral only

        return {
            "unlock_timestamp": unlock_ts,
            "lock_timestamp":   now,
            "lock_round":       lock_round,   # index only — stored
            "lock_pulse":       lock_pulse,   # value only — NOT stored
        }
