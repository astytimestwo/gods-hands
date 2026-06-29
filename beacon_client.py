"""
beacon_client.py

Client for NIST Randomness Beacon.
Provides "Future Randomness" to mathematically gate time-locked vaults.

KEY DESIGN PROPERTY:
  Pulse VALUES are never cached locally — always fetched live from NIST.
  This means:  offline + code-modification = cannot decrypt.
  You MUST reach NIST to derive the key.

Multi-source support:
  BeaconClient now supports multiple beacon sources with fallback.
  Each source is a BeaconSource subclass with fetch_pulse(), get_pulse_by_round(),
  and get_pulse_by_time() methods. _try_sources() iterates until one succeeds
  for each public API call. Add sources via BeaconClient.add_source().
"""

import time
import logging
from datetime import datetime, timezone
from typing import Optional, List, Tuple, Any

try:
    import requests
except ImportError:
    requests = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 7
_DEFAULT_RETRIES = 3


class BeaconError(Exception):
    pass


# ── Source hierarchy ──────────────────────────────────────────────────────────

class BeaconSource:
    """
    A single beacon source with a name and pulse-fetching callable.
    Subclasses implement specific beacon protocols (NIST, BlockClock, etc.).
    """

    def __init__(self, name: str, pulse_fn=None):
        self.name = name
        self._pulse_fn = pulse_fn
        self.call_count = 0

    def fetch_pulse(self, timeout: int = _DEFAULT_TIMEOUT) -> dict:
        """Fetch the latest pulse from this source. Override in subclasses."""
        self.call_count += 1
        if self._pulse_fn:
            return self._pulse_fn()
        raise BeaconError(f"Source '{self.name}' has no fetch_pulse implementation")

    def get_pulse_by_round(self, round_index: int, timeout: int = _DEFAULT_TIMEOUT) -> str:
        """Fetch outputValue for a specific round index. Override in subclasses."""
        raise BeaconError(f"Source '{self.name}' does not support get_pulse_by_round")

    def get_pulse_by_time(self, timestamp: float, timeout: int = _DEFAULT_TIMEOUT) -> Optional[str]:
        """Fetch outputValue for a specific POSIX timestamp. Override in subclasses."""
        raise BeaconError(f"Source '{self.name}' does not support get_pulse_by_time")


class NISTBeaconSource(BeaconSource):
    """
    NIST Randomness Beacon v2.0 source.

    Pulse interval: 60 seconds.
    timeStamp format: ISO 8601 string, e.g. "2026-02-19T17:47:00.000Z"
    """

    NIST_URL = "https://beacon.nist.gov/beacon/2.0/pulse"
    PULSE_INTERVAL = 60  # seconds between NIST pulses

    def __init__(self):
        super().__init__("nist")

    # ── NIST-specific fetch methods ─────────────────────────────────────────

    def fetch_pulse(self, timeout: int = _DEFAULT_TIMEOUT) -> dict:
        """Fetch the most-recently published pulse from NIST."""
        self.call_count += 1
        resp = requests.get(f"{self.NIST_URL}/last", timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    def get_pulse_by_round(self, round_index: int, timeout: int = _DEFAULT_TIMEOUT) -> str:
        """Fetch outputValue for a specific round index from NIST."""
        resp = requests.get(
            f"{self.NIST_URL}/chain/2/pulse/{round_index}",
            timeout=timeout
        )
        resp.raise_for_status()
        return resp.json()["pulse"]["outputValue"]

    def get_pulse_by_time(self, timestamp: float, timeout: int = _DEFAULT_TIMEOUT) -> Optional[str]:
        """
        Fetch outputValue for a specific POSIX timestamp from NIST.

        Returns:
          str   — hex outputValue if that moment has passed (unlocked).
          None  — if the timestamp is still in the future (locked).

        Raises BeaconError on genuine network/API failure (non-404 errors).
        """
        ts_ms = int(timestamp * 1000)
        resp = requests.get(
            f"{self.NIST_URL}/time/{ts_ms}",
            timeout=timeout
        )
        # NIST returns 404 when no pulse exists yet for a future timestamp.
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()

        pulse_ts = self.parse_ts(data["pulse"]["timeStamp"])
        now_utc = time.time()

        # Guard: NIST returned a pulse implausibly ahead of local clock.
        # This detects significant clock skew or API anomalies. 5s tolerance
        # covers normal network transit jitter; anything more is suspicious.
        if pulse_ts > now_utc + 5:
            logger.warning("NIST pulse timestamp is more than 5s ahead of wall-clock.")
            return None

        # Core check: pulse must be at or after the unlock timestamp.
        # A pulse from before the unlock moment cannot authorize early reveal.
        if pulse_ts < timestamp:
            return None

        return data["pulse"]["outputValue"]

    @staticmethod
    def parse_ts(ts_str: str) -> float:
        """Parse NIST ISO timestamp string → POSIX float (UTC)."""
        dt = datetime.fromisoformat(ts_str.strip().rstrip("Z"))
        return dt.replace(tzinfo=timezone.utc).timestamp()


# ── Client with fallback ──────────────────────────────────────────────────────

class BeaconClient:
    """
    Multi-source beacon client. Tries sources in order until one succeeds.

    Default sources: NISTBeaconSource.
    Add fallbacks via BeaconClient.add_source() or via constructor.

    Public API (backward-compatible with class-method callers in vault_logic.py):
      get_latest_pulse()   → full pulse dict
      get_pulse_by_round(round_index) → outputValue hex string
      get_pulse_by_time(timestamp) → outputValue hex string or None
      get_lock_criteria(duration_seconds) → dict with unlock_timestamp, lock_timestamp, lock_round, lock_pulse
    """

    _TIMEOUT = _DEFAULT_TIMEOUT
    _RETRIES = _DEFAULT_RETRIES

    # Class-level source registry — can be overridden per-instance or subclass
    _sources: List[Tuple[str, BeaconSource]] = [("nist", NISTBeaconSource())]

    # ── source management ───────────────────────────────────────────────────

    @classmethod
    def add_source(cls, source: BeaconSource) -> None:
        """
        Add a fallback beacon source globally.
        Thread-safe enough for this single-threaded use case.
        """
        cls._sources.append((source.name, source))

    @classmethod
    def _try_sources(cls, method_name: str, *args, **kwargs) -> Any:
        """
        Try each source in order until one succeeds.
        A source returning None is treated as a terminal result for that method
        (e.g., get_pulse_by_time returning None means "still locked").
        Raises BeaconError only when all sources fail with exceptions.
        """
        last_err = None
        for name, source in cls._sources:
            try:
                fn = getattr(source, method_name)
                result = fn(*args, **kwargs)
                logger.info(f"Beacon source '{name}' responded for {method_name}")
                return result
            except BeaconError as e:
                last_err = e
                logger.warning(f"Beacon source '{name}' failed for {method_name}: {e}")
                continue
        raise BeaconError(f"All beacon sources failed. Last error: {last_err}")

    # ── public API (classmethods for backward compatibility) ────────────────

    @classmethod
    def get_latest_pulse(cls) -> dict:
        """Fetch the most-recently published pulse. Raises BeaconError on failure."""
        return cls._try_sources("fetch_pulse", cls._TIMEOUT)

    @classmethod
    def get_pulse_by_round(cls, round_index: int) -> str:
        """
        Fetch the outputValue for a specific NIST round index.
        Round indices are always in the past, so this should always succeed.
        Raises BeaconError on failure.
        """
        last_err = None
        for name, source in cls._sources:
            try:
                return source.get_pulse_by_round(round_index, cls._TIMEOUT)
            except Exception as e:
                last_err = e
                logger.warning(f"Source '{name}' failed get_pulse_by_round({round_index}): {e}")
                continue
        raise BeaconError(
            f"Could not fetch round {round_index} from any source. Last error: {last_err}"
        )

    @classmethod
    def get_pulse_by_time(cls, timestamp: float) -> Optional[str]:
        """
        Fetch the outputValue for a specific POSIX timestamp.

        Returns:
          str   — hex outputValue if that moment has passed (unlocked).
          None  — if the timestamp is still in the future (locked).

        Raises BeaconError on genuine network/API failure (all sources fail with non-404 errors).
        """
        last_err = None
        for name, source in cls._sources:
            try:
                result = source.get_pulse_by_time(timestamp, cls._TIMEOUT)
                logger.info(f"Beacon source '{name}' responded for get_pulse_by_time")
                return result
            except BeaconError as e:
                last_err = e
                logger.warning(f"Beacon source '{name}' failed get_pulse_by_time: {e}")
                continue
        raise BeaconError(f"All beacon sources failed for time {timestamp}. Last error: {last_err}")

    @classmethod
    def get_lock_criteria(cls, duration_seconds: float) -> dict:
        """
        Returns metadata for creating a new time-lock entry.
        Fetches current pulse live — value NOT stored in vault.
        Returns round INDEX only (used to fetch pulse at decrypt time).
        Raises BeaconError if all sources are unreachable.
        """
        latest = cls.get_latest_pulse()
        now = time.time()
        unlock_ts = now + duration_seconds
        lock_round = latest["pulse"]["pulseIndex"]   # int — stored in vault.json
        lock_pulse = latest["pulse"]["outputValue"]   # 512-bit hex — ephemeral only

        return {
            "unlock_timestamp": unlock_ts,
            "lock_timestamp": now,
            "lock_round": lock_round,    # index only — stored
            "lock_pulse": lock_pulse,    # value only — NOT stored
        }

    # ── backward-compatibility shims ──────────────────────────────────────

    @classmethod
    def _get(cls, url: str) -> dict:
        """
        GET with retries. Raises BeaconError on failure.
        DEPRECATED: Internal helper kept for any legacy subclass usage.
        """
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

    @staticmethod
    def _parse_ts(ts_str: str) -> float:
        """
        Parse NIST ISO timestamp string → POSIX float (UTC).
        DEPRECATED: Delegates to NISTBeaconSource.parse_ts for new code.
        """
        return NISTBeaconSource.parse_ts(ts_str)
