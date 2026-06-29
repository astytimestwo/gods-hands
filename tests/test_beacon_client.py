import os

import pytest

from beacon_client import BeaconClient, BeaconError, NISTBeaconSource, BeaconSource

RUN_LIVE_BEACON_TESTS = os.getenv("RUN_LIVE_BEACON_TESTS") == "1"
live_beacon = pytest.mark.skipif(
    not RUN_LIVE_BEACON_TESTS,
    reason="set RUN_LIVE_BEACON_TESTS=1 to call the live NIST beacon",
)


def test_beacon_client_imports():
    """Verify BeaconClient and BeaconError are importable."""
    assert BeaconClient is not None
    assert BeaconError is not None
    assert NISTBeaconSource is not None
    assert BeaconSource is not None


class MockSource:
    def __init__(self, fail=False, pulse_data=None):
        self.fail = fail
        self.pulse_data = pulse_data or {"pulse": {"outputValue": "AABBCCDD" * 16, "pulseIndex": 12345, "timeStamp": "2026-01-01T00:00:00.000Z"}}
        self.call_count = 0
    def fetch_pulse(self, timeout=None):
        self.call_count += 1
        if self.fail:
            raise BeaconError("source down")
        return self.pulse_data
    def get_pulse_by_round(self, round_index, timeout=None):
        self.call_count += 1
        if self.fail:
            raise BeaconError("source down")
        return self.pulse_data["pulse"]["outputValue"]
    def get_pulse_by_time(self, timestamp, timeout=None):
        self.call_count += 1
        if self.fail:
            raise BeaconError("source down")
        return self.pulse_data["pulse"]["outputValue"]


def test_primary_fails_falls_back_to_secondary():
    """When primary source fails, fallback source is tried and succeeds."""
    primary = MockSource(fail=True)
    secondary = MockSource(pulse_data={"pulse": {"outputValue": "DEADBEEF" * 16, "pulseIndex": 999, "timeStamp": "2026-01-01T00:00:00.000Z"}})
    # Set on the CLASS so _try_sources sees the override (it reads cls._sources)
    original = BeaconClient._sources
    BeaconClient._sources = [("primary", primary), ("secondary", secondary)]
    try:
        result = BeaconClient.get_latest_pulse()
        assert secondary.call_count == 1
        assert result["pulse"]["outputValue"] == "DEADBEEF" * 16
    finally:
        BeaconClient._sources = original


def test_all_sources_fail_raises_beacon_error():
    """When all sources fail, BeaconError is raised."""
    primary = MockSource(fail=True)
    secondary = MockSource(fail=True)
    original = BeaconClient._sources
    BeaconClient._sources = [("primary", primary), ("secondary", secondary)]
    try:
        with pytest.raises(BeaconError):
            BeaconClient.get_latest_pulse()
    finally:
        BeaconClient._sources = original


@pytest.mark.live_beacon
@live_beacon
def test_beacon_get_latest_pulse_returns_dict():
    """get_latest_pulse returns a dict with a pulse key. Requires network."""
    import socket
    try:
        socket.getaddrinfo("beacon.nist.gov", 443, socket.AF_INET)
    except socket.gaierror:
        pytest.skip("No network connectivity")
    client = BeaconClient()
    result = client.get_latest_pulse()
    assert isinstance(result, dict)
    assert "pulse" in result


@pytest.mark.live_beacon
@live_beacon
def test_beacon_get_pulse_by_round_returns_str():
    """get_pulse_by_round(1690000) returns a string (hex outputValue). Requires live NIST beacon."""
    import socket
    try:
        socket.getaddrinfo("beacon.nist.gov", 443, socket.AF_INET)
    except socket.gaierror:
        pytest.skip("No network connectivity")
    result = BeaconClient.get_pulse_by_round(1690000)
    assert isinstance(result, str)
    assert len(result) > 0


@pytest.mark.live_beacon
@live_beacon
def test_beacon_get_pulse_by_time_returns_none_for_future(tmp_path):
    """A future timestamp returns None (not yet published)."""
    import time
    client = BeaconClient()
    future_ts = time.time() + 99999  # far future
    result = client.get_pulse_by_time(future_ts)
    assert result is None
