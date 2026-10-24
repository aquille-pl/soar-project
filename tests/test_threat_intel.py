import httpx
import pytest

from app import threat_intel


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("8.8.8.8", True),
        ("10.0.0.5", False),
        ("192.168.1.10", False),
        ("127.0.0.1", False),
        ("169.254.1.1", False),
    ],
)
def test_is_public_ip(ip, expected):
    assert threat_intel.is_public_ip(ip) is expected


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        pass

    def json(self):
        return {"data": self._data}


def test_private_ip_never_calls_the_api(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "key")

    def boom(*args, **kwargs):
        raise AssertionError("API must not be called for a private IP")

    monkeypatch.setattr(threat_intel.httpx, "get", boom)
    assert threat_intel.check_ip_reputation("10.0.0.5")["checked"] is False


def test_missing_api_key_is_reported():
    result = threat_intel.check_ip_reputation("8.8.8.8")
    assert result["checked"] is False
    assert "key" in result["reason"].lower()


def test_network_failure_returns_unchecked(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "key")

    def fail(*args, **kwargs):
        raise httpx.ConnectError("network down")

    monkeypatch.setattr(threat_intel.httpx, "get", fail)
    assert threat_intel.check_ip_reputation("8.8.8.8")["checked"] is False


def test_successful_lookup_is_parsed(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "key")
    data = {
        "abuseConfidenceScore": 88,
        "totalReports": 12,
        "countryCode": "RU",
        "isp": "Example ISP",
    }
    monkeypatch.setattr(
        threat_intel.httpx, "get", lambda *a, **k: FakeResponse(data)
    )
    assert threat_intel.check_ip_reputation("8.8.8.8") == {
        "checked": True,
        "abuse_score": 88,
        "total_reports": 12,
        "country": "RU",
        "isp": "Example ISP",
    }