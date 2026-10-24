import pytest

from app.blockers.azure_nsg import AzureNsgBlocker, _rule_name


def test_rule_name_for_ipv4():
    assert _rule_name("1.2.3.4") == "soar-block-1-2-3-4"


def test_rule_name_for_ipv6_has_no_colons():
    assert ":" not in _rule_name("2001:db8::1")


def test_refuses_to_block_a_private_ip():
    # Skip __init__ so no Azure credentials are needed; the guard runs first.
    blocker = AzureNsgBlocker.__new__(AzureNsgBlocker)
    with pytest.raises(ValueError):
        blocker.block("10.0.0.5")