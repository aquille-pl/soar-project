from app import response


def rep(score):
    return {"checked": True, "abuse_score": score}


def test_blocks_at_threshold():
    assert response.decide("1.2.3.4", rep(75))["action"] == "block"


def test_blocks_above_threshold():
    assert response.decide("1.2.3.4", rep(100))["action"] == "block"


def test_no_block_below_threshold():
    assert response.decide("1.2.3.4", rep(74))["action"] == "none"


def test_unchecked_reputation_fails_safe():
    result = response.decide("1.2.3.4", {"checked": False, "reason": "API down"})
    assert result["action"] == "none"


def test_allowlist_overrides_a_bad_score(monkeypatch):
    monkeypatch.setattr(response, "ALLOWLIST", ["1.2.3.0/24"])
    assert response.decide("1.2.3.4", rep(100))["action"] == "none"