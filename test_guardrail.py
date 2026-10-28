from guardrail import evaluate_scenario


def test_safe_scenario_is_allowed():
    result = evaluate_scenario("safe", "What is a firewall?")
    assert result["decision"] == "ALLOW"

def test_jailbreak_is_blocked():
    result = evaluate_scenario("jailbreak")
    assert result["decision"] == "BLOCK"


def test_exfiltration_is_blocked():
    result = evaluate_scenario("exfiltration")
    assert result["decision"] == "BLOCK"


def test_recon_is_blocked():
    result = evaluate_scenario("recon")
    assert result["decision"] == "BLOCK"


def test_injection_is_blocked():
    result = evaluate_scenario("injection")
    assert result["decision"] == "BLOCK"


def test_unknown_scenario_is_blocked():
    result = evaluate_scenario("unknown")
    assert result["decision"] == "BLOCK"
