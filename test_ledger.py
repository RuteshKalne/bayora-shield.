from ledger import AuditLedger


def test_new_ledger_is_valid(tmp_path):
    ledger = AuditLedger(filename=tmp_path / "audit.jsonl")
    assert ledger.verify() is True


def test_append_records_event(tmp_path):
    ledger = AuditLedger(filename=tmp_path / "audit.jsonl")

    event = ledger.append(
        "EVALUATION_BLOCK",
        "session-alpha",
        "BLOCK",
        "Guardrail bypass attempt detected",
    )

    assert event["id"] == 1
    assert event["event_type"] == "EVALUATION_BLOCK"
    assert ledger.verify() is True


def test_events_are_linked_by_hash(tmp_path):
    ledger = AuditLedger(filename=tmp_path / "audit.jsonl")

    first = ledger.append(
        "EVALUATION_BLOCK",
        "session-alpha",
        "BLOCK",
        "Test event one",
    )

    second = ledger.append(
        "SESSION_CLEANUP",
        "session-alpha",
        "PASS",
        "Test event two",
    )

    assert second["previous_hash"] == first["hash"]
    assert ledger.verify() is True


def test_tampered_event_is_detected(tmp_path):
    ledger_path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(filename=ledger_path)

    ledger.append(
        "EVALUATION_BLOCK",
        "session-alpha",
        "BLOCK",
        "Original details",
    )

    # Modify the saved event without recalculating its hash.
    import json

    event = json.loads(ledger_path.read_text(encoding="utf-8"))
    event["details"] = "Unauthorized modification"
    ledger_path.write_text(
        json.dumps(event) + "\n",
        encoding="utf-8",
    )

    # Loading the modified ledger should fail verification.
    import pytest

    with pytest.raises(ValueError, match="verification failed"):
        AuditLedger(filename=ledger_path)


def test_ledger_survives_reload(tmp_path):
    ledger_path = tmp_path / "audit.jsonl"

    first_ledger = AuditLedger(filename=ledger_path)
    first_ledger.append(
        "SESSION_CLEANUP",
        "session-alpha",
        "PASS",
        "Evaluation state cleared",
    )

    reloaded_ledger = AuditLedger(filename=ledger_path)

    assert len(reloaded_ledger.events) == 1
    assert reloaded_ledger.verify() is True

