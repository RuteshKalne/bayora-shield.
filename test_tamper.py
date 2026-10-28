import json
import tempfile
from pathlib import Path

from ledger import AuditLedger

# Create a temporary ledger for testing.
with tempfile.TemporaryDirectory() as temp_dir:
    ledger_path = Path(temp_dir) / "audit.jsonl"

    ledger = AuditLedger(filename=ledger_path)

    # Create two linked audit events.
    ledger.append(
        "TEST_ALLOW",
        "session-alpha",
        "ALLOW",
        "First test event",
    )

    ledger.append(
        "TEST_BLOCK",
        "session-bravo",
        "BLOCK",
        "Second test event",
    )

    print("Before tampering:", ledger.verify())

    # Change an event without updating its hash.
    events = ledger_path.read_text(encoding="utf-8").splitlines()
    event = json.loads(events[0])
    event["decision"] = "BLOCK"
    events[0] = json.dumps(event)

    ledger_path.write_text(
        "\n".join(events) + "\n",
        encoding="utf-8",
    )

    # Load the modified ledger and check whether tampering is detected.
    try:
        AuditLedger(filename=ledger_path)
        print("After tampering: NOT DETECTED")
    except ValueError:
        print("After tampering: DETECTED")
