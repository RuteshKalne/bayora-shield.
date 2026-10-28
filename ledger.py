import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

class AuditLedger:
    def __init__(self, filename=None):
        if filename is None:
            filename = os.environ.get(
                "AUDIT_LEDGER_FILE",
                "audit.jsonl",
            )

        self.filename = Path(filename)
        self.filename.parent.mkdir(parents=True, exist_ok=True)
        self.events = []
        self._load_events()

    def _calculate_hash(self, event):
        canonical = json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
        )

        return hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

    def _load_events(self):
        """Load previously saved audit events."""
        if not self.filename.exists():
            return

        with self.filename.open("r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue

                self.events.append(json.loads(line))

        if not self.verify():
            self.events.clear()
            raise ValueError(
                f"Audit ledger verification failed: {self.filename}"
            )

    def append(self, event_type, session_id, decision, details):
        previous_hash = (
            self.events[-1]["hash"]
            if self.events
            else "GENESIS"
        )

        event = {
            "id": len(self.events) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "session_id": session_id,
            "decision": decision,
            "details": details,
            "previous_hash": previous_hash,
        }

        event["hash"] = self._calculate_hash(event)

        # Persist the event before adding it to the in-memory list.
        with self.filename.open("a", encoding="utf-8") as file:
            file.write(
                json.dumps(event, sort_keys=True) + "\n"
            )
            file.flush()

        self.events.append(event)
        return event

    def verify(self):
        """Verify event IDs, previous hashes, and event hashes."""
        previous_hash = "GENESIS"

        for index, event in enumerate(self.events, start=1):
            if event.get("id") != index:
                return False

            if event.get("previous_hash") != previous_hash:
                return False

            stored_hash = event.get("hash")
            original = {
                key: value
                for key, value in event.items()
                if key != "hash"
            }

            if stored_hash != self._calculate_hash(original):
                return False

            previous_hash = stored_hash

        return True
