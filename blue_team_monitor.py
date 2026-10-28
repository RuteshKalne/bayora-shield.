import json
import time
import urllib.request
import urllib.error
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta

GATEWAY_URL = "http://bayora-shield:5000"
POLL_SECONDS = 15
WINDOW_MINUTES = 5
BLOCK_ALERT_THRESHOLD = 5


def get_json(path):
    request = urllib.request.Request(
        f"{GATEWAY_URL}{path}",
        headers={"Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_events():
    data = get_json("/ledger")
    return data.get("events", [])


def verify_ledger():
    result = get_json("/ledger/verify")
    return result.get("valid") is True, result


def parse_timestamp(value):
    if not isinstance(value, str):
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def analyze_events(events):
    counts = Counter()
    blocked_by_session = defaultdict(int)
    suspicious = []

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=WINDOW_MINUTES)
    recent_block_count = 0

    for event in events:
        if not isinstance(event, dict):
            continue

        event_type = str(
            event.get("event_type")
            or event.get("event")
            or event.get("action")
            or "UNKNOWN"
        ).upper()

        counts[event_type] += 1

        if "BLOCK" in event_type or "DENY" in event_type:
            suspicious.append(event)

            event_time = parse_timestamp(event.get("timestamp"))

            if event_time is None:
                continue

            if cutoff <= event_time <= now:
                recent_block_count += 1
                session_id = str(event.get("session_id", "unknown"))
                blocked_by_session[session_id] += 1

    repeated_sessions = {
        session: count
        for session, count in blocked_by_session.items()
        if count >= BLOCK_ALERT_THRESHOLD
    }

    return counts, suspicious, repeated_sessions, recent_block_count


def main():
    print("BLUE TEAM MONITOR STARTED", flush=True)
    print(f"Monitoring {GATEWAY_URL}/ledger", flush=True)
    print(f"Polling every {POLL_SECONDS} seconds", flush=True)
    print(f"Detection window: {WINDOW_MINUTES} minutes", flush=True)

    last_report = None
    last_ledger_status = None

    while True:
        try:
            events = fetch_events()
            ledger_valid, verification = verify_ledger()

            counts, suspicious, repeated_sessions, recent_block_count = (
                analyze_events(events)
            )

            report = (
                len(events),
                tuple(sorted(counts.items())),
                ledger_valid,
                recent_block_count,
                tuple(sorted(repeated_sessions.items())),
            )

            if report != last_report:
                print("\n=== BLUE TEAM REPORT ===", flush=True)
                print(f"Ledger events: {len(events)}", flush=True)
                print(f"Event types: {dict(counts)}", flush=True)
                print(
                    f"Blocked events in the last {WINDOW_MINUTES} minutes: "
                    f"{recent_block_count}",
                    flush=True,
                )
                print(f"Ledger integrity valid: {ledger_valid}", flush=True)
                print(f"Verification details: {verification}", flush=True)

                if not ledger_valid:
                    print(
                        "CRITICAL ALERT: Audit ledger verification failed!",
                        flush=True,
                    )

                for session, count in repeated_sessions.items():
                    print(
                        f"SECURITY ALERT: Session {session} has {count} "
                        f"blocked events in the last {WINDOW_MINUTES} minutes.",
                        flush=True,
                    )

                last_report = report

            if ledger_valid != last_ledger_status:
                print(
                    f"LEDGER STATUS CHANGED: valid={ledger_valid}",
                    flush=True,
                )
                last_ledger_status = ledger_valid

        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            print(f"Monitor warning: {exc}", flush=True)

        except Exception as exc:
            print(f"Unexpected monitor error: {exc}", flush=True)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
