import sys

from app.detection.brute_force import BruteForceDetector
from app.ingestion.log_reader import read_authentication_logs


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python -m app.main <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]

    try:
        events = read_authentication_logs(log_file)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    detector = BruteForceDetector()
    alerts = detector.detect(events)

    print("BRO-FO Brute Force Detection")
    print("============================")
    print()
    print(f"Analyzing: {log_file}")
    print(f"Events processed: {len(events)}")
    print(f"Alerts detected: {len(alerts)}")
    print()

    for alert in alerts:
        print(f"[{alert.severity}] {alert.alert_type}")
        print(f"Source IP: {alert.source_ip}")
        print(f"Failures: {alert.failure_count}")
        print(
            f"Window: {alert.window_start} → {alert.window_end}"
        )
        print()


if __name__ == "__main__":
    main()