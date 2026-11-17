
import sys

from app.detection.brute_force import BruteForceDetector
from app.detection.password_spray import PasswordSprayDetector
from app.detection.distributed_brute_force import DistributedBruteForceDetector
from app.ingestion.log_reader import read_authentication_logs
from app.models.alert import SecurityAlert


def print_alerts(alerts: list[SecurityAlert]) -> None:
    if not alerts:
        print("No security alerts detected.")
        return

    for alert in alerts:
        print(f"[{alert.severity}] {alert.alert_type}")

        if alert.source_ip:
            print(f"Source IP: {alert.source_ip}")

        if alert.username:
            print(f"Username: {alert.username}")

        if alert.source_ips:
            print(f"Source IPs: {', '.join(alert.source_ips)}")

        if alert.failure_count:
            print(f"Failures: {alert.failure_count}")

        if alert.targeted_accounts:
            print(f"Targeted accounts: {alert.targeted_accounts}")

        print(f"Window: {alert.window_start} -> {alert.window_end}")
        print()


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

    detectors = [
        BruteForceDetector(),
        PasswordSprayDetector(),
        DistributedBruteForceDetector(),
    ]

    all_alerts: list[SecurityAlert] = []

    for detector in detectors:
        all_alerts.extend(detector.detect(events))

    print("BRO-FO Security Analysis")
    print("========================")
    print()
    print(f"Analyzing: {log_file}")
    print(f"Events processed: {len(events)}")
    print(f"Alerts detected: {len(all_alerts)}")
    print()

    print_alerts(all_alerts)


if __name__ == "__main__":
    main()
