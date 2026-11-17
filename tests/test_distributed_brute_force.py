from datetime import datetime, timedelta

from app.detection.distributed_brute_force import (
    DistributedBruteForceDetector,
)
from app.models.event import AuthenticationEvent


def create_event(seconds, source_ip, username="admin", success=False):
    return AuthenticationEvent(
        timestamp=datetime(2026, 8, 31, 12, 0, 0)
        + timedelta(seconds=seconds),
        username=username,
        source_ip=source_ip,
        success=success,
    )


def test_multiple_ips_targeting_same_user_trigger_alert():
    events = [
        create_event(0, "192.168.1.10"),
        create_event(10, "192.168.1.11"),
        create_event(20, "192.168.1.12"),
        create_event(30, "192.168.1.13"),
        create_event(40, "192.168.1.14"),
    ]

    detector = DistributedBruteForceDetector()
    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "DISTRIBUTED_BRUTE_FORCE"
    assert alerts[0].username == "admin"
    assert len(alerts[0].source_ips) == 5


def test_same_ip_does_not_trigger_distributed_alert():
    events = [
        create_event(0, "192.168.1.10"),
        create_event(10, "192.168.1.10"),
        create_event(20, "192.168.1.10"),
        create_event(30, "192.168.1.10"),
        create_event(40, "192.168.1.10"),
    ]

    detector = DistributedBruteForceDetector()
    alerts = detector.detect(events)

    assert len(alerts) == 0


def test_different_usernames_are_not_combined():
    events = [
        create_event(0, "192.168.1.10", "alice"),
        create_event(10, "192.168.1.11", "bob"),
        create_event(20, "192.168.1.12", "charlie"),
        create_event(30, "192.168.1.13", "root"),
        create_event(40, "192.168.1.14", "guest"),
    ]

    detector = DistributedBruteForceDetector()
    alerts = detector.detect(events)

    assert len(alerts) == 0


def test_successful_events_are_not_counted():
    events = [
        create_event(0, "192.168.1.10"),
        create_event(10, "192.168.1.11"),
        create_event(20, "192.168.1.12"),
        create_event(30, "192.168.1.13"),
        create_event(40, "192.168.1.14", success=True),
    ]

    detector = DistributedBruteForceDetector()
    alerts = detector.detect(events)

    assert len(alerts) == 0