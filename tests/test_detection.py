from datetime import datetime, timedelta

from app.detection.brute_force import BruteForceDetector
from app.models.event import AuthenticationEvent


def create_event(
    seconds: int,
    username: str = "admin",
    source_ip: str = "192.168.1.50",
    success: bool = False,
) -> AuthenticationEvent:
    return AuthenticationEvent(
        timestamp=datetime(2026, 8, 31, 12, 0, 0)
        + timedelta(seconds=seconds),
        username=username,
        source_ip=source_ip,
        success=success,
    )


def test_five_failures_within_60_seconds_trigger_alert():
    events = [
        create_event(0),
        create_event(10),
        create_event(20),
        create_event(30),
        create_event(40),
    ]

    detector = BruteForceDetector()

    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].source_ip == "192.168.1.50"
    assert alerts[0].failure_count == 5
    assert alerts[0].severity == "HIGH"


def test_four_failures_do_not_trigger_alert():
    events = [
        create_event(0),
        create_event(10),
        create_event(20),
        create_event(30),
    ]

    detector = BruteForceDetector()

    alerts = detector.detect(events)

    assert len(alerts) == 0


def test_failures_outside_time_window_do_not_trigger_alert():
    events = [
        create_event(0),
        create_event(10),
        create_event(20),
        create_event(30),
        create_event(61),
    ]

    detector = BruteForceDetector()

    alerts = detector.detect(events)

    assert len(alerts) == 0


def test_successful_logins_are_not_counted():
    events = [
        create_event(0, success=True),
        create_event(10),
        create_event(20),
        create_event(30),
        create_event(40),
    ]

    detector = BruteForceDetector()

    alerts = detector.detect(events)

    assert len(alerts) == 0


def test_different_ips_are_not_combined():
    events = [
        create_event(0, source_ip="192.168.1.10"),
        create_event(10, source_ip="192.168.1.10"),
        create_event(20, source_ip="192.168.1.10"),
        create_event(30, source_ip="192.168.1.11"),
        create_event(40, source_ip="192.168.1.11"),
    ]

    detector = BruteForceDetector()

    alerts = detector.detect(events)

    assert len(alerts) == 0


def test_same_ip_attacking_different_users_triggers_alert():
    events = [
        create_event(0, username="alice"),
        create_event(10, username="bob"),
        create_event(20, username="charlie"),
        create_event(30, username="admin"),
        create_event(40, username="root"),
    ]

    detector = BruteForceDetector()

    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].source_ip == "192.168.1.50"