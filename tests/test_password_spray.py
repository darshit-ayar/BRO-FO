from datetime import datetime, timedelta

from app.detection.password_spray import PasswordSprayDetector
from app.models.event import AuthenticationEvent


def create_event(seconds, username, source_ip="192.168.1.50", success=False):
    return AuthenticationEvent(
        timestamp=datetime(2026, 8, 31, 12, 0, 0)
        + timedelta(seconds=seconds),
        username=username,
        source_ip=source_ip,
        success=success,
    )


def test_five_different_users_trigger_password_spray():
    events = [
        create_event(0, "alice"),
        create_event(10, "bob"),
        create_event(20, "charlie"),
        create_event(30, "admin"),
        create_event(40, "root"),
    ]

    detector = PasswordSprayDetector()
    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "PASSWORD_SPRAYING"
    assert alerts[0].targeted_accounts == 5


def test_repeated_attempts_against_same_user_do_not_trigger_spray():
    events = [
        create_event(0, "admin"),
        create_event(10, "admin"),
        create_event(20, "admin"),
        create_event(30, "admin"),
        create_event(40, "admin"),
    ]

    detector = PasswordSprayDetector()
    alerts = detector.detect(events)

    assert len(alerts) == 0


def test_successful_logins_are_not_counted():
    events = [
        create_event(0, "alice", success=True),
        create_event(10, "bob"),
        create_event(20, "charlie"),
        create_event(30, "admin"),
        create_event(40, "root"),
    ]

    detector = PasswordSprayDetector()
    alerts = detector.detect(events)

    assert len(alerts) == 0


def test_different_ips_are_not_combined():
    events = [
        create_event(0, "alice", "192.168.1.10"),
        create_event(10, "bob", "192.168.1.10"),
        create_event(20, "charlie", "192.168.1.11"),
        create_event(30, "admin", "192.168.1.11"),
        create_event(40, "root", "192.168.1.12"),
    ]

    detector = PasswordSprayDetector()
    alerts = detector.detect(events)

    assert len(alerts) == 0