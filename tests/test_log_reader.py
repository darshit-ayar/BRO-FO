import pytest

from app.ingestion.log_reader import read_authentication_logs
from app.models.event import AuthenticationEvent


def test_read_authentication_logs():
    events = read_authentication_logs("data/sample_auth.log")

    assert len(events) == 10

    assert events[0] == AuthenticationEvent(
    timestamp=events[0].timestamp,
    username="alice",
    source_ip="192.168.1.10",
    success=True,
    service="ssh",
    event_type="authentication",
)


def test_invalid_result(tmp_path):
    log_file = tmp_path / "invalid.log"

    log_file.write_text(
        "2026-08-31T21:00:01 alice 192.168.1.10 UNKNOWN\n"
    )

    with pytest.raises(ValueError, match="Invalid authentication result"):
        read_authentication_logs(str(log_file))


def test_invalid_ip(tmp_path):
    log_file = tmp_path / "invalid.log"

    log_file.write_text(
        "2026-08-31T21:00:01 alice invalid-ip FAILED\n"
    )

    with pytest.raises(ValueError, match="Invalid IP address"):
        read_authentication_logs(str(log_file))


def test_invalid_timestamp(tmp_path):
    log_file = tmp_path / "invalid.log"

    log_file.write_text(
        "not-a-date alice 192.168.1.10 FAILED\n"
    )

    with pytest.raises(ValueError, match="Invalid timestamp"):
        read_authentication_logs(str(log_file))


def test_invalid_log_format(tmp_path):
    log_file = tmp_path / "invalid.log"

    log_file.write_text(
        "2026-08-31T21:00:01 alice 192.168.1.10\n"
    )

    with pytest.raises(ValueError, match="Invalid log format"):
        read_authentication_logs(str(log_file))


def test_missing_file():
    with pytest.raises(FileNotFoundError):
        read_authentication_logs("data/does_not_exist.log")
