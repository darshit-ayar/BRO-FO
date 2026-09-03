from app.detection.brute_force import BruteForceDetector
from app.ingestion.log_reader import read_authentication_logs


def test_log_file_to_brute_force_alert():
    events = read_authentication_logs("data/sample_auth.log")

    detector = BruteForceDetector()

    alerts = detector.detect(events)

    assert len(events) == 10
    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.alert_type == "BRUTE_FORCE"
    assert alert.source_ip == "10.0.0.50"
    assert alert.failure_count == 5
    assert alert.severity == "HIGH"
