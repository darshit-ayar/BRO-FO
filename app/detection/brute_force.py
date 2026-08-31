from dataclasses import dataclass
from datetime import datetime, timedelta

from app.models.event import AuthenticationEvent


@dataclass(frozen=True)
class BruteForceAlert:
    alert_type: str
    source_ip: str
    failure_count: int
    window_start: datetime
    window_end: datetime
    severity: str


class BruteForceDetector:
    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 60,
    ):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def detect(
        self,
        events: list[AuthenticationEvent],
    ) -> list[BruteForceAlert]:

        failed_events = [
            event
            for event in events
            if not event.success
        ]

        events_by_ip: dict[str, list[AuthenticationEvent]] = {}

        for event in failed_events:
            events_by_ip.setdefault(event.source_ip, []).append(event)

        alerts = []

        for source_ip, ip_events in events_by_ip.items():
            ip_events.sort(key=lambda event: event.timestamp)

            left = 0

            for right in range(len(ip_events)):
                while (
                    ip_events[right].timestamp
                    - ip_events[left].timestamp
                    > self.window
                ):
                    left += 1

                failure_count = right - left + 1

                if failure_count >= self.threshold:
                    alerts.append(
                        BruteForceAlert(
                            alert_type="BRUTE_FORCE",
                            source_ip=source_ip,
                            failure_count=failure_count,
                            window_start=ip_events[left].timestamp,
                            window_end=ip_events[right].timestamp,
                            severity="HIGH",
                        )
                    )
                    break

        return alerts