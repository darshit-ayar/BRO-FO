from datetime import timedelta

from app.models.alert import SecurityAlert
from app.models.event import AuthenticationEvent


class BruteForceDetector:
    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 60,
    ):
        if threshold < 1:
            raise ValueError("Threshold must be at least 1")

        if window_seconds < 1:
            raise ValueError("Window must be at least 1 second")

        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

    def detect(
        self,
        events: list[AuthenticationEvent],
    ) -> list[SecurityAlert]:

        failed_events = [
            event for event in events if not event.success
        ]

        events_by_target: dict[
            tuple[str, str],
            list[AuthenticationEvent],
        ] = {}

        for event in failed_events:
            key = (event.source_ip, event.username)

            events_by_target.setdefault(key, []).append(event)

        alerts = []

        for (source_ip, username), target_events in events_by_target.items():
            target_events.sort(key=lambda event: event.timestamp)

            left = 0

            for right in range(len(target_events)):
                while (
                    target_events[right].timestamp
                    - target_events[left].timestamp
                    > self.window
                ):
                    left += 1

                failure_count = right - left + 1

                if failure_count >= self.threshold:
                    alerts.append(
                        SecurityAlert(
                            alert_type="BRUTE_FORCE",
                            source_ip=source_ip,
                            username=username,
                            failure_count=failure_count,
                            window_start=target_events[left].timestamp,
                            window_end=target_events[right].timestamp,
                            severity="HIGH",
                        )
                    )
                    break

        return alerts