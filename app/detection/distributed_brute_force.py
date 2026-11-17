from datetime import timedelta

from app.models.alert import SecurityAlert
from app.models.event import AuthenticationEvent


class DistributedBruteForceDetector:
    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 60,
    ):
        if threshold < 2:
            raise ValueError("Threshold must be at least 2")

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

        events_by_username = {}

        for event in failed_events:
            events_by_username.setdefault(
                event.username, []
            ).append(event)

        alerts = []

        for username, user_events in events_by_username.items():
            user_events.sort(key=lambda event: event.timestamp)

            left = 0

            for right, event in enumerate(user_events):
                while (
                    event.timestamp - user_events[left].timestamp
                    > self.window
                ):
                    left += 1

                window_events = user_events[left:right + 1]

                source_ips = {
                    item.source_ip for item in window_events
                }

                if (
                    len(window_events) >= self.threshold
                    and len(source_ips) >= self.threshold
                ):
                    alerts.append(
                        SecurityAlert(
                            alert_type="DISTRIBUTED_BRUTE_FORCE",
                            username=username,
                            source_ips=tuple(sorted(source_ips)),
                            failure_count=len(window_events),
                            window_start=user_events[left].timestamp,
                            window_end=event.timestamp,
                            severity="HIGH",
                        )
                    )
                    break

        return alerts