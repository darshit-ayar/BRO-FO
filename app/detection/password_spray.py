from datetime import timedelta

from app.models.alert import SecurityAlert
from app.models.event import AuthenticationEvent


class PasswordSprayDetector:
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

        events_by_ip = {}

        for event in failed_events:
            events_by_ip.setdefault(event.source_ip, []).append(event)

        alerts = []

        for source_ip, ip_events in events_by_ip.items():
            ip_events.sort(key=lambda event: event.timestamp)

            left = 0
            username_counts = {}

            for right, event in enumerate(ip_events):
                username_counts[event.username] = (
                    username_counts.get(event.username, 0) + 1
                )

                while (
                    event.timestamp - ip_events[left].timestamp
                    > self.window
                ):
                    old_username = ip_events[left].username
                    username_counts[old_username] -= 1

                    if username_counts[old_username] == 0:
                        del username_counts[old_username]

                    left += 1

                if len(username_counts) >= self.threshold:
                    alerts.append(
                        SecurityAlert(
                            alert_type="PASSWORD_SPRAYING",
                            source_ip=source_ip,
                            targeted_accounts=len(username_counts),
                            window_start=ip_events[left].timestamp,
                            window_end=event.timestamp,
                            severity="HIGH",
                        )
                    )
                    break

        return alerts