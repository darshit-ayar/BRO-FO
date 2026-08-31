from datetime import datetime
from pathlib import Path

from app.models.event import AuthenticationEvent


def read_authentication_logs(file_path: str) -> list[AuthenticationEvent]:
    events = []

    path = Path(file_path)

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) != 4:
                raise ValueError(
                    f"Invalid log format on line {line_number}: {line}"
                )

            timestamp_str, username, source_ip, result = parts

            timestamp = datetime.fromisoformat(timestamp_str)

            if result not in {"SUCCESS", "FAILED"}:
                raise ValueError(
                    f"Invalid authentication result on line {line_number}: {result}"
                )

            event = AuthenticationEvent(
                timestamp=timestamp,
                username=username,
                source_ip=source_ip,
                success=result == "SUCCESS",
            )

            events.append(event)

    return events