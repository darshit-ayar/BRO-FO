from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

from app.models.event import AuthenticationEvent


VALID_RESULTS = {"SUCCESS", "FAILED"}


def read_authentication_logs(file_path: str) -> list[AuthenticationEvent]:
    events = []

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

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

            try:
                timestamp = datetime.fromisoformat(timestamp_str)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid timestamp on line {line_number}: "
                    f"{timestamp_str}"
                ) from exc

            if not username:
                raise ValueError(
                    f"Empty username on line {line_number}"
                )

            try:
                ip_address(source_ip)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid IP address on line {line_number}: "
                    f"{source_ip}"
                ) from exc

            if result not in VALID_RESULTS:
                raise ValueError(
                    f"Invalid authentication result on line {line_number}: "
                    f"{result}"
                )

            event = AuthenticationEvent(
            timestamp=timestamp,
            username=username,
            source_ip=source_ip,
            success=result == "SUCCESS",
            service="ssh",
            event_type="authentication",
                )  

            events.append(event)

    return events