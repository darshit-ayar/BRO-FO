from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class SecurityAlert:
    alert_type: str
    severity: str
    window_start: datetime
    window_end: datetime

    source_ip: str | None = None
    username: str | None = None
    source_ips: tuple[str, ...] = ()
    failure_count: int = 0
    targeted_accounts: int = 0