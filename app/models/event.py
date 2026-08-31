from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class AuthenticationEvent:
    timestamp: datetime
    username: str
    source_ip: str
    success: bool