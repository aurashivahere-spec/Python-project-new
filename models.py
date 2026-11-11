"""Data model for a single trust anchor."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import date
from typing import Any, Dict

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

VALID_STATUS = frozenset({"active", "revoked"})
VALID_ALGORITHMS = frozenset(
    {"ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s", "Ed25519"}
)


@dataclass(frozen=True)
class Anchor:
    """An immutable entry describing one trusted signing key."""

    name: str
    algorithm: str
    fingerprint: str  # SHA3-256 of the public key, lowercase hex
    not_after: date
    status: str = "active"

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("anchor name must not be empty")
        if self.algorithm not in VALID_ALGORITHMS:
            raise ValueError(f"unsupported algorithm: {self.algorithm!r}")
        if not _HEX64.match(self.fingerprint):
            raise ValueError("fingerprint must be 64 lowercase hex characters")
        if self.status not in VALID_STATUS:
            raise ValueError(f"unknown status: {self.status!r}")

    def is_valid_on(self, day: date) -> bool:
        """True if the anchor is active and not yet expired on `day`."""
        return self.status == "active" and day <= self.not_after

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["not_after"] = self.not_after.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Anchor":
        return cls(
            name=data["name"],
            algorithm=data["algorithm"],
            fingerprint=data["fingerprint"],
            not_after=date.fromisoformat(data["not_after"]),
            status=data.get("status", "active"),
        )
