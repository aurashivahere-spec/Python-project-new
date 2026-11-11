"""In-memory trust registry with JSON persistence."""
from __future__ import annotations

import heapq
import json
import os
import tempfile
from collections import defaultdict
from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Union

from .models import Anchor


class DuplicateAnchorError(ValueError):
    """Raised when a fingerprint is already registered."""


class UnknownAnchorError(KeyError):
    """Raised when a fingerprint is not in the registry."""


class TrustRegistry:
    """Hash-map backed registry: O(1) lookup by fingerprint."""

    def __init__(self, anchors: Iterable[Anchor] = ()) -> None:
        self._by_fp: Dict[str, Anchor] = {}
        for anchor in anchors:
            self.add(anchor)

    # ---- basic container protocol -------------------------------------
    def __len__(self) -> int:
        return len(self._by_fp)

    def __contains__(self, fingerprint: object) -> bool:
        return fingerprint in self._by_fp

    def __iter__(self) -> Iterator[Anchor]:
        return iter(sorted(self._by_fp.values(), key=lambda a: a.name))

    # ---- mutation -------------------------------------------------------
    def add(self, anchor: Anchor) -> None:
        if anchor.fingerprint in self._by_fp:
            raise DuplicateAnchorError(anchor.fingerprint)
        self._by_fp[anchor.fingerprint] = anchor

    def revoke(self, fingerprint: str) -> Anchor:
        try:
            current = self._by_fp[fingerprint]
        except KeyError:
            raise UnknownAnchorError(fingerprint) from None
        updated = replace(current, status="revoked")
        self._by_fp[fingerprint] = updated
        return updated

    # ---- queries --------------------------------------------------------
    def get(self, fingerprint: str) -> Optional[Anchor]:
        return self._by_fp.get(fingerprint)

    def is_trusted(self, fingerprint: str, on: Optional[date] = None) -> bool:
        anchor = self._by_fp.get(fingerprint)
        return anchor is not None and anchor.is_valid_on(on or date.today())

    def expiring_within(self, days: int, on: Optional[date] = None) -> List[Anchor]:
        """Active anchors expiring in the next `days` days, soonest first.

        Uses a min-heap keyed by expiry date so we only pop what we need.
        """
        today = on or date.today()
        cutoff = today + timedelta(days=days)
        heap = [
            (a.not_after, a.name, a.fingerprint)
            for a in self._by_fp.values()
            if a.status == "active"
        ]
        heapq.heapify(heap)
        result: List[Anchor] = []
        while heap:
            not_after, _, fp = heapq.heappop(heap)
            if not_after < today:
                continue  # already expired
            if not_after > cutoff:
                break  # heap order: everything left is later
            result.append(self._by_fp[fp])
        return result

    def group_by_algorithm(self) -> Dict[str, List[Anchor]]:
        groups: Dict[str, List[Anchor]] = defaultdict(list)
        for anchor in self:
            groups[anchor.algorithm].append(anchor)
        return dict(groups)

    # ---- persistence (file operations) ----------------------------------
    @classmethod
    def load(cls, path: Union[str, Path]) -> "TrustRegistry":
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return cls(Anchor.from_dict(item) for item in payload["anchors"])

    def save(self, path: Union[str, Path]) -> None:
        """Atomic write: temp file in same folder, then os.replace()."""
        target = Path(path)
        payload = {"schema": 1, "anchors": [a.to_dict() for a in self]}
        fd, tmp_name = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=True)
                handle.write("\n")
            os.replace(tmp_name, target)
        except BaseException:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise
