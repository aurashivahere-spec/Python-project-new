"""Bounded audit trail kept in memory and appended to a JSONL file."""
from __future__ import annotations

import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Union


class AuditLog:
    def __init__(self, path: Optional[Union[str, Path]] = None, capacity: int = 100):
        self._path = Path(path) if path else None
        self._events: Deque[Dict[str, Any]] = deque(maxlen=capacity)

    def record(self, event: str, **details: Any) -> Dict[str, Any]:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
            **details,
        }
        self._events.append(entry)  # oldest entry drops automatically
        if self._path:
            with open(self._path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
        return entry

    def recent(self, n: int = 10) -> List[Dict[str, Any]]:
        return list(self._events)[-n:]

    @staticmethod
    def tail(path: Union[str, Path], n: int = 10) -> List[Dict[str, Any]]:
        """Stream a file line by line, keeping only the last n lines."""
        last: Deque[str] = deque(maxlen=n)
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last.append(line)
        return [json.loads(line) for line in last]
