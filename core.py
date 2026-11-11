"""Helpers: locate the bundled registry and compute fingerprints."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Union

from .registry import TrustRegistry

_CHUNK = 64 * 1024


def where() -> str:
    """Path of the bundled anchors.json file."""
    return str(Path(__file__).with_name("anchors.json"))


def load_default() -> TrustRegistry:
    return TrustRegistry.load(where())


def fingerprint_bytes(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def fingerprint_file(path: Union[str, Path]) -> str:
    """Hash a (possibly large) key file in fixed-size chunks."""
    digest = hashlib.sha3_256()
    with open(path, "rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()
