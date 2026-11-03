"""Stable finding IDs.

Python's built-in hash() is randomised per process, so IDs built from it
change on every run. A SHA-256 digest gives the same ID for the same
finding every time, which keeps exports comparable between scans.
"""

from __future__ import annotations

import hashlib


def stable_hash(text: str) -> int:
    """Return a number in 0..9999 that depends only on `text`."""
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest(), 16) % 10000
