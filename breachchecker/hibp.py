"""Query the Have I Been Pwned Pwned Passwords range API with k-anonymity.

The password itself never leaves the machine. We SHA-1 it, send only the first
five hex characters of the hash, and compare the rest against the API's reply
locally. No API key is needed.
"""

from __future__ import annotations

import hashlib
from typing import Callable, Dict

import requests

API_ROOT = "https://api.pwnedpasswords.com/range/"
_TIMEOUT = 10

# A fetcher takes a 5-character hash prefix and returns the raw API response
# text. Injecting it keeps the network out of the unit tests.
Fetcher = Callable[[str], str]


def sha1_upper(password: str) -> str:
    """Return the uppercase hex SHA-1 of the password, as HIBP uses."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def split_hash(sha1_hex: str) -> tuple[str, str]:
    """Split a SHA-1 hash into the 5-char prefix sent to the API and the rest."""
    return sha1_hex[:5], sha1_hex[5:]


def _default_fetcher(prefix: str) -> str:
    # Add-Padding asks the API to pad the reply with decoy hashes so the size of
    # the response does not hint at how many real matches there are.
    resp = requests.get(
        API_ROOT + prefix,
        headers={"Add-Padding": "true", "User-Agent": "password-breach-checker"},
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.text


def parse_range(body: str) -> Dict[str, int]:
    """Parse the API body ('SUFFIX:COUNT' per line) into {suffix: count}.

    Padding entries have a count of 0 and are dropped.
    """
    counts: Dict[str, int] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        suffix, _, count = line.partition(":")
        try:
            n = int(count)
        except ValueError:
            continue
        if n > 0:
            counts[suffix.strip().upper()] = n
    return counts


def pwned_count(password: str, fetcher: Fetcher = _default_fetcher) -> int:
    """Return how many breaches the password appears in (0 if not found)."""
    prefix, suffix = split_hash(sha1_upper(password))
    counts = parse_range(fetcher(prefix))
    return counts.get(suffix, 0)
