"""A simple password strength rating based on length and character variety.

This is a rough guide, not a substitute for the breach check. A long, varied
password can still be a known-breached one, which is why the tool shows both.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class Strength:
    rating: str
    length: int
    categories: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


def _categories(password: str) -> List[str]:
    cats = []
    if any(c.islower() for c in password):
        cats.append("lowercase")
    if any(c.isupper() for c in password):
        cats.append("uppercase")
    if any(c.isdigit() for c in password):
        cats.append("digit")
    if any((not c.isalnum()) and (not c.isspace()) for c in password):
        cats.append("symbol")
    return cats


def rate(password: str) -> Strength:
    length = len(password)
    cats = _categories(password)
    variety = len(cats)

    score = 0
    if length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    score += variety  # 0..4

    if score <= 2:
        rating = "Weak"
    elif score <= 4:
        rating = "Fair"
    elif score == 5:
        rating = "Good"
    else:
        rating = "Strong"

    suggestions: List[str] = []
    if length < 12:
        suggestions.append("use at least 12 characters")
    if variety < 3:
        missing = [c for c in ("lowercase", "uppercase", "digit", "symbol") if c not in cats]
        suggestions.append("mix in " + ", ".join(missing))

    return Strength(rating=rating, length=length, categories=cats, suggestions=suggestions)
