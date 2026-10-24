import pytest

from breachchecker.strength import rate


def test_short_single_category_is_weak():
    s = rate("abc")
    assert s.rating == "Weak"
    assert s.categories == ["lowercase"]


def test_common_word_length_eight_is_weak():
    assert rate("password").rating == "Weak"


def test_mixed_medium_is_fair():
    assert rate("Password1").rating == "Fair"


def test_long_all_categories_is_strong():
    s = rate("Password123!")   # 12 chars, 4 categories
    assert s.rating == "Strong"
    assert set(s.categories) == {"lowercase", "uppercase", "digit", "symbol"}


def test_suggestions_point_at_gaps():
    s = rate("abc")
    assert any("12 characters" in tip for tip in s.suggestions)
    assert any("uppercase" in tip for tip in s.suggestions)


def test_length_counts_toward_score():
    # Same single category, longer password scores at least as high.
    assert rate("aaaaaaaaaaaa").rating in ("Fair", "Good", "Strong")
