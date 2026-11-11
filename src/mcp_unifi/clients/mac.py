"""MAC address normalisation for lookups.

The controller stores MACs in lower case, colon separated
(``f4:e2:c6:00:00:02``). Operators and agents paste them in whatever form the
label, the UI or another tool showed: upper case, dash separated
(``F4-E2-C6-00-00-02``), Cisco dotted (``f4e2.c600.0002``) or bare hex. A
plain ``==`` against the stored value finds nothing for any of those, so
every comparison of a caller-supplied MAC goes through :func:`normalize_mac`
on both sides.
"""

from __future__ import annotations

import re

#: The separator-free form must be exactly twelve hex digits.
_HEX12 = re.compile(r"\A[0-9a-f]{12}\Z")

#: Grouped forms the separators may come in: six pairs (``:`` or ``-``) or
#: three quads (``.``). Anything else is not reshaped.
_GROUPED = (
    re.compile(r"\A[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}\Z"),
    re.compile(r"\A[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\Z"),
)


def normalize_mac(value: object) -> str:
    """Return ``value`` as a lower-case, colon-separated MAC when it is one.

    A string that is not a recognisable MAC comes back stripped and lower
    cased rather than raising, so a comparison against it simply finds
    nothing, exactly as before.
    """
    text = str(value or "").strip().lower()
    if _HEX12.match(text):
        digits = text
    elif any(pattern.match(text) for pattern in _GROUPED):
        digits = re.sub(r"[:.-]", "", text)
    else:
        return text
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def same_mac(a: object, b: object) -> bool:
    """``True`` when ``a`` and ``b`` name the same MAC in any accepted form."""
    left = normalize_mac(a)
    return bool(left) and left == normalize_mac(b)


__all__ = ["normalize_mac", "same_mac"]
