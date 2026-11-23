"""Neutralise spreadsheet formulas in the cells of an exported CSV (a text starting with = + - @ is run by Excel)."""

_DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


def cell(value):
    """The cell as text, with a quote in front when a spreadsheet would take it for a formula."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_DANGEROUS) else text
