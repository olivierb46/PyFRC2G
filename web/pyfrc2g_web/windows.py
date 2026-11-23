"""
Maintenance windows: when configuration changes are expected. One window per line, local server time:

    mon-fri 22:00-06:00        days (names, ranges or lists), then start-end (a window may cross midnight)
    sat,sun 00:00-24:00

A change detected by an analysis outside every window raises the "change outside the window" alert. The time is
the one of the analysis that detects the change (a configuration does not say when it was modified).
"""

import re

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_LINE = re.compile(r"^(?P<days>[a-z,\-]+)\s+(?P<start>\d{1,2}:\d{2})\s*-\s*(?P<end>\d{1,2}:\d{2})$")


class WindowError(ValueError):
    pass


def _minutes(text):
    hours, minutes = (int(x) for x in text.split(":"))
    if not (0 <= hours <= 24 and 0 <= minutes <= 59) or (hours == 24 and minutes):
        raise WindowError(f"Invalid time {text!r} (00:00 to 24:00).")
    return hours * 60 + minutes


def _days(text):
    days = set()
    for part in text.split(","):
        first, dash, last = part.partition("-")
        if first not in DAYS or (dash and last not in DAYS):
            raise WindowError(f"Invalid day {part!r}: use mon, tue, wed, thu, fri, sat, sun.")
        start = DAYS.index(first)
        end = DAYS.index(last) if dash else start
        days.update(range(start, end + 1) if start <= end else [*range(start, 7), *range(0, end + 1)])
    return days


def parse(text):
    """Return a list of (days, start minute, end minute); an empty text gives []. Raises WindowError."""
    windows = []
    for number, line in enumerate((text or "").splitlines(), 1):
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        match = _LINE.match(line)
        if not match:
            raise WindowError(f"Line {number}: expected 'mon-fri 22:00-06:00'.")
        start, end = _minutes(match["start"]), _minutes(match["end"])
        if start == end:
            raise WindowError(f"Line {number}: empty window.")
        windows.append((_days(match["days"]), start, end))
    return windows


def contains(windows, moment):
    """True if `moment` (datetime) is inside one of the windows. No window at all means 'always allowed'."""
    if not windows:
        return True
    day, minute = moment.weekday(), moment.hour * 60 + moment.minute
    for days, start, end in windows:
        if start < end and day in days and start <= minute < end:
            return True
        if start > end and ((day in days and minute >= start) or ((day - 1) % 7 in days and minute < end)):
            return True
    return False
