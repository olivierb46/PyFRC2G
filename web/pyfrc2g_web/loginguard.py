"""
Protection of the sign-in against guessing.

* Failures are counted for each (user name, address) pair: five of them lock that pair, so somebody who guesses
  from one address locks themselves out and cannot lock the real user out (who comes from another address).
* An address that fails with many different names (password spraying: one password tried on every account) is
  locked as a whole after four times as many failures. A successful sign-in does not clear the address.
* Locks grow: 10 minutes, then 20, 40... up to 24 hours for whoever keeps coming back (the strikes are
  remembered for a day).
* Many failures on one account, from anywhere, raise an "account under attack" event (event log, SIEM, and the
  notification channels subscribed to it) but lock nobody.
* An administrator can clear the locks of a user (Administration > Users).

    PYFRC2G_LOGIN_MAX_FAILURES   failures that lock a pair (default 5)
    PYFRC2G_LOGIN_LOCK_MINUTES   first lock (default 10)
    PYFRC2G_LOGIN_MAX_LOCK_HOURS longest lock (default 24)

The counters live in Redis when it is configured (shared by every instance), else in memory.
"""

import math

WINDOW = 600  # Seconds over which the failures are counted.
ADDRESS_FACTOR = 4  # An address may fail this many times more than a pair before it is locked.
ATTACK_FACTOR = 6  # Failures on one account in an hour (times the limit) that raise the alert.
ATTACK_WINDOW = 3600


class LoginGuard:
    def __init__(self, app):
        self.app = app

    # ------------------------------------------------------------------ settings

    def _config(self):
        config = self.app.config
        limit = config.get("LOGIN_MAX_FAILURES", 5)
        return (limit, config.get("LOGIN_LOCK_MINUTES", 10) * 60, config.get("LOGIN_MAX_LOCK_HOURS", 24) * 3600)

    def _pair(self, username, address):
        epoch = self.app.db.get_meta(f"login_epoch:{username.lower()}", "0")  # Raised by the administrator's unlock.
        return f"pair:{epoch}:{username.lower()}|{address}"

    @staticmethod
    def _address(address):
        return f"addr:{address}"

    # ------------------------------------------------------------------ use

    def wait(self, username, address):
        """Seconds before this user name may be tried from this address (0 if it may)."""
        throttle = self.app.throttle
        return max(throttle.lock_remaining(self._pair(username, address)),
                   throttle.lock_remaining(self._address(address)))

    @staticmethod
    def message(seconds):
        minutes = max(1, math.ceil(seconds / 60))
        if minutes >= 120:
            return f"Too many failed attempts: try again in {math.ceil(minutes / 60)} hours."
        return f"Too many failed attempts: try again in {minutes} minute{'s' if minutes > 1 else ''}."

    def failed(self, username, address):
        """Count a failed attempt. Return the lock (seconds) it triggered, 0 if none."""
        limit, base, cap = self._config()
        throttle = self.app.throttle
        locked = max(throttle.strike(self._pair(username, address), limit, WINDOW, base, cap),
                     throttle.strike(self._address(address), limit * ADDRESS_FACTOR, WINDOW, base, cap))
        if username and throttle.tally(f"user:{username.lower()}", ATTACK_WINDOW) == limit * ATTACK_FACTOR:
            self._alert(username, limit * ATTACK_FACTOR)
        return locked

    def succeeded(self, username, address):
        """A good sign-in clears the pair (not the address: it could belong to somebody spraying passwords)."""
        self.app.throttle.forget(self._pair(username, address))

    def unlock(self, username):
        """Clear every lock of a user name (all addresses). Return the addresses of its recent failures too."""
        db = self.app.db
        epoch = int(db.get_meta(f"login_epoch:{username.lower()}", "0") or 0) + 1
        db.set_meta(f"login_epoch:{username.lower()}", str(epoch))
        addresses = {e["detail"] for e in db.events(limit=300)
                     if e["action"] == "failed sign-in" and e["username"].lower() == username.lower()}
        self.app.throttle.forget(*[self._address(a.split()[0]) for a in addresses if a])
        self.app.throttle.forget(f"user:{username.lower()}")
        return len(addresses)

    def _alert(self, username, count):
        from pyfrc2g_web import notify

        db = self.app.db
        db.add_event("system", "account under attack", f"{username}: {count} failed sign-ins within an hour")
        notifier = getattr(db, "notifier", None)
        if notifier is not None:
            notify.attack_alert(notifier, username, count)
