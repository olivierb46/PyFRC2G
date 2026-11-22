"""
Optional Redis connection (PYFRC2G_REDIS_URL): shared sign-in throttle and, with OIDC, the
server-side sessions. Always authenticated; TLS (rediss://) verifies the server certificate.

    PYFRC2G_REDIS_URL        redis://USER@host:6379/0, or rediss:// for TLS
    PYFRC2G_REDIS_PASSWORD   kept out of the URL (required unless the URL has one)
    PYFRC2G_REDIS_CA         CA bundle to verify the server of a rediss:// URL
"""

import logging
import os
from urllib.parse import urlparse


class RedisConfigError(Exception):
    pass


def settings_from_env(env=None):
    """Return the Redis settings from the environment, or None when PYFRC2G_REDIS_URL is unset."""
    env = os.environ if env is None else env
    url = env.get("PYFRC2G_REDIS_URL", "").strip()
    if not url:
        return None
    return {"url": url, "password": env.get("PYFRC2G_REDIS_PASSWORD", "") or None,
            "ca": env.get("PYFRC2G_REDIS_CA", "").strip() or None}


def connect(settings):
    """Return an authenticated client (TLS for rediss://); raise RedisConfigError if Redis is unreachable."""
    try:
        import redis
    except ImportError as e:
        raise RedisConfigError("PYFRC2G_REDIS_URL needs the redis package: pip install redis") from e
    url = urlparse(settings["url"])
    if url.scheme not in ("redis", "rediss"):
        raise RedisConfigError("PYFRC2G_REDIS_URL must start with redis:// or rediss://")
    if not (url.password or settings["password"]):
        raise RedisConfigError("Redis without a password is refused: set PYFRC2G_REDIS_PASSWORD.")
    options = {"socket_timeout": 5, "socket_connect_timeout": 5, "health_check_interval": 30}
    if settings["password"]:
        # Takes precedence over the URL and avoids escaping special characters.
        options["password"] = settings["password"]
    if url.scheme == "rediss":
        options["ssl_cert_reqs"] = "required"
        if settings["ca"]:
            options["ssl_ca_certs"] = settings["ca"]
    else:
        logging.warning(f"Redis over plain TCP ({url.hostname}): only acceptable on a private network "
                        "(docker internal network, loopback); use rediss:// otherwise")
    client = redis.Redis.from_url(settings["url"], **options)
    try:
        client.ping()
    except redis.exceptions.RedisError as e:
        raise RedisConfigError(f"Redis unreachable or authentication failed ({url.hostname}): "
                               f"{e.__class__.__name__}") from e  # Never echo the URL (password).
    return client
