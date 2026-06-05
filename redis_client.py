"""Safe Redis client wrapper used by the API.

This module reads connection settings from environment variables and
exposes a `redis_client` object with `get`, `set`, and `delete` methods.
If Redis is unavailable the methods become no-ops (safe for caching).
"""

import os
from typing import Any, Optional

import redis


REDIS_URL = os.getenv("REDIS_URL")
_client: Optional[redis.Redis] = None

try:
    if REDIS_URL:
        _client = redis.from_url(REDIS_URL, decode_responses=True)
        _client.ping()
    else:
        REDIS_HOST = os.getenv("REDIS_HOST", "redis")
        REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
        REDIS_DB = int(os.getenv("REDIS_DB", "0"))
        _client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
        _client.ping()
except Exception:
    _client = None


class SafeRedis:
    def __init__(self, client: Optional[redis.Redis]):
        self.client = client

    def get(self, key: str) -> Any:
        if not self.client:
            return None
        try:
            return self.client.get(key)
        except Exception:
            return None

    def set(self, key: str, value: Any, ex: int | None = None) -> bool:
        if not self.client:
            return False
        try:
            return self.client.set(key, value, ex=ex)
        except Exception:
            return False

    def delete(self, key: str) -> int:
        if not self.client:
            return 0
        try:
            return self.client.delete(key)
        except Exception:
            return 0


redis_client = SafeRedis(_client)
REDIS_AVAILABLE = _client is not None