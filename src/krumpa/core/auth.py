"""
GateKrumpa core — authentication middleware.

``AuthProvider`` injects authentication credentials into outgoing
HTTP request headers.  Supported schemes:

* **bearer** — ``Authorization: Bearer <token>``
* **api_key** — custom header (default ``X-API-Key``)
* **basic** — ``Authorization: Basic <base64(user:pass)>``
* **custom** — arbitrary header key/value pairs
"""

from __future__ import annotations

import base64
import logging
from typing import Dict, Optional

logger = logging.getLogger("krumpa.auth")


class AuthProvider:
    """Inject authentication credentials into request headers.

    Parameters
    ----------
    auth_type:
        One of ``"bearer"``, ``"api_key"``, ``"basic"``, ``"custom"``,
        or ``"none"`` (default — no injection).
    token:
        Bearer token value (for ``auth_type="bearer"``).
    api_key:
        API key value (for ``auth_type="api_key"``).
    api_key_header:
        Header name for the API key (default ``X-API-Key``).
    username / password:
        Credentials for ``auth_type="basic"``.
    custom_headers:
        Arbitrary ``{header: value}`` dict (for ``auth_type="custom"``).
    """

    def __init__(
        self,
        auth_type: str = "none",
        *,
        token: Optional[str] = None,
        api_key: Optional[str] = None,
        api_key_header: str = "X-API-Key",
        username: Optional[str] = None,
        password: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.auth_type = auth_type.lower()
        self._token = token
        self._api_key = api_key
        self._api_key_header = api_key_header
        self._username = username
        self._password = password
        self._custom_headers = custom_headers or {}

    # -- public interface ---------------------------------------------------

    def inject(self, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Return a **new** headers dict with auth credentials merged in.

        Existing header values are preserved; auth headers are only added
        if they are not already present (no overwrite).
        """
        out = dict(headers) if headers else {}

        if self.auth_type == "bearer" and self._token:
            out.setdefault("Authorization", f"Bearer {self._token}")
        elif self.auth_type == "api_key" and self._api_key:
            out.setdefault(self._api_key_header, self._api_key)
        elif self.auth_type == "basic" and self._username is not None:
            creds = f"{self._username}:{self._password or ''}"
            encoded = base64.b64encode(creds.encode()).decode()
            out.setdefault("Authorization", f"Basic {encoded}")
        elif self.auth_type == "custom":
            for k, v in self._custom_headers.items():
                out.setdefault(k, v)

        return out

    def __repr__(self) -> str:
        return f"AuthProvider(type={self.auth_type!r})"
