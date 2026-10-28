"""Microsoft Graph の呼び出し。資格情報は workload identity federation だけを使う。

長期の client secret は使わない（defense-system.md 節6.2）。Pod に投影された
ServiceAccount token を client assertion として Entra に渡す。
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Iterator

import httpx


class GraphClient:
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        token_file: str,
        *,
        authority: str = "https://login.microsoftonline.com",
        base_url: str = "https://graph.microsoft.com/v1.0",
        http: httpx.Client | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.token_file = token_file
        self.authority = authority.rstrip("/")
        self.base_url = base_url.rstrip("/")
        self.http = http or httpx.Client(timeout=30)
        self._token: str | None = None
        self._expires = 0.0

    def _access_token(self) -> str:
        if self._token and time.time() < self._expires - 300:
            return self._token
        # 投影 token は kubelet が更新するので、毎回読み直す
        assertion = Path(self.token_file).read_text(encoding="utf-8").strip()
        r = self.http.post(
            f"{self.authority}/{self.tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "scope": "https://graph.microsoft.com/.default",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
            },
        )
        r.raise_for_status()
        body = r.json()
        self._token = body["access_token"]
        self._expires = time.time() + int(body.get("expires_in", 3600))
        return self._token

    def request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        url = path if path.startswith("https://") else f"{self.base_url}{path}"
        headers = {"Authorization": f"Bearer {self._access_token()}", **kw.pop("headers", {})}
        r = self.http.request(method, url, headers=headers, **kw)
        r.raise_for_status()
        return r

    def get(self, path: str, **kw: Any) -> dict:
        return self.request("GET", path, **kw).json()

    def paged(self, path: str, params: dict | None = None) -> Iterator[dict]:
        body = self.get(path, params=params)
        while True:
            yield from body.get("value", [])
            nxt = body.get("@odata.nextLink")
            if not nxt:
                return
            body = self.get(nxt)
