"""呼び出し元の確認。Kubernetes の TokenReview で ServiceAccount token を検証する。

静的な共有鍵は置かない。呼び出し側は audience を指定した投影 token を Bearer で送る。
"""

from __future__ import annotations

import time
from pathlib import Path

import httpx

SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")


class TokenReviewer:
    def __init__(
        self,
        allowed_users: set[str],
        audience: str,
        *,
        api: str = "https://kubernetes.default.svc",
        http: httpx.Client | None = None,
        own_token_file: Path = SA_DIR / "token",
        ca_file: Path = SA_DIR / "ca.crt",
    ) -> None:
        self.allowed = allowed_users
        self.audience = audience
        self.api = api
        self.own_token_file = own_token_file
        self.http = http or httpx.Client(verify=str(ca_file), timeout=10)
        self._cache: dict[str, tuple[float, str | None]] = {}

    def user(self, token: str) -> str | None:
        hit = self._cache.get(token)
        if hit and hit[0] > time.time():
            return hit[1]
        own = self.own_token_file.read_text(encoding="utf-8").strip()
        r = self.http.post(
            f"{self.api}/apis/authentication.k8s.io/v1/tokenreviews",
            headers={"Authorization": f"Bearer {own}"},
            json={
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "TokenReview",
                "spec": {"token": token, "audiences": [self.audience]},
            },
        )
        r.raise_for_status()
        status = r.json().get("status", {})
        name = status.get("user", {}).get("username") if status.get("authenticated") else None
        if len(self._cache) > 1000:
            now = time.time()
            self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
        self._cache[token] = (time.time() + 60, name)
        return name

    def allowed_user(self, token: str) -> str | None:
        name = self.user(token)
        return name if name in self.allowed else None
