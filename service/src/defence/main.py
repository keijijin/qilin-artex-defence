"""起動。設定はすべて環境変数と ConfigMap から読む。"""

from __future__ import annotations

import logging
import os
from datetime import timedelta

import httpx
import uvicorn

from .api import create_app
from .auth import TokenReviewer
from .collector import Collector
from .config import load_settings
from .enforce import Enforcer
from .graph import GraphClient
from .policy import Engine
from .store import Store


def _graph() -> GraphClient | None:
    tenant, client = os.getenv("AZURE_TENANT_ID"), os.getenv("AZURE_CLIENT_ID")
    token_file = os.getenv("AZURE_FEDERATED_TOKEN_FILE")
    if not (tenant and client and token_file):
        return None
    return GraphClient(
        tenant,
        client,
        token_file,
        authority=os.getenv("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.com"),
        base_url=os.getenv("GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0"),
    )


def build_app():
    settings = load_settings(os.getenv("POLICY_FILE", "/etc/defence/policy.yaml"))
    store = Store(os.getenv("LEDGER_DB", "/var/lib/defence/ledger.db"))
    reviewer = None
    if os.getenv("AUTH_MODE", "tokenreview") == "tokenreview":
        reviewer = TokenReviewer(
            {u.strip() for u in os.getenv("ALLOWED_CALLERS", "").split(",") if u.strip()},
            os.getenv("TOKEN_AUDIENCE", "defence-ledger"),
        )
    enforcer = Enforcer(store, settings, _graph())
    return create_app(store, Engine(store, settings), enforcer, reviewer)


def run_ledger() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    uvicorn.run(
        build_app(),
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8443")),
        ssl_certfile=os.getenv("TLS_CERT_FILE") or None,
        ssl_keyfile=os.getenv("TLS_KEY_FILE") or None,
        log_config=None,
    )


class _ProjectedAuth(httpx.Auth):
    """台帳への呼び出しに、投影された ServiceAccount token を付ける。token は都度読み直す。"""

    def __init__(self, path: str) -> None:
        self.path = path

    def auth_flow(self, request):
        with open(self.path, encoding="utf-8") as f:
            request.headers["Authorization"] = f"Bearer {f.read().strip()}"
        yield request


def run_collector() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    graph = _graph()
    if graph is None:
        raise SystemExit("AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_FEDERATED_TOKEN_FILE が必要")
    ca = os.getenv("LEDGER_CA_FILE")
    ledger_http = httpx.Client(
        verify=ca if ca else True,
        timeout=30,
        auth=_ProjectedAuth(os.getenv("LEDGER_TOKEN_FILE", "/var/run/secrets/defence/token")),
    )
    Collector(
        graph,
        os.getenv("LEDGER_URL", "https://defence-ledger:8443"),
        ledger_http=ledger_http,
        lookback=timedelta(minutes=int(os.getenv("LOOKBACK_MINUTES", "15"))),
    ).run(float(os.getenv("POLL_SECONDS", "60")))
