"""強制点への指示の実行。

- dry-run が既定。enforce でも、automatic_kinds に無い種類は提案として記録するだけ
- application や service principal のオブジェクトを削除する処理は持たない（admission-control.md 節3.2）
- 証明書の取り消しは、所有の証明が要るため人へ回す
"""

from __future__ import annotations

import logging
from typing import Callable

import httpx

from .config import EnforcementMode, Settings, utcnow
from .graph import GraphClient
from .models import ActionRequest
from .store import Store

log = logging.getLogger(__name__)


class Escalate(Exception):
    """自動では実行できず、人の判断へ回す。"""


class Enforcer:
    def __init__(
        self,
        store: Store,
        settings: Settings,
        graph: GraphClient | None = None,
        http: httpx.Client | None = None,
    ) -> None:
        self.store = store
        self.settings = settings
        self.graph = graph
        self.http = http or httpx.Client(timeout=15)
        self.handlers: dict[str, Callable[[ActionRequest, str], str]] = {
            "remove_sp_credential": self._remove_credential,
            "remove_role_assignment": self._remove_role_assignment,
            "isolate_host_east_west": self._webhook,
            "revoke_privileged_activation": self._webhook,
        }

    def execute(self, event_id: str, actions: list[ActionRequest]) -> list[dict]:
        results = []
        for a in actions:
            status, detail = self._run(event_id, a)
            self.store.log_action(event_id, a, status, detail, utcnow())
            results.append({"kind": a.kind, "status": status, "detail": detail})
        return results

    def _run(self, event_id: str, a: ActionRequest) -> tuple[str, str]:
        if not a.automatic:
            return "proposed", "人の判断を待つ"
        if self.settings.enforcement.mode == EnforcementMode.dry_run:
            return "dry-run", "enforce モードではないため実行していない"
        handler = self.handlers.get(a.kind)
        if handler is None:
            return "proposed", "実行手段が無い種類"
        try:
            return "done", handler(a, event_id)
        except Escalate as e:
            return "escalated", str(e)
        except Exception as e:  # 強制の失敗は記録し、評価は止めない
            log.exception("action %s failed", a.kind)
            return "failed", f"{type(e).__name__}: {e}"

    def _require_graph(self) -> GraphClient:
        if self.graph is None:
            raise Escalate("Graph の資格情報が設定されていない")
        return self.graph

    def _remove_credential(self, a: ActionRequest, event_id: str) -> str:
        g = self._require_graph()
        sp, key_id = a.params.get("service_principal_id"), a.params.get("key_id")
        if not sp or not key_id:
            raise Escalate("対象または keyId が不明")
        kind = "applications" if a.params.get("object_type") == "application" else "servicePrincipals"
        obj = g.get(f"/{kind}/{sp}", params={"$select": "id,passwordCredentials,keyCredentials"})
        if any(c.get("keyId") == key_id for c in obj.get("passwordCredentials", [])):
            g.request("POST", f"/{kind}/{sp}/removePassword", json={"keyId": key_id})
            return f"{kind}/{sp} の secret {key_id} を無効化した"
        if any(c.get("keyId") == key_id for c in obj.get("keyCredentials", [])):
            raise Escalate("証明書の取り消しには所有の証明が要る。人が行う")
        return f"{kind}/{sp} に keyId {key_id} は既に無い"

    def _remove_role_assignment(self, a: ActionRequest, event_id: str) -> str:
        g = self._require_graph()
        principal, role = a.params.get("principal_id"), a.params.get("role_definition_id")
        if not principal or not role:
            raise Escalate("主体またはロールが不明")
        flt = f"principalId eq '{principal}' and roleDefinitionId eq '{role}'"
        removed = []
        for ra in g.paged("/roleManagement/directory/roleAssignments", params={"$filter": flt}):
            g.request("DELETE", f"/roleManagement/directory/roleAssignments/{ra['id']}")
            removed.append(ra["id"])
        return f"ロール割り当て {removed or 'なし'} を取り消した"

    def _webhook(self, a: ActionRequest, event_id: str) -> str:
        url = self.settings.enforcement.host_webhook_url
        if not url:
            raise Escalate("端末側の強制点（EDR や NAC の webhook）が設定されていない")
        r = self.http.post(url, json={"event_id": event_id, "kind": a.kind, "params": a.params})
        r.raise_for_status()
        return f"webhook {r.status_code}"
