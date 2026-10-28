"""Entra の監査ログを取り込み、事象に変換して台帳へ送る。

監査ログは到着が遅れるので、取り込み位置より前を重ねて読み、事象 ID（監査記録の ID）で重複を除く。
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone

import httpx

from .graph import GraphClient
from .models import Action, ActorType, Event, Outcome, Plane

log = logging.getLogger(__name__)

SOURCE = "entra-audit"
KEY_ID = re.compile(r"KeyIdentifier=([0-9a-fA-F-]{36})")
GUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
# PIM 経由の割り当ては、監査上 MS-PIM が実行者になる ※要確認
PIM_ACTORS = {"MS-PIM"}


def _action(name: str) -> tuple[Action, str | None] | None:
    n = name.strip()
    if n == "Add service principal credentials":
        return Action.credential_add, "servicePrincipal"
    if n.startswith("Update application") and "Certificates and secrets" in n:
        return Action.credential_add, "application"
    if n == "Add member to role":
        return Action.role_assign, None
    if n in ("Add owner to service principal", "Add owner to application"):
        return Action.owner_add, None
    if n in (
        "Add app role assignment to service principal",
        "Consent to application",
        "Add delegated permission grant",
    ):
        return Action.consent_change, None
    return None


def _prop(target: dict, name: str) -> str | None:
    for p in target.get("modifiedProperties") or []:
        if p.get("displayName") == name:
            return p.get("newValue")
    return None


def normalize(rec: dict) -> Event | None:
    mapped = _action(rec.get("activityDisplayName", ""))
    if mapped is None:
        return None
    action, object_type = mapped
    by = rec.get("initiatedBy") or {}
    app, user = by.get("app") or {}, by.get("user") or {}
    targets = rec.get("targetResources") or []

    e = Event(
        event_id=rec["id"],
        time=datetime.fromisoformat(rec["activityDateTime"].replace("Z", "+00:00")),
        source=SOURCE,
        plane=Plane.application,
        action=action,
        outcome=Outcome.success if rec.get("result") == "success" else Outcome.failure,
        actor_label=app.get("displayName") or user.get("userPrincipalName"),
    )
    if app.get("servicePrincipalId"):
        e.actor_type = ActorType.service_principal
        e.actor_id = app["servicePrincipalId"]
        e.service_principal_id = app["servicePrincipalId"]
        e.application_id = app.get("appId")
    elif user.get("id"):
        e.actor_type = ActorType.user
        e.actor_id = user["id"]
        e.source_ip = user.get("ipAddress")
        e.service_principal_id = None

    principal = next(
        (t for t in targets if t.get("type") in ("ServicePrincipal", "User", "Application")), None
    )
    if principal:
        e.target_principal_id = principal.get("id")
        if e.service_principal_id is None:
            e.service_principal_id = principal.get("id")

    if action == Action.credential_add:
        e.target = object_type
        for t in targets:
            m = KEY_ID.search(_prop(t, "KeyDescription") or "")
            if m:
                e.credential_key_id = m.group(1)
    if action == Action.role_assign:
        for t in targets:
            raw = _prop(t, "Role.TemplateId") or ""
            m = GUID.search(raw)
            if m:
                e.role_definition_id = m.group(0)
        e.via_pim = app.get("displayName") in PIM_ACTORS
    return e


class Collector:
    def __init__(
        self,
        graph: GraphClient,
        ledger_url: str,
        *,
        ledger_http: httpx.Client,
        lookback: timedelta = timedelta(minutes=15),
        initial: timedelta = timedelta(hours=1),
    ) -> None:
        self.graph = graph
        self.ledger_url = ledger_url.rstrip("/")
        self.http = ledger_http
        self.lookback = lookback
        self.initial = initial

    def _cursor(self) -> datetime:
        r = self.http.get(f"{self.ledger_url}/v1/cursors/{SOURCE}")
        if r.status_code == 200 and r.json().get("value"):
            return datetime.fromisoformat(r.json()["value"])
        return datetime.now(timezone.utc) - self.initial

    def poll_once(self) -> int:
        cursor = self._cursor()
        since = (cursor - self.lookback).strftime("%Y-%m-%dT%H:%M:%SZ")
        records = list(
            self.graph.paged(
                "/auditLogs/directoryAudits",
                params={"$filter": f"activityDateTime ge {since}"},
            )
        )
        events = [e for e in (normalize(r) for r in records) if e is not None]
        events.append(Event(source=SOURCE, plane=Plane.host, action=Action.heartbeat, host="collector"))
        payload = [e.model_dump(mode="json") for e in events]
        self.http.post(f"{self.ledger_url}/v1/events", json=payload).raise_for_status()
        newest = max(
            (datetime.fromisoformat(r["activityDateTime"].replace("Z", "+00:00")) for r in records),
            default=cursor,
        )
        self.http.put(
            f"{self.ledger_url}/v1/cursors/{SOURCE}", json={"value": max(newest, cursor).isoformat()}
        ).raise_for_status()
        return len(events) - 1

    def run(self, interval: float) -> None:
        while True:
            try:
                n = self.poll_once()
                log.info("取り込み %d 件", n)
            except Exception:
                log.exception("取り込みに失敗")
            time.sleep(interval)
