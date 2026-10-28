"""収集の変換、強制の Graph 呼び出し、API と TokenReview。外部は httpx.MockTransport で置き換える。"""

import json
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from conftest import T0

from defence.api import create_app
from defence.auth import TokenReviewer
from defence.collector import Collector, normalize
from defence.config import EnforcementMode
from defence.enforce import Enforcer
from defence.graph import GraphClient
from defence.models import Action, ActionRequest, ActorType

KEY = "11111111-2222-3333-4444-555555555555"
GA = "62e90394-69f5-4237-9190-012177145e10"


def audit(name, **kw):
    rec = {
        "id": kw.pop("id", "rec-1"),
        "activityDateTime": "2026-10-15T03:42:00Z",
        "activityDisplayName": name,
        "result": "success",
        "initiatedBy": {"app": {"servicePrincipalId": "sp-x", "appId": "app-x", "displayName": "Teams"}},
        "targetResources": [],
    }
    rec.update(kw)
    return rec


def test_normalize_credential_add():
    e = normalize(audit(
        "Add service principal credentials",
        targetResources=[{
            "id": "sp-x", "type": "ServicePrincipal",
            "modifiedProperties": [{
                "displayName": "KeyDescription",
                "newValue": f'["[KeyIdentifier={KEY},KeyType=Password,KeyUsage=Verify,DisplayName=x]"]',
            }],
        }],
    ))
    assert e.action == Action.credential_add and e.actor_type == ActorType.service_principal
    assert e.credential_key_id == KEY and e.target == "servicePrincipal"


def test_normalize_role_assign_and_pim():
    tr = [
        {"id": "sp-sib", "type": "ServicePrincipal"},
        {"id": "role", "type": "Role",
         "modifiedProperties": [{"displayName": "Role.TemplateId", "newValue": f'"{GA}"'}]},
    ]
    e = normalize(audit("Add member to role", targetResources=tr))
    assert e.role_definition_id == GA and e.target_principal_id == "sp-sib" and e.via_pim is False
    pim = normalize(audit("Add member to role", targetResources=tr,
                          initiatedBy={"app": {"displayName": "MS-PIM", "servicePrincipalId": "pim"}}))
    assert pim.via_pim is True


def test_normalize_ignores_unrelated():
    assert normalize(audit("Update user")) is None


def graph_with(handler, tmp_path: Path) -> GraphClient:
    tok = tmp_path / "token"
    tok.write_text("projected-jwt")

    def route(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/oauth2/v2.0/token"):
            body = dict(x.split("=", 1) for x in req.content.decode().split("&"))
            assert body["client_assertion"] == "projected-jwt"
            assert "client_secret" not in body
            return httpx.Response(200, json={"access_token": "at", "expires_in": 3600})
        return handler(req)

    return GraphClient("tenant", "client", str(tok), http=httpx.Client(transport=httpx.MockTransport(route)))


def test_enforce_removes_password_and_role(tmp_path, store, settings):
    calls = []

    def handler(req):
        calls.append((req.method, req.url.path))
        if req.method == "GET" and req.url.path.endswith("/servicePrincipals/sp-x"):
            return httpx.Response(200, json={"passwordCredentials": [{"keyId": KEY}], "keyCredentials": []})
        if req.method == "GET" and "roleAssignments" in req.url.path:
            return httpx.Response(200, json={"value": [{"id": "ra-1"}]})
        return httpx.Response(204)

    settings.enforcement.mode = EnforcementMode.enforce
    enf = Enforcer(store, settings, graph_with(handler, tmp_path))
    res = enf.execute("ev", [
        ActionRequest(kind="remove_sp_credential", params={"service_principal_id": "sp-x", "key_id": KEY}),
        ActionRequest(kind="remove_role_assignment", params={"principal_id": "sp-x", "role_definition_id": GA}),
    ])
    assert [r["status"] for r in res] == ["done", "done"]
    assert ("POST", "/v1.0/servicePrincipals/sp-x/removePassword") in calls
    assert ("DELETE", "/v1.0/roleManagement/directory/roleAssignments/ra-1") in calls
    assert not any(m == "DELETE" and "servicePrincipals" in p for m, p in calls)


def test_enforce_certificate_escalates(tmp_path, store, settings):
    def handler(req):
        return httpx.Response(200, json={"passwordCredentials": [], "keyCredentials": [{"keyId": KEY}]})

    settings.enforcement.mode = EnforcementMode.enforce
    enf = Enforcer(store, settings, graph_with(handler, tmp_path))
    res = enf.execute("ev", [ActionRequest(kind="remove_sp_credential",
                                           params={"service_principal_id": "sp-x", "key_id": KEY})])
    assert res[0]["status"] == "escalated"


def test_enforce_kind_not_automatic_stays_proposal(store, settings):
    settings.enforcement.mode = EnforcementMode.enforce
    enf = Enforcer(store, settings)
    res = enf.execute("ev", [ActionRequest(kind="suspend_sp_token_refresh", automatic=False)])
    assert res[0]["status"] == "proposed"


def make_client(store, engine, enforcer, reviewer=None):
    return TestClient(create_app(store, engine, enforcer, reviewer, source_check_interval=None))


def test_api_ingest_and_cases(store, engine, enforcer):
    c = make_client(store, engine, enforcer)
    payload = {
        "time": T0.isoformat(), "plane": "application", "action": "role_assign",
        "actor_type": "service_principal", "actor_id": "sp-x", "service_principal_id": "sp-x",
        "target_principal_id": "sp-x", "role_definition_id": GA,
    }
    r = c.post("/v1/events", json=payload)
    assert r.status_code == 200 and r.json()[0]["rule"] == "P4"
    assert r.json()[0]["results"][0]["status"] == "dry-run"
    assert c.get("/v1/cases").json()[0]["rule"] == "P4"
    assert c.put("/v1/cursors/x", json={"value": "v"}).status_code == 200
    assert c.get("/v1/cursors/x").json() == {"value": "v"}
    assert c.get("/readyz").status_code == 200


def test_api_tokenreview(store, engine, enforcer, tmp_path):
    own = tmp_path / "own"
    own.write_text("ledger-sa")

    def route(req):
        body = json.loads(req.content)
        assert body["spec"]["audiences"] == ["defence-ledger"]
        tok = body["spec"]["token"]
        user = {"good": "system:serviceaccount:defence-system:defence-collector",
                "other": "system:serviceaccount:x:y"}.get(tok)
        return httpx.Response(201, json={"status": {"authenticated": user is not None,
                                                    "user": {"username": user}}})

    rv = TokenReviewer({"system:serviceaccount:defence-system:defence-collector"}, "defence-ledger",
                       http=httpx.Client(transport=httpx.MockTransport(route)), own_token_file=own)
    c = make_client(store, engine, enforcer, rv)
    assert c.get("/v1/cases").status_code == 401
    assert c.get("/v1/cases", headers={"Authorization": "Bearer other"}).status_code == 403
    assert c.get("/v1/cases", headers={"Authorization": "Bearer bad"}).status_code == 403
    assert c.get("/v1/cases", headers={"Authorization": "Bearer good"}).status_code == 200
    assert c.get("/healthz").status_code == 200


def test_collector_poll_round_trip(tmp_path, store, engine, enforcer):
    ledger = make_client(store, engine, enforcer)

    def graph_handler(req):
        assert "activityDateTime ge" in req.url.params["$filter"]
        return httpx.Response(200, json={"value": [audit(
            "Add member to role", id="rec-9",
            targetResources=[{"id": "sp-x", "type": "ServicePrincipal"},
                             {"id": "r", "type": "Role", "modifiedProperties": [
                                 {"displayName": "Role.TemplateId", "newValue": f'"{GA}"'}]}],
        )]})

    col = Collector(graph_with(graph_handler, tmp_path), "http://testserver", ledger_http=ledger)
    assert col.poll_once() == 1
    assert col.poll_once() == 1  # 重ねて読んでも、事象 ID で重複しない
    assert len([x for x in store.cases() if x["rule"] == "P4"]) == 1
    # 取り込み位置は、古い記録を受け取っても後ろへ戻らない
    assert store.get_cursor("entra-audit") > "2026-10-15T03:42"
    assert "entra-audit" in store.sources_last_seen()
