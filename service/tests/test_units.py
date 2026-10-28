"""部品ごとの単体テスト。方針の失敗モードは test_failure_modes.py にある。"""

import threading
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from conftest import T0, auth, mins

from defence import main as main_mod
from defence.api import create_app
from defence.auth import TokenReviewer
from defence.collector import Collector, normalize
from defence.config import EnforcementMode, Settings, load_settings
from defence.enforce import Enforcer
from defence.graph import GraphClient
from defence.models import Action, ActionRequest, ActorType, Event, Outcome, Plane, Presence, Response
from defence.store import Store

KEY = "11111111-2222-3333-4444-555555555555"


# 設定


def test_load_settings_file_and_missing(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("windows:\n  spray_distinct_accounts: 3\nenforcement:\n  mode: enforce\n")
    s = load_settings(p)
    assert s.windows.spray_distinct_accounts == 3 and s.enforcement.mode == EnforcementMode.enforce
    assert load_settings(tmp_path / "none.yaml") == Settings()
    assert load_settings(None) == Settings()
    (tmp_path / "empty.yaml").write_text("")
    assert load_settings(tmp_path / "empty.yaml") == Settings()


def test_repo_policy_file_loads():
    s = load_settings(Path(__file__).parents[2] / "deploy/base/policy.yaml")
    assert s.enforcement.mode == EnforcementMode.dry_run
    assert [x.name for x in s.registrations.sources] == ["entra-audit"]


# 台帳


def test_store_prune_keeps_decisions(engine, store):
    e = auth(outcome=Outcome.success)
    d = engine.evaluate(e)
    store.add_block("k", "all", T0 + mins(1), "P3", "x")
    assert store.prune(timedelta(hours=1), T0 + timedelta(hours=2)) == 1
    assert store.active_blocks("k", T0) == []
    assert engine.evaluate(e.model_copy()) == d  # 事象を消しても、同じ ID は再評価しない


def test_store_extend_only_lengthens(store):
    store.add_block("k", "all", T0 + mins(10), "P3", "x")
    assert store.extend_blocks("k", T0 + mins(5)) == 0
    assert store.extend_blocks("k", T0 + mins(50)) == 1
    assert store.active_blocks("k", T0 + mins(40))


def test_store_event_filters(engine, store):
    engine.evaluate(Event(time=T0, plane=Plane.host, action=Action.lateral_denied, host="h1", actor_id="a"))
    engine.evaluate(Event(time=T0, plane=Plane.host, action=Action.lateral_denied, host="h2", actor_id="b"))
    assert len(store.events("lateral_denied", T0 - mins(1), T0, actor_id="a")) == 1
    assert len(store.events("lateral_denied", T0 - mins(1), T0, chain_key="host:h2")) == 1
    assert store.events("lateral_denied", T0 + mins(1), T0 + mins(2)) == []


def test_store_file_backed(tmp_path):
    db = tmp_path / "sub" / "ledger.db"
    s = Store(db)
    s.set_cursor("c", "1")
    assert Store(db).get_cursor("c") == "1"
    assert s.get_cursor("none") is None


def test_naive_time_is_utc(engine, store):
    e = auth(t=T0.replace(tzinfo=None), outcome=Outcome.success)
    engine.evaluate(e)
    assert store.events("auth_attempt", T0 - mins(1), T0 + mins(1))[0].time == T0


# 方針の残りの分岐


def test_p4_owner_and_consent_are_proposals(engine):
    for action, kind in ((Action.owner_add, "remove_owner"), (Action.consent_change, "revoke_consent")):
        d = engine.evaluate(Event(time=T0, plane=Plane.application, action=action,
                                  actor_type=ActorType.service_principal, actor_id="sp", service_principal_id="sp"))
        assert d.actions[0].kind == kind and d.actions[0].automatic is False


def test_p4_failed_change_not_contained(engine):
    d = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.role_assign, outcome=Outcome.failure,
                              actor_type=ActorType.service_principal, actor_id="sp", service_principal_id="sp"))
    assert "P4" not in d.matched


def test_p4_application_object_credential(engine):
    d = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.credential_add, target="application",
                              actor_type=ActorType.service_principal, actor_id="sp", service_principal_id="sp",
                              target_principal_id="app-obj", credential_key_id=KEY))
    assert d.actions[0].params["object_type"] == "application"


def test_automatic_kinds_gate(engine, settings):
    settings.enforcement.automatic_kinds = []
    d = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.credential_add,
                              actor_type=ActorType.service_principal, actor_id="sp", service_principal_id="sp",
                              credential_key_id=KEY))
    assert d.actions[0].automatic is False


def test_q4_approved_change_passes(engine):
    d = engine.evaluate(Event(time=T0, plane=Plane.host, action=Action.backup_policy_change, approved=True, host="v"))
    assert "Q4" not in d.matched


def test_q7_pim_assignment_not_flagged(engine):
    d = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.role_assign, actor_type=ActorType.user,
                              actor_id="u", via_pim=True, role_definition_id="62e90394-69f5-4237-9190-012177145e10"))
    assert "Q7" not in d.matched


def test_q6_without_prior_denial(engine):
    d = engine.evaluate(Event(time=T0, plane=Plane.host, action=Action.egress_denied, host="clean"))
    assert "Q6" not in d.matched


def test_q1_needs_actor(engine):
    d = engine.evaluate(Event(time=T0, plane=Plane.host, action=Action.process_denied, host="h"))
    assert d.rule == "default" and d.chain_key == "host:h"


def test_chain_keys(engine):
    from defence.policy import chain_key
    assert chain_key(Event(plane=Plane.host, action=Action.heartbeat, actor_id="a")) == "actor:a"
    assert chain_key(Event(plane=Plane.interactive, action=Action.decoy_hit, source_ip="1.2.3.4")) == "ip:1.2.3.4"
    e = Event(plane=Plane.interactive, action=Action.decoy_hit)
    assert chain_key(e) == f"event:{e.event_id}"
    assert chain_key(auth(cert=Presence.present, device="d")) == "device:d"


def test_block_scope_all_applies_even_with_cert(engine, store):
    key = "device:d1"
    store.add_block(key, "all", T0 + mins(10), "Q6", "x")
    d = engine.evaluate(auth(cert=Presence.present, mfa=Presence.present, device="d1", outcome=Outcome.success))
    assert d.rule == "BLOCKED:Q6" and d.response == Response.deny


def test_concurrent_duplicate_event_single_case(engine, store):
    e = Event(time=T0, plane=Plane.application, action=Action.role_assign, actor_type=ActorType.service_principal,
              actor_id="sp", service_principal_id="sp", role_definition_id="r")
    threads = [threading.Thread(target=engine.evaluate, args=(e.model_copy(),)) for _ in range(20)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(store.cases()) == 1


# 強制


def _graph(tmp_path, handler, counter=None):
    tok = tmp_path / "t"
    tok.write_text("jwt")

    def route(req):
        if req.url.path.endswith("/token"):
            if counter is not None:
                counter.append(1)
            return httpx.Response(200, json={"access_token": "a", "expires_in": 3600})
        return handler(req)

    return GraphClient("t", "c", str(tok), http=httpx.Client(transport=httpx.MockTransport(route)))


@pytest.fixture
def enforce_settings(settings):
    settings.enforcement.mode = EnforcementMode.enforce
    settings.enforcement.automatic_kinds.append("isolate_host_east_west")
    return settings


def test_enforce_without_graph_escalates(store, enforce_settings):
    r = Enforcer(store, enforce_settings).execute("e", [ActionRequest(kind="remove_sp_credential",
                                                                     params={"service_principal_id": "s", "key_id": KEY})])
    assert r[0]["status"] == "escalated"


def test_enforce_missing_params_escalates(tmp_path, store, enforce_settings):
    enf = Enforcer(store, enforce_settings, _graph(tmp_path, lambda r: httpx.Response(200, json={})))
    r = enf.execute("e", [ActionRequest(kind="remove_sp_credential", params={"service_principal_id": "s"}),
                          ActionRequest(kind="remove_role_assignment", params={"principal_id": "p"})])
    assert [x["status"] for x in r] == ["escalated", "escalated"]


def test_enforce_application_object_and_already_removed(tmp_path, store, enforce_settings):
    seen = []

    def h(req):
        seen.append(req.url.path)
        return httpx.Response(200, json={"passwordCredentials": [], "keyCredentials": []})

    enf = Enforcer(store, enforce_settings, _graph(tmp_path, h))
    r = enf.execute("e", [ActionRequest(kind="remove_sp_credential",
                                        params={"service_principal_id": "o", "key_id": KEY, "object_type": "application"})])
    assert r[0]["status"] == "done" and "既に無い" in r[0]["detail"]
    assert seen == ["/v1.0/applications/o"]


def test_enforce_graph_error_is_failed_and_logged(tmp_path, store, enforce_settings):
    enf = Enforcer(store, enforce_settings, _graph(tmp_path, lambda r: httpx.Response(500)))
    r = enf.execute("e", [ActionRequest(kind="remove_role_assignment",
                                        params={"principal_id": "p", "role_definition_id": "r"})])
    assert r[0]["status"] == "failed"
    assert store.action_log()[0]["status"] == "failed"


def test_enforce_webhook(store, enforce_settings):
    got = []
    http = httpx.Client(transport=httpx.MockTransport(lambda r: got.append(r.content) or httpx.Response(202)))
    a = ActionRequest(kind="isolate_host_east_west", params={"host": "h"})
    assert Enforcer(store, enforce_settings, http=http).execute("e", [a])[0]["status"] == "escalated"
    enforce_settings.enforcement.host_webhook_url = "https://edr.example/hook"
    assert Enforcer(store, enforce_settings, http=http).execute("e", [a])[0]["status"] == "done"
    assert b'"host":"h"' in got[0]


def test_enforce_unknown_automatic_kind(store, enforce_settings):
    r = Enforcer(store, enforce_settings).execute("e", [ActionRequest(kind="something_new")])
    assert r[0]["status"] == "proposed"


# Graph と TokenReview


def test_graph_token_cached_and_paged(tmp_path):
    calls = []

    def h(req):
        if "skip" in str(req.url):
            return httpx.Response(200, json={"value": [{"id": 2}]})
        return httpx.Response(200, json={"value": [{"id": 1}], "@odata.nextLink": "https://graph.microsoft.com/v1.0/x?skip=1"})

    g = _graph(tmp_path, h, calls)
    assert [x["id"] for x in g.paged("/x")] == [1, 2]
    g.get("/y")
    assert len(calls) == 1


def test_graph_raises_on_error(tmp_path):
    g = _graph(tmp_path, lambda r: httpx.Response(403))
    with pytest.raises(httpx.HTTPStatusError):
        g.get("/x")


def test_tokenreview_caches(tmp_path):
    own = tmp_path / "own"
    own.write_text("sa")
    calls = []

    def route(req):
        calls.append(1)
        return httpx.Response(201, json={"status": {"authenticated": True, "user": {"username": "u"}}})

    rv = TokenReviewer({"u"}, "aud", http=httpx.Client(transport=httpx.MockTransport(route)), own_token_file=own)
    assert rv.allowed_user("t") == "u" and rv.allowed_user("t") == "u"
    assert len(calls) == 1
    for i in range(1005):
        rv._cache[f"old{i}"] = (0, None)
    rv.user("new")
    assert len(rv._cache) < 10


# 収集の変換の残り


def _rec(name, **kw):
    r = {"id": "r", "activityDateTime": "2026-10-15T03:42:00Z", "activityDisplayName": name, "result": "success",
         "initiatedBy": {"app": {"servicePrincipalId": "sp", "appId": "a"}}, "targetResources": []}
    r.update(kw)
    return r


@pytest.mark.parametrize("name,action", [
    ("Update application – Certificates and secrets management ", Action.credential_add),
    ("Add owner to service principal", Action.owner_add),
    ("Add owner to application", Action.owner_add),
    ("Add app role assignment to service principal", Action.consent_change),
    ("Consent to application", Action.consent_change),
    ("Add delegated permission grant", Action.consent_change),
])
def test_normalize_mapping(name, action):
    e = normalize(_rec(name, targetResources=[{"id": "obj", "type": "Application"}]))
    assert e.action == action
    if action == Action.credential_add:
        assert e.target == "application" and e.target_principal_id == "obj"


def test_normalize_user_actor_and_failure():
    e = normalize(_rec("Add member to role", result="failure",
                       initiatedBy={"user": {"id": "u1", "ipAddress": "203.0.113.1", "userPrincipalName": "a@x"}},
                       targetResources=[{"id": "t", "type": "User"}]))
    assert e.actor_type == ActorType.user and e.outcome == Outcome.failure
    assert e.source_ip == "203.0.113.1" and e.service_principal_id == "t" and e.actor_label == "a@x"


def test_collector_run_survives_errors(monkeypatch):
    class Boom(Collector):
        n = 0

        def poll_once(self):
            Boom.n += 1
            raise RuntimeError("x")

    def stop(_):
        if Boom.n >= 2:
            raise KeyboardInterrupt

    monkeypatch.setattr("defence.collector.time.sleep", stop)
    with pytest.raises(KeyboardInterrupt):
        Boom(None, "http://l", ledger_http=None).run(0)
    assert Boom.n == 2


# API の残り


def test_api_list_body_housekeeping_and_lifespan(store, engine, enforcer, settings):
    from defence.config import Source
    settings.registrations.sources.append(Source(name="s", registered_at=T0 - timedelta(days=9)))
    app = create_app(store, engine, enforcer, None, source_check_interval=0.01)
    with TestClient(app) as c:
        r = c.post("/v1/events", json=[{"plane": "host", "action": "heartbeat", "host": "h"},
                                       {"plane": "host", "action": "audit_disable", "host": "h"}])
        assert [x["rule"] for x in r.json()] == ["default", "Q2"]
        app.state.housekeeping()
        assert any(x["rule"] == "I5b" for x in c.get("/v1/cases").json())
        assert c.get("/v1/actions").status_code == 200


def test_api_housekeeping_logs_errors(store, engine, enforcer, monkeypatch):
    app = create_app(store, engine, enforcer, None, source_check_interval=None)
    monkeypatch.setattr(engine, "check_sources", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    app.state.housekeeping()  # 例外を外へ出さない


# 起動


def test_build_app_from_env(tmp_path, monkeypatch):
    (tmp_path / "p.yaml").write_text("enforcement:\n  mode: dry-run\n")
    monkeypatch.setenv("POLICY_FILE", str(tmp_path / "p.yaml"))
    monkeypatch.setenv("LEDGER_DB", str(tmp_path / "db" / "l.db"))
    monkeypatch.setenv("AUTH_MODE", "none")
    for k in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_FEDERATED_TOKEN_FILE"):
        monkeypatch.delenv(k, raising=False)
    with TestClient(main_mod.build_app()) as c:
        assert c.get("/readyz").status_code == 200
        assert c.get("/v1/cases").status_code == 200


def test_build_app_tokenreview_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("LEDGER_DB", str(tmp_path / "l.db"))
    monkeypatch.setenv("AUTH_MODE", "tokenreview")
    monkeypatch.setenv("ALLOWED_CALLERS", "a, b,")
    monkeypatch.setattr(main_mod, "TokenReviewer", lambda users, aud: ("rv", users, aud))
    captured = {}
    monkeypatch.setattr(main_mod, "create_app", lambda s, e, f, r: captured.setdefault("r", r))
    main_mod.build_app()
    assert captured["r"] == ("rv", {"a", "b"}, "defence-ledger")


def test_graph_from_env(tmp_path, monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    assert main_mod._graph() is None
    monkeypatch.setenv("AZURE_TENANT_ID", "t")
    monkeypatch.setenv("AZURE_CLIENT_ID", "c")
    monkeypatch.setenv("AZURE_FEDERATED_TOKEN_FILE", "/f")
    monkeypatch.setenv("GRAPH_BASE_URL", "http://mock/v1.0")
    g = main_mod._graph()
    assert g.base_url == "http://mock/v1.0" and g.tenant_id == "t"


def test_projected_auth_reads_token_each_time(tmp_path):
    p = tmp_path / "tok"
    p.write_text("one\n")
    seen = []
    c = httpx.Client(auth=main_mod._ProjectedAuth(str(p)),
                     transport=httpx.MockTransport(lambda r: seen.append(r.headers["authorization"]) or httpx.Response(200)))
    c.get("http://x/")
    p.write_text("two")
    c.get("http://x/")
    assert seen == ["Bearer one", "Bearer two"]


def test_run_collector_requires_env(monkeypatch):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    with pytest.raises(SystemExit):
        main_mod.run_collector()


def test_run_entrypoints_wire_up(tmp_path, monkeypatch):
    called = {}
    monkeypatch.setattr(main_mod.uvicorn, "run", lambda app, **kw: called.setdefault("uvicorn", kw))
    monkeypatch.setattr(main_mod, "build_app", lambda: "app")
    monkeypatch.setenv("PORT", "9000")
    main_mod.run_ledger()
    assert called["uvicorn"]["port"] == 9000

    monkeypatch.setattr(main_mod, "_graph", lambda: "graph")
    monkeypatch.setattr(main_mod.Collector, "run", lambda self, interval: called.setdefault("interval", interval))
    monkeypatch.setenv("POLL_SECONDS", "5")
    main_mod.run_collector()
    assert called["interval"] == 5.0
