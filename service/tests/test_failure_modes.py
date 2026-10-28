"""admission-control.md 節10（F1〜F12）と defense-system.md 節12（G 系）のうち、台帳で判定できるもの。

製品側の拒否（app management policy、App Control、Resource Guard など）は検証環境で実証する。
ここで確かめるのは、それらの事象を受けた台帳の判定と、期待しない結果にならないことである。
"""

from datetime import datetime, timedelta, timezone

from conftest import T0, auth, mins

from defence.config import DiagnosticWindow, Indicator, RegisteredApp, Source
from defence.models import Action, ActorType, Event, Outcome, Plane, Presence, Response


def test_f1_password_only_denied_without_lock(engine):
    d = engine.evaluate(auth(outcome=Outcome.success))
    assert d.rule == "P1" and d.response == Response.deny
    assert not any("lock" in a.kind for a in d.actions)


def test_f2_spray_rate_limits_chain_not_ip_wide(engine):
    for i in range(10):
        d = engine.evaluate(auth(t=T0 + timedelta(seconds=i), account=f"u{i}"))
    assert "P2" in d.matched
    # 同じ IP でも、節3.1を満たす利用者は通る
    ok = engine.evaluate(
        auth(t=T0 + mins(1), account="bob", cert=Presence.present, mfa=Presence.present,
             device="dev-1", outcome=Outcome.success)
    )
    assert ok.response == Response.allow
    # 証明書の無い後続は制限される
    nxt = engine.evaluate(auth(t=T0 + mins(1), account="carol"))
    assert nxt.rule.startswith("BLOCKED") and nxt.response == Response.rate_limit


def test_f2_below_threshold_no_rate_limit(engine):
    for i in range(9):
        d = engine.evaluate(auth(t=T0 + timedelta(seconds=i), account=f"u{i}"))
    assert "P2" not in d.matched


def test_f3_decoy_then_prod_blocks_chain(engine):
    engine.evaluate(Event(time=T0, plane=Plane.interactive, action=Action.decoy_hit,
                          source_ip="198.51.100.7", target="/admin"))
    d = engine.evaluate(auth(t=T0 + mins(10), ip="198.51.100.7"))
    assert "P3" in d.matched
    again = engine.evaluate(auth(t=T0 + mins(20), ip="198.51.100.7"))
    assert again.rule == "BLOCKED:P3"


def test_f3_decoy_outside_window_no_block(engine):
    engine.evaluate(Event(time=T0, plane=Plane.interactive, action=Action.decoy_hit,
                          source_ip="198.51.100.7"))
    d = engine.evaluate(auth(t=T0 + mins(31), ip="198.51.100.7"))
    assert "P3" not in d.matched


def test_f4_registered_crawler_record_only(engine, settings):
    settings.registrations.crawler_ips.append("192.0.2.50")
    settings.registrations.diagnostic_windows.append(
        DiagnosticWindow(source_ip="192.0.2.60", start=T0 - mins(5), end=T0 + mins(60))
    )
    for ip in ("192.0.2.50", "192.0.2.60"):
        d = engine.evaluate(Event(time=T0, plane=Plane.interactive, action=Action.decoy_hit, source_ip=ip))
        assert d.rule == "P7" and d.response == Response.record
        after = engine.evaluate(auth(t=T0 + mins(1), ip=ip))
        assert "P3" not in after.matched


def test_f5_registered_app_in_scope_allowed_regardless_of_ip(engine, settings):
    settings.registrations.applications.append(
        RegisteredApp(application_id="app-1", service_principal_id="sp-1", scopes=["Mail.Read"])
    )
    settings.indicators.ips.append(
        Indicator(value="144.172.64.99", expires=T0 + timedelta(days=30))
    )
    d = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.resource_access,
                              application_id="app-1", service_principal_id="sp-1",
                              scope="Mail.Read", source_ip="144.172.64.99"))
    assert d.response == Response.allow and "P5" in d.matched


def test_f6_sp_self_credential_and_role_contained_not_deleted(engine, enforcer):
    cred = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.credential_add,
                                 actor_type=ActorType.service_principal, actor_id="sp-x",
                                 service_principal_id="sp-x", target_principal_id="sp-x",
                                 credential_key_id="11111111-2222-3333-4444-555555555555"))
    assert cred.rule == "P4" and cred.response == Response.contain and cred.open_case
    assert [a.kind for a in cred.actions] == ["remove_sp_credential"]
    role = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.role_assign,
                                 actor_type=ActorType.service_principal, actor_id="sp-x",
                                 service_principal_id="sp-x", target_principal_id="sp-sibling",
                                 role_definition_id="62e90394-69f5-4237-9190-012177145e10"))
    assert role.rule == "P4"
    assert role.actions[0].kind == "remove_role_assignment"
    assert role.actions[0].params["principal_id"] == "sp-sibling"
    kinds = {a.kind for d in (cred, role) for a in d.actions}
    assert not any("delete" in k for k in kinds)
    # 既定は dry-run。人の当番を待たず判定は出るが、実行はしない
    results = enforcer.execute(cred.event_id, cred.actions)
    assert results[0]["status"] == "dry-run"


def test_f6_unknown_key_id_goes_to_human(engine):
    d = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.credential_add,
                              actor_type=ActorType.service_principal, actor_id="sp-x",
                              service_principal_id="sp-x"))
    assert d.actions[0].automatic is False


def test_f7_ioc_ip_alone_records_only(engine, settings):
    settings.indicators.ips.append(Indicator(value="144.172.64.99", expires=T0 + timedelta(days=1)))
    d = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.policy_change,
                              source_ip="144.172.64.99", service_principal_id="sp-1"))
    assert d.rule == "P5" and d.response == Response.record


def test_f7_expired_indicator_ignored(engine, settings):
    settings.indicators.ips.append(Indicator(value="144.172.64.99", expires=T0 - timedelta(days=1)))
    d = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.policy_change,
                              source_ip="144.172.64.99", service_principal_id="sp-1"))
    assert "P5" not in d.matched


def test_f8_published_user_agent_records_only(engine, settings):
    settings.indicators.user_agents.append(
        Indicator(value="python-requests/2.31.0", expires=T0 + timedelta(days=1))
    )
    d = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.policy_change,
                              user_agent="python-requests/2.31.0", service_principal_id="sp-1"))
    assert d.rule == "P6" and d.response == Response.record


def test_f9_mixed_ip_only_no_cert_chain_limited(engine):
    ip = "198.51.100.7"
    engine.evaluate(Event(time=T0, plane=Plane.interactive, action=Action.decoy_hit, source_ip=ip))
    engine.evaluate(auth(t=T0 + mins(1), ip=ip))
    managed = engine.evaluate(
        auth(t=T0 + mins(2), ip=ip, account="bob", cert=Presence.present, mfa=Presence.present,
             device="dev-1", outcome=Outcome.success)
    )
    assert managed.response == Response.allow


def test_f10_lockout_ratio_suppresses_account_lock(engine):
    for i in range(10):
        d = engine.evaluate(auth(t=T0 + timedelta(seconds=i), account=f"u{i}", outcome=Outcome.lockout))
    assert "P2" in d.matched and d.suppress_account_lockout


def test_f11_gpo_change_committed_opens_case(engine, store):
    d = engine.evaluate(Event(time=T0, plane=Plane.host, action=Action.gpo_change,
                              host="dc01", actor_id="adm", target="Default Domain Policy"))
    assert d.rule == "Q8" and d.open_case
    assert store.cases()[0]["rule"] == "Q8"


def test_f12_no_graph_logs_no_auto_block(engine, settings):
    settings.registrations.applications.append(
        RegisteredApp(application_id="app-1", service_principal_id="sp-1", scopes=["Mail.Read"])
    )
    d = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.resource_access,
                              application_id="app-1", service_principal_id="sp-1", scope="Mail.Read"))
    assert d.response == Response.allow and not d.actions


def test_p8_out_of_scope_proposal_only(engine, settings):
    settings.registrations.applications.append(
        RegisteredApp(application_id="app-1", service_principal_id="sp-1", scopes=["Mail.Read"])
    )
    d = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.resource_access,
                              application_id="app-1", service_principal_id="sp-1",
                              scope="Files.ReadWrite.All"))
    assert d.rule == "P8" and d.actions[0].automatic is False


def test_g5_lateral_on_three_hosts_isolates_without_lock(engine):
    for i, h in enumerate(["ws1", "ws2", "ws3"]):
        d = engine.evaluate(Event(time=T0 + mins(i), plane=Plane.host, action=Action.lateral_denied,
                                  host=h, actor_id="u-attacker"))
    assert d.rule == "Q1"
    kinds = [a.kind for a in d.actions]
    assert kinds.count("isolate_host_east_west") == 3
    assert "revoke_privileged_activation" in kinds
    assert not any("lock" in k for k in kinds)


def test_g6_audit_disable_detected_not_claimed_denied(engine):
    d = engine.evaluate(Event(time=T0, plane=Plane.host, action=Action.audit_disable, host="dc01"))
    assert d.rule == "Q2" and d.response == Response.record and d.open_case


def test_g10_unapproved_backup_change(engine):
    denied = engine.evaluate(Event(time=T0, plane=Plane.host, action=Action.backup_policy_change,
                                   outcome=Outcome.denied, approved=False, host="vault"))
    assert denied.response == Response.record and denied.open_case
    passed = engine.evaluate(Event(time=T0, plane=Plane.host, action=Action.backup_policy_change,
                                   outcome=Outcome.success, approved=False, host="vault"))
    assert passed.response == Response.contain


def test_g11_canary_isolates_east_west(engine):
    d = engine.evaluate(Event(time=T0, plane=Plane.host, action=Action.canary_touch, host="fs1"))
    assert d.rule == "Q3"
    assert d.actions[0].kind == "isolate_host_east_west"


def test_q5_unregistered_bulk_secret_read(engine, settings):
    settings.registrations.secret_readers.append("sp-backup")
    ok = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.secret_bulk_read,
                               actor_id="sp-backup", service_principal_id="sp-backup"))
    assert ok.rule != "Q5"
    bad = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.secret_bulk_read,
                                actor_id="sp-x", service_principal_id="sp-x"))
    assert bad.rule == "Q5"


def test_q6_egress_after_denial_extends_block(engine, store):
    engine.evaluate(Event(time=T0, plane=Plane.host, action=Action.canary_touch, host="fs1"))
    d = engine.evaluate(Event(time=T0 + mins(1), plane=Plane.host, action=Action.egress_denied, host="fs1"))
    assert d.rule == "Q6"
    assert store.active_blocks("host:fs1", T0 + mins(100))


def test_g15_source_silence_after_grace(engine, settings, store, clock):
    settings.registrations.sources.append(Source(name="wef-dc01", registered_at=T0 - timedelta(days=5)))
    settings.registrations.sources.append(Source(name="new-src", registered_at=T0 - timedelta(hours=1)))
    engine.evaluate(Event(time=T0, source="wef-dc01", plane=Plane.host, action=Action.heartbeat, host="dc01"))
    clock.now = T0 + mins(10)
    assert engine.check_sources() == []
    clock.now = T0 + mins(16)
    assert engine.check_sources() == ["wef-dc01"]
    engine.check_sources()
    assert len([c for c in store.cases() if c["rule"] == "I5b"]) == 1


def test_g16_role_outside_pim_proposal(engine):
    d = engine.evaluate(Event(time=T0, plane=Plane.application, action=Action.role_assign,
                              actor_type=ActorType.user, actor_id="admin-1", via_pim=False,
                              target_principal_id="user-2",
                              role_definition_id="62e90394-69f5-4237-9190-012177145e10"))
    assert d.rule == "Q7" and d.actions[0].automatic is False


def test_idempotent_event_id(engine, store):
    e = auth(outcome=Outcome.success)
    a = engine.evaluate(e)
    b = engine.evaluate(e.model_copy())
    assert a == b
