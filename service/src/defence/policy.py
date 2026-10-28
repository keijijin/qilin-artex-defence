"""方針評価。admission-control.md 節5〜6 と defense-system.md 節10.2。

評価順は P1, P4, P3, P2, P8, P7, A1, A2, P5, P6 で、先に一致した規則が応答になる。
ただし P3 と P2 の遮断は、応答にならなくても連鎖台帳に残す。P1 が token を拒否した後も、
同じ連鎖の次の試行を止めるためである。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from .config import Settings, utcnow
from .models import (
    Action,
    ActionRequest,
    ActorType,
    Decision,
    Event,
    Outcome,
    Plane,
    Presence,
    Response,
)
from .store import Store

SP_CHANGE_ACTIONS = {
    Action.credential_add,
    Action.owner_add,
    Action.role_assign,
    Action.consent_change,
}
HOST_DENIAL_ACTIONS = [Action.process_denied.value, Action.lateral_denied.value]

# 遮断の範囲。no_cert は管理端末証明書を提示しない認証だけに効く（節5）
SCOPE_ALL = "all"
SCOPE_NO_CERT = "no_cert"


@dataclass
class Match:
    rule: str
    response: Response
    actions: list[ActionRequest] = field(default_factory=list)
    open_case: bool = False
    note: str = ""
    blocks: list[tuple[str, str, timedelta]] = field(default_factory=list)
    suppress_lockout: bool = False


def chain_key(e: Event) -> str:
    """admission-control.md 節5。IP 全体を鍵にするのは、端末も account も無いおとりだけ。"""
    if e.plane == Plane.application:
        return f"sp:{e.service_principal_id or e.actor_id or e.application_id}"
    if e.plane == Plane.host:
        return f"host:{e.host}" if e.host else f"actor:{e.actor_id}"
    if e.device_cert == Presence.present and e.device_id:
        return f"device:{e.device_id}"
    if e.account_id:
        return f"acct_ip:{e.account_id}|{e.source_ip}"
    if e.source_ip:
        return f"ip:{e.source_ip}"
    return f"event:{e.event_id}"


class Engine:
    def __init__(
        self, store: Store, settings: Settings, clock: Callable[[], datetime] = utcnow
    ) -> None:
        self.store = store
        self.settings = settings
        self.clock = clock
        # 窓の集計と記録の間に別の事象が割り込まないよう、評価は一件ずつ行う
        self._lock = threading.Lock()

    # 公開

    def evaluate(self, e: Event) -> Decision:
        with self._lock:
            return self._evaluate(e)

    def _evaluate(self, e: Event) -> Decision:
        e.time = e.time.astimezone(timezone.utc) if e.time.tzinfo else e.time.replace(
            tzinfo=timezone.utc
        )
        key = chain_key(e)
        prior = self.store.get_decision(e.event_id)
        if prior is not None:
            return prior
        self.store.add_event(e, key)

        matches = [m for m in (r(e, key) for r in self._rules()) if m is not None]
        primary = matches[0] if matches else Match("default", Response.record)
        now = self.clock()

        for m in matches:
            for bkey, scope, dur in m.blocks:
                self.store.add_block(bkey, scope, e.time + dur, m.rule, e.event_id)

        actions = []
        for m in matches:
            for a in m.actions:
                a.automatic = a.automatic and a.kind in self.settings.enforcement.automatic_kinds
                actions.append(a)

        d = Decision(
            event_id=e.event_id,
            chain_key=key,
            rule=primary.rule,
            response=primary.response,
            matched=[m.rule for m in matches],
            actions=actions,
            open_case=any(m.open_case for m in matches),
            suppress_account_lockout=any(m.suppress_lockout for m in matches),
            note=" / ".join(m.note for m in matches if m.note),
        )
        self.store.add_decision(d)
        if d.open_case:
            self.store.open_case(d.rule, e.event_id, d.note or d.rule, now)
        return d

    def check_sources(self) -> list[str]:
        """I5b。登録された発生源から事象が途絶えたら案件を開く。猶予期間中の発生源は除く。"""
        now = self.clock()
        w = self.settings.windows
        last = self.store.sources_last_seen()
        silent = []
        for src in self.settings.registrations.sources:
            if now - src.registered_at < timedelta(hours=w.source_grace_hours):
                continue
            seen = last.get(src.name)
            if seen is None or now - seen > timedelta(minutes=w.source_silence_minutes):
                silent.append(src.name)
                summary = f"発生源 {src.name} からの事象が途絶えている"
                if not self.store.has_open_case("I5b", summary):
                    self.store.open_case("I5b", "-", summary, now)
        return silent

    # 規則

    def _rules(self):
        return [
            self.blocked,
            self.p1, self.p4, self.p3, self.p2, self.p8, self.p7, self.a1, self.a2,
            self.q1, self.q2, self.q3, self.q4, self.q5, self.q6, self.q7, self.q8,
            self.p5, self.p6,
        ]

    def _is_auth(self, e: Event) -> bool:
        return e.plane == Plane.interactive and e.action == Action.auth_attempt

    def _meets_interactive(self, e: Event) -> bool:
        return (
            e.device_cert == Presence.present
            and e.phishing_resistant_mfa == Presence.present
        )

    def blocked(self, e: Event, key: str) -> Match | None:
        if not self._is_auth(e):
            return None
        no_cert = e.device_cert != Presence.present
        keys = [key] + ([f"ip:{e.source_ip}"] if e.source_ip else [])
        for k in keys:
            for b in self.store.active_blocks(k, e.time):
                if b["scope"] == SCOPE_ALL or (b["scope"] == SCOPE_NO_CERT and no_cert):
                    resp = Response.rate_limit if b["rule"] == "P2" else Response.deny
                    return Match(f"BLOCKED:{b['rule']}", resp, note=f"{k} は {b['rule']} で遮断中")
        return None

    def p1(self, e: Event, key: str) -> Match | None:
        if self._is_auth(e) and not self._meets_interactive(e):
            return Match("P1", Response.deny, note="token を出さない。account 状態は変えない")
        return None

    def p4(self, e: Event, key: str) -> Match | None:
        if not (
            e.plane == Plane.application
            and e.actor_type == ActorType.service_principal
            and e.action in SP_CHANGE_ACTIONS
            and e.outcome == Outcome.success
        ):
            return None
        target = e.target_principal_id or e.service_principal_id
        acts: list[ActionRequest] = []
        if e.action == Action.credential_add:
            acts.append(
                ActionRequest(
                    kind="remove_sp_credential",
                    params={
                        "service_principal_id": target,
                        "key_id": e.credential_key_id,
                        "object_type": e.target if e.target == "application" else "servicePrincipal",
                    },
                    automatic=e.credential_key_id is not None,
                )
            )
        elif e.action == Action.role_assign:
            acts.append(
                ActionRequest(
                    kind="remove_role_assignment",
                    params={"principal_id": target, "role_definition_id": e.role_definition_id},
                )
            )
        elif e.action == Action.owner_add:
            acts.append(ActionRequest(kind="remove_owner", params={"target": target}, automatic=False))
        else:
            acts.append(ActionRequest(kind="revoke_consent", params={"target": target}, automatic=False))
        return Match(
            "P4",
            Response.contain,
            acts,
            open_case=True,
            note="service principal による変更。application オブジェクトは残し、監査を保全する",
        )

    def _excluded_decoy(self, d: Event) -> bool:
        reg = self.settings.registrations
        if d.source_ip in reg.crawler_ips:
            return True
        return any(
            w.source_ip == d.source_ip and w.start <= d.time <= w.end
            for w in reg.diagnostic_windows
        )

    def p3(self, e: Event, key: str) -> Match | None:
        if not (self._is_auth(e) and e.device_cert != Presence.present and e.source_ip):
            return None
        w = self.settings.windows
        since = e.time - timedelta(minutes=w.decoy_to_auth_minutes)
        decoys = [
            d for d in self.store.events(Action.decoy_hit.value, since, e.time, source_ip=e.source_ip)
            if not self._excluded_decoy(d)
        ]
        if not decoys:
            return None
        dur = timedelta(minutes=w.chain_block_minutes)
        return Match(
            "P3",
            Response.block_chain,
            blocks=[(key, SCOPE_ALL, dur), (f"ip:{e.source_ip}", SCOPE_NO_CERT, dur)],
            note="おとりの後に証明書の無い本番認証。連鎖を期限付きで遮断する",
        )

    def p2(self, e: Event, key: str) -> Match | None:
        if not (
            self._is_auth(e)
            and e.outcome in (Outcome.failure, Outcome.lockout)
            and e.device_cert != Presence.present
            and e.source_ip
        ):
            return None
        w = self.settings.windows
        since = e.time - timedelta(minutes=w.spray_window_minutes)
        fails = [
            f for f in self.store.events(Action.auth_attempt.value, since, e.time, source_ip=e.source_ip)
            if f.outcome in (Outcome.failure, Outcome.lockout) and f.device_cert != Presence.present
        ]
        if len({f.account_id for f in fails if f.account_id}) < w.spray_distinct_accounts:
            return None
        lockouts = sum(1 for f in fails if f.outcome == Outcome.lockout)
        suppress = lockouts / len(fails) > w.lockout_ratio_suppress
        note = "連鎖を速度制限する。節3.1を満たす後続には追加認証を求める"
        if suppress:
            note += "。ロックアウトが失敗の半数を超えたため account ロックを追加しない"
        return Match(
            "P2",
            Response.rate_limit,
            blocks=[(f"ip:{e.source_ip}", SCOPE_NO_CERT, timedelta(minutes=w.chain_block_minutes))],
            suppress_lockout=suppress,
            note=note,
        )

    def p8(self, e: Event, key: str) -> Match | None:
        if not (e.plane == Plane.application and e.action == Action.resource_access):
            return None
        app = self.settings.app(e.application_id, e.service_principal_id)
        if app and (e.scope in app.scopes) and (not app.resources or e.target in app.resources):
            return None
        return Match(
            "P8",
            Response.contain,
            [
                ActionRequest(
                    kind="suspend_sp_token_refresh",
                    params={"service_principal_id": e.service_principal_id},
                    automatic=False,
                )
            ],
            open_case=True,
            note="登録範囲を超える application 操作",
        )

    def p7(self, e: Event, key: str) -> Match | None:
        if e.action == Action.decoy_hit and self._excluded_decoy(e):
            return Match("P7", Response.record, note="登録済みクローラーまたは診断窓")
        return None

    def a1(self, e: Event, key: str) -> Match | None:
        if self._is_auth(e) and self._meets_interactive(e):
            return Match("A1", Response.allow)
        return None

    def a2(self, e: Event, key: str) -> Match | None:
        # P8 に一致しなかった resource_access は、登録範囲内である
        if e.plane == Plane.application and e.action == Action.resource_access:
            return Match("A2", Response.allow)
        return None

    def q1(self, e: Event, key: str) -> Match | None:
        if e.action.value not in HOST_DENIAL_ACTIONS or not e.actor_id:
            return None
        w = self.settings.windows
        since = e.time - timedelta(minutes=w.lateral_window_minutes)
        evs = self.store.events(HOST_DENIAL_ACTIONS, since, e.time, actor_id=e.actor_id)
        hosts = sorted({x.host for x in evs if x.host})
        if len(hosts) < w.lateral_distinct_hosts:
            return None
        acts = [
            ActionRequest(kind="isolate_host_east_west", params={"host": h}) for h in hosts
        ]
        acts.append(
            ActionRequest(kind="revoke_privileged_activation", params={"principal_id": e.actor_id})
        )
        return Match(
            "Q1",
            Response.contain,
            acts,
            open_case=True,
            note="複数端末で実行または横展開を拒否。端末は東西通信だけ隔離し、account はロックしない",
        )

    def q2(self, e: Event, key: str) -> Match | None:
        if e.action == Action.audit_disable:
            # 監査の停止は拒否できない（precommit-feasibility.md 節4）。記録の保全と案件で扱う
            return Match("Q2", Response.record, open_case=True, note="監査の停止または消去")
        return None

    def q3(self, e: Event, key: str) -> Match | None:
        if e.action == Action.canary_touch and e.outcome == Outcome.success:
            return Match(
                "Q3",
                Response.contain,
                [
                    ActionRequest(kind="isolate_host_east_west", params={"host": e.host}),
                    ActionRequest(kind="extend_backup_delete_delay", params={}, automatic=False),
                ],
                open_case=True,
                note="おとりのファイルへの書き込み",
            )
        return None

    def q4(self, e: Event, key: str) -> Match | None:
        if e.action != Action.backup_policy_change or e.approved:
            return None
        if e.outcome == Outcome.denied:
            return Match("Q4", Response.record, open_case=True, note="承認の無いバックアップ変更を製品が拒否した")
        return Match(
            "Q4",
            Response.contain,
            [ActionRequest(kind="restore_backup_policy", params={"target": e.target}, automatic=False)],
            open_case=True,
            note="承認の無いバックアップ変更が通った。I6a が機能していない",
        )

    def q5(self, e: Event, key: str) -> Match | None:
        if e.action != Action.secret_bulk_read:
            return None
        if e.actor_id in self.settings.registrations.secret_readers:
            return None
        return Match(
            "Q5",
            Response.contain,
            [
                ActionRequest(
                    kind="suspend_sp_token_refresh",
                    params={"service_principal_id": e.actor_id},
                    automatic=False,
                ),
                ActionRequest(kind="reissue_secrets", params={"target": e.target}, automatic=False),
            ],
            open_case=True,
            note="登録範囲外の主体による secret の一括読み取り",
        )

    def q6(self, e: Event, key: str) -> Match | None:
        if e.action != Action.egress_denied:
            return None
        prior = [
            d for d in self.store.decisions_for_chain(key)
            if d.response in (Response.deny, Response.block_chain, Response.contain)
        ]
        if not prior:
            return None
        until = e.time + timedelta(minutes=self.settings.windows.chain_block_extend_minutes)
        self.store.extend_blocks(key, until)
        return Match(
            "Q6",
            Response.block_chain,
            blocks=[(key, SCOPE_ALL, until - e.time)],
            note="拒否と同じ連鎖での外向き通信の拒否。遮断を延長する",
        )

    def q7(self, e: Event, key: str) -> Match | None:
        if not (
            e.action == Action.role_assign
            and e.actor_type == ActorType.user
            and e.via_pim is False
            and e.role_definition_id in self.settings.privileged_role_ids
        ):
            return None
        return Match(
            "Q7",
            Response.contain,
            [
                ActionRequest(
                    kind="remove_role_assignment",
                    params={
                        "principal_id": e.target_principal_id,
                        "role_definition_id": e.role_definition_id,
                    },
                    automatic=False,
                )
            ],
            open_case=True,
            note="PIM の外での高権限ロールの割り当て（I6b）",
        )

    def q8(self, e: Event, key: str) -> Match | None:
        if e.action in (Action.gpo_change, Action.sysvol_write) and e.outcome == Outcome.success:
            return Match(
                "Q8",
                Response.record,
                open_case=True,
                note="GPO または SYSVOL の変更が commit された（I3c 事後検出）",
            )
        return None

    def p5(self, e: Event, key: str) -> Match | None:
        if e.ioc_match or self.settings.ioc_ip(e.source_ip, e.time):
            return Match("P5", Response.record, note="公開 IOC の IP と一致。単独では遮断しない")
        return None

    def p6(self, e: Event, key: str) -> Match | None:
        if self.settings.ioc_user_agent(e.user_agent, e.time):
            return Match("P6", Response.record, note="公表 User-Agent と一致。単独では遮断しない")
        return None
