"""事象と判定のスキーマ。admission-control.md 節4、defense-system.md 節10.1。"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class Plane(StrEnum):
    interactive = "interactive"
    application = "application"
    host = "host"  # L2〜L6 の端末・サーバー・バックアップ由来


class Action(StrEnum):
    auth_attempt = "auth_attempt"
    decoy_hit = "decoy_hit"
    credential_add = "credential_add"
    owner_add = "owner_add"
    role_assign = "role_assign"
    consent_change = "consent_change"
    policy_change = "policy_change"
    resource_access = "resource_access"
    gpo_change = "gpo_change"
    sysvol_write = "sysvol_write"
    audit_disable = "audit_disable"
    process_denied = "process_denied"
    lateral_denied = "lateral_denied"
    secret_bulk_read = "secret_bulk_read"
    egress_denied = "egress_denied"
    backup_policy_change = "backup_policy_change"
    canary_touch = "canary_touch"
    heartbeat = "heartbeat"


class Outcome(StrEnum):
    success = "success"
    failure = "failure"
    lockout = "lockout"
    denied = "denied"


class Presence(StrEnum):
    present = "present"
    absent = "absent"
    not_applicable = "not_applicable"


class ActorType(StrEnum):
    user = "user"
    service_principal = "service_principal"
    unknown = "unknown"


class Event(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "unknown"  # 発生源。I5b の途絶検出に使う
    plane: Plane
    action: Action
    outcome: Outcome = Outcome.success

    account_id: str | None = None
    device_id: str | None = None
    device_cert: Presence = Presence.absent
    phishing_resistant_mfa: Presence = Presence.not_applicable

    # アプリ面。service_principal_id は操作した主体、target_principal_id は操作された主体
    application_id: str | None = None
    service_principal_id: str | None = None
    actor_type: ActorType = ActorType.unknown
    actor_id: str | None = None
    target_principal_id: str | None = None
    role_definition_id: str | None = None
    credential_key_id: str | None = None
    scope: str | None = None
    via_pim: bool | None = None

    host: str | None = None
    approved: bool | None = None  # I6a の承認の有無
    target: str | None = None

    # 補助属性。単独の遮断条件にしない
    source_ip: str | None = None
    user_agent: str | None = None
    tls_fingerprint: str | None = None
    ioc_match: bool = False

    # 事後の案件記録用。方針の入力にしない
    actor_label: str | None = None


class Response(StrEnum):
    allow = "allow"
    deny = "deny"  # token や session を出さない、変更を通さない
    block_chain = "block_chain"
    rate_limit = "rate_limit"
    contain = "contain"  # 資格情報の無効化、ロールの取り消し、端末の隔離
    record = "record"


class ActionRequest(BaseModel):
    """強制点への指示。automatic=False は人の判断を要する提案。"""

    kind: str
    params: dict[str, str | int | list[str] | None] = Field(default_factory=dict)
    automatic: bool = True


class Decision(BaseModel):
    event_id: str
    chain_key: str
    rule: str
    response: Response
    matched: list[str]
    actions: list[ActionRequest] = Field(default_factory=list)
    open_case: bool = False
    suppress_account_lockout: bool = False
    note: str = ""
