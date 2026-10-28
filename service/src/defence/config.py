"""方針の閾値と台帳データ。値は ConfigMap から読む。コードの定数にしない。

既定値はすべて初期仮説である（admission-control.md 節5〜6 の ※要確認）。
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class Windows(BaseModel):
    decoy_to_auth_minutes: int = 30
    chain_block_minutes: int = 60
    spray_window_minutes: int = 5
    spray_distinct_accounts: int = 10
    lockout_ratio_suppress: float = 0.5
    lateral_window_minutes: int = 10
    lateral_distinct_hosts: int = 3
    chain_block_extend_minutes: int = 120
    source_silence_minutes: int = 15
    # Entra の診断設定は、送り先に届くまで最大3日かかる。新しい発生源はこの間、途絶と見なさない
    source_grace_hours: int = 72
    # 窓の集計に使う事象の保持期間。最長の窓より十分に長くする
    event_retention_hours: int = 168


class RegisteredApp(BaseModel):
    application_id: str
    service_principal_id: str | None = None
    scopes: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)


class DiagnosticWindow(BaseModel):
    source_ip: str
    start: datetime
    end: datetime


class Source(BaseModel):
    name: str
    registered_at: datetime


class Registrations(BaseModel):
    applications: list[RegisteredApp] = Field(default_factory=list)
    crawler_ips: list[str] = Field(default_factory=list)
    diagnostic_windows: list[DiagnosticWindow] = Field(default_factory=list)
    secret_readers: list[str] = Field(default_factory=list)
    sources: list[Source] = Field(default_factory=list)


class Indicator(BaseModel):
    value: str
    expires: datetime
    reference: str = ""

    def active(self, now: datetime) -> bool:
        return now < self.expires


class Indicators(BaseModel):
    ips: list[Indicator] = Field(default_factory=list)
    user_agents: list[Indicator] = Field(default_factory=list)


class EnforcementMode(StrEnum):
    dry_run = "dry-run"
    enforce = "enforce"


class Enforcement(BaseModel):
    mode: EnforcementMode = EnforcementMode.dry_run
    # 自動で実行してよい種類。ここに無い種類は、mode が enforce でも提案に留める
    automatic_kinds: list[str] = Field(
        default_factory=lambda: ["remove_sp_credential", "remove_role_assignment"]
    )
    host_webhook_url: str | None = None  # 端末隔離を EDR や NAC へ渡す先


class Settings(BaseModel):
    windows: Windows = Field(default_factory=Windows)
    registrations: Registrations = Field(default_factory=Registrations)
    indicators: Indicators = Field(default_factory=Indicators)
    # Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator,
    # Application Administrator, Cloud Application Administrator のロールテンプレート ID
    privileged_role_ids: list[str] = Field(
        default_factory=lambda: [
            "62e90394-69f5-4237-9190-012177145e10",
            "e8611ab8-c189-46e8-94e1-60213ab1f814",
            "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
            "158c047a-c907-4556-b7ef-446551a6b5f7",
        ]
    )
    enforcement: Enforcement = Field(default_factory=Enforcement)

    def app(self, application_id: str | None, sp_id: str | None) -> RegisteredApp | None:
        for a in self.registrations.applications:
            if application_id and a.application_id == application_id:
                return a
            if sp_id and a.service_principal_id == sp_id:
                return a
        return None

    def ioc_ip(self, ip: str | None, now: datetime) -> bool:
        return bool(ip) and any(i.value == ip and i.active(now) for i in self.indicators.ips)

    def ioc_user_agent(self, ua: str | None, now: datetime) -> bool:
        return bool(ua) and any(
            i.value == ua and i.active(now) for i in self.indicators.user_agents
        )


def load_settings(path: str | Path | None) -> Settings:
    if path is None or not Path(path).exists():
        return Settings()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return Settings.model_validate(data)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
