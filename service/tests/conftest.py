from datetime import datetime, timedelta, timezone

import pytest

from defence.config import Settings
from defence.enforce import Enforcer
from defence.models import Event, Plane, Action, Outcome, Presence
from defence.policy import Engine
from defence.store import Store

T0 = datetime(2026, 10, 28, 9, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def settings():
    return Settings()


@pytest.fixture
def store():
    return Store(":memory:")


@pytest.fixture
def engine(store, settings, clock):
    return Engine(store, settings, clock)


@pytest.fixture
def enforcer(store, settings):
    return Enforcer(store, settings)


def auth(
    *,
    t: datetime = T0,
    account: str = "alice",
    ip: str = "203.0.113.10",
    cert: Presence = Presence.absent,
    mfa: Presence = Presence.absent,
    outcome: Outcome = Outcome.failure,
    device: str | None = None,
    **kw,
) -> Event:
    return Event(
        time=t,
        plane=Plane.interactive,
        action=Action.auth_attempt,
        outcome=outcome,
        account_id=account,
        source_ip=ip,
        device_cert=cert,
        device_id=device,
        phishing_resistant_mfa=mfa,
        **kw,
    )


def mins(n: float) -> timedelta:
    return timedelta(minutes=n)
