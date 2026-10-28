"""本物の台帳（service/）と組み合わせる。台帳のパッケージが入っていなければ飛ばす。"""

from datetime import datetime, timezone

import httpx
import pytest

pytest.importorskip("defence.api")
from fastapi.testclient import TestClient  # noqa: E402

from defence.api import create_app  # noqa: E402
from defence.config import Settings  # noqa: E402
from defence.enforce import Enforcer  # noqa: E402
from defence.policy import Engine  # noqa: E402
from defence.store import Store  # noqa: E402

from defence_client import FailMode, LedgerClient, LedgerRejected  # noqa: E402

FAR_PAST = datetime(2000, 1, 1, tzinfo=timezone.utc)
FAR_FUTURE = datetime(2100, 1, 1, tzinfo=timezone.utc)
PASSWORD_ONLY = {
    "plane": "interactive", "action": "auth_attempt", "outcome": "success",
    "account_id": "alice", "source_ip": "203.0.113.10",
    "device_cert": "absent", "phishing_resistant_mfa": "absent",
}


@pytest.fixture
def ledger():
    store = Store(":memory:")
    settings = Settings()
    app = create_app(store, Engine(store, settings), Enforcer(store, settings), None,
                     source_check_interval=None)
    return store, TestClient(app, base_url="https://ledger.test")


@pytest.fixture
def client(ledger, tmp_path):
    token = tmp_path / "token"
    token.write_text("t")
    return LedgerClient("https://ledger.test", source="myapp", token_file=str(token),
                        http=ledger[1], retries=0)


def test_password_only_login_is_denied_by_p1(client):
    v = client.submit(PASSWORD_ONLY)
    assert (v.response, v.rule, v.degraded) == ("deny", "P1", False)
    assert not v.allowed


def test_device_cert_and_mfa_pass(client):
    v = client.submit({**PASSWORD_ONLY, "device_cert": "present", "phishing_resistant_mfa": "present"})
    assert v.allowed


def test_malformed_event_is_rejected(client):
    with pytest.raises(LedgerRejected) as exc:
        client.submit({"plane": "interactive", "action": "no_such_action"})
    assert exc.value.status == 422


def test_events_lost_in_outage_reach_ledger_once(ledger, client):
    store, live = ledger
    client._http = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    v = client.submit({**PASSWORD_ONLY, "event_id": "outage-1"}, fail=FailMode.open)
    assert v.degraded and v.allowed and client.pending == 1

    client._http = live
    assert client.flush() == 1
    assert store.get_decision("outage-1").rule == "P1"
    # 同じ事象をもう一度送っても、台帳では一件として扱われる
    again = client.submit({**PASSWORD_ONLY, "event_id": "outage-1"})
    assert again.rule == "P1"
    assert len(store.events("auth_attempt", FAR_PAST, FAR_FUTURE)) == 1


def test_heartbeat_marks_source_alive(ledger, client):
    store, _ = ledger
    assert client.heartbeat()
    assert "myapp" in store.sources_last_seen()
