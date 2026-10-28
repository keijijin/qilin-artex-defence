import json
import threading

import httpx
import pytest

from defence_client import FailMode, LedgerClient, LedgerRejected, Verdict

URL = "https://ledger.test:8443"


class Ledger:
    """台帳の代わり。plan の順に応答し、尽きたら判定を返す。"""

    def __init__(self, plan=()):
        self.plan = list(plan)
        self.requests = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append((request, body))
        step = self.plan.pop(0) if self.plan else 200
        if isinstance(step, Exception):
            raise step
        if step != 200:
            return httpx.Response(step, text="no")
        return httpx.Response(200, json=[
            {"event_id": e["event_id"], "chain_key": "x", "rule": "p1", "response": "deny",
             "matched": ["p1"], "actions": [], "open_case": True, "suppress_account_lockout": True,
             "note": "", "results": []}
            for e in body
        ])


@pytest.fixture
def token(tmp_path):
    p = tmp_path / "token"
    p.write_text("tok-1\n")
    return p


def make(ledger, token, **kw):
    sleeps = []
    c = LedgerClient(
        URL, source="myapp", token_file=str(token),
        http=httpx.Client(transport=httpx.MockTransport(ledger)), sleep=sleeps.append, **kw,
    )
    return c, sleeps


AUTH = {"plane": "interactive", "action": "auth_attempt", "account_id": "alice"}
DOWN = httpx.ConnectError("refused")


def test_submit_fills_event_and_maps_verdict(token):
    ledger = Ledger()
    c, _ = make(ledger, token)
    v = c.submit(AUTH)
    req, body = ledger.requests[0]
    assert req.url == f"{URL}/v1/events"
    assert req.headers["authorization"] == "Bearer tok-1"
    assert body[0]["source"] == "myapp" and body[0]["event_id"] and body[0]["time"]
    assert body[0]["account_id"] == "alice"
    assert "event_id" not in AUTH  # 呼び出し側の dict は変えない
    assert v == Verdict.from_decision(v.raw)
    assert (v.response, v.rule, v.allowed, v.degraded) == ("deny", "p1", False, False)
    assert v.suppress_account_lockout and v.open_case


def test_caller_supplied_fields_are_kept(token):
    ledger = Ledger()
    c, _ = make(ledger, token)
    c.submit({**AUTH, "event_id": "e-1", "source": "vpn", "time": "2026-10-28T09:00:00+00:00"})
    body = ledger.requests[0][1][0]
    assert (body["event_id"], body["source"], body["time"]) == ("e-1", "vpn", "2026-10-28T09:00:00+00:00")


def test_token_is_reread_each_call(token):
    ledger = Ledger()
    c, _ = make(ledger, token)
    c.submit(AUTH)
    token.write_text("tok-2")
    c.submit(AUTH)
    assert [r.headers["authorization"] for r, _ in ledger.requests] == ["Bearer tok-1", "Bearer tok-2"]


def test_submit_many_keeps_order(token):
    c, _ = make(Ledger(), token)
    vs = c.submit_many([{**AUTH, "event_id": "a"}, {**AUTH, "event_id": "b"}])
    assert [v.event_id for v in vs] == ["a", "b"]


@pytest.mark.parametrize("failure", [503, 500, 429, DOWN, httpx.ReadTimeout("slow")])
def test_retries_with_backoff_then_succeeds(token, failure):
    ledger = Ledger([failure, failure])
    c, sleeps = make(ledger, token, retries=2, backoff=0.1)
    v = c.submit(AUTH)
    assert not v.degraded and len(ledger.requests) == 3
    assert sleeps == [0.1, 0.2]
    assert len({b[0]["event_id"] for _, b in ledger.requests}) == 1  # 再送でも同じ ID


def test_fail_closed_denies_and_queues(token):
    c, _ = make(Ledger([DOWN] * 3), token, retries=2)
    v = c.submit(AUTH)
    assert (v.response, v.rule, v.degraded, v.allowed) == ("deny", "fail-closed", True, False)
    assert c.pending == 1


def test_fail_open_allows_and_queues(token):
    c, _ = make(Ledger([503] * 3), token, retries=2, fail=FailMode.open)
    v = c.submit(AUTH)
    assert (v.response, v.rule, v.degraded, v.allowed) == ("allow", "fail-open", True, True)
    assert c.pending == 1


def test_fail_mode_can_be_chosen_per_call(token):
    c, _ = make(Ledger([DOWN] * 2), token, retries=0, fail=FailMode.open)
    assert c.submit(AUTH, fail=FailMode.closed).response == "deny"
    assert c.submit(AUTH, fail="open").response == "allow"


@pytest.mark.parametrize("status", [401, 403, 404, 422])
def test_rejection_raises_and_is_not_queued(token, status):
    ledger = Ledger([status])
    c, _ = make(ledger, token, fail=FailMode.open)
    with pytest.raises(LedgerRejected) as exc:
        c.submit(AUTH)
    assert exc.value.status == status
    assert len(ledger.requests) == 1 and c.pending == 0


def test_flush_resends_same_event_in_order(token):
    ledger = Ledger([DOWN, DOWN])
    c, _ = make(ledger, token, retries=0)
    c.submit({**AUTH, "event_id": "a"})
    c.submit({**AUTH, "event_id": "b"})
    first_time = ledger.requests[0][1][0]["time"]
    assert c.flush() == 2 and c.pending == 0
    resent = ledger.requests[-1][1]
    assert [e["event_id"] for e in resent] == ["a", "b"]
    assert resent[0]["time"] == first_time  # 届かなかった時の時刻のまま


def test_flush_in_batches_and_stops_when_ledger_down(token):
    ledger = Ledger([DOWN] * 5)
    c, _ = make(ledger, token, retries=0, batch_size=2)
    for i in range(5):
        c.submit({**AUTH, "event_id": str(i)})
    ledger.plan = [200, DOWN]  # 一束目は届き、二束目で落ちる
    assert c.flush() == 2
    assert c.pending == 3
    assert c.flush() == 3  # 順番を保って残りを送る
    assert [e["event_id"] for e in ledger.requests[-1][1]] == ["4"]


def test_flush_drops_rejected_batch(token):
    ledger = Ledger([DOWN])
    c, _ = make(ledger, token, retries=0)
    c.submit(AUTH)
    ledger.plan = [422]
    assert c.flush() == 0
    assert c.pending == 0 and c.dropped == 1


def test_queue_is_bounded(token):
    c, _ = make(Ledger([DOWN] * 5), token, retries=0, max_pending=3)
    for i in range(5):
        c.submit({**AUTH, "event_id": str(i)})
    assert c.pending == 3 and c.dropped == 2
    assert [e["event_id"] for e in c._pending] == ["2", "3", "4"]  # 古いものから捨てる


def test_heartbeat_is_not_queued(token):
    ledger = Ledger([DOWN])
    c, _ = make(ledger, token, retries=0)
    assert c.heartbeat() is False
    assert c.pending == 0
    assert c.heartbeat(plane="host") is True
    body = ledger.requests[-1][1][0]
    assert (body["action"], body["plane"], body["source"]) == ("heartbeat", "host", "myapp")


def test_heartbeat_thread_sends_and_flushes(token):
    ledger = Ledger([DOWN])
    c, _ = make(ledger, token, retries=0)
    c.submit({**AUTH, "event_id": "late"})
    flushed = threading.Event()
    original = c.flush

    def flush():
        n = original()
        if n:
            flushed.set()
        return n

    c.flush = flush
    with c:
        c.start_heartbeat(0.01)
        c.start_heartbeat(0.01)  # 二度目は何もしない
        assert flushed.wait(2)
    assert c._heartbeat is None
    actions = [b[0]["action"] for _, b in ledger.requests]
    assert "heartbeat" in actions
    assert c.pending == 0


def test_heartbeat_thread_survives_errors(token, caplog):
    ledger = Ledger()
    c, _ = make(ledger, token)
    calls = []

    def boom(**kw):
        calls.append(1)
        raise LedgerRejected(403, "no")

    c.heartbeat = boom
    c.start_heartbeat(0.01)
    try:
        for _ in range(200):
            if len(calls) >= 2:
                break
            threading.Event().wait(0.01)
    finally:
        c.close()
    assert len(calls) >= 2
    assert "生存通知の処理に失敗" in caplog.text


def test_defaults_from_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("LEDGER_URL", URL + "/")
    monkeypatch.setenv("LEDGER_TOKEN_FILE", "/x/token")
    ca = tmp_path / "ca.crt"
    monkeypatch.setenv("LEDGER_CA_FILE", str(ca))
    captured = {}

    class FakeClient:
        def __init__(self, **kw):
            captured.update(kw)

    monkeypatch.setattr(httpx, "Client", FakeClient)
    c = LedgerClient(source="myapp")
    assert (c.url, c.token_file) == (URL, "/x/token")
    assert captured == {"verify": str(ca), "timeout": 2.0}


def test_close_releases_own_http_only(token):
    shared = httpx.Client(transport=httpx.MockTransport(Ledger()))
    LedgerClient(URL, source="a", token_file=str(token), http=shared).close()
    assert not shared.is_closed
