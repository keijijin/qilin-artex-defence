"""台帳（defence-ledger）へ事象を送り、判定を受け取るクライアント。docs/integration.md。

台帳に届かないときの判定は、呼び出し側が FailMode で決める。届かなかった事象は
同じ event_id のまま溜めておき、後で送り直す（台帳は event_id で重複を除く）。
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Callable
from uuid import uuid4

import httpx

__all__ = ["FailMode", "LedgerClient", "LedgerRejected", "Verdict"]

log = logging.getLogger(__name__)

PASSING = frozenset({"allow", "record"})


class FailMode(StrEnum):
    open = "open"  # 台帳に届かなければ通す
    closed = "closed"  # 台帳に届かなければ拒否する


class LedgerRejected(Exception):
    """台帳が要求を受け付けなかった。token、ALLOWED_CALLERS、事象の形を確かめる。"""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"台帳が {status} を返した: {body[:200]}")
        self.status = status
        self.body = body


@dataclass(frozen=True)
class Verdict:
    event_id: str
    response: str
    rule: str = ""
    degraded: bool = False  # 台帳に届かず、FailMode で決めた判定
    suppress_account_lockout: bool = False
    open_case: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.response in PASSING

    @classmethod
    def from_decision(cls, d: dict[str, Any]) -> Verdict:
        return cls(
            event_id=d["event_id"],
            response=d["response"],
            rule=d.get("rule", ""),
            suppress_account_lockout=bool(d.get("suppress_account_lockout")),
            open_case=bool(d.get("open_case")),
            raw=d,
        )


class _Unavailable(Exception):
    pass


class LedgerClient:
    """スレッドから共有してよい。heartbeat を使うなら close() するか with で囲む。"""

    def __init__(
        self,
        url: str | None = None,
        *,
        source: str,
        token_file: str | None = None,
        ca_file: str | None = None,
        timeout: float = 2.0,
        retries: int = 2,
        backoff: float = 0.2,
        fail: FailMode = FailMode.closed,
        max_pending: int = 1000,
        batch_size: int = 100,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.url = (url or os.environ["LEDGER_URL"]).rstrip("/")
        self.source = source
        self.token_file = token_file or os.getenv("LEDGER_TOKEN_FILE", "/var/run/defence/token")
        self.retries = retries
        self.backoff = backoff
        self.fail = FailMode(fail)
        self.batch_size = batch_size
        self.dropped = 0
        self._sleep = sleep
        self._pending: deque[dict[str, Any]] = deque()
        self._max_pending = max_pending
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._heartbeat: threading.Thread | None = None
        self._owns_http = http is None
        self._http = http or httpx.Client(
            verify=ca_file or os.getenv("LEDGER_CA_FILE", "/etc/defence-ca/service-ca.crt"),
            timeout=timeout,
        )

    # 送信

    def submit(self, event: dict[str, Any], *, fail: FailMode | None = None) -> Verdict:
        return self.submit_many([event], fail=fail)[0]

    def submit_many(
        self, events: list[dict[str, Any]], *, fail: FailMode | None = None
    ) -> list[Verdict]:
        batch = [self._complete(e) for e in events]
        try:
            return [Verdict.from_decision(d) for d in self._post(batch)]
        except _Unavailable as exc:
            mode = FailMode(fail or self.fail)
            log.warning("台帳に届かない（%s）。%s として扱い、後で送り直す", exc, mode.value)
            self._enqueue(batch)
            response = "allow" if mode is FailMode.open else "deny"
            return [
                Verdict(event_id=e["event_id"], response=response, rule=f"fail-{mode.value}", degraded=True)
                for e in batch
            ]

    def heartbeat(self, *, plane: str = "application") -> bool:
        """生存通知を一件送る。溜めて送り直すことはしない（古い生存通知に意味はない）。"""
        try:
            self._post([self._complete({"plane": plane, "action": "heartbeat"})])
            return True
        except _Unavailable as exc:
            log.warning("生存通知が届かない（%s）", exc)
            return False

    # 送り直し

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._pending)

    def flush(self) -> int:
        """溜めた事象を送り直し、届いた件数を返す。台帳が受け付けない事象は捨てる。"""
        sent = 0
        while True:
            with self._lock:
                batch = [self._pending.popleft() for _ in range(min(self.batch_size, len(self._pending)))]
            if not batch:
                return sent
            try:
                self._post(batch)
            except _Unavailable:
                with self._lock:
                    self._pending.extendleft(reversed(batch))
                    self._trim()
                return sent
            except LedgerRejected as exc:
                log.error("送り直した %d 件を台帳が受け付けないため捨てる: %s", len(batch), exc)
                with self._lock:
                    self.dropped += len(batch)
                continue
            sent += len(batch)

    # 定期処理

    def start_heartbeat(self, interval: float = 60.0, *, plane: str = "application") -> None:
        """interval 秒ごとに生存通知を送り、溜めた事象を送り直す。"""
        if self._heartbeat is not None:
            return

        def loop() -> None:
            while not self._stop.wait(interval):
                try:
                    if self.heartbeat(plane=plane):
                        self.flush()
                except Exception:
                    log.exception("生存通知の処理に失敗")

        self._heartbeat = threading.Thread(target=loop, name="defence-heartbeat", daemon=True)
        self._heartbeat.start()

    def close(self) -> None:
        self._stop.set()
        if self._heartbeat is not None:
            self._heartbeat.join(timeout=5)
            self._heartbeat = None
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> LedgerClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # 内部

    def _complete(self, event: dict[str, Any]) -> dict[str, Any]:
        # 送り直しても同じ事象として数えられるよう、ID と時刻はここで決める
        e = dict(event)
        e.setdefault("event_id", str(uuid4()))
        e.setdefault("time", datetime.now(timezone.utc).isoformat())
        e.setdefault("source", self.source)
        return e

    def _enqueue(self, batch: list[dict[str, Any]]) -> None:
        with self._lock:
            self._pending.extend(batch)
            self._trim()

    def _trim(self) -> None:
        # 古いものから捨てる。self._lock を持って呼ぶ
        while len(self._pending) > self._max_pending:
            self._pending.popleft()
            self.dropped += 1

    def _post(self, batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # token は kubelet が期限前に差し替えるので、送るたびに読む
        with open(self.token_file) as f:
            headers = {"Authorization": "Bearer " + f.read().strip()}
        last: str = ""
        for attempt in range(self.retries + 1):
            if attempt:
                self._sleep(self.backoff * 2 ** (attempt - 1))
            try:
                r = self._http.post(f"{self.url}/v1/events", json=batch, headers=headers)
            except httpx.TransportError as exc:
                last = type(exc).__name__
                continue
            if r.status_code == 429 or r.status_code >= 500:
                last = f"HTTP {r.status_code}"
                continue
            if r.status_code >= 400:
                # 送り直しても結果は変わらない。token、ALLOWED_CALLERS、事象の形の誤り
                raise LedgerRejected(r.status_code, r.text)
            return r.json()
        raise _Unavailable(last)
