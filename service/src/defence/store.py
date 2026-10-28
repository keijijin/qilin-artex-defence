"""連鎖台帳。SQLite を PersistentVolume 上に置く単一書き手の構成。"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from .models import ActionRequest, Decision, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  time TEXT NOT NULL,
  source TEXT NOT NULL,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL,
  chain_key TEXT NOT NULL,
  source_ip TEXT,
  account_id TEXT,
  actor_id TEXT,
  host TEXT,
  body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_action_time ON events(action, time);
CREATE INDEX IF NOT EXISTS events_chain_time ON events(chain_key, time);
CREATE INDEX IF NOT EXISTS events_ip_time ON events(source_ip, action, time);
CREATE INDEX IF NOT EXISTS events_actor_time ON events(actor_id, action, time);
CREATE TABLE IF NOT EXISTS blocks (
  chain_key TEXT NOT NULL,
  scope TEXT NOT NULL,
  until TEXT NOT NULL,
  rule TEXT NOT NULL,
  event_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS blocks_key ON blocks(chain_key);
CREATE TABLE IF NOT EXISTS decisions (
  event_id TEXT PRIMARY KEY,
  chain_key TEXT NOT NULL,
  rule TEXT NOT NULL,
  body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS decisions_chain ON decisions(chain_key);
CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY,
  opened TEXT NOT NULL,
  rule TEXT NOT NULL,
  event_id TEXT NOT NULL,
  status TEXT NOT NULL,
  summary TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS action_log (
  action_id TEXT PRIMARY KEY,
  time TEXT NOT NULL,
  event_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  automatic INTEGER NOT NULL,
  status TEXT NOT NULL,
  params TEXT NOT NULL,
  detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sources (
  name TEXT PRIMARY KEY,
  last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cursors (
  name TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""


def _ts(t: datetime) -> str:
    # 文字列比較で時刻順になるよう、UTC と固定桁にそろえる
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self._lock = threading.RLock()

    def ping(self) -> None:
        with self._lock:
            self._db.execute("SELECT 1")

    # 事象

    def add_event(self, e: Event, chain_key: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    e.event_id, _ts(e.time), e.source, e.action.value, e.outcome.value,
                    chain_key, e.source_ip, e.account_id, e.actor_id, e.host,
                    e.model_dump_json(),
                ),
            )
            self._db.execute(
                "INSERT INTO sources VALUES (?,?) ON CONFLICT(name) DO UPDATE SET "
                "last_seen=MAX(last_seen, excluded.last_seen)",
                (e.source, _ts(e.time)),
            )

    def events(
        self,
        action: str | list[str],
        since: datetime,
        until: datetime,
        *,
        source_ip: str | None = None,
        actor_id: str | None = None,
        chain_key: str | None = None,
    ) -> list[Event]:
        actions = [action] if isinstance(action, str) else action
        sql = (
            f"SELECT body FROM events WHERE action IN ({','.join('?' * len(actions))}) "
            "AND time>=? AND time<=?"
        )
        args: list[str] = [*actions, _ts(since), _ts(until)]
        if source_ip is not None:
            sql += " AND source_ip=?"
            args.append(source_ip)
        if actor_id is not None:
            sql += " AND actor_id=?"
            args.append(actor_id)
        if chain_key is not None:
            sql += " AND chain_key=?"
            args.append(chain_key)
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
        return [Event.model_validate_json(r["body"]) for r in rows]

    # 遮断

    def add_block(self, chain_key: str, scope: str, until: datetime, rule: str, event_id: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO blocks VALUES (?,?,?,?,?)",
                (chain_key, scope, _ts(until), rule, event_id),
            )

    def active_blocks(self, chain_key: str, now: datetime) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(
                "SELECT * FROM blocks WHERE chain_key=? AND until>?", (chain_key, _ts(now))
            ).fetchall()

    def extend_blocks(self, chain_key: str, until: datetime) -> int:
        with self._lock:
            cur = self._db.execute(
                "UPDATE blocks SET until=? WHERE chain_key=? AND until<?",
                (_ts(until), chain_key, _ts(until)),
            )
            return cur.rowcount

    # 判定と案件

    def add_decision(self, d: Decision) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO decisions VALUES (?,?,?,?)",
                (d.event_id, d.chain_key, d.rule, d.model_dump_json()),
            )

    def get_decision(self, event_id: str) -> Decision | None:
        with self._lock:
            row = self._db.execute(
                "SELECT body FROM decisions WHERE event_id=?", (event_id,)
            ).fetchone()
        return Decision.model_validate_json(row["body"]) if row else None

    def decisions_for_chain(self, chain_key: str) -> list[Decision]:
        with self._lock:
            rows = self._db.execute(
                "SELECT body FROM decisions WHERE chain_key=?", (chain_key,)
            ).fetchall()
        return [Decision.model_validate_json(r["body"]) for r in rows]

    def open_case(self, rule: str, event_id: str, summary: str, now: datetime) -> str:
        case_id = str(uuid4())
        with self._lock:
            self._db.execute(
                "INSERT INTO cases VALUES (?,?,?,?,?,?)",
                (case_id, _ts(now), rule, event_id, "open", summary),
            )
        return case_id

    def cases(self, status: str = "open") -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM cases WHERE status=? ORDER BY opened", (status,)
            ).fetchall()
        return [dict(r) for r in rows]

    def has_open_case(self, rule: str, summary: str) -> bool:
        with self._lock:
            return self._db.execute(
                "SELECT 1 FROM cases WHERE rule=? AND summary=? AND status='open'",
                (rule, summary),
            ).fetchone() is not None

    def log_action(
        self, event_id: str, req: ActionRequest, status: str, detail: str, now: datetime
    ) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO action_log VALUES (?,?,?,?,?,?,?,?)",
                (
                    str(uuid4()), _ts(now), event_id, req.kind, int(req.automatic), status,
                    json.dumps(req.params, ensure_ascii=False), detail,
                ),
            )

    def action_log(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM action_log ORDER BY time").fetchall()
        return [dict(r) for r in rows]

    # 発生源と取り込み位置

    def sources_last_seen(self) -> dict[str, datetime]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM sources").fetchall()
        return {r["name"]: datetime.fromisoformat(r["last_seen"]) for r in rows}

    def get_cursor(self, name: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM cursors WHERE name=?", (name,)).fetchone()
        return row["value"] if row else None

    def set_cursor(self, name: str, value: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO cursors VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                (name, value),
            )

    def prune(self, older_than: timedelta, now: datetime) -> int:
        """保持期間を過ぎた事象と、期限の切れた遮断を消す。判定、案件、強制の記録は残す。"""
        cutoff = _ts(now - older_than)
        with self._lock:
            n = self._db.execute("DELETE FROM events WHERE time<?", (cutoff,)).rowcount
            self._db.execute("DELETE FROM blocks WHERE until<?", (_ts(now),))
        return n
