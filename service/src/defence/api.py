"""台帳の HTTP API。"""


import logging
import threading
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .auth import TokenReviewer
from .enforce import Enforcer
from .models import Decision, Event
from .policy import Engine
from .store import Store

log = logging.getLogger(__name__)


class CursorBody(BaseModel):
    value: str


def create_app(
    store: Store,
    engine: Engine,
    enforcer: Enforcer,
    reviewer: TokenReviewer | None,
    *,
    source_check_interval: float | None = 60,
) -> FastAPI:
    stop = threading.Event()

    def housekeeping() -> None:
        try:
            silent = engine.check_sources()
            if silent:
                log.warning("途絶している発生源: %s", silent)
            hours = engine.settings.windows.event_retention_hours
            store.prune(timedelta(hours=hours), engine.clock())
        except Exception:
            log.exception("定期処理に失敗")

    def loop() -> None:
        while not stop.wait(source_check_interval):
            housekeeping()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if source_check_interval:
            threading.Thread(target=loop, daemon=True).start()
        yield
        stop.set()

    app = FastAPI(title="defence-ledger", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.housekeeping = housekeeping

    def caller(authorization: Annotated[str | None, Header()] = None) -> str:
        if reviewer is None:
            return "unauthenticated"
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401)
        user = reviewer.allowed_user(authorization.removeprefix("Bearer "))
        if user is None:
            raise HTTPException(403)
        return user

    Caller = Annotated[str, Depends(caller)]

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> dict:
        store.ping()
        return {"status": "ready"}

    @app.post("/v1/events")
    def ingest(events: Event | list[Event], who: Caller) -> list[dict]:
        out = []
        for e in events if isinstance(events, list) else [events]:
            d: Decision = engine.evaluate(e)
            results = enforcer.execute(e.event_id, d.actions) if d.actions else []
            out.append({**d.model_dump(mode="json"), "results": results})
        return out

    @app.get("/v1/cases")
    def cases(who: Caller, status: str = "open") -> list[dict]:
        return store.cases(status)

    @app.get("/v1/actions")
    def actions(who: Caller) -> list[dict]:
        return store.action_log()

    @app.get("/v1/cursors/{name}")
    def get_cursor(name: str, who: Caller) -> dict:
        return {"value": store.get_cursor(name)}

    @app.put("/v1/cursors/{name}")
    def put_cursor(name: str, body: CursorBody, who: Caller) -> dict:
        store.set_cursor(name, body.value)
        return {"value": body.value}

    return app
