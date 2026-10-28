"""台帳の負荷試験。事象を並行に送り、処理量、遅延、取りこぼしの有無を確かめる。

ARTEX の spray は毎分約2,900件の失敗だった（Microsoft 2026-10-21）。その水準を上回るかを見る。
P4（service principal の自己権限付与）は、負荷の下でも一件残らず案件になることを確かめる。

使い方: python stress.py --url URL [--ca CA] [--token-file F | --no-token] --events N --concurrency C
"""

import argparse
import asyncio
import json
import random
import statistics
import time
import uuid

import httpx


def make_events(n: int, run: str, rng: random.Random) -> tuple[list[dict], set[str]]:
    ips = [f"198.18.{i // 250}.{i % 250}" for i in range(200)]
    events, p4 = [], set()
    for i in range(n):
        r = rng.random()
        eid = f"{run}-{i}"
        if r < 0.70:
            events.append({"event_id": eid, "plane": "interactive", "action": "auth_attempt",
                           "outcome": rng.choice(["failure", "failure", "lockout", "success"]),
                           "account_id": f"user{rng.randrange(5000)}", "source_ip": rng.choice(ips),
                           "device_cert": "absent", "source": f"stress-{run}"})
        elif r < 0.80:
            events.append({"event_id": eid, "plane": "application", "action": "resource_access",
                           "application_id": f"app{rng.randrange(50)}", "service_principal_id": f"sp{rng.randrange(50)}",
                           "scope": "Mail.Read", "source": f"stress-{run}"})
        elif r < 0.90:
            events.append({"event_id": eid, "plane": "host", "action": rng.choice(["process_denied", "lateral_denied"]),
                           "host": f"ws{rng.randrange(300)}", "actor_id": f"op{rng.randrange(40)}",
                           "source": f"stress-{run}"})
        else:
            p4.add(eid)
            events.append({"event_id": eid, "plane": "application", "action": "role_assign",
                           "actor_type": "service_principal", "actor_id": f"sp-x{i}", "service_principal_id": f"sp-x{i}",
                           "target_principal_id": f"sp-x{i}", "role_definition_id": "62e90394-69f5-4237-9190-012177145e10",
                           "source": f"stress-{run}"})
    return events, p4


async def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--ca")
    p.add_argument("--token-file", default="/tok/token")
    p.add_argument("--no-token", action="store_true")
    p.add_argument("--events", type=int, default=5000)
    p.add_argument("--concurrency", type=int, default=32)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--p99-limit-ms", type=float, default=2000)
    a = p.parse_args()

    run = uuid.uuid4().hex[:8]
    events, p4 = make_events(a.events, run, random.Random(a.seed))
    token = None if a.no_token else open(a.token_file).read().strip()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    queue: asyncio.Queue = asyncio.Queue()
    for e in events:
        queue.put_nowait(e)
    lat, p4_lat, errors = [], [], []

    async with httpx.AsyncClient(verify=a.ca or True, timeout=60, headers=headers,
                                 limits=httpx.Limits(max_connections=a.concurrency)) as c:
        async def worker():
            while not queue.empty():
                e = queue.get_nowait()
                t = time.perf_counter()
                try:
                    r = await c.post(f"{a.url}/v1/events", json=e)
                    ms = (time.perf_counter() - t) * 1000
                    if r.status_code != 200:
                        errors.append(r.status_code)
                        continue
                    lat.append(ms)
                    if e["event_id"] in p4:
                        p4_lat.append(ms)
                        if r.json()[0]["rule"] != "P4":
                            errors.append("P4-misjudged")
                except Exception as ex:
                    errors.append(type(ex).__name__)

        t0 = time.perf_counter()
        await asyncio.gather(*(worker() for _ in range(a.concurrency)))
        elapsed = time.perf_counter() - t0
        cases = (await c.get(f"{a.url}/v1/cases")).json()

    p4_cases = sum(1 for x in cases if x["event_id"] in p4 and x["rule"] == "P4")
    q = statistics.quantiles(lat, n=100) if len(lat) > 1 else [0] * 99
    out = {
        "events": a.events, "concurrency": a.concurrency, "ok": len(lat), "errors": len(errors),
        "error_kinds": sorted({str(x) for x in errors}),
        "seconds": round(elapsed, 2), "events_per_sec": round(len(lat) / elapsed, 1),
        "events_per_min": round(len(lat) / elapsed * 60),
        "p50_ms": round(q[49], 1), "p95_ms": round(q[94], 1), "p99_ms": round(q[98], 1), "max_ms": round(max(lat), 1),
        "p4_sent": len(p4), "p4_cases": p4_cases,
        "p4_max_ms": round(max(p4_lat), 1) if p4_lat else None,
    }
    out["pass"] = (out["errors"] == 0 and out["p4_cases"] == out["p4_sent"]
                   and out["p99_ms"] <= a.p99_limit_ms and out["events_per_min"] > 2900)
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
