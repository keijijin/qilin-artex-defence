"""発生源（転送元）として台帳へ事象を送る。標準入力の JSON 配列を送り、判定を JSON で出力する。

使い方: python send.py [--token-file F] [--no-token] [--path /v1/events] < events.json
"""

import argparse
import json
import os
import sys

import httpx

p = argparse.ArgumentParser()
p.add_argument("--url", default=os.getenv("LEDGER_URL"))
p.add_argument("--ca", default=os.getenv("LEDGER_CA_FILE", "/ca/ca.crt"))
p.add_argument("--token-file", default="/tok/token")
p.add_argument("--no-token", action="store_true")
p.add_argument("--get", help="GET するパス")
p.add_argument("--timeout", type=float, default=15)
a = p.parse_args()

headers = {} if a.no_token else {"Authorization": "Bearer " + open(a.token_file).read().strip()}
c = httpx.Client(verify=a.ca, timeout=a.timeout)
try:
    if a.get:
        r = c.get(a.url + a.get, headers=headers)
    else:
        r = c.post(a.url + "/v1/events", headers=headers, json=json.load(sys.stdin))
    print(json.dumps({"status": r.status_code, "body": r.json() if r.content else None}, ensure_ascii=False))
except httpx.TimeoutException as e:
    print(json.dumps({"status": "timeout", "error": type(e).__name__}))
