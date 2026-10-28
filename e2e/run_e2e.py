"""OpenShift 上の E2E テスト。

本番と同じマニフェスト（deploy/overlays/openshift）を専用の名前空間へ展開し、
Entra と Graph と EDR の webhook だけを模擬サーバー（mock_entra.py）に置き換える。

確かめること
  S1 ARTEX: 収集が監査ログを読み、台帳が攻撃者の secret と GA 付与を取り消す。正規の secret と人の GA は残す
  S2 取り込みの重複: 何度読み直しても、取り消しと案件は一回だけ
  S3 Qilin: VPN、spray、おとり、GPO、監査停止、横展開、おとりファイル、外向き、バックアップの各判定
  S4 認証と通信: token なし 401、未登録の SA 403、未登録の Pod は NetworkPolicy で届かない
  S5 永続性: 台帳 Pod を消しても、案件と遮断が残る
  S6 発生源の途絶: 登録した発生源が黙ると案件が開く
  S7 実行権限: restricted-v2 SCC、任意 UID で動く
  S8 負荷: クラスター内から並行送信し、取りこぼしと再起動が無い

使い方: python e2e/run_e2e.py [--keep] [--stress-events N]
前提: oc でクラスター管理者としてログイン済み
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
NS = "defence-e2e"
SRC = "defence-e2e-src"
REG = "image-registry.openshift-image-registry.svc:5000"
IMAGE = f"{REG}/{NS}/defence-ledger:latest"
GA = "62e90394-69f5-4237-9190-012177145e10"
K_ATTACKER = "aaaaaaaa-0000-0000-0000-000000000001"
K_LEGIT = "bbbbbbbb-0000-0000-0000-000000000002"
MOCK = f"http://mock-entra.{NS}.svc:8080"
LEDGER = f"https://defence-ledger.{NS}.svc:8443"

results: list[tuple[str, bool, str]] = []


def oc(*args: str, input: str | None = None, check: bool = True, timeout: int = 600) -> str:
    p = subprocess.run(["oc", *args], input=input, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"oc {' '.join(args)}\n{p.stderr}")
    return p.stdout


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail and not ok else ""), flush=True)


def wait(cond, timeout: float, every: float = 3):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(every)
    return cond()


# 展開


def render() -> list[dict]:
    text = subprocess.run(["kustomize", "build", str(ROOT / "deploy/overlays/openshift")],
                          capture_output=True, text=True, check=True).stdout
    text = text.replace("defence-system", NS)
    docs = [d for d in yaml.safe_load_all(text) if d]
    policy = yaml.safe_load((ROOT / "deploy/base/policy.yaml").read_text())
    policy["enforcement"] = {
        "mode": "enforce",
        "automatic_kinds": ["remove_sp_credential", "remove_role_assignment",
                            "isolate_host_east_west", "revoke_privileged_activation"],
        "host_webhook_url": f"{MOCK}/webhook",
    }
    policy["windows"].update({"source_silence_minutes": 1})
    policy["registrations"]["sources"].append({"name": "edr-silent", "registered_at": "2026-01-01T00:00:00+00:00"})
    env_extra = [{"name": "AZURE_AUTHORITY_HOST", "value": MOCK}, {"name": "GRAPH_BASE_URL", "value": f"{MOCK}/v1.0"}]
    for d in docs:
        kind, name = d["kind"], d["metadata"]["name"]
        if kind == "ClusterRoleBinding":
            d["metadata"]["name"] = name + "-e2e"
        if kind == "ConfigMap" and name.startswith("defence-policy"):
            d["data"]["policy.yaml"] = yaml.safe_dump(policy, sort_keys=False)
        if kind == "ConfigMap" and name.startswith("defence-entra"):
            d["data"] = {"tenant_id": "e2e-tenant", "enforcer_client_id": "e2e-enforcer",
                         "collector_client_id": "e2e-collector"}
        if kind in ("StatefulSet", "Deployment"):
            for c in d["spec"]["template"]["spec"]["containers"]:
                c["image"] = IMAGE
                c["env"] += env_extra
                for e in c["env"]:
                    if e["name"] == "ALLOWED_CALLERS":
                        e["value"] += f",system:serviceaccount:{SRC}:forwarder"
                    if e["name"] == "POLL_SECONDS":
                        e["value"] = "5"
    return docs


def mock_manifests() -> list[dict]:
    restricted = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}
    pod_sc = {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}}
    return [
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "mock-entra", "namespace": NS},
         "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "mock-entra"}},
                  "template": {"metadata": {"labels": {"app": "mock-entra"}},
                               "spec": {"securityContext": pod_sc, "containers": [{
                                   "name": "mock", "image": IMAGE, "command": ["python", "/e2e/mock_entra.py"],
                                   "securityContext": restricted,
                                   "readinessProbe": {"httpGet": {"path": "/_calls", "port": 8080}},
                                   "volumeMounts": [{"name": "e2e", "mountPath": "/e2e"}]}],
                                   "volumes": [{"name": "e2e", "configMap": {"name": "e2e-scripts"}}]}}}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "mock-entra", "namespace": NS},
         "spec": {"selector": {"app": "mock-entra"}, "ports": [{"port": 8080, "targetPort": 8080}]}},
        # 模擬サーバーへの通信だけを追加で通す。本番の方針は変えない
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
         "metadata": {"name": "e2e-mock", "namespace": NS},
         "spec": {"podSelector": {}, "policyTypes": ["Egress"],
                  "egress": [{"to": [{"podSelector": {"matchLabels": {"app": "mock-entra"}}}],
                              "ports": [{"protocol": "TCP", "port": 8080}]}]}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
         "metadata": {"name": "e2e-mock-ingress", "namespace": NS},
         "spec": {"podSelector": {"matchLabels": {"app": "mock-entra"}}, "policyTypes": ["Ingress"],
                  "ingress": [{"from": [{"podSelector": {}}], "ports": [{"protocol": "TCP", "port": 8080}]}]}},
    ]


def client_pod(name: str, ns: str, sa: str, labels: dict) -> dict:
    return {
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": ns, "labels": labels},
        "spec": {
            "serviceAccountName": sa, "automountServiceAccountToken": False,
            "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "c", "image": IMAGE, "command": ["python", "-c", "import time; time.sleep(10**9)"],
                "env": [{"name": "LEDGER_URL", "value": LEDGER}],
                "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                "resources": {"limits": {"memory": "512Mi"}},
                "volumeMounts": [{"name": "tok", "mountPath": "/tok"}, {"name": "ca", "mountPath": "/ca"},
                                 {"name": "e2e", "mountPath": "/e2e"}]}],
            "volumes": [
                {"name": "tok", "projected": {"sources": [{"serviceAccountToken": {
                    "path": "token", "audience": "defence-ledger", "expirationSeconds": 3600}}]}},
                {"name": "ca", "configMap": {"name": "defence-service-ca",
                                             "items": [{"key": "service-ca.crt", "path": "ca.crt"}]}},
                {"name": "e2e", "configMap": {"name": "e2e-scripts"}}]}}


def apply(docs: list[dict]) -> None:
    oc("apply", "-f", "-", input=yaml.safe_dump_all(docs, sort_keys=False))


def deploy() -> None:
    for ns, labels in ((NS, {}), (SRC, {"defence.example/event-source": "true"})):
        apply([{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns, "labels": {
            "pod-security.kubernetes.io/enforce": "restricted", **labels}}}])
    print("イメージをクラスター内でビルドする", flush=True)
    if not oc("get", "bc", "defence-ledger", "-n", NS, "--ignore-not-found"):
        oc("new-build", "--name=defence-ledger", "--binary", "--strategy=docker", "-n", NS)
        oc("patch", "bc/defence-ledger", "-n", NS, "--type=merge",
           "-p", '{"spec":{"strategy":{"dockerStrategy":{"dockerfilePath":"Containerfile"}}}}')
    oc("start-build", "defence-ledger", "-n", NS, f"--from-dir={ROOT / 'service'}", "--follow", "--wait", timeout=900)
    oc("policy", "add-role-to-group", "system:image-puller", f"system:serviceaccounts:{SRC}", "-n", NS)

    scripts = {"mock_entra.py": (ROOT / "e2e/mock_entra.py").read_text(),
               "send.py": (ROOT / "e2e/send.py").read_text(),
               "stress.py": (ROOT / "e2e/stress.py").read_text()}
    for ns in (NS, SRC):
        apply([{"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "e2e-scripts", "namespace": ns},
                "data": scripts}])
    apply([{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "forwarder", "namespace": SRC}},
           {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
               "name": "defence-service-ca", "namespace": SRC,
               "annotations": {"service.beta.openshift.io/inject-cabundle": "true"}}}])

    # 模擬サーバーを先に立て、収集が最初に読む時点で監査記録が揃っているようにする
    apply(mock_manifests())
    oc("rollout", "status", "deploy/mock-entra", "-n", NS, "--timeout=300s")
    apply(render())
    oc("rollout", "status", "statefulset/defence-ledger", "-n", NS, "--timeout=300s")
    oc("rollout", "status", "deploy/defence-collector", "-n", NS, "--timeout=300s")
    apply([client_pod("forwarder", SRC, "forwarder", {"app": "forwarder"}),
           client_pod("unregistered", SRC, "default", {"app": "unregistered"}),
           client_pod("outsider", NS, "default", {"app": "outsider"})])
    for ns, pod in ((SRC, "forwarder"), (SRC, "unregistered"), (NS, "outsider")):
        oc("wait", "--for=condition=Ready", f"pod/{pod}", "-n", ns, "--timeout=300s")


def teardown() -> None:
    for ns in (NS, SRC):
        oc("delete", "ns", ns, "--ignore-not-found", "--wait=false", check=False)
    oc("delete", "clusterrolebinding", "defence-ledger-auth-delegator-e2e", "--ignore-not-found", check=False)


# 操作


def mock_calls() -> dict:
    out = oc("exec", "-n", NS, "deploy/mock-entra", "--", "python", "-c",
             "import urllib.request;print(urllib.request.urlopen('http://localhost:8080/_calls').read().decode())")
    return json.loads(out)


def send(events: list[dict], pod: str = "forwarder", ns: str = SRC, *extra: str) -> dict:
    out = oc("exec", "-i", "-n", ns, pod, "--", "python", "/e2e/send.py", *extra, input=json.dumps(events))
    return json.loads(out.strip().splitlines()[-1])


def get(path: str, pod: str = "forwarder", ns: str = SRC, *extra: str) -> dict:
    out = oc("exec", "-n", ns, pod, "--", "python", "/e2e/send.py", "--get", path, *extra)
    return json.loads(out.strip().splitlines()[-1])


def cases() -> list[dict]:
    return get("/v1/cases")["body"]


def auth(account, ip, outcome="failure", cert="absent", mfa="absent", device=None, **kw):
    return {"plane": "interactive", "action": "auth_attempt", "outcome": outcome, "account_id": account,
            "source_ip": ip, "device_cert": cert, "phishing_resistant_mfa": mfa, "device_id": device,
            "source": "e2e-forwarder", **kw}


# シナリオ


def s1_s2_artex() -> None:
    def done():
        c = mock_calls()
        kinds = [x["kind"] for x in c["calls"]]
        return c if kinds.count("removePassword") >= 1 and kinds.count("deleteRoleAssignment") >= 2 else None

    c = wait(done, 180) or mock_calls()
    calls = c["calls"]
    removed = [x["keyId"] for x in calls if x["kind"] == "removePassword"]
    deleted = sorted(x["id"] for x in calls if x["kind"] == "deleteRoleAssignment")
    check("S1 攻撃者の secret だけを無効化した", removed == [K_ATTACKER] and c["sp_teams_keys"] == [K_LEGIT],
          f"removed={removed} remaining={c['sp_teams_keys']}")
    check("S1 自己付与と兄弟への GA を取り消した", deleted == ["ra-self", "ra-sibling"], f"deleted={deleted}")
    check("S1 人の GA 割り当ては残した", "ra-human" in c["role_assignments"])
    check("S1 application / service principal を削除していない",
          not any(x["kind"] == "FORBIDDEN_DELETE" for x in calls))
    tokens = [x for x in calls if x["kind"] == "token"]
    subs = {x["sub"] for x in tokens}
    check("S1 Entra への認証は投影 token のみ（client secret なし）",
          all("api://AzureADTokenExchange" in (x["aud"] if isinstance(x["aud"], list) else [x["aud"]])
              and not x["has_secret"] for x in tokens)
          and {f"system:serviceaccount:{NS}:defence-collector", f"system:serviceaccount:{NS}:defence-ledger"} <= subs,
          f"subs={subs}")
    p4 = [x for x in cases() if x["rule"] == "P4"]
    check("S1 P4 の案件が3件開いた", len(p4) == 3, f"P4={len(p4)}")

    reads = sum(1 for x in calls if x["kind"] == "audit_read")
    wait(lambda: sum(1 for x in mock_calls()["calls"] if x["kind"] == "audit_read") >= reads + 3, 60)
    c2 = mock_calls()["calls"]
    check("S2 読み直しても取り消しは一回だけ",
          sum(1 for x in c2 if x["kind"] == "removePassword") == 1
          and sum(1 for x in c2 if x["kind"] == "deleteRoleAssignment") == 2)
    check("S2 読み直しても案件は増えない", len([x for x in cases() if x["rule"] == "P4"]) == 3)


def s3_qilin() -> None:
    r = send([auth("vpn-user", "203.0.113.5", outcome="success", target="vpn")])["body"][0]
    check("S3 パスワードだけの VPN 認証は P1 で拒否", r["rule"] == "P1" and r["response"] == "deny")

    spray = [auth(f"spray{i}", "203.0.113.66") for i in range(10)]
    last = send(spray)["body"][-1]
    check("S3 10 account への spray は P2 で速度制限", "P2" in last["matched"])
    managed = send([auth("alice", "203.0.113.66", outcome="success", cert="present", mfa="present", device="pc-1")])
    check("S3 同じ IP でも管理端末と MFA の利用者は通る", managed["body"][0]["response"] == "allow")
    nocert = send([auth("bob", "203.0.113.66")])["body"][0]
    check("S3 同じ IP の証明書なしの後続は制限が続く", nocert["rule"] == "BLOCKED:P2", nocert["rule"])

    send([{"plane": "interactive", "action": "decoy_hit", "source_ip": "198.51.100.9", "target": "/admin",
           "source": "e2e-forwarder"}])
    p3 = send([auth("carol", "198.51.100.9")])["body"][0]
    check("S3 おとりの後の本番認証は P3 で連鎖を遮断", "P3" in p3["matched"])

    host = lambda action, **kw: {"plane": "host", "action": action, "source": "e2e-forwarder", **kw}
    gpo = send([host("gpo_change", host="dc01", actor_id="qilin-op", target="Default Domain Policy")])["body"][0]
    check("S3 GPO の変更は Q8 で案件化", gpo["rule"] == "Q8" and gpo["open_case"])
    aud = send([host("audit_disable", host="dc01", actor_id="qilin-op")])["body"][0]
    check("S3 監査の停止は Q2 で案件化（拒否したとは扱わない）", aud["rule"] == "Q2" and aud["response"] == "record")

    lat = send([host("lateral_denied", host=f"ws{i}", actor_id="qilin-op") for i in range(1, 4)])["body"][-1]
    statuses = [x["status"] for x in lat["results"]]
    check("S3 3端末の横展開拒否は Q1 で隔離と権限取り消し", lat["rule"] == "Q1" and statuses == ["done"] * 4, str(statuses))
    can = send([host("canary_touch", host="fs1", actor_id="qilin-op")])["body"][0]
    check("S3 おとりファイルへの書き込みは Q3 で隔離", can["rule"] == "Q3" and can["results"][0]["status"] == "done")
    eg = send([host("egress_denied", host="fs1")])["body"][0]
    check("S3 拒否の後の外向き通信は Q6 で遮断延長", eg["rule"] == "Q6")
    bk = send([host("backup_policy_change", host="vault", approved=False, outcome="success")])["body"][0]
    check("S3 承認なしのバックアップ変更は Q4 で提案と案件", bk["rule"] == "Q4" and bk["results"][0]["status"] == "proposed")

    hooks = [x for x in mock_calls()["calls"] if x["kind"] == "webhook"]
    isolated = sorted(x["action"]["params"]["host"] for x in hooks
                      if x["action"]["kind"] == "isolate_host_east_west")
    check("S3 webhook に隔離が届いた（ws1-3, fs1）", isolated == ["fs1", "ws1", "ws2", "ws3"], str(isolated))
    check("S3 account をロックする指示は出ていない",
          not any("lock" in x["action"]["kind"] for x in hooks))


def s4_auth_network() -> None:
    r = get("/v1/cases", "forwarder", SRC, "--no-token")
    check("S4 token なしは 401", r["status"] == 401, str(r["status"]))
    r = get("/v1/cases", "unregistered", SRC)
    check("S4 登録外の ServiceAccount は 403", r["status"] == 403, str(r["status"]))
    r = get("/v1/cases", "outsider", NS, "--timeout", "8")
    check("S4 収集でも発生源でもない Pod は NetworkPolicy で届かない", r["status"] == "timeout", str(r["status"]))


def s5_persistence() -> None:
    before = len(cases())
    oc("delete", "pod", "defence-ledger-0", "-n", NS)
    oc("wait", "--for=condition=Ready", "pod/defence-ledger-0", "-n", NS, "--timeout=300s")
    wait(lambda: get("/v1/cases")["status"] == 200, 60)
    after = len(cases())
    check("S5 再起動後も案件が残る", after >= before, f"before={before} after={after}")
    r = send([auth("dave", "198.51.100.9")])["body"][0]
    check("S5 再起動後も P3 の遮断が効く", r["rule"] == "BLOCKED:P3", r["rule"])


def s6_silence() -> None:
    hit = wait(lambda: [x for x in cases() if x["rule"] == "I5b" and "edr-silent" in x["summary"]], 150, 10)
    check("S6 黙った発生源 edr-silent の案件が開いた", bool(hit))
    check("S6 動いている収集（entra-audit）は途絶扱いにならない",
          not any(x["rule"] == "I5b" and "entra-audit" in x["summary"] for x in cases()))


def s7_runtime() -> None:
    pod = json.loads(oc("get", "pod", "defence-ledger-0", "-n", NS, "-o", "json"))
    scc = pod["metadata"]["annotations"].get("openshift.io/scc")
    uid = pod["spec"]["containers"][0]["securityContext"].get("runAsUser")
    check("S7 SCC restricted-v2、任意 UID で動く", scc == "restricted-v2" and uid not in (None, 0, 1001), f"{scc} {uid}")


def s8_stress(n: int) -> None:
    restarts = lambda: json.loads(oc("get", "pod", "defence-ledger-0", "-n", NS, "-o", "json"))[
        "status"]["containerStatuses"][0]["restartCount"]
    r0 = restarts()
    out = oc("exec", "-n", SRC, "forwarder", "--", "python", "/e2e/stress.py", "--url", LEDGER, "--ca", "/ca/ca.crt",
             "--events", str(n), "--concurrency", "32", timeout=1800)
    res = json.loads(out.strip().splitlines()[-1])
    print("     " + json.dumps(res, ensure_ascii=False))
    check(f"S8 {n} 件を取りこぼしなく処理（エラー0、P4 は全件案件化）",
          res["errors"] == 0 and res["p4_cases"] == res["p4_sent"], json.dumps(res))
    check("S8 ARTEX の spray の最大速度（毎分2,900件）を上回る", res["events_per_min"] > 2900, str(res["events_per_min"]))
    check("S8 負荷の後も台帳は再起動していない", restarts() == r0)
    check("S8 負荷の後も準備完了", get("/v1/cases")["status"] == 200)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="終了後も名前空間を残す")
    ap.add_argument("--stress-events", type=int, default=5000)
    a = ap.parse_args()
    teardown()
    wait(lambda: not oc("get", "ns", NS, SRC, "--ignore-not-found"), 300, 5)
    try:
        deploy()
        for s in (s7_runtime, s1_s2_artex, s3_qilin, s4_auth_network, s5_persistence, s6_silence):
            try:
                s()
            except Exception as e:
                check(f"{s.__name__} 実行時の例外", False, repr(e))
        if a.stress_events:
            s8_stress(a.stress_events)
    finally:
        if not a.keep:
            teardown()
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
