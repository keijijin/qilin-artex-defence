# アプリへの組み込み

アプリから台帳（defence-ledger）へ事象を送り、返ってくる判定に従って動かすまでの手順。台帳は呼び出し元を Kubernetes の TokenReview で確かめるので、アプリは同じクラスターの Pod として動いている前提で書く。クラスターの外にあるアプリは [7. クラスターの外のアプリ](#7-クラスターの外のアプリ) を見る。

クライアントは [`client/`](../client/)（`defence_client`）にある。依存は httpx だけ。

## 1. 組み込み方を決める

| 方式 | アプリがすること | 向いている用途 |
|---|---|---|
| 報告だけ | 事象を送る。判定は使わない | 管理操作や監査の記録（Q 系の案件化） |
| 判定に従う | 認証や変更を通す前に送り、`response` に従う | ログイン、VPN、API の入口（P1〜P3 の拒否と速度制限） |

判定に従う場合は、台帳に届かないときにどうするか（[5.](#5-台帳に届かないとき)）も決めておく。

## 2. クラスター側の登録

次の三つを行う。(a) と (b) は両方とも要る。片方だけでは、台帳に届かないか 403 が返る。

### (a) 呼び出せる ServiceAccount に加える

台帳は `ALLOWED_CALLERS` にない ServiceAccount からの呼び出しを 403 で拒否する。overlay にパッチを足す。

```yaml
# deploy/overlays/openshift/allow-myapp.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: defence-ledger, namespace: defence-system}
spec:
  template:
    spec:
      containers:
        - name: ledger
          env:
            - name: ALLOWED_CALLERS
              value: system:serviceaccount:defence-system:defence-collector,system:serviceaccount:myapp:myapp
```

```yaml
# deploy/overlays/openshift/kustomization.yaml に追記
patches:
  - path: allow-myapp.yaml
```

### (b) NetworkPolicy を通す

台帳への通信は、ラベルを付けた名前空間からしか通らない。ラベルがない Pod からは、パケットが届かない（E2E の S4 で確認済み）。

```bash
oc label namespace myapp defence.example/event-source=true
```

### (c) 途絶の検出に加える（任意）

アプリを発生源として登録すると、アプリからの事象が止まったときに案件が開く（I5b）。登録したら、アプリは生存通知を定期的に送る（[4.3](#43-生存通知と送り直し)）。

```yaml
# deploy/base/policy.yaml
registrations:
  sources:
    - name: entra-audit
      registered_at: "2026-10-28T00:00:00+00:00"
    - name: myapp                                   # LedgerClient の source と同じ名前
      registered_at: "2026-10-28T00:00:00+00:00"    # ここから source_grace_hours の間は途絶を問わない
```

## 3. アプリの Pod 側

台帳に送る token と、台帳の証明書を確かめるための CA を Pod に渡す。

```yaml
# OpenShift: アプリの名前空間に service-ca の CA を注入させる
apiVersion: v1
kind: ConfigMap
metadata:
  name: defence-service-ca
  namespace: myapp
  annotations: {service.beta.openshift.io/inject-cabundle: "true"}
```

```yaml
# Deployment の Pod spec（抜粋）
serviceAccountName: myapp
volumes:
  - name: ledger-token
    projected:
      sources:
        - serviceAccountToken: {path: token, audience: defence-ledger, expirationSeconds: 3600}
  - name: ledger-ca
    configMap: {name: defence-service-ca}
containers:
  - name: app
    env:
      - {name: LEDGER_URL, value: "https://defence-ledger.defence-system.svc:8443"}
      # 次の二つは既定値と同じなら省ける
      - {name: LEDGER_TOKEN_FILE, value: /var/run/defence/token}
      - {name: LEDGER_CA_FILE, value: /etc/defence-ca/service-ca.crt}
    volumeMounts:
      - {name: ledger-token, mountPath: /var/run/defence, readOnly: true}
      - {name: ledger-ca, mountPath: /etc/defence-ca, readOnly: true}
```

- token の audience は必ず `defence-ledger` にする。既定の audience の token は、台帳が受け付けない。
- 素の Kubernetes では、cert-manager の CA（[`deploy/overlays/kubernetes/`](../deploy/overlays/kubernetes/)）の `ca.crt` を Secret として渡し、`LEDGER_CA_FILE` をそのパスに合わせる。

## 4. アプリのコード

```bash
pip install "git+https://github.com/keijijin/qilin-artex-defence.git#subdirectory=client"
```

### 4.1 判定に従う

```python
from defence_client import FailMode, LedgerClient, LedgerRejected

ledger = LedgerClient(source="myapp", fail=FailMode.closed)   # URL などは環境変数から読む

def login(user, device, client_ip, has_cert, used_fido2):
    v = ledger.submit({
        "plane": "interactive",
        "action": "auth_attempt",
        "outcome": "success",            # 一次認証（パスワードなど）の結果
        "account_id": user.id,
        "device_id": device.id,
        "device_cert": "present" if has_cert else "absent",
        "phishing_resistant_mfa": "present" if used_fido2 else "absent",
        "source_ip": client_ip,
    })
    if v.response == "rate_limit":
        return http_429()
    if not v.allowed:
        return http_403()                # deny / block_chain / contain
    return issue_session(user)
```

`event_id`、`time`、`source` は書かなければクライアントが埋める。

### 4.2 判定の扱い

| `response` | アプリがすること |
|---|---|
| `allow` / `record` | そのまま通す（`v.allowed` が真） |
| `deny` | 認証や変更を通さない。token や session を出さない |
| `rate_limit` | 429 を返すか、遅らせる |
| `block_chain` | 拒否する。同じ連鎖（端末、IP、主体）からの後続も、遮断の間は拒否が返る |
| `contain` | 拒否する。資格情報の取り消しや端末の隔離は、台帳の側（enforcer）が行う |

ほかに次の属性がある。

- `v.suppress_account_lockout` が真なら、アカウントをロックしない。spray をロックで受けると、攻撃者が正規の利用者を締め出せてしまう。
- `v.degraded` が真なら、台帳に届かず、`FailMode` で決めた判定である。

### 4.3 生存通知と送り直し

```python
ledger.start_heartbeat(interval=60)   # 生存通知を送り、届いたら溜めた事象を送り直す
...
ledger.close()                        # 終了時。with LedgerClient(...) as ledger: でもよい
```

2(c) で発生源として登録したなら、`interval` を方針の `source_silence_minutes`（既定15分）より十分短くする。

### 4.4 用途ごとの主な項目

スキーマの全体は [`service/src/defence/models.py`](../service/src/defence/models.py) にある。

| 用途 | `plane` / `action` | 判定に効く項目 |
|---|---|---|
| ログイン、VPN | `interactive` / `auth_attempt` | `account_id`, `device_id`, `device_cert`, `phishing_resistant_mfa`, `source_ip`, `outcome` |
| おとりのアカウントや URL | `interactive` / `decoy_hit` | `source_ip`, `device_id` |
| 秘密情報の大量読み出し | `application` / `secret_bulk_read` | `service_principal_id`, `target` |
| バックアップ設定の変更 | `host` / `backup_policy_change` | `host`, `approved` |
| 生存通知 | 任意 / `heartbeat` | `source`（`heartbeat()` が送る） |

## 5. 台帳に届かないとき

台帳が応答しないときにどうするかは、アプリの側で決める。台帳には決めようがない。

| 入口 | 推奨 | 理由 |
|---|---|---|
| 管理者のログイン、権限の変更 | `FailMode.closed` | 台帳を止めれば素通りできる、という抜け道を作らない |
| 一般利用者のログイン | `FailMode.open` | 台帳の障害が、そのまま全利用者の障害になるのを避ける |

既定は `closed`。`submit(..., fail=FailMode.open)` のように、呼び出しごとに変えることもできる。

クライアントの振る舞いは次のとおり。

- **再送**: 接続できない、時間切れ、5xx、429 のときは、`retries` 回まで送り直す。間隔は `backoff` から倍々に延ばす。最悪の待ち時間はおよそ `(retries + 1) × timeout + backoff × (2^retries − 1)` で、既定（2秒、2回、0.2秒）では約6.6秒になる。ログインの経路では `timeout` と `retries` を短くする。
- **溜めて後で送る**: 届かなかった事象は、どちらの FailMode でも溜めておき、`flush()` か生存通知のときに送り直す。送り直しても `event_id` と `time` は変わらないので、台帳は一件として数え、起きた時刻で評価する。溜める件数は `max_pending`（既定1000）までで、超えたら古いものから捨てて `dropped` に数える。生存通知は溜めない。
- **例外にするもの**: 401、403、404、422 などは送り直しても結果が変わらないので、`LedgerRejected` を投げる。token の audience、`ALLOWED_CALLERS`、事象の形を確かめる。送り直しの途中で受け付けられなかった事象は、捨てて `dropped` に数える。

## 6. 確かめてから強制に切り替える

1. 方針の既定は `enforcement.mode: dry-run`。判定と案件は記録するが、Graph や webhook は呼ばない。アプリが受け取る `response` は dry-run でも本番と同じなので、アプリの側の拒否はこの時点で効く。アプリの拒否も止めたいなら、まず報告だけの方式で入れる。
2. 試しの事象を送り、案件が開くことを確かめる。証明書もフィッシング耐性のある MFA もない認証は、P1 で `deny` になる。

   ```bash
   oc -n myapp exec deploy/myapp -- python -c '
   from defence_client import LedgerClient
   c = LedgerClient(source="myapp")
   print(c.submit({"plane": "interactive", "action": "auth_attempt", "outcome": "success",
                   "account_id": "probe", "device_cert": "absent", "phishing_resistant_mfa": "absent"}))'
   ```

   ```bash
   oc -n myapp exec deploy/myapp -- sh -c 'curl -s --cacert /etc/defence-ca/service-ca.crt -H "Authorization: Bearer $(cat /var/run/defence/token)" https://defence-ledger.defence-system.svc:8443/v1/cases'
   ```

3. 誤検知がないことをしばらく見てから、`policy.yaml` の `enforcement.mode` を `enforce` にする。自動で実行する対応は `automatic_kinds` で絞る。

## 7. クラスターの外のアプリ

オンプレの VPN 装置や Windows サーバーなど、クラスターの外にあるものは TokenReview を通らない。そのため、クラスターの中に転送役の Pod を置き、ログを受けてから `LedgerClient` で送る。転送役の ServiceAccount と名前空間には、2. の登録を行う。

転送役は、受け取ったログの `event_id` に元のログの一意な ID を使う。転送役が再起動して同じログを読み直しても、台帳は一件として扱う。最小の例は [`e2e/send.py`](../e2e/send.py)。

## 8. よくある失敗

| 症状 | 原因 |
|---|---|
| 接続が時間切れになる | 名前空間にラベル `defence.example/event-source=true` がない |
| 401 | token がない。または audience が `defence-ledger` でない |
| 403 | ServiceAccount が `ALLOWED_CALLERS` にない |
| 422 | 事象の形が違う（`plane` や `action` の値など） |
| 証明書の検証で失敗する | `LEDGER_CA_FILE` が台帳の CA を指していない。URL のホスト名が `defence-ledger.defence-system.svc` でない |
| 途絶の案件が開く | 生存通知の間隔が `source_silence_minutes` より長い。または `source` の名前が方針と違う |
