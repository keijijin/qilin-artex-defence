"""E2E 用の模擬 Entra。token 発行、Graph の一部、端末側 webhook を持ち、受けた呼び出しを記録する。

本物の Entra には接続しない。シナリオは ARTEX（Storm-0940）の公開事例を模した監査記録である。
"""

import base64
import json
import os
import re
from urllib.parse import parse_qsl
import threading
from datetime import datetime, timezone
from uuid import uuid4

import uvicorn
from fastapi import FastAPI, Request, Response

GA = "62e90394-69f5-4237-9190-012177145e10"
K_ATTACKER = "aaaaaaaa-0000-0000-0000-000000000001"
K_LEGIT = "bbbbbbbb-0000-0000-0000-000000000002"

lock = threading.Lock()
calls: list[dict] = []
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

service_principals = {
    "sp-teams": {"id": "sp-teams", "passwordCredentials": [{"keyId": K_LEGIT}, {"keyId": K_ATTACKER}],
                 "keyCredentials": []},
    "sp-sibling": {"id": "sp-sibling", "passwordCredentials": [], "keyCredentials": []},
}
role_assignments = {
    "ra-self": {"id": "ra-self", "principalId": "sp-teams", "roleDefinitionId": GA},
    "ra-sibling": {"id": "ra-sibling", "principalId": "sp-sibling", "roleDefinitionId": GA},
    "ra-human": {"id": "ra-human", "principalId": "admin-user", "roleDefinitionId": GA},
}


def _app_actor():
    return {"app": {"servicePrincipalId": "sp-teams", "appId": "app-teams", "displayName": "Teams-connector"}}


audits = [
    {"id": "audit-cred", "activityDateTime": now, "result": "success",
     "activityDisplayName": "Add service principal credentials", "initiatedBy": _app_actor(),
     "targetResources": [{"id": "sp-teams", "type": "ServicePrincipal", "modifiedProperties": [
         {"displayName": "KeyDescription",
          "newValue": f'["[KeyIdentifier={K_ATTACKER},KeyType=Password,KeyUsage=Verify,DisplayName=x]"]'}]}]},
    {"id": "audit-role-self", "activityDateTime": now, "result": "success",
     "activityDisplayName": "Add member to role", "initiatedBy": _app_actor(),
     "targetResources": [{"id": "sp-teams", "type": "ServicePrincipal"},
                         {"id": "role", "type": "Role", "modifiedProperties": [
                             {"displayName": "Role.TemplateId", "newValue": f'"{GA}"'}]}]},
    {"id": "audit-role-sibling", "activityDateTime": now, "result": "success",
     "activityDisplayName": "Add member to role", "initiatedBy": _app_actor(),
     "targetResources": [{"id": "sp-sibling", "type": "ServicePrincipal"},
                         {"id": "role", "type": "Role", "modifiedProperties": [
                             {"displayName": "Role.TemplateId", "newValue": f'"{GA}"'}]}]},
    {"id": "audit-unrelated", "activityDateTime": now, "result": "success",
     "activityDisplayName": "Update user", "initiatedBy": {"user": {"id": "u"}}, "targetResources": []},
]

app = FastAPI()


def record(kind: str, **kw) -> None:
    with lock:
        calls.append({"kind": kind, **kw})


def _claims(jwt: str) -> dict:
    try:
        part = jwt.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:
        return {}


@app.post("/{tenant}/oauth2/v2.0/token")
async def token(tenant: str, request: Request):
    # python-multipart に依存しないよう、フォームは自分で解く
    form = dict(parse_qsl((await request.body()).decode()))
    c = _claims(form.get("client_assertion", ""))
    record("token", tenant=tenant, client_id=form.get("client_id"), grant=form.get("grant_type"),
           has_secret="client_secret" in form, aud=c.get("aud"), sub=c.get("sub"))
    return {"access_token": f"mock-{uuid4()}", "expires_in": 3600, "token_type": "Bearer"}


@app.get("/v1.0/auditLogs/directoryAudits")
def directory_audits(request: Request):
    record("audit_read", filter=request.query_params.get("$filter"))
    return {"value": audits}


@app.get("/v1.0/servicePrincipals/{sp}")
def get_sp(sp: str):
    with lock:
        return service_principals.get(sp, {"id": sp, "passwordCredentials": [], "keyCredentials": []})


@app.post("/v1.0/servicePrincipals/{sp}/removePassword")
async def remove_password(sp: str, request: Request):
    key = (await request.json())["keyId"]
    with lock:
        creds = service_principals[sp]["passwordCredentials"]
        service_principals[sp]["passwordCredentials"] = [c for c in creds if c["keyId"] != key]
    record("removePassword", sp=sp, keyId=key)
    return Response(status_code=204)


@app.get("/v1.0/roleManagement/directory/roleAssignments")
def list_roles(request: Request):
    flt = request.query_params.get("$filter", "")
    p = re.search(r"principalId eq '([^']+)'", flt)
    r = re.search(r"roleDefinitionId eq '([^']+)'", flt)
    with lock:
        hits = [a for a in role_assignments.values()
                if p and r and a["principalId"] == p.group(1) and a["roleDefinitionId"] == r.group(1)]
    return {"value": hits}


@app.delete("/v1.0/roleManagement/directory/roleAssignments/{ra}")
def delete_role(ra: str):
    with lock:
        role_assignments.pop(ra, None)
    record("deleteRoleAssignment", id=ra)
    return Response(status_code=204)


@app.api_route("/v1.0/{kind}/{obj}", methods=["DELETE"])
def forbidden_delete(kind: str, obj: str):
    # 台帳はオブジェクトを削除してはならない。来たら記録して E2E を失敗させる
    record("FORBIDDEN_DELETE", path=f"{kind}/{obj}")
    return Response(status_code=204)


@app.post("/webhook")
async def webhook(request: Request):
    record("webhook", action=await request.json())
    return Response(status_code=202)


@app.get("/_calls")
def get_calls():
    with lock:
        return {"calls": calls, "role_assignments": sorted(role_assignments),
                "sp_teams_keys": [c["keyId"] for c in service_principals["sp-teams"]["passwordCredentials"]]}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")), log_level="warning")
