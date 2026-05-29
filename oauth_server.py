import os
import json
import time
import secrets
import hashlib
import base64
from typing import Optional, List

import jwt
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI()

ISSUER = os.environ.get("ISSUER", "https://oauthserver-nm5l.onrender.com").rstrip("/")
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")
USERS_FILE = os.environ.get("USERS_FILE", "users.json")
CLIENTS_FILE = os.environ.get("CLIENTS_FILE", "clients.json")

AUTH_CODES = {}

STATIC_CLIENTS = {
    "vscode-mcp": {
        "client_id": "vscode-mcp",
        "client_name": "VS Code MCP",
        "redirect_uris": ["http://127.0.0.1", "http://localhost", "vscode://"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
}


def load_dynamic_clients() -> dict:
    if not os.path.exists(CLIENTS_FILE):
        return {}
    try:
        with open(CLIENTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_dynamic_clients(clients: dict):
    with open(CLIENTS_FILE, "w", encoding="utf-8") as f:
        json.dump(clients, f, indent=2)


# In-memory clients: static + dynamic loaded from disk
CLIENTS = {**STATIC_CLIENTS, **load_dynamic_clients()}


class ClientRegistrationRequest(BaseModel):
    redirect_uris: List[str]
    client_name: Optional[str] = "Dynamic MCP Client"
    grant_types: Optional[List[str]] = Field(default_factory=lambda: ["authorization_code"])
    response_types: Optional[List[str]] = Field(default_factory=lambda: ["code"])
    token_endpoint_auth_method: Optional[str] = "none"
    scope: Optional[str] = ""


def load_users():
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)["users"]


def verify_user(username: str, password: str) -> bool:
    users = load_users()
    for user in users:
        if user["username"] == username and user["password"] == password:
            return True
    return False


def is_allowed_redirect_uri(client_id: str, redirect_uri: str) -> bool:
    if client_id not in CLIENTS:
        return False
    allowed_prefixes = CLIENTS[client_id]["redirect_uris"]
    return any(redirect_uri.startswith(prefix) for prefix in allowed_prefixes)


def pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@app.get("/")
def root():
    return {"status": "oauth server running"}


@app.get("/.well-known/oauth-authorization-server")
def oauth_metadata():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "registration_endpoint": f"{ISSUER}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "token_endpoint_auth_methods_supported": ["none"],
    }


@app.get("/.well-known/oauth-authorization-server/mcp")
def oauth_metadata_mcp():
    return oauth_metadata()


@app.get("/.well-known/openid-configuration")
def openid_configuration():
    return oauth_metadata()


@app.post("/register")
def register_client(req: ClientRegistrationRequest):
    client_id = "client_" + secrets.token_urlsafe(24)
    print(f"[register] new client: {req.client_name} — {req.redirect_uris}")

    entry = {
        "client_id": client_id,
        "client_name": req.client_name,
        "redirect_uris": req.redirect_uris,
        "grant_types": req.grant_types,
        "response_types": req.response_types,
        "token_endpoint_auth_method": req.token_endpoint_auth_method,
        "scope": req.scope,
        "created_at": int(time.time()),
    }

    CLIENTS[client_id] = entry

    # Persist only dynamic clients (exclude static ones)
    dynamic = {k: v for k, v in CLIENTS.items() if k not in STATIC_CLIENTS}
    save_dynamic_clients(dynamic)

    return {
        "client_id": client_id,
        "client_name": req.client_name,
        "redirect_uris": req.redirect_uris,
        "grant_types": req.grant_types,
        "response_types": req.response_types,
        "token_endpoint_auth_method": req.token_endpoint_auth_method,
        "scope": req.scope,
        "client_id_issued_at": int(time.time()),
    }


@app.get("/authorize", response_class=HTMLResponse)
def authorize_page(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    state: Optional[str] = None,
    scope: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = "plain",
):
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Only response_type=code is supported")

    if client_id not in CLIENTS:
        raise HTTPException(status_code=400, detail="Unknown client_id")

    if not is_allowed_redirect_uri(client_id, redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    return f"""
    <html>
      <body>
        <h2>Test OAuth Login</h2>
        <form method="post" action="/authorize">
          <input type="hidden" name="client_id" value="{client_id}">
          <input type="hidden" name="redirect_uri" value="{redirect_uri}">
          <input type="hidden" name="state" value="{state or ''}">
          <input type="hidden" name="scope" value="{scope or ''}">
          <input type="hidden" name="code_challenge" value="{code_challenge or ''}">
          <input type="hidden" name="code_challenge_method" value="{code_challenge_method or 'plain'}">

          <label>Username:</label><br>
          <input name="username"><br><br>

          <label>Password:</label><br>
          <input name="password" type="password"><br><br>

          <button type="submit">Login</button>
        </form>
      </body>
    </html>
    """


@app.get("/authorize/mcp", response_class=HTMLResponse)
def authorize_page_mcp(
    response_type: str,
    client_id: str,
    redirect_uri: str,
    state: Optional[str] = None,
    scope: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = "plain",
):
    return authorize_page(
        response_type=response_type,
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        scope=scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )


@app.post("/authorize")
def authorize_submit(
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    state: str = Form(""),
    scope: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form("plain"),
):
    if client_id not in CLIENTS:
        raise HTTPException(status_code=400, detail="Unknown client_id")

    if not is_allowed_redirect_uri(client_id, redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    if not verify_user(username, password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    code = secrets.token_urlsafe(32)

    AUTH_CODES[code] = {
        "username": username,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at": time.time() + 300,
    }

    url = f"{redirect_uri}?code={code}"
    if state:
        url += f"&state={state}"

    return RedirectResponse(url, status_code=302)


@app.post("/authorize/mcp")
def authorize_submit_mcp(
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    state: str = Form(""),
    scope: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form("plain"),
):
    return authorize_submit(
        client_id=client_id,
        redirect_uri=redirect_uri,
        username=username,
        password=password,
        state=state,
        scope=scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )


@app.post("/token")
def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    code_verifier: Optional[str] = Form(None),
):
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Only authorization_code is supported")

    if client_id not in CLIENTS:
        raise HTTPException(status_code=400, detail="Unknown client_id")

    if not is_allowed_redirect_uri(client_id, redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    data = AUTH_CODES.pop(code, None)

    if not data:
        raise HTTPException(status_code=400, detail="Invalid code")

    if time.time() > data["expires_at"]:
        raise HTTPException(status_code=400, detail="Code expired")

    if data["redirect_uri"] != redirect_uri:
        raise HTTPException(status_code=400, detail="redirect_uri mismatch")

    if data["client_id"] != client_id:
        raise HTTPException(status_code=400, detail="client_id mismatch")

    challenge = data.get("code_challenge")
    method = data.get("code_challenge_method")

    if challenge:
        if not code_verifier:
            raise HTTPException(status_code=400, detail="Missing code_verifier")

        if method == "S256":
            expected = pkce_s256(code_verifier)
        else:
            expected = code_verifier

        if expected != challenge:
            raise HTTPException(status_code=400, detail="Invalid PKCE verifier")

    now = int(time.time())

    access_token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": data["username"],
            "aud": "mcp-server",
            "iat": now,
            "exp": now + 3600,
            "scope": data["scope"],
        },
        JWT_SECRET,
        algorithm="HS256",
    )

    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": data["scope"],
        }
    )


@app.post("/token/mcp")
def token_mcp(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    code_verifier: Optional[str] = Form(None),
):
    return token(
        grant_type=grant_type,
        code=code,
        redirect_uri=redirect_uri,
        client_id=client_id,
        code_verifier=code_verifier,
    )