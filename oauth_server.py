import os
import json
import time
import secrets
import hashlib
import base64
from typing import Optional

import jwt
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI()

ISSUER = os.environ.get("ISSUER", "https://your-oauth-server.onrender.com")
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")
USERS_FILE = os.environ.get("USERS_FILE", "users.json")

# auth_code -> data
AUTH_CODES = {}


def load_users():
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)["users"]


def verify_user(username: str, password: str) -> bool:
    users = load_users()
    for user in users:
        if user["username"] == username and user["password"] == password:
            return True
    return False


def pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@app.get("/.well-known/oauth-authorization-server")
def oauth_metadata():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "token_endpoint_auth_methods_supported": ["none"],
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


@app.get("/")
def root():
    return {"status": "oauth server running"}