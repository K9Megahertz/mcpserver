import os
import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ISSUER = os.environ["JWT_ISSUER"].rstrip("/")
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "mcp-server")
MCP_BASE_URL = os.environ["MCP_BASE_URL"].rstrip("/")

token_verifier = JWTVerifier(
    public_key=JWT_SECRET,
    issuer=JWT_ISSUER,
    audience=JWT_AUDIENCE,
    algorithm="HS256",
)

auth = RemoteAuthProvider(
    token_verifier=token_verifier,
    authorization_servers=[JWT_ISSUER],
    base_url=MCP_BASE_URL,
)

mcp = FastMCP(
    name="SimpleMathServer",
    auth=auth,
)


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_metadata(request: Request):
    """Point VS Code directly at the OAuth server — no redirects needed."""
    return JSONResponse({
        "issuer": JWT_ISSUER,
        "authorization_endpoint": f"{JWT_ISSUER}/authorize",
        "token_endpoint": f"{JWT_ISSUER}/token",
        "registration_endpoint": f"{JWT_ISSUER}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "token_endpoint_auth_methods_supported": ["none"],
    })


@mcp.custom_route("/authorize", methods=["GET"])
async def authorize_redirect(request: Request):
    """Fallback redirect in case something hits /authorize on the MCP server."""
    query = request.url.query
    return RedirectResponse(
        url=f"{JWT_ISSUER}/authorize?{query}",
        status_code=302,
    )


@mcp.custom_route("/token", methods=["POST"])
async def token_proxy(request: Request):
    """Proxy token requests instead of redirecting (clients don't follow POST redirects)."""
    body = await request.body()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{JWT_ISSUER}/token", content=body, headers=headers)
    return JSONResponse(resp.json(), status_code=resp.status_code)


@mcp.tool()
def add(a: float, b: float) -> float:
    """Use this tool to add two numbers together."""
    return a + b


if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", 10000))
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=PORT,
    )