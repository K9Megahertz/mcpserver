from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from starlette.requests import Request
from starlette.responses import RedirectResponse
import os

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


@mcp.custom_route("/authorize", methods=["GET"])
async def authorize_redirect(request: Request):
    query = request.url.query
    return RedirectResponse(
        url=f"{JWT_ISSUER}/authorize?{query}",
        status_code=302,
    )


@mcp.custom_route("/token", methods=["POST"])
async def token_redirect(request: Request):
    return RedirectResponse(
        url=f"{JWT_ISSUER}/token",
        status_code=307,
    )


@mcp.tool()
def add(a: float, b: float) -> float:
    """
    Use this tool to add two numbers together.
    """
    return a + b


if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", 10000))
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=PORT,
    )