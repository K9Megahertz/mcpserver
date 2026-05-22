from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import JWTVerifier
import os

JWT_SECRET = os.environ.get("JWT_SECRET")
JWT_ISSUER = os.environ.get("JWT_ISSUER")
JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "mcp-server")

if not JWT_SECRET:
    raise RuntimeError("Missing JWT_SECRET environment variable")

if not JWT_ISSUER:
    raise RuntimeError("Missing JWT_ISSUER environment variable")

verifier = JWTVerifier(
    public_key=JWT_SECRET,
    issuer=JWT_ISSUER,
    audience=JWT_AUDIENCE,
    algorithm="HS256",
)

mcp = FastMCP(
    name="SimpleMathServer",
    auth=verifier,
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






    # from fastmcp import FastMCP
# import os

# mcp = FastMCP("SimpleMathServer")

# @mcp.tool()
# def add(a: float, b: float) -> float:
#     """
#     Use this tool to add two numbers together
#     """
#     return a + b

# if __name__ == "__main__":
#     PORT = int(os.environ.get("PORT", 10000))
#     mcp.run(transport="streamable-http", host="0.0.0.0", port=PORT)
