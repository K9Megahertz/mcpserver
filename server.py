from fastmcp import FastMCP
import os

mcp = FastMCP("SimpleMathServer")

@mcp.tool()
def add(a: float, b: float) -> float:
    return a + b

if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", 10000))
    mcp.run_http(host="0.0.0.0", port=PORT)