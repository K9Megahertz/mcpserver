from fastmcp import FastMCP
import os


PORT = os.environ.get("PORT", 10000)

# Create MCP server
mcp = FastMCP("SimpleMathServer", host="0.0.0.0", port=PORT)

# Define a tool
@mcp.tool()
def add(a: float, b: float) -> float:
    """
    Add two numbers together.
    """
    return a + b

# Run the server
if __name__ == "__main__":
    mcp.run()