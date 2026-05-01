from fastmcp import FastMCP

# Create MCP server
mcp = FastMCP("SimpleMathServer")

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