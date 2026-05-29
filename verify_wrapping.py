"""Verify all @mcp.tool() functions have try as first code statement."""
import ast

with open("C:/Za/sic/mcp_server.py", encoding="utf-8") as f:
    source = f.read()

tree = ast.parse(source)

mcp_tools = []
for node in ast.walk(tree):
    if not isinstance(node, ast.FunctionDef):
        continue
    for dec in node.decorator_list:
        if (isinstance(dec, ast.Call) and
                isinstance(dec.func, ast.Attribute) and
                dec.func.attr == "tool"):
            mcp_tools.append(node)
            break

print(f"Total @mcp.tool() functions: {len(mcp_tools)}")

no_try = []
for fn in mcp_tools:
    body = fn.body
    code_stmts = body
    if (body and isinstance(body[0], ast.Expr) and
            isinstance(body[0].value, ast.Constant) and
            isinstance(body[0].value.value, str)):
        code_stmts = body[1:]
    if not code_stmts or not isinstance(code_stmts[0], ast.Try):
        no_try.append(fn.name)

if no_try:
    print(f"FAIL - tools missing try wrapper: {no_try}")
else:
    print("PASS - All tools have try as first code statement.")
