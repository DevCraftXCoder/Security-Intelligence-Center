"""
Script to wrap all @mcp.tool() function bodies with try/except error handling.
Uses ast to find exact function boundaries, avoiding f-string / multi-line issues.

The MCP tools are nested FunctionDefs inside setup_mcp_server().
They are decorated with @mcp.tool() — a Call node with func.attr == "tool".
"""
import ast


def get_func_info(source: str) -> list[dict]:
    """
    Parse source with ast to extract info about each @mcp.tool()-decorated function.
    Returns list of dicts with function metadata.
    """
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    results = []

    # Walk ALL nodes — tools are inside setup_mcp_server FunctionDef
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue

        # Check if decorated with @mcp.tool() — decorator is a Call on an Attribute named "tool"
        has_mcp_tool = False
        for dec in node.decorator_list:
            # @mcp.tool() → Call(func=Attribute(attr='tool'), args=[], keywords=[])
            if (isinstance(dec, ast.Call) and
                    isinstance(dec.func, ast.Attribute) and
                    dec.func.attr == "tool"):
                has_mcp_tool = True
                break

        if not has_mcp_tool:
            continue

        func_name = node.name
        def_lineno = node.lineno  # 1-indexed

        body = node.body
        if not body:
            continue

        # Check if first non-docstring stmt is a Try
        first_stmt = body[0]
        code_stmts = body

        docstring_end_line = def_lineno  # fallback

        if (isinstance(first_stmt, ast.Expr) and
                isinstance(first_stmt.value, ast.Constant) and
                isinstance(first_stmt.value.value, str)):
            # It's a docstring
            docstring_end_line = first_stmt.end_lineno  # 1-indexed inclusive
            code_stmts = body[1:]

        has_try_first = bool(code_stmts and isinstance(code_stmts[0], ast.Try))

        # Body end line (end_lineno exists in Python 3.8+)
        body_end = node.end_lineno  # 1-indexed, inclusive

        # Compute indent from the def line
        def_line_content = lines[def_lineno - 1]
        def_indent = len(def_line_content) - len(def_line_content.lstrip())
        body_indent = def_indent + 4

        first_code_lineno = code_stmts[0].lineno if code_stmts else None

        results.append({
            "name": func_name,
            "def_lineno": def_lineno,
            "body_end": body_end,
            "has_try_first": has_try_first,
            "body_indent": body_indent,
            "first_code_lineno": first_code_lineno,
            "has_code": bool(code_stmts),
        })

    return results


def wrap_tools(input_path: str, output_path: str) -> dict:
    with open(input_path, "r", encoding="utf-8") as f:
        source = f.read()

    lines = source.splitlines(keepends=True)

    func_infos = get_func_info(source)

    stats = {"wrapped": 0, "skipped": 0, "tools_seen": len(func_infos)}
    wrapped_names = []
    skipped_names = []

    # Sort in REVERSE order so line number modifications don't affect earlier functions
    func_infos.sort(key=lambda x: x["def_lineno"], reverse=True)

    for info in func_infos:
        if info["has_try_first"] or not info["has_code"] or info["first_code_lineno"] is None:
            stats["skipped"] += 1
            skipped_names.append(info["name"])
            continue

        body_indent_str = " " * info["body_indent"]
        func_name = info["name"]

        # first_code_lineno: 1-indexed line where code begins (after docstring)
        # body_end: 1-indexed last line of function (inclusive)
        insert_try_idx = info["first_code_lineno"] - 1  # 0-indexed
        last_body_idx = info["body_end"] - 1            # 0-indexed (inclusive)

        # Collect the code lines that need indenting
        code_section = lines[insert_try_idx: last_body_idx + 1]

        # Indent each non-blank line by 4 spaces
        indented_code = []
        for cl in code_section:
            if cl.strip() == "":
                indented_code.append(cl)
            else:
                indented_code.append("    " + cl)

        # Build the replacement: try: + indented code + except block
        try_line = f"{body_indent_str}try:\n"
        except_line = f"{body_indent_str}except Exception as e:\n"
        log_line = f'{body_indent_str}    logger.error(f"Error in {func_name}: {{str(e)}}")\n'
        return_line = f'{body_indent_str}    return {{"success": False, "error": str(e), "tool": "{func_name}"}}\n'

        replacement = [try_line] + indented_code + [except_line, log_line, return_line]

        # Replace the lines in the lines array
        lines[insert_try_idx: last_body_idx + 1] = replacement

        stats["wrapped"] += 1
        wrapped_names.append(func_name)

    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    return {
        "stats": stats,
        "wrapped_names": list(reversed(wrapped_names)),
        "skipped_names": list(reversed(skipped_names)),
    }


if __name__ == "__main__":
    input_file = "C:/Za/sic/hexstrike_mcp.py"
    output_file = "C:/Za/sic/hexstrike_mcp.py"

    print(f"Processing {input_file}...")
    result = wrap_tools(input_file, output_file)
    stats = result["stats"]

    print(f"Tools seen:           {stats['tools_seen']}")
    print(f"Wrapped (new):        {stats['wrapped']}")
    print(f"Already wrapped/skip: {stats['skipped']}")
    print()
    print("Already-wrapped/skipped tools:")
    for name in result["skipped_names"]:
        print(f"  - {name}")
    print()
    print("First 10 newly wrapped tools:")
    for name in result["wrapped_names"][:10]:
        print(f"  + {name}")
    print(f"  ... ({len(result['wrapped_names'])} total)")
