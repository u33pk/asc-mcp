"""ASC (Droid ASC) Model Context Protocol (MCP) Server.
Exposes 16 high-performance, token-efficient reverse engineering tools to LLMs.
"""

import json
import os
import subprocess
import sys
from typing import Literal, Optional
from mcp.server.mcpserver import MCPServer

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_PYTHON_EXE = sys.executable or os.path.join(_REPO_ROOT, ".venv", "bin", "python")


def _invoke_worker(command: str, payload: dict, timeout: int = 120) -> dict:
    """Invoke the isolated worker subprocess via stdin/stdout JSON IPC.
    Ensures complete isolation from sys.modules monkey-patching in the decompiler.
    """
    cmd = [_PYTHON_EXE, "-m", "src.asc_mcp.worker", command]
    env = dict(os.environ)
    env["PYTHONPATH"] = _REPO_ROOT

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=_REPO_ROOT,
        env=env,
        text=True,
        encoding="utf-8",
    )

    try:
        stdout_data, stderr_data = proc.communicate(
            input=json.dumps(payload, ensure_ascii=False),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise TimeoutError(f"Worker command '{command}' timed out after {timeout} seconds.")

    if not stdout_data.strip():
        err_msg = stderr_data.strip() or f"Worker process exited with code {proc.returncode} and empty output."
        raise RuntimeError(err_msg)

    try:
        response = json.loads(stdout_data)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse worker output: {stdout_data}\nStderr: {stderr_data}") from exc

    if response.get("status") != "ok":
        error_detail = response.get("error", "Unknown worker error")
        raise RuntimeError(error_detail)

    return response.get("data", {})


server = MCPServer(
    name="asc",
    title="Droid ASC Reverse Engineering Server",
    description=(
        "High-performance Android APK reverse engineering MCP server. "
        "Operates directly on compiled APK/DEX artifacts as a database without full inflate or heavy pre-indexing. "
        "Provides ultra-fast single-class decompilation (100-200ms), global cross-reference searches (1-2s), "
        "manifest extraction, and token-saving class outlining."
    ),
    version="1.0.0",
)


@server.tool()
def apk_get_manifest(
    apk_path: str,
    raw_xml: bool = False,
) -> dict:
    """Extract AndroidManifest.xml from an APK.

    Args:
        apk_path: Path to the target APK file.
        raw_xml: If True, returns full raw XML. If False (default), returns a structured
                 summary (package, version, permissions, main activity, exported components)
                 optimized for LLM context windows.
    """
    try:
        return _invoke_worker("manifest", {"apk_path": apk_path, "raw_xml": raw_xml})
    except Exception as e:
        return {"status": "error", "error": str(e), "apk_path": apk_path}


@server.tool()
def apk_list_classes(
    apk_path: str,
    query: str = "",
    package_prefix: str = "",
    limit: int = 50,
) -> dict:
    """List and filter class names across all DEX files in an APK without full decompilation.

    Args:
        apk_path: Path to the target APK file.
        query: Substring to filter class names (case-insensitive, e.g. 'crypto', 'auth', 'payment').
        package_prefix: Package prefix filter (e.g. 'com.example.app').
        limit: Maximum number of class names to return (1-200, default 50).
    """
    try:
        return _invoke_worker(
            "list_classes",
            {
                "apk_path": apk_path,
                "query": query,
                "package_prefix": package_prefix,
                "limit": limit,
            },
        )
    except Exception as e:
        return {"status": "error", "error": str(e), "apk_path": apk_path}


@server.tool()
def apk_get_class_outline(
    apk_path: str,
    class_name: str,
) -> dict:
    """Extract structural skeleton (superclass, interfaces, fields, method signatures) of a class.
    Does NOT decompile method bodies. Highly token-efficient for exploring class architecture
    before deciding whether full decompilation is needed.

    Args:
        apk_path: Path to the target APK file.
        class_name: Class name in dot format (e.g. 'com.example.MainActivity') or Dalvik format (e.g. 'Lcom/example/MainActivity;').
    """
    try:
        return _invoke_worker("outline", {"apk_path": apk_path, "class_name": class_name})
    except Exception as e:
        return {"status": "error", "error": str(e), "apk_path": apk_path, "class_name": class_name}


@server.tool()
def apk_get_class_source(
    apk_path: str,
    class_name: str,
) -> dict:
    """Decompile a single target class into Java source code on-demand in milliseconds.
    Performs surgical single-class DEX hollowing, index remapping, and targeted decompilation
    with zero full-APK inflate overhead.

    Args:
        apk_path: Path to the target APK file.
        class_name: Class name in dot format (e.g. 'com.example.MainActivity') or Dalvik format (e.g. 'Lcom/example/MainActivity;').
    """
    try:
        return _invoke_worker("getclass", {"apk_path": apk_path, "class_name": class_name})
    except Exception as e:
        return {"status": "error", "error": str(e), "apk_path": apk_path, "class_name": class_name}


@server.tool()
def apk_find_references(
    apk_path: str,
    find_type: Literal["string", "type", "method", "field"],
    query: str,
    class_name: Optional[str] = None,
    fuzzy_class: bool = False,
    limit: int = 30,
) -> dict:
    """Global cross-reference search across all DEX entries in an APK (equivalent to 'Find Usages / Xref').
    Scans raw bytecode using native C-regex and O(1) bucket mapping in 1-2 seconds.

    Args:
        apk_path: Path to the target APK file.
        find_type: Reference search dimension:
                   - 'string': search occurrences of string literals (query is string).
                   - 'type': search references to class/type descriptors (query is class/type name).
                   - 'method': search invocations of methods (query is method name).
                   - 'field': search accesses of fields (query is field name).
        query: The string, type, method name, or field name to search for.
        class_name: Optional class name to narrow down method or field search.
        fuzzy_class: If True, treats class_name as a fuzzy pattern; if False, exact class match.
        limit: Maximum number of matched references to return (1-100, default 30).
    """
    try:
        return _invoke_worker(
            "findrefs",
            {
                "apk_path": apk_path,
                "find_type": find_type,
                "query": query,
                "class_name": class_name,
                "fuzzy_class": fuzzy_class,
                "limit": limit,
            },
        )
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "apk_path": apk_path,
            "find_type": find_type,
            "query": query,
        }


@server.tool()
def apk_list_methods(
    apk_path: str,
    query: str = "",
    class_name: str = "",
    limit: int = 50,
) -> dict:
    """Search methods by name across all DEX files in an APK (fuzzy match).
    Reverse lookup: find which classes contain methods matching a keyword (e.g. 'encrypt', 'AES', 'onCreate').
    Much more efficient than listing classes then checking outlines one by one.

    Args:
        apk_path: Path to the target APK file.
        query: Substring to match against method names (case-sensitive, e.g. 'encrypt', 'AES', 'init').
               Can be empty if class_name is provided to list all methods of a class.
        class_name: Optional class name to narrow search (dot or Dalvik format).
        limit: Maximum number of methods to return (1-200, default 50).
    """
    try:
        return _invoke_worker(
            "list_methods",
            {
                "apk_path": apk_path,
                "query": query,
                "class_name": class_name,
                "limit": limit,
            },
        )
    except Exception as e:
        return {"status": "error", "error": str(e), "apk_path": apk_path}


@server.tool()
def apk_search_strings(
    apk_path: str,
    pattern: str,
    limit: int = 50,
) -> dict:
    """Global string search across the entire DEX string pool with regex support.
    Returns matching string values directly (not their usage locations — use apk_find_references for that).
    Useful for bulk extraction: URLs, IPs, API endpoints, key patterns, hardcoded secrets, etc.

    Args:
        apk_path: Path to the target APK file.
        pattern: Regex pattern or substring to search for in the string pool
                 (e.g. 'https?://', 'api[_-]?key', 'AKIA[0-9A-Z]{16}').
        limit: Maximum number of strings to return (1-500, default 50).
    """
    try:
        return _invoke_worker(
            "search_strings",
            {
                "apk_path": apk_path,
                "pattern": pattern,
                "limit": limit,
            },
        )
    except Exception as e:
        return {"status": "error", "error": str(e), "apk_path": apk_path}


@server.tool()
def apk_list_native_libs(
    apk_path: str,
) -> dict:
    """List all native shared libraries (.so files) packaged in the APK.
    Shows architecture (arm64-v8a, armeabi-v7a, x86_64, etc.), file names and sizes.
    Essential for JNI-heavy apps — identifies native code surface for further analysis.

    Args:
        apk_path: Path to the target APK file.
    """
    try:
        return _invoke_worker("list_native_libs", {"apk_path": apk_path})
    except Exception as e:
        return {"status": "error", "error": str(e), "apk_path": apk_path}


@server.tool()
def apk_extract_dex(
    apk_path: str,
    output_path: Optional[str] = None,
    dex_name: Optional[str] = None,
) -> dict:
    """Export DEX file(s) from the APK to disk for external analysis with JADX, Ghidra, IDA, etc.
    By default exports all DEX files; pass dex_name to export a specific one.

    Args:
        apk_path: Path to the target APK file.
        output_path: Directory to write DEX files to. If omitted, writes to current directory.
        dex_name: Specific DEX entry name to export (e.g. 'classes2.dex'). If omitted, exports all.
    """
    try:
        return _invoke_worker(
            "extract_dex",
            {
                "apk_path": apk_path,
                "output_path": output_path,
                "dex_name": dex_name,
            },
        )
    except Exception as e:
        return {"status": "error", "error": str(e), "apk_path": apk_path}


@server.tool()
def apk_list_resources(
    apk_path: str,
    prefix: str = "",
    limit: int = 100,
) -> dict:
    """List resource files in an APK (res/, assets/, lib/, META-INF/, etc.) with size and category.
    Provides a summary breakdown by category and res/ subdirectory type (layout, drawable, values...).
    Useful for analyzing UI structure, discovering hidden resources, and detecting packed payloads.

    Args:
        apk_path: Path to the target APK file.
        prefix: Optional path prefix filter (e.g. 'res/layout', 'assets/').
        limit: Maximum number of files to return (1-500, default 100).
    """
    try:
        return _invoke_worker(
            "list_resources",
            {"apk_path": apk_path, "prefix": prefix, "limit": limit},
        )
    except Exception as e:
        return {"status": "error", "error": str(e), "apk_path": apk_path}


@server.tool()
def apk_get_string_constants(
    apk_path: str,
    class_name: str,
    limit: int = 100,
) -> dict:
    """Extract all string constants (const-string instructions) from a specific class.
    Much lighter than full decompilation — quickly reveals hardcoded API keys, URLs, tokens,
    and other string literals used by a class without generating Java source code.

    Args:
        apk_path: Path to the target APK file.
        class_name: Class name in dot format (e.g. 'com.example.Config') or Dalvik format.
        limit: Maximum total strings to return (1-500, default 100).
    """
    try:
        return _invoke_worker(
            "get_string_constants",
            {"apk_path": apk_path, "class_name": class_name, "limit": limit},
        )
    except Exception as e:
        return {"status": "error", "error": str(e), "apk_path": apk_path, "class_name": class_name}


@server.tool()
def apk_scan_secrets(
    apk_path: str,
    patterns: list[str] = [],
    limit: int = 100,
) -> dict:
    """Scan the entire DEX string pool for hardcoded secrets and sensitive patterns.
    Built-in pattern library covers: AWS keys, Google API keys, JWT tokens, private key headers,
    Slack/GitHub/Telegram tokens, hardcoded passwords, JDBC strings, IPs with ports, and more.
    Results are ranked by severity (critical > high > medium > low).

    Args:
        apk_path: Path to the target APK file.
        patterns: List of pattern names to run (e.g. ['aws_access_key', 'jwt_token']).
                  If empty (default), all built-in patterns are checked.
        limit: Maximum number of findings to return (1-500, default 100).
    """
    try:
        return _invoke_worker(
            "scan_secrets",
            {"apk_path": apk_path, "patterns": patterns, "limit": limit},
        )
    except Exception as e:
        return {"status": "error", "error": str(e), "apk_path": apk_path}


@server.tool()
def apk_disassemble_method(
    apk_path: str,
    class_name: str,
    method_name: str,
    method_signature: Optional[str] = None,
) -> dict:
    """Disassemble a single method into smali bytecode. More reliable than Java decompilation
    for obfuscated code, complex control flow, or when precise bytecode analysis is needed.

    Args:
        apk_path: Path to the target APK file.
        class_name: Class name in dot format (e.g. 'com.example.MyClass') or Dalvik format.
        method_name: Method name to disassemble (e.g. 'encrypt', 'onCreate').
        method_signature: Optional signature fragment to disambiguate overloaded methods
                         (e.g. 'java.lang.String' to match a specific parameter type).
    """
    try:
        return _invoke_worker(
            "disassemble_method",
            {
                "apk_path": apk_path,
                "class_name": class_name,
                "method_name": method_name,
                "method_signature": method_signature,
            },
        )
    except Exception as e:
        return {"status": "error", "error": str(e), "apk_path": apk_path, "class_name": class_name, "method_name": method_name}


@server.tool()
def apk_get_certificate(
    apk_path: str,
) -> dict:
    """Extract signing certificate information from an APK (V1 JAR signing).
    Returns issuer, subject, serial number, validity period, signature algorithm,
    public key info, and SHA256/SHA1 fingerprints. Essential for verifying if an APK
    is an official release or has been repackaged.

    Args:
        apk_path: Path to the target APK file.
    """
    try:
        return _invoke_worker("get_certificate", {"apk_path": apk_path})
    except Exception as e:
        return {"status": "error", "error": str(e), "apk_path": apk_path}


@server.tool()
def apk_call_graph(
    apk_path: str,
    class_name: str,
    method_name: str,
    method_signature: Optional[str] = None,
    direction: str = "both",
    depth: int = 1,
) -> dict:
    """Get the call graph for a method — who calls it (callers) and what it calls (callees).
    Traces function call relationships to analyze data flow and understand code structure.

    Args:
        apk_path: Path to the target APK file.
        class_name: Class name in dot or Dalvik format.
        method_name: Method name (e.g. 'encrypt', 'onCreate').
        method_signature: Optional signature fragment to disambiguate overloaded methods.
        direction: 'callers' (who calls this), 'callees' (what this calls), or 'both' (default).
        depth: Traversal depth 1-5 (default 1). Higher depth follows the call chain deeper.
    """
    try:
        return _invoke_worker(
            "call_graph",
            {
                "apk_path": apk_path,
                "class_name": class_name,
                "method_name": method_name,
                "method_signature": method_signature,
                "direction": direction,
                "depth": depth,
            },
        )
    except Exception as e:
        return {"status": "error", "error": str(e), "apk_path": apk_path, "class_name": class_name, "method_name": method_name}


@server.tool()
def apk_diff(
    old_apk: str,
    new_apk: str,
    level: int = 2,
    package_prefix: str = "",
    limit: int = 50,
) -> dict:
    """Compare two APK versions and report differences in classes and methods.
    Supports three diff levels:
      1 = class list only (added/removed classes)
      2 = method list per class (added/removed methods)
      3 = bytecode diff with smali output for modified methods
    Essential for version comparison and security audit.

    Args:
        old_apk: Path to the older/base APK file.
        new_apk: Path to the newer/target APK file.
        level: Diff depth 1-3 (default 2).
        package_prefix: Optional package prefix filter (e.g. 'com.example.app').
        limit: Maximum number of changed classes/methods to return (1-200, default 50).
    """
    try:
        return _invoke_worker(
            "apk_diff",
            {
                "old_apk": old_apk,
                "new_apk": new_apk,
                "level": level,
                "package_prefix": package_prefix,
                "limit": limit,
            },
        )
    except Exception as e:
        return {"status": "error", "error": str(e), "old_apk": old_apk, "new_apk": new_apk}


def main():
    """Run the MCP server over stdio transport."""
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
