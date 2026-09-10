# ASC MCP Server

High-performance Android APK reverse engineering MCP server, powered by [Droid ASC](https://github.com/MG1937/ASC) core engine.

Operates directly on compiled APK/DEX artifacts as a read-only database — no full inflate, no heavy preprocessing. Global cross-reference searches in ~1.8s, class decompilation in ~177ms, using only ~141MB of RAM even against 352MB commercial APKs.

## Quick Start

```bash
# Install dependencies into .venv
uv sync

# Run MCP server (stdio transport)
uv run run_mcp.py
```

Configure in any MCP-compatible client (e.g. Claude Desktop, Kimi Code):

```json
{
  "mcpServers": {
    "asc": {
      "command": "uv",
      "args": ["run", "/path/to/ASC/run_mcp.py"]
    }
  }
}
```

## Tools (19)

### Core Analysis

| Tool | Description |
|------|-------------|
| `apk_get_manifest` | Extract AndroidManifest.xml (structured summary or raw XML) |
| `apk_list_classes` | List/filter class names across all DEX files |
| `apk_get_class_outline` | Structural skeleton of a class (fields, method signatures, no bodies) |
| `apk_get_class_source` | Full on-demand Java decompilation of a single class |
| `apk_disassemble_method` | Disassemble a single method into smali bytecode |
| `apk_call_graph` | Caller/callee call graph for a method (configurable depth 1-5) |
| `apk_get_class_hierarchy` | Superclass chain, subclasses, and interface implementors |

### Search & Reference

| Tool | Description |
|------|-------------|
| `apk_find_references` | Global cross-reference search (string/type/method/field usages) |
| `apk_list_methods` | Search methods by name across all DEX files (fuzzy match) |
| `apk_search_strings` | Global regex search in the DEX string pool |
| `apk_get_string_constants` | Extract all `const-string` values from a specific class |
| `apk_search_in_methods` | Global regex search inside all method bodies (like JADX Ctrl+Shift+F) |

### Security & Signing

| Tool | Description |
|------|-------------|
| `apk_scan_secrets` | Scan for hardcoded secrets with 16 built-in patterns (AWS keys, JWT, private keys, passwords, etc.) |
| `apk_get_certificate` | Extract signing certificate (issuer, fingerprints, algorithm, validity) |

### APK Structure

| Tool | Description |
|------|-------------|
| `apk_list_resources` | List resource files with category breakdown (res/, assets/, lib/) |
| `apk_get_resource_content` | Decode binary XML resources (layouts, menus, etc.) into readable XML |
| `apk_list_native_libs` | List .so files by architecture (arm64-v8a, armeabi-v7a, etc.) |
| `apk_extract_dex` | Export DEX files to disk for external tools (JADX, Ghidra, IDA) |

### Version Comparison

| Tool | Description |
|------|-------------|
| `apk_diff` | Compare two APK versions — added/removed classes, method diffs, bytecode-level smali diff |

## Architecture

```
MCP Client (LLM)
    │  stdio JSON-RPC
    ▼
┌─────────────────────┐
│  server.py          │  Tool definitions & dispatch
└────────┬────────────┘
         │  subprocess JSON IPC
         ▼
┌─────────────────────┐
│  worker.py          │  Isolated worker process
├─────────────────────┤
│  asc_client/        │  APK I/O, decompilation
│  asc_core/          │  DEX parsing, bytecode engine
│  smali_renderer.py  │  Smali disassembly
└─────────────────────┘
```

Worker subprocess isolation is required because the decompiler aggressively monkey-patches `sys.modules`.

## CLI Usage

```bash
# Decompile a class
python main.py getclass app.apk Lcom/example/MyClass; -o output.java

# Cross-reference search
python main.py findrefs app.apk string "token"
python main.py findrefs app.apk method onCreate --class com.example.MyClass

# GUI
python main.py app.apk --gui
```

## Credits

Core engine by [MG1937](https://github.com/MG1937) — presented at Black Hat Europe Arsenal. See [ASC.md](./ASC.md) for the original project description and benchmarks.
