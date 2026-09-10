#!/usr/bin/env python3
"""Entry point for ASC MCP server.
Usage:
    .venv/bin/python run_mcp.py
"""

import os
import sys

# Ensure repository root is on sys.path
_REPO_ROOT = os.path.abspath(os.path.dirname(__file__))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.asc_mcp.server import main

if __name__ == "__main__":
    main()
