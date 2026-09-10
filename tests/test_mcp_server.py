import asyncio
import json
import os
import subprocess
import sys
import unittest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

SAMPLE_APK = "/home/OGC/project/wxtrace/demo/app/build/outputs/apk/debug/app-debug.apk"
SAMPLE_CLASS = "wx.trace.demo.MainActivity"


class TestAscMcpServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(SAMPLE_APK):
            raise unittest.SkipTest(f"Sample APK not found: {SAMPLE_APK}")
        from src.asc_mcp.server import server
        cls.server = server

    def test_01_tools_registration(self):
        """Verify that exactly 16 expected tools are registered with valid schemas."""
        tools_map = self.server._tool_manager._tools
        expected_tools = {
            "apk_get_manifest",
            "apk_list_classes",
            "apk_get_class_outline",
            "apk_get_class_source",
            "apk_find_references",
            "apk_list_methods",
            "apk_search_strings",
            "apk_list_native_libs",
            "apk_extract_dex",
            "apk_list_resources",
            "apk_get_string_constants",
            "apk_scan_secrets",
            "apk_disassemble_method",
            "apk_get_certificate",
            "apk_call_graph",
            "apk_diff",
        }
        self.assertEqual(set(tools_map.keys()), expected_tools)
        for tool_name in expected_tools:
            tool = tools_map[tool_name]
            self.assertTrue(bool(tool.description))
            self.assertIsNotNone(tool.parameters)

    def test_02_apk_get_manifest_summary(self):
        """Verify apk_get_manifest structured summary output."""
        async def run():
            res = await self.server.call_tool(
                "apk_get_manifest",
                {"apk_path": SAMPLE_APK, "raw_xml": False},
            )
            self.assertFalse(res.is_error)
            text = res.content[0].text
            data = json.loads(text)
            self.assertEqual(data.get("package"), "wx.trace.demo")
            self.assertEqual(data.get("main_activity"), "wx.trace.demo.MainActivity")
            self.assertIn("wx.trace.demo.DroidGuardLoaderActivity", data.get("activities", []))
            self.assertGreater(data.get("permissions_count", 0), 0)

        asyncio.run(run())

    def test_03_apk_get_manifest_raw(self):
        """Verify apk_get_manifest raw XML output."""
        async def run():
            res = await self.server.call_tool(
                "apk_get_manifest",
                {"apk_path": SAMPLE_APK, "raw_xml": True},
            )
            self.assertFalse(res.is_error)
            data = json.loads(res.content[0].text)
            self.assertIn("raw_xml", data)
            self.assertIn("<manifest", data["raw_xml"])

        asyncio.run(run())

    def test_04_apk_list_classes(self):
        """Verify apk_list_classes with query and limit."""
        async def run():
            res = await self.server.call_tool(
                "apk_list_classes",
                {"apk_path": SAMPLE_APK, "query": "MainActivity", "limit": 5},
            )
            self.assertFalse(res.is_error)
            data = json.loads(res.content[0].text)
            self.assertGreater(data["total_classes"], 1000)
            self.assertGreaterEqual(data["matched_count"], 1)
            self.assertLessEqual(len(data["classes"]), 5)
            self.assertIn("wx.trace.demo.MainActivity", data["classes"])

        asyncio.run(run())

    def test_05_apk_get_class_outline(self):
        """Verify apk_get_class_outline token-saving structure."""
        async def run():
            res = await self.server.call_tool(
                "apk_get_class_outline",
                {"apk_path": SAMPLE_APK, "class_name": SAMPLE_CLASS},
            )
            self.assertFalse(res.is_error)
            data = json.loads(res.content[0].text)
            self.assertEqual(data["class_name"], "wx.trace.demo.MainActivity")
            self.assertEqual(data["superclass"], "androidx.appcompat.app.AppCompatActivity")
            self.assertGreater(data["fields_count"], 0)
            self.assertGreater(data["methods_count"], 0)
            field_names = [f["name"] for f in data["fields"]]
            self.assertIn("TAG", field_names)

        asyncio.run(run())

    def test_06_apk_get_class_source(self):
        """Verify apk_get_class_source targeted on-demand decompilation."""
        async def run():
            res = await self.server.call_tool(
                "apk_get_class_source",
                {"apk_path": SAMPLE_APK, "class_name": SAMPLE_CLASS},
            )
            self.assertFalse(res.is_error)
            data = json.loads(res.content[0].text)
            self.assertEqual(data["class_name"], "wx.trace.demo.MainActivity")
            source = data["source"]
            self.assertIn("public class MainActivity", source)
            self.assertIn("wxtrace-demo", source)

        asyncio.run(run())

    def test_07_apk_find_references(self):
        """Verify apk_find_references global cross-reference search."""
        async def run():
            res = await self.server.call_tool(
                "apk_find_references",
                {
                    "apk_path": SAMPLE_APK,
                    "find_type": "string",
                    "query": "wxtrace-demo",
                    "limit": 5,
                },
            )
            self.assertFalse(res.is_error)
            data = json.loads(res.content[0].text)
            self.assertEqual(data["find_type"], "string")
            self.assertEqual(data["query"], "wxtrace-demo")
            self.assertGreater(data["total_matches"], 0)
            self.assertLessEqual(len(data["references"]), 5)
            first_ref = data["references"][0]
            self.assertIn("caller_class", first_ref)
            self.assertIn("caller_method", first_ref)

        asyncio.run(run())

    def test_08_error_handling_nonexistent_class(self):
        """Verify graceful error reporting when class does not exist."""
        async def run():
            res = await self.server.call_tool(
                "apk_get_class_source",
                {"apk_path": SAMPLE_APK, "class_name": "com.nonexistent.NoSuchClass"},
            )
            data = json.loads(res.content[0].text)
            self.assertEqual(data.get("status"), "error")
            self.assertIn("not found", data.get("error", "").lower())

        asyncio.run(run())

    def test_09_stdio_handshake(self):
        """Verify run_mcp.py launches and responds to stdio JSON-RPC handshake."""
        python_exe = sys.executable
        run_script = os.path.join(_REPO_ROOT, "run_mcp.py")

        proc = subprocess.Popen(
            [python_exe, run_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=_REPO_ROOT,
        )

        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
        }

        try:
            proc.stdin.write(json.dumps(init_request) + "\n")
            proc.stdin.flush()
            response_line = proc.stdout.readline()
            self.assertTrue(bool(response_line))
            resp = json.loads(response_line)
            self.assertEqual(resp.get("id"), 1)
            self.assertIn("result", resp)
            self.assertEqual(resp["result"]["serverInfo"]["name"], "asc")
        finally:
            proc.terminate()
            proc.wait(timeout=2)
            if proc.stdin:
                proc.stdin.close()
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()

if __name__ == "__main__":
    unittest.main(verbosity=2)
