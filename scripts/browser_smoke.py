"""Optional local Chrome smoke test; uses an isolated SQLite database, not MySQL."""

import json
import base64
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen

from websockets.sync.client import connect


ROOT = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        return server.getsockname()[1]


def wait_json(url):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=1) as response:
                return json.load(response)
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"Service did not become ready: {url}")


class Browser:
    def __init__(self, websocket_url):
        self.socket = connect(websocket_url, open_timeout=5)
        self.sequence = 0
        self.errors = []
        self.call("Runtime.enable")

    def call(self, method, params=None):
        self.sequence += 1
        self.socket.send(json.dumps({"id": self.sequence, "method": method, "params": params or {}}))
        while True:
            result = json.loads(self.socket.recv(timeout=20))
            if result.get("method") == "Runtime.exceptionThrown":
                self.errors.append(result)
            if result.get("id") == self.sequence:
                if "error" in result:
                    raise RuntimeError(result["error"])
                return result.get("result", {})

    def evaluate(self, expression):
        result = self.call("Runtime.evaluate", {"expression": expression, "awaitPromise": True, "returnByValue": True})
        if "exceptionDetails" in result:
            raise RuntimeError(result["exceptionDetails"])
        return result.get("result", {}).get("value")

    def wait(self, expression):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.evaluate(expression):
                return
            time.sleep(0.1)
        raise AssertionError(f"Browser condition timed out: {expression}")


def main():
    chrome = next((Path(p) for p in (
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    ) if Path(p).exists()), None)
    if chrome is None:
        raise RuntimeError("Chrome or Edge is required for this optional test")
    port, debug_port = free_port(), free_port()
    with tempfile.TemporaryDirectory(prefix="safety-ui-") as directory:
        temp = Path(directory)
        env = {**os.environ, "SAFETY_DB_BACKEND": "sqlite", "SAFETY_DATA_DIR": str(temp / "data")}
        for key in list(env):
            if key.startswith("SAFETY_LLM_"):
                env[key] = ""
        env["SAFETY_LLM_ENABLED"] = "false"
        processes = []
        browser = None
        try:
            processes.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "safety_assessment.app:app", "--host", "127.0.0.1", "--port", str(port)], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            wait_json(f"http://127.0.0.1:{port}/api/system/status")
            processes.append(subprocess.Popen([str(chrome), "--headless=new", "--disable-gpu", "--disable-background-networking", "--no-first-run", "--no-default-browser-check", f"--remote-debugging-port={debug_port}", f"--user-data-dir={temp / 'browser'}", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            tabs = wait_json(f"http://127.0.0.1:{debug_port}/json")
            browser = Browser(next(tab["webSocketDebuggerUrl"] for tab in tabs if tab["type"] == "page"))
            browser.call("Page.navigate", {"url": f"http://127.0.0.1:{port}/"})
            browser.wait("Boolean(document.querySelector('#auth-form'))")
            browser.evaluate("""document.querySelector('#auth-form [name=username]').value='ui_test_admin';document.querySelector('#auth-form [name=password]').value='ui-test-password';document.querySelector('#auth-form').requestSubmit()""")
            browser.wait("Boolean(document.querySelector('a[href=\"#config\"]'))")
            assert browser.evaluate("date('2026/10/23/10.11')") == "2026/10/23/10.11"
            assert browser.evaluate("date('2026-10-23T02:11:59.999+00:00')") == "2026/10/23/10.11"
            assert browser.evaluate("date(null)") == "—"
            assert browser.evaluate("date('invalid-date')") == "—"
            browser.evaluate("location.hash='#config'")
            browser.wait("Boolean(document.querySelector('[data-action=test-llm]'))")
            assert browser.evaluate("Boolean(document.querySelector('#llm-form [name=base_url]') && document.querySelector('#llm-form [name=api_key]'))")
            browser.evaluate("document.querySelector('[data-action=test-llm]').click()")
            browser.wait("document.querySelector('#toast').classList.contains('error')")
            project_id = browser.evaluate("""fetch('/api/projects',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({project_name:'UI smoke',source_type:'inline'})}).then(r=>r.json()).then(p=>p.id)""")
            browser.evaluate(f"location.hash='#project/{project_id}/submit'")
            browser.wait("Boolean(document.querySelector('#submission-form'))")
            code = "# 中文源码\nprint('hello')\n"
            browser.evaluate(f"document.querySelector('#submission-form [name=code]').value={json.dumps(code)};document.querySelector('#submission-form').requestSubmit()")
            browser.wait("location.hash.endsWith('/vulnerabilities')")
            browser.evaluate(f"location.hash='#project/{project_id}/submit'")
            browser.wait("Boolean(document.querySelector('[data-action=load-submission]'))")
            assert browser.evaluate("/\\d{4}\\/\\d{2}\\/\\d{2}\\/\\d{2}\\.\\d{2}/.test(document.querySelector('main').textContent)")
            assert browser.evaluate("!document.querySelector('main').textContent.includes('Invalid Date')")
            browser.evaluate("document.querySelector('[data-action=load-submission]').click()")
            browser.wait(f"document.querySelector('#submission-form [name=code]').value==={json.dumps(code)}")

            browser.call("Emulation.setDeviceMetricsOverride", {"width": 1440, "height": 1000, "deviceScaleFactor": 1, "mobile": False})
            browser.evaluate("location.hash='#new'")
            browser.wait("Boolean(document.querySelector('#source-dropzone'))")
            assert browser.evaluate("document.querySelector('.advanced-import').open === false")
            browser.evaluate("document.querySelector('#import-start').click()")
            browser.wait("document.querySelector('#toast').textContent.includes('选择源码')")
            browser.evaluate(f"""(() => {{const data = new DataTransfer();data.items.add(new File([{json.dumps(code)}],'上传示例.py',{{type:'text/x-python'}}));const input=document.querySelector('#source-files');input.files=data.files;input.dispatchEvent(new Event('change',{{bubbles:true}}));}})()""")
            browser.wait("document.querySelector('#import-file-list').textContent.includes('上传示例.py')")
            browser.evaluate("document.querySelector('#toast').style.display='none'")
            screenshot = browser.call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True})
            (ROOT / "data" / "upload-desktop.png").write_bytes(base64.b64decode(screenshot["data"]))
            browser.evaluate("document.querySelector('#import-start').click()")
            browser.wait("location.hash.endsWith('/monitor')")
            uploaded_id = browser.evaluate("Number(location.hash.split('/')[1])")
            browser.wait(f"fetch('/api/projects/{uploaded_id}').then(r=>r.json()).then(p=>p.project_status==='completed')")
            assert browser.evaluate(f"fetch('/api/projects/{uploaded_id}/report').then(r=>r.ok)")

            browser.evaluate("location.hash='#new'")
            browser.wait("Boolean(document.querySelector('#import-form'))")
            browser.evaluate("document.querySelector('#toast').style.display='none'")
            browser.call("Emulation.setDeviceMetricsOverride", {"width": 390, "height": 844, "deviceScaleFactor": 1, "mobile": True})
            assert browser.evaluate("document.documentElement.scrollWidth<=window.innerWidth")
            screenshot = browser.call("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True})
            (ROOT / "data" / "upload-mobile.png").write_bytes(base64.b64decode(screenshot["data"]))
            browser.evaluate("document.querySelector('[data-action=import-mode][data-mode=paste]').click()")
            browser.wait("document.querySelector('#import-paste').hidden === false")
            browser.evaluate(f"document.querySelector('#import-form [name=code]').value={json.dumps(code)};document.querySelector('#import-start').click()")
            browser.wait("location.hash.endsWith('/monitor')")
            pasted_id = browser.evaluate("Number(location.hash.split('/')[1])")
            browser.wait(f"fetch('/api/projects/{pasted_id}').then(r=>r.json()).then(p=>p.project_status==='completed')")
            browser.call("Emulation.setDeviceMetricsOverride", {"width": 390, "height": 844, "deviceScaleFactor": 1, "mobile": True})
            assert browser.evaluate("document.documentElement.scrollWidth<=window.innerWidth")
            assert not browser.errors, browser.errors
            print("PASS: compact Beijing timestamps and legacy dates, admin settings, code readback, file upload and automatic report, pasted assessment, mobile layout; no JavaScript exceptions")
        finally:
            if browser:
                try:
                    browser.call("Browser.close")
                except Exception:
                    pass
                browser.socket.close()
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=10)
            # Chromium may briefly retain its profile handles after exiting.
            for _ in range(20):
                try:
                    shutil.rmtree(temp / "browser", ignore_errors=False)
                    break
                except FileNotFoundError:
                    break
                except OSError:
                    time.sleep(0.2)


if __name__ == "__main__":
    main()
