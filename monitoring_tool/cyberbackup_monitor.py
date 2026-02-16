#!/usr/bin/env python3
"""Cyber Backup monitoring tool with configurable widgets.

Features:
- OAuth2 token retrieval via /idp/token
- Data collection from /resources, /policies, /tasks, /activities, /credentials/{id}
- JSON-based widget configuration
- Lightweight web dashboard using only Python stdlib
"""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urljoin
from urllib.request import Request, urlopen


DEFAULT_REFRESH_SECONDS = 30
SUPPORTED_WIDGET_TYPES = {
    "resources_count",
    "policies_count",
    "tasks_by_state",
    "activities_by_state",
    "credentials_detail",
}


@dataclass
class CyberBackupConfig:
    host: str
    port: int
    api_version: str
    username: str
    password: str
    client_id: str
    client_secret: str
    scope: str
    verify_ssl: bool = True

    @property
    def token_base_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    @property
    def api_base_url(self) -> str:
        return f"https://{self.host}:{self.port}/api/{self.api_version}"


class CyberBackupClient:
    def __init__(self, config: CyberBackupConfig) -> None:
        self.config = config
        self._token: Optional[str] = None
        self._token_exp_at: float = 0

    def _request_json(
        self,
        method: str,
        url: str,
        data: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        req = Request(url, method=method, data=data)
        for k, v in (headers or {}).items():
            req.add_header(k, v)

        # ssl verification flag intentionally ignored in stdlib-only tool.
        with urlopen(req, timeout=30) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}

    def get_token(self) -> str:
        now = time.time()
        if self._token and now < self._token_exp_at:
            return self._token

        form = urlencode(
            {
                "grant_type": "password",
                "username": self.config.username,
                "password": self.config.password,
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "scope": self.config.scope,
            }
        ).encode("utf-8")

        token_resp = self._request_json(
            "POST",
            f"{self.config.token_base_url}/idp/token",
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self._token = token_resp.get("access_token", "")
        expires_in = int(token_resp.get("expires_in", 300))
        self._token_exp_at = now + max(60, expires_in - 15)
        if not self._token:
            raise RuntimeError("Access token is empty in token response")
        return self._token

    def _api_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Any:
        query = ""
        if params:
            query = "?" + urlencode({k: v for k, v in params.items() if v is not None})
        url = urljoin(self.config.api_base_url + "/", endpoint.lstrip("/")) + query
        token = self.get_token()
        return self._request_json(
            "GET",
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )

    def list_resources(self, limit: int = 100) -> Any:
        return self._api_get("/resources", {"limit": limit})

    def list_policies(self, limit: int = 100) -> Any:
        return self._api_get("/policies", {"limit": limit})

    def list_tasks(self, limit: int = 100, state: Optional[str] = None) -> Any:
        return self._api_get("/tasks", {"limit": limit, "state": state})

    def list_activities(self, limit: int = 100, state: Optional[str] = None) -> Any:
        return self._api_get("/activities", {"limit": limit, "state": state})

    def get_credentials(self, credentials_id: str, tenant_id: Optional[str] = None) -> Any:
        return self._api_get(f"/credentials/{credentials_id}", {"tenant_id": tenant_id})


class WidgetEngine:
    def __init__(self, client: CyberBackupClient, widgets_config: List[Dict[str, Any]]) -> None:
        self.client = client
        self.widgets_config = widgets_config

    @staticmethod
    def validate_widgets_config(widgets: List[Dict[str, Any]]) -> None:
        for idx, widget in enumerate(widgets):
            w_type = widget.get("type")
            if w_type not in SUPPORTED_WIDGET_TYPES:
                raise ValueError(f"Widget #{idx} has unsupported type: {w_type}")
            if "title" not in widget:
                raise ValueError(f"Widget #{idx} must have a title")

    def collect(self) -> Dict[str, Any]:
        rendered: List[Dict[str, Any]] = []

        for widget in self.widgets_config:
            w_type = widget["type"]
            title = widget["title"]
            params = widget.get("params", {})
            result = {"title": title, "type": w_type, "status": "ok", "data": {}}
            try:
                if w_type == "resources_count":
                    payload = self.client.list_resources(limit=int(params.get("limit", 100)))
                    items = payload.get("items") or payload.get("resources") or []
                    result["data"] = {"count": len(items)}

                elif w_type == "policies_count":
                    payload = self.client.list_policies(limit=int(params.get("limit", 100)))
                    items = payload.get("items") or payload.get("policies") or []
                    result["data"] = {"count": len(items)}

                elif w_type == "tasks_by_state":
                    payload = self.client.list_tasks(limit=int(params.get("limit", 100)))
                    items = payload.get("items") or payload.get("tasks") or []
                    grouped: Dict[str, int] = {}
                    for item in items:
                        state = item.get("state", "unknown")
                        grouped[state] = grouped.get(state, 0) + 1
                    result["data"] = {"total": len(items), "by_state": grouped}

                elif w_type == "activities_by_state":
                    payload = self.client.list_activities(limit=int(params.get("limit", 100)))
                    items = payload.get("items") or payload.get("activities") or []
                    grouped = {}
                    for item in items:
                        state = item.get("state", "unknown")
                        grouped[state] = grouped.get(state, 0) + 1
                    result["data"] = {"total": len(items), "by_state": grouped}

                elif w_type == "credentials_detail":
                    creds_id = params.get("credentials_id")
                    if not creds_id:
                        raise ValueError("credentials_detail widget requires params.credentials_id")
                    payload = self.client.get_credentials(
                        credentials_id=creds_id,
                        tenant_id=params.get("tenant_id"),
                    )
                    result["data"] = {
                        "id": payload.get("id", creds_id),
                        "name": payload.get("name"),
                        "kind": payload.get("kind"),
                        "created_at": payload.get("created_at"),
                    }

            except Exception as exc:  # surface failures per-widget instead of full dashboard crash
                result["status"] = "error"
                result["error"] = str(exc)

            rendered.append(result)

        return {"generated_at": int(time.time()), "widgets": rendered}


class DashboardState:
    def __init__(self, engine: WidgetEngine, refresh_seconds: int) -> None:
        self.engine = engine
        self.refresh_seconds = refresh_seconds
        self.latest: Dict[str, Any] = {"generated_at": 0, "widgets": []}
        self._stop = threading.Event()

    def start(self) -> None:
        thread = threading.Thread(target=self._loop, daemon=True)
        thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.latest = self.engine.collect()
            self._stop.wait(self.refresh_seconds)


def build_dashboard_html(refresh_seconds: int) -> str:
    return f"""<!doctype html>
<html lang=\"ru\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
  <title>CyberBackup Monitor</title>
  <style>
    body {{ font-family: Arial, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:24px; }}
    h1 {{ margin-top:0; }}
    #widgets {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(280px,1fr)); gap:16px; }}
    .card {{ background:#1e293b; border-radius:12px; padding:16px; box-shadow:0 2px 12px rgba(0,0,0,.25); }}
    .ok {{ border-left:4px solid #22c55e; }}
    .error {{ border-left:4px solid #ef4444; }}
    pre {{ white-space:pre-wrap; word-wrap:break-word; margin:0; }}
    .meta {{ opacity:.8; margin-bottom:12px; }}
  </style>
</head>
<body>
  <h1>CyberBackup Monitor</h1>
  <div class=\"meta\">Автообновление: каждые {refresh_seconds} сек.</div>
  <div id=\"updated\" class=\"meta\"></div>
  <div id=\"widgets\"></div>
  <script>
    async function refresh() {{
      const res = await fetch('/api/widgets');
      const payload = await res.json();
      const root = document.getElementById('widgets');
      root.innerHTML = '';
      const dt = new Date(payload.generated_at * 1000);
      document.getElementById('updated').innerText = 'Последнее обновление: ' + dt.toLocaleString();
      for (const w of payload.widgets) {{
        const card = document.createElement('div');
        card.className = 'card ' + (w.status === 'ok' ? 'ok' : 'error');
        const title = document.createElement('h3');
        title.innerText = w.title;
        const body = document.createElement('pre');
        body.innerText = w.status === 'ok' ? JSON.stringify(w.data, null, 2) : (w.error || 'unknown error');
        card.appendChild(title);
        card.appendChild(body);
        root.appendChild(card);
      }}
    }}
    refresh();
    setInterval(refresh, {refresh_seconds * 1000});
  </script>
</body>
</html>
"""


def make_handler(state: DashboardState):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path.startswith("/api/widgets"):
                body = json.dumps(state.latest).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if self.path == "/" or self.path.startswith("/index.html"):
                body = build_dashboard_html(state.refresh_seconds).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self.send_response(404)
            self.end_headers()

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    return Handler


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        config = json.load(fh)

    required_root_keys = {"cyberbackup", "dashboard"}
    missing = required_root_keys - set(config.keys())
    if missing:
        raise ValueError(f"Config missing keys: {', '.join(sorted(missing))}")

    widgets = config["dashboard"].get("widgets", [])
    WidgetEngine.validate_widgets_config(widgets)
    return config


def run_server(config: Dict[str, Any]) -> None:
    cb = config["cyberbackup"]
    dash = config["dashboard"]

    cb_conf = CyberBackupConfig(
        host=cb["host"],
        port=int(cb["port"]),
        api_version=cb.get("api_version", "2"),
        username=cb["username"],
        password=cb["password"],
        client_id=cb["client_id"],
        client_secret=cb["client_secret"],
        scope=cb.get("scope", "urn:acronis.com::resource_management::read"),
        verify_ssl=bool(cb.get("verify_ssl", True)),
    )

    client = CyberBackupClient(cb_conf)
    engine = WidgetEngine(client, dash["widgets"])
    state = DashboardState(engine, int(dash.get("refresh_seconds", DEFAULT_REFRESH_SECONDS)))
    state.start()

    bind_host = dash.get("bind_host", "0.0.0.0")
    bind_port = int(dash.get("bind_port", 8080))
    server = HTTPServer((bind_host, bind_port), make_handler(state))
    print(f"CyberBackup Monitor started on http://{bind_host}:{bind_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        state.stop()
        server.server_close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CyberBackup monitoring dashboard")
    parser.add_argument(
        "--config",
        default=os.environ.get("CYBERBACKUP_MONITOR_CONFIG", "monitoring_tool/config.example.json"),
        help="Path to JSON config file",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = load_config(args.config)
    run_server(config)


if __name__ == "__main__":
    main()
