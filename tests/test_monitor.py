import json
import tempfile
import unittest

from monitoring_tool.cyberbackup_monitor import (
    CyberBackupClient,
    CyberBackupConfig,
    WidgetEngine,
    load_config,
)


class FakeClient:
    def list_resources(self, limit=100):
        return {"items": [{"id": 1}, {"id": 2}]}

    def list_policies(self, limit=100):
        return {"policies": [{"id": "p1"}]}

    def list_tasks(self, limit=100, state=None):
        return {"tasks": [{"state": "running"}, {"state": "running"}, {"state": "failed"}]}

    def list_activities(self, limit=100, state=None):
        return {"activities": [{"state": "ok"}, {"state": "ok"}, {"state": "ok"}]}

    def get_credentials(self, credentials_id, tenant_id=None):
        return {"id": credentials_id, "name": "root", "kind": "username_password", "created_at": "now"}


class AuthClientForTest(CyberBackupClient):
    def _request_token(self):
        return {
            "access_token": "abcdefghijklmnopqrstuvwxyz0123456789",
            "refresh_token": "refresh-1",
            "expires_in": 120,
            "token_type": "Bearer",
            "scope": self.config.scope,
        }


class MonitorTests(unittest.TestCase):
    def test_widget_collection(self):
        widgets = [
            {"title": "R", "type": "resources_count", "params": {}},
            {"title": "P", "type": "policies_count", "params": {}},
            {"title": "T", "type": "tasks_by_state", "params": {}},
            {"title": "A", "type": "activities_by_state", "params": {}},
            {
                "title": "C",
                "type": "credentials_detail",
                "params": {"credentials_id": "cred-1", "tenant_id": "t1"},
            },
        ]
        engine = WidgetEngine(FakeClient(), widgets)
        payload = engine.collect()
        self.assertEqual(len(payload["widgets"]), 5)
        self.assertEqual(payload["widgets"][0]["data"]["count"], 2)
        self.assertEqual(payload["widgets"][2]["data"]["by_state"]["running"], 2)

    def test_invalid_widget_type_raises(self):
        with self.assertRaises(ValueError):
            WidgetEngine.validate_widgets_config([{"title": "bad", "type": "unknown"}])

    def test_load_config_validates_root_keys(self):
        bad = {"dashboard": {"widgets": []}}
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".json") as fh:
            json.dump(bad, fh)
            fh.flush()
            with self.assertRaises(ValueError):
                load_config(fh.name)

    def test_explicit_auth_and_token_status(self):
        config = CyberBackupConfig(
            host="example.local",
            port=443,
            api_version="2",
            username="u",
            password="p",
            client_id="cid",
            client_secret="sec",
            scope="scope:read",
        )
        client = AuthClientForTest(config)

        client.set_auth_credentials("user2", "pass2", "cid2", "sec2", "scope:new")
        payload = client.authenticate_explicit()
        self.assertTrue(payload["authenticated"])
        self.assertEqual(payload["token_type"], "Bearer")

        status = client.token_status()
        self.assertTrue(status["authenticated"])
        self.assertEqual(status["username"], "user2")
        self.assertEqual(status["scope"], "scope:new")
        self.assertGreater(status["seconds_left"], 0)

        token = client.get_token()
        self.assertTrue(token.startswith("abcdefghijkl"))


if __name__ == "__main__":
    unittest.main()
