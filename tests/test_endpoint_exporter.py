"""Tests for endpoint_exporter.py (stdlib unittest, no external deps).

Run from the project root:
    python -m unittest discover -s tests -v
"""

import json
import pathlib
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import endpoint_exporter as ee  # noqa: E402


SAMPLE_LINES = [
    "[2026-10-27 14:31:41,579]  WARN {org.apache.synapse.endpoints.EndpointContext} - Endpoint : UPC_CFT_EP with address http://localhost:8280/services/UPC_Gateway_DataService will be marked SUSPENDED as it failed ",
    "[2026-10-27 14:30:37,335]  WARN {org.apache.synapse.endpoints.EndpointContext} - Endpoint : UPC_CFT_EP with address http://localhost:8280/services/UPC_Gateway_DataService will be marked SUSPENDED as it failed ",
    "[2026-10-27 14:30:19,171]  WARN {org.apache.synapse.endpoints.EndpointContext} - Endpoint : DVNOK_CFT_EP with address http://localhost:8280/services/DVN_OK_DataService will be marked SUSPENDED as it failed ",
    "[2026-10-27 14:21:07,874]  WARN {org.apache.synapse.endpoints.EndpointContext} - Endpoint : DBZ_AnyWaySOAP2 with address https://anyc2b-p.zenit.ru:443/csp/awl/AWGW.WS.cls will be marked SUSPENDED as it failed ",
]

RESUME_LINE = (
    "[2026-10-27 14:35:00,000]  INFO {org.apache.synapse.endpoints.EndpointContext} - "
    "Endpoint : UPC_CFT_EP with address http://localhost:8280/services/UPC_Gateway_DataService "
    "will be marked ACTIVE as it has been suspended for 60000 ms"
)

# WSO2 APIM writes a "warn TID: ..." prefix in front of the same message.
APIM_LINE = (
    "warn TID: [-1234] [] [2026-10-28 12:47:05,986]  WARN "
    "{org.apache.synapse.endpoints.EndpointContext} - "
    "Endpoint : ISMG_W4_API--vv1_APIsandboxEndpoint with address "
    "https://monty.zenit.ru:8243/ismg/w4 will be marked SUSPENDED as it failed "
)

# Some APIM lines omit "with address"; note the double space before "will".
NO_ADDRESS_LINE = (
    "TID: [-1234] [] [2026-10-28 17:16:58,696]  WARN "
    "{org.apache.synapse.endpoints.EndpointContext} - "
    "Endpoint : RCP_BPA--vv2_APIproductionEndpoint  "
    "will be marked SUSPENDED as it failed"
)


def now_ns():
    return int(time.time() * 1_000_000_000)


class FakeLokiHandler(BaseHTTPRequestHandler):
    """Minimal Loki query_range API returning canned entries."""

    entries = []          # [(ts_ns, line)]
    resume_entries = []   # [(ts_ns, line)]
    apim_entries = []     # [(ts_ns, line)] for queries mentioning apimlogs
    fail_next = 0         # respond 500 that many times

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if parsed.path != "/loki/api/v1/query_range":
            self.send_error(404)
            return
        if FakeLokiHandler.fail_next > 0:
            FakeLokiHandler.fail_next -= 1
            self.send_error(500, "boom")
            return

        query = params.get("query", [""])[0]
        start = int(params.get("start", ["0"])[0])
        end = int(params.get("end", ["0"])[0])
        if "ACTIVE" in query:
            source = FakeLokiHandler.resume_entries
        elif "apimlogs" in query:
            source = FakeLokiHandler.apim_entries
        else:
            source = FakeLokiHandler.entries
        values = [[str(ts), line] for ts, line in source if start <= ts <= end]
        body = json.dumps(
            {
                "status": "success",
                "data": {
                    "resultType": "streams",
                    "result": [{"stream": {"job": "wso2logs-os"}, "values": values}],
                },
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeLoki:
    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeLokiHandler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"


def make_settings(**overrides):
    base = dict(
        loki_url="http://127.0.0.1:1",
        mode="window",
        window_seconds=60.0,
        poll_interval_seconds=60.0,
        history_hours=0.0,
        state_file="",
        metrics_file="",
    )
    base.update(overrides)
    return ee.Settings(**base)


class CapturingLokiClient:
    """Loki client stub: records query ranges and returns no entries."""

    def __init__(self):
        self.calls = []

    def query_range(self, logql, start_ns, end_ns):
        self.calls.append((logql, start_ns, end_ns))
        return []


class ParseTests(unittest.TestCase):
    def test_suspend_lines_are_parsed(self):
        store = ee.Store(make_settings())
        events = store.parse_events(
            [(now_ns(), line) for line in SAMPLE_LINES], "suspend"
        )
        self.assertEqual(len(events), 4)
        names = [event[1] for event in events]
        self.assertEqual(
            names, ["UPC_CFT_EP", "UPC_CFT_EP", "DVNOK_CFT_EP", "DBZ_AnyWaySOAP2"]
        )
        self.assertEqual(
            events[3][2], "https://anyc2b-p.zenit.ru:443/csp/awl/AWGW.WS.cls"
        )

    def test_unrelated_lines_are_ignored(self):
        store = ee.Store(make_settings())
        events = store.parse_events(
            [(now_ns(), "[2026-10-27 10:00:00,000] INFO something else entirely")],
            "suspend",
        )
        self.assertEqual(events, [])

    def test_resume_line_is_parsed(self):
        store = ee.Store(make_settings(mode="state"))
        events = store.parse_events([(now_ns(), RESUME_LINE)], "resume")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][1], "UPC_CFT_EP")
        self.assertEqual(events[0][3], "resume")

    def test_apim_line_is_parsed(self):
        store = ee.Store(make_settings())
        events = store.parse_events([(now_ns(), APIM_LINE)], "suspend")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][1], "ISMG_W4_API--vv1_APIsandboxEndpoint")
        self.assertEqual(events[0][2], "https://monty.zenit.ru:8243/ismg/w4")

    def test_line_without_address_is_parsed(self):
        store = ee.Store(make_settings())
        events = store.parse_events([(now_ns(), NO_ADDRESS_LINE)], "suspend")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][1], "RCP_BPA--vv2_APIproductionEndpoint")
        self.assertEqual(events[0][2], "")

    def test_endpoint_name_with_spaces_is_parsed(self):
        line = (
            "[2026-10-27 14:31:41,579]  WARN {x} - Endpoint : My Endpoint Name "
            "with address http://example.org/svc will be marked SUSPENDED as it failed"
        )
        store = ee.Store(make_settings())
        events = store.parse_events([(now_ns(), line)], "suspend")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][1], "My Endpoint Name")
        self.assertEqual(events[0][2], "http://example.org/svc")

    def test_resume_line_without_address_is_parsed(self):
        line = (
            "[2026-10-27 14:35:00,000]  INFO {x} - Endpoint : RCP_BPA--vv2_APIproductionEndpoint "
            "will be marked ACTIVE as it has been suspended for 60000 ms"
        )
        store = ee.Store(make_settings(mode="state"))
        events = store.parse_events([(now_ns(), line)], "resume")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][1], "RCP_BPA--vv2_APIproductionEndpoint")
        self.assertEqual(events[0][2], "")

    def test_missing_named_group_is_rejected(self):
        with self.assertRaises(ee.ConfigError):
            ee._check_regex(r"Endpoint : (\S+)", "suspend_regex")


class WindowModeTests(unittest.TestCase):
    def test_status_is_one_only_inside_window(self):
        store = ee.Store(make_settings())
        store.ensure_known_endpoints()
        ts = now_ns()
        events = store.parse_events([(ts, SAMPLE_LINES[0])], "suspend")
        store.reset_window()
        store.apply_events(events, in_window=True)
        metrics = store.render_metrics()
        self.assertIn(
            'wso2_endpoint_suspended{endpoint="UPC_CFT_EP",'
            'address="http://localhost:8280/services/UPC_Gateway_DataService"} 1',
            metrics,
        )

    def test_status_falls_back_to_zero_without_events(self):
        store = ee.Store(make_settings())
        store.ensure_known_endpoints()
        events = store.parse_events([(now_ns(), SAMPLE_LINES[2])], "suspend")
        store.reset_window()
        store.apply_events(events, in_window=True)
        self.assertIn('endpoint="DVNOK_CFT_EP"', store.render_metrics())
        # next window has no events -> gauge must be 0
        store.reset_window()
        store.apply_events([], in_window=True)
        self.assertIn(
            'wso2_endpoint_suspended{endpoint="DVNOK_CFT_EP",'
            'address="http://localhost:8280/services/DVN_OK_DataService"} 0',
            store.render_metrics(),
        )

    def test_known_endpoints_are_exported_with_zero(self):
        settings = make_settings(
            known_endpoints=[("UPC_CFT_EP", "http://localhost:8280/services/UPC_Gateway_DataService")]
        )
        store = ee.Store(settings)
        store.ensure_known_endpoints()
        metrics = store.render_metrics()
        self.assertIn('endpoint="UPC_CFT_EP"', metrics)
        self.assertIn("wso2_exporter_known_endpoints 1", metrics)

    def test_history_events_do_not_set_window_flag(self):
        store = ee.Store(make_settings())
        events = store.parse_events([(now_ns(), SAMPLE_LINES[0])], "suspend")
        store.reset_window()
        store.apply_events(events, in_window=False)
        self.assertIn(
            'wso2_endpoint_suspended{endpoint="UPC_CFT_EP",'
            'address="http://localhost:8280/services/UPC_Gateway_DataService"} 0',
            store.render_metrics(),
        )

    def test_duplicates_are_counted_once(self):
        store = ee.Store(make_settings())
        ts = now_ns()
        events = store.parse_events([(ts, SAMPLE_LINES[0]), (ts, SAMPLE_LINES[0])], "suspend")
        self.assertEqual(store.apply_events(events, in_window=True), 1)
        self.assertEqual(store.apply_events(events, in_window=True), 0)
        self.assertIn("wso2_endpoint_suspension_events_total{", store.render_metrics())
        self.assertRegex(
            store.render_metrics(),
            r'wso2_endpoint_suspension_events_total\{endpoint="UPC_CFT_EP",address="[^"]+"\} 1\n',
        )

    def test_window_status_expires_without_new_events(self):
        store = ee.Store(make_settings())
        ts = now_ns()
        store.apply_events(store.parse_events([(ts, SAMPLE_LINES[0])], "suspend"), in_window=True)
        self.assertIn(
            'wso2_endpoint_suspended{endpoint="UPC_CFT_EP",'
            'address="http://localhost:8280/services/UPC_Gateway_DataService"} 1',
            store.render_metrics(),
        )
        # simulate a prolonged Loki outage: no new poll, but time passes
        store.endpoints["UPC_CFT_EP"].window_last_event_ts -= 120
        self.assertIn(
            'wso2_endpoint_suspended{endpoint="UPC_CFT_EP",'
            'address="http://localhost:8280/services/UPC_Gateway_DataService"} 0',
            store.render_metrics(),
        )

    def test_event_inside_overlap_does_not_set_window_status(self):
        store = ee.Store(make_settings())  # window_seconds = 60
        old_ns = now_ns() - 90_000_000_000  # older than the window
        applied = store.apply_events(
            store.parse_events([(old_ns, SAMPLE_LINES[0])], "suspend"), in_window=True
        )
        self.assertEqual(applied, 1)  # still counted in events_total
        self.assertIn(
            'wso2_endpoint_suspended{endpoint="UPC_CFT_EP",'
            'address="http://localhost:8280/services/UPC_Gateway_DataService"} 0',
            store.render_metrics(),
        )


class StateModeTests(unittest.TestCase):
    def test_suspend_then_resume(self):
        store = ee.Store(make_settings(mode="state"))
        suspend = store.parse_events([(now_ns(), SAMPLE_LINES[0])], "suspend")
        store.apply_events(suspend, in_window=False)
        self.assertIn(
            'wso2_endpoint_suspended{endpoint="UPC_CFT_EP",'
            'address="http://localhost:8280/services/UPC_Gateway_DataService"} 1',
            store.render_metrics(),
        )
        resume = store.parse_events([(now_ns(), RESUME_LINE)], "resume")
        store.apply_events(resume, in_window=False)
        self.assertIn(
            'wso2_endpoint_suspended{endpoint="UPC_CFT_EP",'
            'address="http://localhost:8280/services/UPC_Gateway_DataService"} 0',
            store.render_metrics(),
        )

    def test_state_expires_by_ttl(self):
        store = ee.Store(make_settings(mode="state", state_ttl_seconds=3600.0))
        suspend = store.parse_events([(now_ns(), SAMPLE_LINES[0])], "suspend")
        store.apply_events(suspend, in_window=False)
        info = store.endpoints["UPC_CFT_EP"]
        info.last_suspended_ts -= 7200  # two hours ago
        self.assertIn(
            'wso2_endpoint_suspended{endpoint="UPC_CFT_EP",'
            'address="http://localhost:8280/services/UPC_Gateway_DataService"} 0',
            store.render_metrics(),
        )

    def test_reload_does_not_recount_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = str(pathlib.Path(tmp) / "state.json")
            settings = make_settings(mode="state", state_file=state_path)
            ts = now_ns()
            store = ee.Store(settings)
            events = store.parse_events([(ts, SAMPLE_LINES[0])], "suspend")
            self.assertEqual(store.apply_events(events, in_window=False), 1)
            store.save_state()

            restored = ee.Store(settings)
            restored.load_state()
            self.assertEqual(restored.endpoints["UPC_CFT_EP"].events_total, 1)
            # re-reading the same history after a restart must not count it twice
            self.assertEqual(
                restored.apply_events(
                    restored.parse_events([(ts, SAMPLE_LINES[0])], "suspend"),
                    in_window=False,
                ),
                0,
            )
            self.assertEqual(restored.endpoints["UPC_CFT_EP"].events_total, 1)


class RenderingTests(unittest.TestCase):
    def test_label_values_are_escaped(self):
        store = ee.Store(make_settings())
        store.apply_events([(now_ns(), 'a"b\\c', "x", "suspend")], in_window=True)
        metrics = store.render_metrics()
        self.assertIn('endpoint="a\\"b\\\\c"', metrics)

    def test_html_page_renders(self):
        store = ee.Store(make_settings())
        events = store.parse_events([(now_ns(), SAMPLE_LINES[0])], "suspend")
        store.apply_events(events, in_window=True)
        page = store.render_html()
        self.assertIn("UPC_CFT_EP", page)
        self.assertIn("SUSPENDED", page)

    def test_state_json_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = str(pathlib.Path(tmp) / "state.json")
            store = ee.Store(make_settings(state_file=state_path))
            events = store.parse_events([(now_ns(), SAMPLE_LINES[0])], "suspend")
            store.apply_events(events, in_window=True)
            store.save_state()
            restored = ee.Store(make_settings(state_file=state_path))
            restored.load_state()
            self.assertIn("UPC_CFT_EP", restored.endpoints)
            self.assertEqual(restored.endpoints["UPC_CFT_EP"].events_total, 1)


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        FakeLokiHandler.entries = []
        FakeLokiHandler.resume_entries = []
        FakeLokiHandler.apim_entries = []
        FakeLokiHandler.fail_next = 0
        self.loki = FakeLoki()
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.loki.stop()
        self.tmp.cleanup()

    def _settings(self, **overrides):
        base = dict(
            loki_url=self.loki.url,
            mode="window",
            window_seconds=60.0,
            history_hours=0.0,
            state_file=str(pathlib.Path(self.tmp.name) / "state.json"),
            metrics_file=str(pathlib.Path(self.tmp.name) / "metrics.prom"),
        )
        base.update(overrides)
        return ee.Settings(**base)

    def test_poll_builds_window_status(self):
        FakeLokiHandler.entries = [
            (now_ns() - 5_000_000_000, SAMPLE_LINES[0]),
            (now_ns() - 4_000_000_000, SAMPLE_LINES[2]),
        ]
        settings = self._settings()
        store = ee.Store(settings)
        exporter = ee.Exporter(settings, store, ee.LokiClient(settings))
        self.assertTrue(exporter.poll())
        metrics = store.render_metrics()
        self.assertIn('endpoint="UPC_CFT_EP",address="http://localhost:8280/services/UPC_Gateway_DataService"} 1', metrics)
        self.assertIn('endpoint="DVNOK_CFT_EP",address="http://localhost:8280/services/DVN_OK_DataService"} 1', metrics)
        self.assertIn("wso2_exporter_poll_success 1", metrics)
        # metrics snapshot is written to disk for debugging
        written = pathlib.Path(settings.metrics_file).read_text(encoding="utf-8")
        self.assertIn("wso2_endpoint_suspended", written)

    def test_poll_failure_keeps_last_snapshot(self):
        FakeLokiHandler.entries = [(now_ns(), SAMPLE_LINES[0])]
        settings = self._settings()
        store = ee.Store(settings)
        exporter = ee.Exporter(settings, store, ee.LokiClient(settings))
        self.assertTrue(exporter.poll())
        FakeLokiHandler.fail_next = 1
        self.assertFalse(exporter.poll())
        metrics = store.render_metrics()
        self.assertIn("wso2_exporter_poll_success 0", metrics)
        self.assertIn("wso2_exporter_loki_errors_total 1", metrics)
        # previous window data is still served
        self.assertIn('endpoint="UPC_CFT_EP",address="http://localhost:8280/services/UPC_Gateway_DataService"} 1', metrics)

    def test_multiple_queries_are_merged(self):
        FakeLokiHandler.entries = [(now_ns() - 3_000_000_000, SAMPLE_LINES[0])]
        FakeLokiHandler.apim_entries = [(now_ns() - 2_000_000_000, APIM_LINE)]
        settings = self._settings(
            loki_queries=[
                '{job="wso2logs-os",level="WARN"} |= "will be marked SUSPENDED"',
                '{job="apimlogs"} |= "will be marked SUSPENDED"',
            ],
        )
        store = ee.Store(settings)
        exporter = ee.Exporter(settings, store, ee.LokiClient(settings))
        self.assertTrue(exporter.poll())
        metrics = store.render_metrics()
        self.assertIn('endpoint="UPC_CFT_EP"', metrics)
        self.assertIn('endpoint="ISMG_W4_API--vv1_APIsandboxEndpoint"', metrics)
        self.assertIn("wso2_exporter_poll_success 1", metrics)

    def test_partial_query_failure_keeps_working_source(self):
        FakeLokiHandler.apim_entries = [(now_ns() - 2_000_000_000, APIM_LINE)]
        FakeLokiHandler.fail_next = 1  # the MI query fails, the APIM query succeeds
        settings = self._settings(
            loki_queries=[
                '{job="wso2logs-os",level="WARN"} |= "x"',
                '{job="apimlogs"} |= "x"',
            ],
        )
        store = ee.Store(settings)
        exporter = ee.Exporter(settings, store, ee.LokiClient(settings))
        self.assertFalse(exporter.poll())
        metrics = store.render_metrics()
        self.assertIn('endpoint="ISMG_W4_API--vv1_APIsandboxEndpoint"', metrics)
        self.assertIn("wso2_exporter_poll_success 0", metrics)
        self.assertIn("wso2_exporter_loki_errors_total 1", metrics)

    def test_state_mode_poll_handles_resume(self):
        FakeLokiHandler.entries = [(now_ns(), SAMPLE_LINES[0])]
        FakeLokiHandler.resume_entries = [(now_ns(), RESUME_LINE)]
        settings = self._settings(
            mode="state",
            loki_resume_query='{job="wso2logs-os"} |~ "ACTIVE"',
        )
        store = ee.Store(settings)
        exporter = ee.Exporter(settings, store, ee.LokiClient(settings))
        self.assertTrue(exporter.poll())
        self.assertIn(
            'wso2_endpoint_suspended{endpoint="UPC_CFT_EP",'
            'address="http://localhost:8280/services/UPC_Gateway_DataService"} 0',
            store.render_metrics(),
        )

    def test_history_priming_populates_inventory(self):
        FakeLokiHandler.entries = [(now_ns() - 3600 * 1_000_000_000, SAMPLE_LINES[3])]
        settings = self._settings(history_hours=24.0)
        store = ee.Store(settings)
        exporter = ee.Exporter(settings, store, ee.LokiClient(settings))
        exporter.prime_history()
        self.assertIn("DBZ_AnyWaySOAP2", store.endpoints)
        # priming must not set the current window flag
        self.assertIn('endpoint="DBZ_AnyWaySOAP2",address="https://anyc2b-p.zenit.ru:443/csp/awl/AWGW.WS.cls"} 0', store.render_metrics())

    def test_restart_priming_does_not_inflate_counter(self):
        FakeLokiHandler.entries = [(now_ns() - 3600 * 1_000_000_000, SAMPLE_LINES[0])]
        settings = self._settings(history_hours=24.0)
        store = ee.Store(settings)
        exporter = ee.Exporter(settings, store, ee.LokiClient(settings))
        exporter.prime_history()
        self.assertTrue(exporter.poll())
        self.assertEqual(store.endpoints["UPC_CFT_EP"].events_total, 1)

        # a restart re-reads the same history; the counter must not grow
        restored = ee.Store(settings)
        restored.load_state()
        exporter = ee.Exporter(settings, restored, ee.LokiClient(settings))
        exporter.prime_history()
        self.assertTrue(exporter.poll())
        self.assertEqual(restored.endpoints["UPC_CFT_EP"].events_total, 1)

    def test_poll_query_includes_overlap(self):
        settings = make_settings(window_seconds=60.0, window_overlap_seconds=15.0)
        store = ee.Store(settings)
        client = CapturingLokiClient()
        exporter = ee.Exporter(settings, store, client)
        self.assertTrue(exporter.poll())
        _query, start_ns, end_ns = client.calls[0]
        self.assertGreaterEqual((end_ns - start_ns) / 1e9, 74.9)

    def test_http_endpoints(self):
        FakeLokiHandler.entries = [(now_ns(), SAMPLE_LINES[0])]
        settings = self._settings()
        store = ee.Store(settings)
        exporter = ee.Exporter(settings, store, ee.LokiClient(settings))
        self.assertTrue(exporter.poll())

        handler = ee.make_handler(exporter)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics") as resp:
                body = resp.read().decode("utf-8")
                self.assertEqual(resp.status, 200)
                self.assertIn("text/plain", resp.headers["Content-Type"])
            self.assertIn("wso2_endpoint_suspended", body)

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as resp:
                self.assertIn("UPC_CFT_EP", resp.read().decode("utf-8"))

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/state.json") as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                self.assertIn("UPC_CFT_EP", payload["endpoints"])

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health") as resp:
                self.assertEqual(resp.status, 200)

            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/nope")
            self.assertEqual(ctx.exception.code, 404)
        finally:
            httpd.shutdown()
            httpd.server_close()


class ConfigTests(unittest.TestCase):
    def test_example_config_is_valid(self):
        example = pathlib.Path(__file__).resolve().parents[1] / "config.ini.example"
        settings = ee.load_config(str(example))
        self.assertEqual(settings.mode, "window")
        self.assertEqual(settings.listen_host, "127.0.0.1")
        self.assertTrue(settings.loki_query.startswith("{"))

    def test_bad_mode_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "config.ini"
            path.write_text("[exporter]\nmode = nonsense\n", encoding="utf-8")
            with self.assertRaises(ee.ConfigError):
                ee.load_config(str(path))

    def test_missing_named_group_is_rejected_in_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "config.ini"
            path.write_text(
                "[parse]\nsuspend_regex = Endpoint : (?P<name>\\S+)\n", encoding="utf-8"
            )
            with self.assertRaises(ee.ConfigError):
                ee.load_config(str(path))

    def test_invalid_log_level_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "config.ini"
            path.write_text("[exporter]\nlog_level = verbose\n", encoding="utf-8")
            with self.assertRaises(ee.ConfigError):
                ee.load_config(str(path))

    def test_extra_queries_are_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "config.ini"
            path.write_text(
                "[loki]\n"
                'query = {job="a"} |= "x"\n'
                "extra_queries =\n"
                '    {job="b"} |= "y"\n'
                '    {job="c"} |= "z"\n'
                "extra_resume_queries =\n"
                '    {job="b"} |~ "ACTIVE"\n',
                encoding="utf-8",
            )
            settings = ee.load_config(str(path))
            self.assertEqual(
                settings.suspend_queries(),
                ['{job="a"} |= "x"', '{job="b"} |= "y"', '{job="c"} |= "z"'],
            )
            self.assertEqual(
                settings.resume_queries(),
                ["", '{job="b"} |~ "ACTIVE"', ""],
            )

    def test_too_many_extra_resume_queries_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "config.ini"
            path.write_text(
                '[loki]\nquery = {job="a"} |= "x"\n'
                "extra_resume_queries =\n"
                '    {job="a"} |~ "ACTIVE"\n',
                encoding="utf-8",
            )
            with self.assertRaises(ee.ConfigError):
                ee.load_config(str(path))

    def test_malformed_state_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "state.json"
            path.write_text("[1, 2, 3]", encoding="utf-8")
            store = ee.Store(make_settings(state_file=str(path)))
            store.load_state()
            self.assertEqual(store.endpoints, {})


class OutputPathTests(unittest.TestCase):
    def test_missing_directory_is_reported_and_not_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "missing-dir" / "state.json"
            problem = ee._output_path_problem(str(target))
            self.assertIsNotNone(problem)
            self.assertIn("does not exist", problem)
            ee._atomic_write(str(target), "{}")
            self.assertFalse(target.parent.exists())
            self.assertFalse(target.exists())

    def test_existing_directory_is_writable(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "state.json"
            self.assertIsNone(ee._output_path_problem(str(target)))
            ee._atomic_write(str(target), "{}")
            self.assertEqual(target.read_text(encoding="utf-8"), "{}")
            self.assertFalse((pathlib.Path(tmp) / "state.json.tmp").exists())

    def test_empty_path_is_disabled(self):
        self.assertIsNone(ee._output_path_problem(""))


if __name__ == "__main__":
    unittest.main()
