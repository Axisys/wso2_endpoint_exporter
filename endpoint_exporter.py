#!/usr/bin/env python3
"""
wso2-endpoint-exporter
======================

Small, dependency-free Prometheus exporter that turns WSO2 Micro Integrator
endpoint-suspension log lines (collected in Grafana Loki) into an endpoint
status table for Grafana.

    Grafana Loki --(LogQL, every N seconds)--> endpoint_exporter.py
    endpoint_exporter.py --(/metrics)--> Prometheus --> Grafana dashboard

The program uses only the Python standard library (Python >= 3.9; target
platform is Debian 12 with a clean Python 3.11, no pip packages allowed).

HTTP endpoints of the built-in server (bound to 127.0.0.1 by default):

    /metrics     Prometheus text exposition format (scraped by Prometheus)
    /            human readable HTML status table
    /state.json  full internal state as JSON (debugging)
    /health      200 when the last Loki poll succeeded recently, else 503

See README.md for configuration, systemd deployment and Grafana setup.
"""

from __future__ import annotations

import argparse
import base64
import configparser
import dataclasses
import html
import json
import logging
import os
import re
import signal
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Sequence, Tuple

__version__ = "1.1.0"

LOG = logging.getLogger("wso2-endpoint-exporter")

# ---------------------------------------------------------------------------
# Default parsing rules for the WSO2 / Synapse endpoint log lines, e.g.:
#
#   [2026-10-27 14:31:41,579]  WARN {org.apache.synapse.endpoints.EndpointContext}
#   - Endpoint : UPC_CFT_EP with address http://localhost:8280/services/UPC_Gateway_DataService
#   will be marked SUSPENDED as it failed
# ---------------------------------------------------------------------------

DEFAULT_SUSPEND_REGEX = (
    r"Endpoint\s*:\s*(?P<endpoint>\S+)\s+with\s+address\s+(?P<address>\S+)\s+"
    r"will\s+be\s+marked\s+SUSPENDED"
)

# The exact "back to ACTIVE" wording differs between Synapse versions, so the
# default rule is intentionally loose: an endpoint line that mentions ACTIVE.
DEFAULT_RESUME_REGEX = (
    r"Endpoint\s*:\s*(?P<endpoint>\S+)\s+with\s+address\s+(?P<address>\S+)\s+"
    r"[^\n]*?\bACTIVE\b"
)

METRIC_NAME_RE = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*\Z")

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def _int_or(value: object, default: int) -> int:
    """Best-effort int conversion for values read back from state.json."""
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


class ConfigError(RuntimeError):
    """Raised for invalid or unreadable configuration."""


class LokiError(RuntimeError):
    """Raised when the Loki query API call fails."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Settings:
    # [loki]
    loki_url: str = "http://127.0.0.1:3100"
    loki_query: str = (
        '{job="wso2logs-os",level="WARN"} '
        '|= "will be marked SUSPENDED as it failed"'
    )
    loki_resume_query: str = ""  # only used in mode = state
    loki_limit: int = 5000
    loki_timeout_seconds: float = 30.0
    loki_verify_tls: bool = False
    loki_ca_bundle: str = ""
    loki_username: str = ""
    loki_password: str = ""
    loki_bearer_token: str = ""
    loki_extra_headers: Dict[str, str] = dataclasses.field(default_factory=dict)

    # [parse]
    suspend_regex: str = DEFAULT_SUSPEND_REGEX
    resume_regex: str = DEFAULT_RESUME_REGEX

    # [exporter]
    listen_host: str = "127.0.0.1"
    listen_port: int = 9187
    poll_interval_seconds: float = 60.0
    window_seconds: float = 60.0
    # Extra look-back added to every query so that clock drift or a slow poll
    # cannot fall into a gap between two polling windows.
    window_overlap_seconds: float = 10.0
    mode: str = "window"  # window | state
    state_ttl_seconds: float = 86400.0
    history_hours: float = 168.0
    state_file: str = "state.json"
    metrics_file: str = "metrics.prom"
    known_endpoints: List[Tuple[str, str]] = dataclasses.field(default_factory=list)
    metric_suspended: str = "wso2_endpoint_suspended"
    metric_last_suspended_timestamp_seconds: str = (
        "wso2_endpoint_last_suspended_timestamp_seconds"
    )
    metric_events_total: str = "wso2_endpoint_suspension_events_total"
    log_level: str = "INFO"


def _parse_bool(raw: str, key: str) -> bool:
    value = raw.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"option {key!r} must be a boolean, got {raw!r}")


def _parse_endpoint_list(raw: str) -> List[Tuple[str, str]]:
    """Parse 'NAME,NAME2=address,...' into a list of (name, address) tuples."""
    result: List[Tuple[str, str]] = []
    for chunk in raw.replace("\n", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" in chunk:
            name, address = chunk.split("=", 1)
            result.append((name.strip(), address.strip()))
        else:
            result.append((chunk, ""))
    return result


def _load_endpoints_file(path: str) -> List[Tuple[str, str]]:
    """Read a CSV-ish file: one endpoint per line, 'endpoint[,address]'."""
    result: List[Tuple[str, str]] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for lineno, raw in enumerate(handle, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [part.strip() for part in line.split(",")]
                if len(parts) == 1 or not parts[1]:
                    result.append((parts[0], ""))
                else:
                    result.append((parts[0], parts[1]))
    except OSError as exc:
        raise ConfigError(f"cannot read known_endpoints_file {path!r}: {exc}") from exc
    return result


def _parse_extra_headers(raw: str) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ConfigError(
                f"loki extra_headers entries must look like 'Name: value', got {line!r}"
            )
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def load_config(path: str) -> Settings:
    settings = Settings()
    if not os.path.isfile(path):
        raise ConfigError(f"config file not found: {path}")

    parser = configparser.ConfigParser(interpolation=None)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            parser.read_file(handle)
    except (OSError, UnicodeDecodeError, configparser.Error) as exc:
        raise ConfigError(f"cannot read config file {path!r}: {exc}") from exc

    def get(section: str, key: str, default: str) -> str:
        if parser.has_option(section, key):
            return parser.get(section, key)
        return default

    def get_int(section: str, key: str, default: int) -> int:
        try:
            return parser.getint(section, key) if parser.has_option(section, key) else default
        except ValueError as exc:
            raise ConfigError(f"[{section}] {key} must be an integer") from exc

    def get_float(section: str, key: str, default: float) -> float:
        try:
            return (
                parser.getfloat(section, key) if parser.has_option(section, key) else default
            )
        except ValueError as exc:
            raise ConfigError(f"[{section}] {key} must be a number") from exc

    def get_bool(section: str, key: str, default: bool) -> bool:
        if not parser.has_option(section, key):
            return default
        return _parse_bool(parser.get(section, key), f"[{section}] {key}")

    # -- [loki] --
    settings.loki_url = get("loki", "url", settings.loki_url).strip()
    settings.loki_query = get("loki", "query", settings.loki_query).strip()
    settings.loki_resume_query = get(
        "loki", "resume_query", settings.loki_resume_query
    ).strip()
    settings.loki_limit = get_int("loki", "limit", settings.loki_limit)
    settings.loki_timeout_seconds = get_float(
        "loki", "timeout_seconds", settings.loki_timeout_seconds
    )
    settings.loki_verify_tls = get_bool("loki", "verify_tls", settings.loki_verify_tls)
    settings.loki_ca_bundle = get("loki", "ca_bundle", settings.loki_ca_bundle).strip()
    settings.loki_username = get("loki", "username", settings.loki_username).strip()
    settings.loki_password = get("loki", "password", settings.loki_password)
    settings.loki_bearer_token = get(
        "loki", "bearer_token", settings.loki_bearer_token
    ).strip()
    settings.loki_extra_headers = _parse_extra_headers(
        get("loki", "extra_headers", "")
    )

    # -- [parse] --
    settings.suspend_regex = get("parse", "suspend_regex", settings.suspend_regex).strip()
    settings.resume_regex = get("parse", "resume_regex", settings.resume_regex).strip()

    # -- [exporter] --
    settings.listen_host = get("exporter", "listen_host", settings.listen_host).strip()
    settings.listen_port = get_int("exporter", "listen_port", settings.listen_port)
    settings.poll_interval_seconds = get_float(
        "exporter", "poll_interval_seconds", settings.poll_interval_seconds
    )
    settings.window_seconds = get_float(
        "exporter", "window_seconds", settings.window_seconds
    )
    settings.window_overlap_seconds = get_float(
        "exporter", "window_overlap_seconds", settings.window_overlap_seconds
    )
    settings.mode = get("exporter", "mode", settings.mode).strip().lower()
    settings.state_ttl_seconds = get_float(
        "exporter", "state_ttl_seconds", settings.state_ttl_seconds
    )
    settings.history_hours = get_float(
        "exporter", "history_hours", settings.history_hours
    )
    settings.state_file = get("exporter", "state_file", settings.state_file).strip()
    settings.metrics_file = get("exporter", "metrics_file", settings.metrics_file).strip()
    settings.metric_suspended = get(
        "exporter", "metric_suspended", settings.metric_suspended
    ).strip()
    settings.metric_last_suspended_timestamp_seconds = get(
        "exporter",
        "metric_last_suspended_timestamp_seconds",
        settings.metric_last_suspended_timestamp_seconds,
    ).strip()
    settings.metric_events_total = get(
        "exporter", "metric_events_total", settings.metric_events_total
    ).strip()
    settings.log_level = get("exporter", "log_level", settings.log_level).strip().upper()

    endpoints = _parse_endpoint_list(get("exporter", "known_endpoints", ""))
    endpoints_file = get("exporter", "known_endpoints_file", "").strip()
    if endpoints_file:
        endpoints.extend(_load_endpoints_file(endpoints_file))
    seen_names = set()
    for name, _address in endpoints:
        if name in seen_names:
            raise ConfigError(f"endpoint {name!r} listed twice in known_endpoints")
        seen_names.add(name)
    settings.known_endpoints = endpoints

    # -- validation --
    if not settings.loki_url.startswith(("http://", "https://")):
        raise ConfigError("[loki] url must start with http:// or https://")
    if not settings.loki_query:
        raise ConfigError("[loki] query must not be empty")
    if settings.loki_limit <= 0:
        raise ConfigError("[loki] limit must be positive")
    if settings.loki_timeout_seconds <= 0:
        raise ConfigError("[loki] timeout_seconds must be positive")
    if settings.listen_port <= 0 or settings.listen_port > 65535:
        raise ConfigError("[exporter] listen_port must be within 1..65535")
    if settings.poll_interval_seconds <= 0:
        raise ConfigError("[exporter] poll_interval_seconds must be positive")
    if settings.window_seconds <= 0:
        raise ConfigError("[exporter] window_seconds must be positive")
    if settings.window_overlap_seconds < 0:
        raise ConfigError("[exporter] window_overlap_seconds must be >= 0")
    if settings.mode not in ("window", "state"):
        raise ConfigError("[exporter] mode must be 'window' or 'state'")
    if settings.log_level not in LOG_LEVELS:
        raise ConfigError(
            "[exporter] log_level must be one of " + ", ".join(LOG_LEVELS)
        )
    if settings.mode == "state" and not settings.loki_resume_query:
        LOG.warning(
            "mode=state but [loki] resume_query is empty: endpoints will only leave "
            "the SUSPENDED state through state_ttl_seconds (%ss)",
            settings.state_ttl_seconds,
        )
    for key, name in (
        ("metric_suspended", settings.metric_suspended),
        ("metric_last_suspended_timestamp_seconds", settings.metric_last_suspended_timestamp_seconds),
        ("metric_events_total", settings.metric_events_total),
    ):
        if not METRIC_NAME_RE.match(name):
            raise ConfigError(f"[exporter] {key} is not a valid metric name: {name!r}")
    _check_regex(settings.suspend_regex, "suspend_regex")
    _check_regex(settings.resume_regex, "resume_regex")
    return settings


def _check_regex(pattern: str, key: str) -> None:
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ConfigError(f"[parse] {key} is not a valid regex: {exc}") from exc
    if "endpoint" not in compiled.groupindex:
        raise ConfigError(f"[parse] {key} must define a named group (?P<endpoint>...)")


# ---------------------------------------------------------------------------
# Loki client
# ---------------------------------------------------------------------------


class LokiClient:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._ssl_context = self._build_ssl_context()

    def _build_ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self.settings.loki_url.startswith("https://"):
            return None
        context = ssl.create_default_context()
        if self.settings.loki_ca_bundle:
            try:
                context.load_verify_locations(self.settings.loki_ca_bundle)
            except OSError as exc:
                raise ConfigError(f"[loki] cannot load ca_bundle: {exc}") from exc
        if not self.settings.loki_verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def query_range(self, logql: str, start_ns: int, end_ns: int) -> List[Tuple[int, str]]:
        """Return [(timestamp_ns, line), ...] matching *logql* in [start_ns, end_ns]."""
        params = urllib.parse.urlencode(
            {
                "query": logql,
                "start": start_ns,
                "end": end_ns,
                "limit": self.settings.loki_limit,
                "direction": "backward",
            }
        )
        url = self.settings.loki_url.rstrip("/") + "/loki/api/v1/query_range?" + params

        headers = {"Accept": "application/json"}
        headers.update(self.settings.loki_extra_headers)
        if self.settings.loki_bearer_token:
            headers["Authorization"] = "Bearer " + self.settings.loki_bearer_token
        elif self.settings.loki_username:
            token = base64.b64encode(
                f"{self.settings.loki_username}:{self.settings.loki_password}".encode("utf-8")
            ).decode("ascii")
            headers["Authorization"] = "Basic " + token

        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.settings.loki_timeout_seconds,
                context=self._ssl_context,
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")[:300]
            except Exception:  # noqa: BLE001 - best effort diagnostics only
                pass
            raise LokiError(f"Loki returned HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise LokiError(f"cannot reach Loki at {self.settings.loki_url}: {exc.reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise LokiError(f"Loki request failed: {exc}") from exc
        except ValueError as exc:
            raise LokiError(f"Loki returned invalid JSON: {exc}") from exc

        return self._extract_entries(payload)

    @staticmethod
    def _extract_entries(payload: dict) -> List[Tuple[int, str]]:
        data = payload.get("data") or {}
        result_type = data.get("resultType")
        if result_type not in (None, "streams"):
            raise LokiError(
                f"unsupported Loki resultType {result_type!r}; the LogQL query must "
                "return raw log streams, not an aggregation"
            )
        entries: List[Tuple[int, str]] = []
        for stream in data.get("result") or []:
            for value in stream.get("values") or []:
                try:
                    ts_ns = int(value[0])
                    line = value[1]
                except (TypeError, ValueError, IndexError) as exc:
                    raise LokiError(f"unexpected Loki entry: {value!r}") from exc
                entries.append((ts_ns, line))
        entries.sort(key=lambda item: item[0])
        return entries


# ---------------------------------------------------------------------------
# State store + metric rendering
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class EndpointInfo:
    name: str
    address: str = ""
    first_seen_ts: int = 0  # unix seconds
    last_suspended_ts: int = 0  # unix seconds, 0 = never seen
    last_resumed_ts: int = 0  # unix seconds, 0 = never seen
    events_total: int = 0
    suspended: bool = False  # state mode: last event was "SUSPENDED"
    window_suspended: bool = False  # window mode: event seen in the current window
    # Timestamps (unix nanoseconds) of the newest event of each kind. They
    # deduplicate repeated sightings of the same log line across polls,
    # restarts and overlapping query windows, and are persisted in state.json.
    last_suspend_ns: int = 0
    last_resume_ns: int = 0
    # Wall-clock time (unix seconds) of the newest suspension event seen inside
    # the current window; lets the window gauge age out when Loki is unreachable.
    window_last_event_ts: int = 0


def escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class Store:
    """Thread-safe state: endpoint inventory + rendering of all output."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.endpoints: Dict[str, EndpointInfo] = {}
        self.stats: Dict[str, float] = {
            "poll_success": 0.0,
            "last_poll_ts": 0.0,
            "last_success_ts": 0.0,
            "last_poll_duration_seconds": 0.0,
            "loki_errors_total": 0.0,
        }
        self._lock = threading.Lock()
        self._suspend_re = re.compile(settings.suspend_regex)
        self._resume_re = re.compile(settings.resume_regex)

    # -- inventory ---------------------------------------------------------

    def ensure_known_endpoints(self) -> None:
        with self._lock:
            for name, address in self.settings.known_endpoints:
                info = self.endpoints.setdefault(name, EndpointInfo(name))
                if address and not info.address:
                    info.address = address

    # -- event ingestion ---------------------------------------------------

    def reset_window(self) -> None:
        with self._lock:
            for info in self.endpoints.values():
                info.window_suspended = False
                info.window_last_event_ts = 0

    def expire_states(self) -> None:
        ttl = self.settings.state_ttl_seconds
        if ttl <= 0:
            return
        now = int(time.time())
        with self._lock:
            for info in self.endpoints.values():
                if info.suspended and now - info.last_suspended_ts > ttl:
                    info.suspended = False

    def parse_events(
        self, entries: Sequence[Tuple[int, str]], kind: str
    ) -> List[Tuple[int, str, str, str]]:
        """Turn raw log entries into (ts_ns, endpoint, address, kind) tuples."""
        regex = self._suspend_re if kind == "suspend" else self._resume_re
        events: List[Tuple[int, str, str, str]] = []
        for ts_ns, line in entries:
            match = regex.search(line)
            if not match:
                continue
            groups = match.groupdict()
            endpoint = (groups.get("endpoint") or "").strip()
            address = (groups.get("address") or "").strip()
            if endpoint:
                events.append((ts_ns, endpoint, address, kind))
        return events

    def apply_events(self, events: Sequence[Tuple[int, str, str, str]], in_window: bool) -> int:
        """Apply parsed events; returns the number of *new* (non-duplicate) events.

        Events must arrive sorted by timestamp. Duplicates are detected per
        endpoint and kind by the newest timestamp already applied, so the
        counter is not inflated by re-reading the same history after a restart.
        """
        now_wall = time.time()
        now_s = int(now_wall)
        now_ns = int(now_wall * 1_000_000_000)
        window_ns = int(self.settings.window_seconds * 1_000_000_000)
        new_events = 0
        with self._lock:
            for ts_ns, name, address, kind in events:
                info = self.endpoints.setdefault(name, EndpointInfo(name))
                if not info.first_seen_ts:
                    info.first_seen_ts = now_s
                if address and address != info.address:
                    info.address = address

                if kind == "suspend":
                    if ts_ns > info.last_suspend_ns:
                        info.last_suspend_ns = ts_ns
                        info.events_total += 1
                        new_events += 1
                        info.last_suspended_ts = max(
                            info.last_suspended_ts, ts_ns // 1_000_000_000
                        )
                        info.suspended = True
                    # The window flag is refreshed by every sighting inside the
                    # window, including duplicates re-read from Loki, but only
                    # for events that are actually young enough to belong to it
                    # (the query also covers the overlap before the window).
                    if in_window and now_ns - ts_ns <= window_ns:
                        info.window_suspended = True
                        info.window_last_event_ts = max(
                            info.window_last_event_ts, ts_ns // 1_000_000_000
                        )
                else:
                    if ts_ns > info.last_resume_ns:
                        info.last_resume_ns = ts_ns
                        new_events += 1
                        info.last_resumed_ts = max(
                            info.last_resumed_ts, ts_ns // 1_000_000_000
                        )
                        info.suspended = False
        return new_events

    # -- persistence -------------------------------------------------------

    def load_state(self) -> None:
        path = self.settings.state_file
        if not path or not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as exc:
            LOG.warning("cannot read state file %s: %s", path, exc)
            return
        if not isinstance(data, dict):
            LOG.warning("ignoring state file %s: expected a JSON object", path)
            return
        stored = data.get("endpoints")
        if not isinstance(stored, dict):
            LOG.warning("ignoring state file %s: 'endpoints' is not an object", path)
            return
        with self._lock:
            for name, raw in stored.items():
                if not isinstance(raw, dict):
                    continue
                info = self.endpoints.setdefault(name, EndpointInfo(name))
                address = raw.get("address")
                if isinstance(address, str) and address:
                    info.address = address
                info.first_seen_ts = _int_or(raw.get("first_seen_ts"), info.first_seen_ts)
                info.last_suspended_ts = _int_or(
                    raw.get("last_suspended_ts"), info.last_suspended_ts
                )
                info.last_resumed_ts = _int_or(
                    raw.get("last_resumed_ts"), info.last_resumed_ts
                )
                info.events_total = _int_or(raw.get("events_total"), info.events_total)
                info.suspended = bool(raw.get("suspended", info.suspended))
                # Older state files have no nanosecond fields; fall back to the
                # stored second-resolution timestamps so a restart does not
                # immediately recount the whole history again.
                info.last_suspend_ns = _int_or(
                    raw.get("last_suspend_ns"),
                    info.last_suspended_ts * 1_000_000_000,
                )
                info.last_resume_ns = _int_or(
                    raw.get("last_resume_ns"),
                    info.last_resumed_ts * 1_000_000_000,
                )
        LOG.info("loaded state for %d endpoint(s) from %s", len(self.endpoints), path)

    def save_state(self) -> None:
        path = self.settings.state_file
        if not path:
            return
        payload = self.render_state_json()
        _atomic_write(path, payload)

    def write_metrics_file(self) -> None:
        path = self.settings.metrics_file
        if not path:
            return
        _atomic_write(path, self.render_metrics())

    # -- rendering ---------------------------------------------------------

    def _suspended_now(self, info: EndpointInfo, now: int) -> bool:
        if self.settings.mode == "state":
            if not info.suspended:
                return False
            ttl = self.settings.state_ttl_seconds
            return ttl <= 0 or now - info.last_suspended_ts <= ttl
        # window mode: age the flag out on its own, so a prolonged Loki outage
        # cannot keep an old suspension displayed as if it were current.
        if not info.window_suspended:
            return False
        return (now - info.window_last_event_ts) <= self.settings.window_seconds

    def render_metrics(self) -> str:
        now = int(time.time())
        with self._lock:
            rows = sorted(self.endpoints.items())
            suspended_flags = {name: self._suspended_now(info, now) for name, info in rows}
            snapshot = [
                (name, info.address, info.last_suspended_ts, info.events_total)
                for name, info in rows
            ]
            stats = dict(self.stats)

        m_susp = self.settings.metric_suspended
        m_ts = self.settings.metric_last_suspended_timestamp_seconds
        m_ev = self.settings.metric_events_total

        out: List[str] = []
        out.append(
            f"# HELP {m_susp} 1 when the WSO2 endpoint is treated as SUSPENDED "
            f"(mode={self.settings.mode}, see exporter docs), 0 otherwise."
        )
        out.append(f"# TYPE {m_susp} gauge")
        for name, address, _last_ts, _total in snapshot:
            value = 1 if suspended_flags[name] else 0
            out.append(f'{m_susp}{{endpoint="{escape_label(name)}",address="{escape_label(address)}"}} {value}')

        out.append(
            f"# HELP {m_ts} Unix timestamp of the last 'marked SUSPENDED' log event "
            "for this endpoint; 0 if it has never been observed."
        )
        out.append(f"# TYPE {m_ts} gauge")
        for name, address, last_ts, _total in snapshot:
            out.append(f'{m_ts}{{endpoint="{escape_label(name)}",address="{escape_label(address)}"}} {int(last_ts)}')

        out.append(
            f"# HELP {m_ev} Number of 'marked SUSPENDED' log events observed for this "
            "endpoint since the exporter state was created."
        )
        out.append(f"# TYPE {m_ev} counter")
        for name, address, _last_ts, total in snapshot:
            out.append(f'{m_ev}{{endpoint="{escape_label(name)}",address="{escape_label(address)}"}} {int(total)}')

        out.append("# HELP wso2_exporter_poll_success 1 when the last Loki poll succeeded, 0 otherwise.")
        out.append("# TYPE wso2_exporter_poll_success gauge")
        out.append(f"wso2_exporter_poll_success {int(stats['poll_success'])}")
        out.append("# HELP wso2_exporter_last_poll_timestamp_seconds Unix time of the last Loki poll attempt.")
        out.append("# TYPE wso2_exporter_last_poll_timestamp_seconds gauge")
        out.append(f"wso2_exporter_last_poll_timestamp_seconds {int(stats['last_poll_ts'])}")
        out.append("# HELP wso2_exporter_last_success_timestamp_seconds Unix time of the last successful Loki poll.")
        out.append("# TYPE wso2_exporter_last_success_timestamp_seconds gauge")
        out.append(f"wso2_exporter_last_success_timestamp_seconds {int(stats['last_success_ts'])}")
        out.append("# HELP wso2_exporter_last_poll_duration_seconds Duration of the last Loki poll in seconds.")
        out.append("# TYPE wso2_exporter_last_poll_duration_seconds gauge")
        out.append(f"wso2_exporter_last_poll_duration_seconds {stats['last_poll_duration_seconds']:.3f}")
        out.append("# HELP wso2_exporter_loki_errors_total Total number of failed Loki polls.")
        out.append("# TYPE wso2_exporter_loki_errors_total counter")
        out.append(f"wso2_exporter_loki_errors_total {int(stats['loki_errors_total'])}")
        out.append("# HELP wso2_exporter_known_endpoints Number of endpoints currently tracked.")
        out.append("# TYPE wso2_exporter_known_endpoints gauge")
        out.append(f"wso2_exporter_known_endpoints {len(snapshot)}")
        out.append("# HELP wso2_exporter_window_seconds Lookback window used for the status gauge.")
        out.append("# TYPE wso2_exporter_window_seconds gauge")
        out.append(f"wso2_exporter_window_seconds {self.settings.window_seconds:g}")
        out.append("# HELP wso2_exporter_build_info Build information of the exporter.")
        out.append("# TYPE wso2_exporter_build_info gauge")
        out.append(f'wso2_exporter_build_info{{version="{__version__}"}} 1')
        return "\n".join(out) + "\n"

    def render_state_json(self) -> str:
        now = int(time.time())
        with self._lock:
            payload = {
                "generated_at": int(time.time()),
                "mode": self.settings.mode,
                "window_seconds": self.settings.window_seconds,
                "stats": dict(self.stats),
                "endpoints": {
                    name: {
                        "address": info.address,
                        "suspended": self._suspended_now(info, now),
                        "last_suspended_ts": info.last_suspended_ts,
                        "last_resumed_ts": info.last_resumed_ts,
                        "first_seen_ts": info.first_seen_ts,
                        "events_total": info.events_total,
                        "last_suspend_ns": info.last_suspend_ns,
                        "last_resume_ns": info.last_resume_ns,
                    }
                    for name, info in sorted(self.endpoints.items())
                },
            }
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"

    def render_html(self) -> str:
        now = int(time.time())
        with self._lock:
            rows = sorted(self.endpoints.items())
            snapshot = [
                (name, info.address, self._suspended_now(info, now), info.last_suspended_ts, info.events_total)
                for name, info in rows
            ]
            stats = dict(self.stats)

        def fmt_ts(ts: int) -> str:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)) + " UTC" if ts else "-"

        body_rows = []
        for name, address, suspended, last_ts, total in snapshot:
            status = (
                '<td class="suspended">SUSPENDED</td>'
                if suspended
                else '<td class="ok">ACTIVE</td>'
            )
            body_rows.append(
                "<tr>"
                f"<td>{html.escape(name)}</td>"
                f"<td class='addr'>{html.escape(address)}</td>"
                f"{status}"
                f"<td>{fmt_ts(last_ts)}</td>"
                f"<td>{total}</td>"
                "</tr>"
            )
        rows_html = "\n".join(body_rows) or "<tr><td colspan='5'>no endpoints tracked yet</td></tr>"
        poll_ok = bool(stats["poll_success"])
        poll_label = "OK" if poll_ok else "FAILED"

        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="60">
<title>WSO2 endpoint status</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2em; color: #222; }}
 table {{ border-collapse: collapse; width: 100%; }}
 th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: 14px; }}
 th {{ background: #f2f2f2; }}
 td.suspended {{ background: #ffd6d6; color: #a00; font-weight: bold; }}
 td.ok {{ background: #e6ffe6; color: #060; }}
 td.addr {{ color: #666; font-size: 12px; }}
 .meta {{ color: #555; }}
</style>
</head>
<body>
<h1>WSO2 Micro Integrator &mdash; endpoint status</h1>
<p class="meta">
 Mode: <b>{html.escape(self.settings.mode)}</b> &middot;
 Window: <b>{self.settings.window_seconds:g}s</b> &middot;
 Last poll: <b>{fmt_ts(int(stats['last_poll_ts']))}</b> ({poll_label}) &middot;
 Endpoints tracked: <b>{len(snapshot)}</b>
</p>
<table>
<thead><tr><th>Endpoint</th><th>Address</th><th>Status</th><th>Last SUSPENDED</th><th>Events</th></tr></thead>
<tbody>
{rows_html}
</tbody>
</table>
</body>
</html>
"""

    def is_healthy(self) -> bool:
        last_success = self.stats["last_success_ts"]
        if not last_success:
            return False
        max_age = max(self.settings.poll_interval_seconds * 3, 180.0)
        return (time.time() - last_success) <= max_age


def _atomic_write(path: str, data: str) -> None:
    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(data)
        os.replace(tmp_path, path)
    except OSError as exc:
        LOG.error("cannot write %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Exporter orchestration
# ---------------------------------------------------------------------------


class Exporter:
    def __init__(self, settings: Settings, store: Store, client: LokiClient):
        self.settings = settings
        self.store = store
        self.client = client

    def _warn_if_truncated(self, entries: Sequence[Tuple[int, str]], what: str) -> None:
        if len(entries) >= self.settings.loki_limit:
            LOG.warning(
                "%s: Loki returned %d entries, the query limit is %d - results may be "
                "truncated, consider raising [loki] limit",
                what,
                len(entries),
                self.settings.loki_limit,
            )

    def prime_history(self) -> None:
        """Fill endpoint inventory and counters from older log data at startup."""
        if self.settings.history_hours <= 0:
            return
        end_ns = int(time.time() * 1_000_000_000)
        start_ns = end_ns - int(self.settings.history_hours * 3600 * 1_000_000_000)
        try:
            entries = self.client.query_range(self.settings.loki_query, start_ns, end_ns)
        except LokiError as exc:
            LOG.warning("history priming skipped: %s", exc)
            return
        self._warn_if_truncated(entries, "history priming")
        events = self.store.parse_events(entries, "suspend")
        if self.settings.mode == "state" and self.settings.loki_resume_query:
            try:
                resume_entries = self.client.query_range(
                    self.settings.loki_resume_query, start_ns, end_ns
                )
                self._warn_if_truncated(resume_entries, "history priming (resume)")
                events += self.store.parse_events(resume_entries, "resume")
            except LokiError as exc:
                LOG.warning("history priming (resume) skipped: %s", exc)
        # History must not influence the current window status.
        events.sort(key=lambda event: event[0])
        new_events = self.store.apply_events(events, in_window=False)
        LOG.info(
            "history priming: %d log line(s), %d endpoint event(s) over %.1f h",
            len(entries),
            new_events,
            self.settings.history_hours,
        )

    def poll(self) -> bool:
        started = time.time()
        end_ns = int(time.time() * 1_000_000_000)
        lookback_seconds = self.settings.window_seconds + max(
            0.0, self.settings.window_overlap_seconds
        )
        start_ns = end_ns - int(lookback_seconds * 1_000_000_000)

        try:
            entries = self.client.query_range(self.settings.loki_query, start_ns, end_ns)
            resume_entries: List[Tuple[int, str]] = []
            if self.settings.mode == "state" and self.settings.loki_resume_query:
                resume_entries = self.client.query_range(
                    self.settings.loki_resume_query, start_ns, end_ns
                )
        except LokiError as exc:
            self.store.stats["loki_errors_total"] += 1
            self.store.stats["poll_success"] = 0
            self.store.stats["last_poll_ts"] = time.time()
            self.store.stats["last_poll_duration_seconds"] = time.time() - started
            LOG.error("Loki poll failed: %s", exc)
            return False

        if self.settings.mode == "window":
            self.store.reset_window()
        else:
            self.store.expire_states()

        events = self.store.parse_events(entries, "suspend")
        if resume_entries:
            events += self.store.parse_events(resume_entries, "resume")
        events.sort(key=lambda event: event[0])
        new_events = self.store.apply_events(
            events, in_window=(self.settings.mode == "window")
        )

        self._warn_if_truncated(entries, "poll")
        self._warn_if_truncated(resume_entries, "poll (resume)")

        self.store.stats["poll_success"] = 1
        self.store.stats["last_poll_ts"] = time.time()
        self.store.stats["last_success_ts"] = time.time()
        self.store.stats["last_poll_duration_seconds"] = time.time() - started
        self.store.save_state()
        self.store.write_metrics_file()
        LOG.info(
            "poll ok: %d log line(s), %d matched event(s) (%d new), %d endpoint(s) tracked",
            len(entries),
            len(events),
            new_events,
            len(self.store.endpoints),
        )
        return True


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------


def make_handler(exporter: Exporter):
    store = exporter.store

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "wso2-endpoint-exporter/" + __version__

        def log_message(self, fmt, *args):  # route HTTP access logging to LOG
            LOG.debug("http: " + fmt, *args)

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - name required by BaseHTTPRequestHandler
            path = urllib.parse.urlparse(self.path).path
            if path == "/metrics":
                body = store.render_metrics().encode("utf-8")
                self._send(200, body, "text/plain; version=0.0.4; charset=utf-8")
            elif path in ("/", "/index.html"):
                body = store.render_html().encode("utf-8")
                self._send(200, body, "text/html; charset=utf-8")
            elif path == "/state.json":
                body = store.render_state_json().encode("utf-8")
                self._send(200, body, "application/json; charset=utf-8")
            elif path == "/health":
                healthy = store.is_healthy()
                payload = {
                    "status": "ok" if healthy else "degraded",
                    "last_poll_ts": int(store.stats["last_poll_ts"]),
                    "last_success_ts": int(store.stats["last_success_ts"]),
                    "endpoints": len(store.endpoints),
                }
                body = (json.dumps(payload) + "\n").encode("utf-8")
                self._send(200 if healthy else 503, body, "application/json; charset=utf-8")
            else:
                self._send(404, b"404 not found\n", "text/plain; charset=utf-8")

    return Handler


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_server(settings: Settings, exporter: Exporter) -> int:
    handler = make_handler(exporter)
    try:
        httpd = ThreadingHTTPServer((settings.listen_host, settings.listen_port), handler)
    except OSError as exc:
        LOG.error(
            "cannot listen on %s:%s: %s", settings.listen_host, settings.listen_port, exc
        )
        return 1
    httpd.daemon_threads = True

    stop = threading.Event()

    def on_signal(signum, _frame):
        LOG.info("received signal %s, shutting down", signum)
        stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, on_signal)

    server_thread = threading.Thread(
        target=httpd.serve_forever, name="http-server", daemon=True
    )
    server_thread.start()
    LOG.info(
        "listening on http://%s:%s/metrics (mode=%s, window=%ss, poll every %ss)",
        settings.listen_host,
        settings.listen_port,
        settings.mode,
        settings.window_seconds,
        settings.poll_interval_seconds,
    )

    def poll_loop() -> None:
        while not stop.is_set():
            started = time.time()
            try:
                exporter.poll()
            except Exception:  # noqa: BLE001 - keep the loop alive no matter what
                LOG.exception("unexpected error during polling")
            wait = max(
                1.0, settings.poll_interval_seconds - (time.time() - started)
            )
            stop.wait(wait)

    # One-time startup look-back so the endpoint table is populated from the
    # first poll on; later polls only look at the sliding window.
    exporter.prime_history()

    poller = threading.Thread(target=poll_loop, name="poller", daemon=True)
    poller.start()

    try:
        while not stop.is_set():
            stop.wait(1.0)
    except KeyboardInterrupt:
        stop.set()
    finally:
        stop.set()
        httpd.shutdown()
        httpd.server_close()
        poller.join(timeout=5)
        exporter.store.save_state()
        LOG.info("stopped")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="endpoint_exporter.py",
        description=(
            "Export WSO2 Micro Integrator endpoint suspension status from Grafana "
            "Loki as Prometheus metrics (stdlib only)."
        ),
    )
    parser.add_argument(
        "--config",
        default="config.ini",
        help="path to the INI configuration file (default: config.ini)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help=(
            "run one poll (after history priming), print metrics to stdout and exit; "
            "the state and metrics files are updated as well"
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the configuration file and exit",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        help="override [exporter] log_level (" + ", ".join(LOG_LEVELS) + ")",
    )
    args = parser.parse_args(argv)

    try:
        settings = load_config(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    level_name = (args.log_level or settings.log_level).upper()
    if level_name not in LOG_LEVELS:
        print(
            "configuration error: log level must be one of " + ", ".join(LOG_LEVELS),
            file=sys.stderr,
        )
        return 2
    level = getattr(logging, level_name)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if args.check:
        print(f"configuration OK: {args.config}")
        print(f"  loki url   : {settings.loki_url}")
        print(f"  loki query : {settings.loki_query}")
        print(
            f"  mode       : {settings.mode} (window={settings.window_seconds:g}s, "
            f"overlap={settings.window_overlap_seconds:g}s)"
        )
        print(f"  listen     : {settings.listen_host}:{settings.listen_port}")
        print(f"  known eps  : {len(settings.known_endpoints)}")
        return 0

    store = Store(settings)
    store.ensure_known_endpoints()
    store.load_state()
    try:
        client = LokiClient(settings)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    exporter = Exporter(settings, store, client)

    if args.once:
        exporter.prime_history()
        ok = exporter.poll()
        sys.stdout.write(store.render_metrics())
        return 0 if ok else 1

    return run_server(settings, exporter)


if __name__ == "__main__":
    sys.exit(main())
