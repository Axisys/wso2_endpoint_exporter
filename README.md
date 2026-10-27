# wso2-endpoint-exporter

Turns WSO2 Micro Integrator endpoint-suspension log lines, collected in
Grafana Loki, into Prometheus metrics and a Grafana dashboard.

    Grafana Loki --(LogQL poll, 60 s)--> endpoint_exporter.py
    endpoint_exporter.py --(/metrics)--> Prometheus --> Grafana

* **Python 3.11, standard library only** - no pip packages, no compilation.
  Made for locked-down dev hosts (Debian 12 + clean `python3`).
* Small embedded HTTP server (`http.server`), bound to `127.0.0.1` by default.
* Logs are polled every 60 seconds; a metric table is rebuilt on every poll
  and also written to disk (`metrics.prom`) for debugging.

---

## 1. Quick start (Debian 12)

```bash
# unprivileged service user + directories
sudo useradd --system --home /var/lib/wso2-endpoint-exporter \
             --shell /usr/sbin/nologin wso2-exporter
sudo mkdir -p /opt/wso2-endpoint-exporter /etc/wso2-endpoint-exporter \
              /var/lib/wso2-endpoint-exporter

# files
sudo cp endpoint_exporter.py /opt/wso2-endpoint-exporter/
sudo cp config.ini.example /etc/wso2-endpoint-exporter/config.ini
sudo chown -R wso2-exporter:wso2-exporter /var/lib/wso2-endpoint-exporter

# edit /etc/wso2-endpoint-exporter/config.ini (at least [loki] url + query)
sudo -u wso2-exporter python3 /opt/wso2-endpoint-exporter/endpoint_exporter.py \
     --config /etc/wso2-endpoint-exporter/config.ini --check

# one-shot run: prints the exact /metrics output to stdout
sudo -u wso2-exporter python3 /opt/wso2-endpoint-exporter/endpoint_exporter.py \
     --config /etc/wso2-endpoint-exporter/config.ini --once | head -30

# systemd
sudo cp systemd/wso2-endpoint-exporter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wso2-endpoint-exporter
journalctl -u wso2-endpoint-exporter -f
```

Then add the scrape job (see `prometheus/prometheus-scrape.yml`) and import
the dashboard (see `grafana/wso2-endpoint-status-dashboard.json`).

---

## 2. What the metrics mean

The exporter reads only these log lines from Loki:

```
[2026-10-27 14:31:41,579]  WARN {...EndpointContext} - Endpoint : UPC_CFT_EP
with address http://localhost:8280/services/UPC_Gateway_DataService
will be marked SUSPENDED as it failed
```

The main gauge has two working modes (`[exporter] mode`):

| mode | value 1 | value 0 |
|------|---------|---------|
| `window` (default) | a suspension event appeared in the log within the last `window_seconds` (60 s) | no suspension event in that window |
| `state` | the endpoint was marked SUSPENDED and no recovery was seen yet | a "back to ACTIVE" line was seen (`resume_query`) or `state_ttl_seconds` passed |

**Read this before choosing.** `window` answers "did it fail in the last
minute?". A dead endpoint that stopped producing log lines (no traffic, or a
message broker gave up retrying) falls back to `0` even though WSO2 may still
have it SUSPENDED. `state` answers "is it suspended right now?", but it needs
recovery log lines (or a TTL) to return to `0`. In practice WSO2 re-logs the
suspension on every failed call, so on a busy endpoint both modes look the
same. Pick `state` if you want stability, and set `resume_query` after you
confirm the exact recovery wording in your logs, e.g. run in Grafana Explore:

```logql
{job="wso2logs-os"} |~ "(?i)ACTIVE"
```

### Endpoint inventory

Endpoints that have *never* been suspended never appear in these logs, so the
log stream alone cannot enumerate all ~20 endpoints. Two ways to get a full
table with zeros:

1. list them statically in `known_endpoints` / `known_endpoints_file`
   (recommended, ~20 lines);
2. rely on `history_hours` (startup look-back, default 168 h) which discovers
   every endpoint that was suspended at least once during that period.

Discovered endpoints are remembered in `state.json`, so the table survives
restarts.

### About the `job` label

Do **not** put `job="wso2logs-os"` into the metric - Prometheus attaches the
`job` label itself from `job_name` in `prometheus.yml`. If a metric carries its
own `job` label, Prometheus renames the target one to `exported_job` and the
dashboards become confusing. Same for `level` and other Loki stream labels.

---

## 3. Metrics reference

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `wso2_endpoint_suspended` | gauge | `endpoint`, `address` | 1 = SUSPENDED (per selected mode), 0 = ok |
| `wso2_endpoint_last_suspended_timestamp_seconds` | gauge | `endpoint`, `address` | Unix time of the last suspension event, 0 = never |
| `wso2_endpoint_suspension_events_total` | counter | `endpoint`, `address` | suspension log events seen since state creation |
| `wso2_exporter_poll_success` | gauge | - | 1 = last Loki poll ok |
| `wso2_exporter_last_poll_timestamp_seconds` | gauge | - | time of the last poll attempt |
| `wso2_exporter_last_success_timestamp_seconds` | gauge | - | time of the last successful poll |
| `wso2_exporter_last_poll_duration_seconds` | gauge | - | poll duration |
| `wso2_exporter_loki_errors_total` | counter | - | failed polls |
| `wso2_exporter_known_endpoints` | gauge | - | tracked endpoints |
| `wso2_exporter_window_seconds` | gauge | - | configured window |
| `wso2_exporter_build_info` | gauge | `version` | always 1 |

Metric names can be renamed in `config.ini`
(`metric_suspended`, `metric_last_suspended_timestamp_seconds`,
`metric_events_total`).

### HTTP API

| Path | Content |
|------|---------|
| `/metrics` | Prometheus text exposition format (`text/plain; version=0.0.4`) |
| `/` | HTML status table for humans (auto-refresh 60 s) |
| `/state.json` | full internal state as JSON, handy while debugging |
| `/health` | 200 `{"status":"ok"}` when the last poll succeeded recently, 503 otherwise |

Prometheus scrapes the **text** format - that is the "file in the right format"
you described; JSON is not needed for scraping (it would only duplicate the
same data). The exporter still writes the current text snapshot to
`metrics_file` after every successful poll.

---

## 4. Configuration

Full commented example: [`config.ini.example`](config.ini.example).
Only section summary here:

| Section | Key settings |
|---------|--------------|
| `[loki]` | `url`, `query` (LogQL for suspensions), `resume_query`, `limit`, `timeout_seconds`, `verify_tls`, `ca_bundle`, `username`/`password`, `bearer_token`, `extra_headers` (e.g. `X-Scope-OrgID`) |
| `[parse]` | `suspend_regex`, `resume_regex` - must contain named group `(?P<endpoint>...)`, optionally `(?P<address>...)` |
| `[exporter]` | `listen_host`/`listen_port`, `poll_interval_seconds`, `mode`, `window_seconds`, `state_ttl_seconds`, `history_hours`, `state_file`, `metrics_file`, `known_endpoints`, metric names, `log_level` |

The default LogQL is the one you already use in Grafana Explore:

```logql
{job="wso2logs-os",level="WARN"} |= "will be marked SUSPENDED as it failed"
```

Notes:

* `listen_host = 127.0.0.1` keeps the exporter local-only. If Prometheus runs
  on another host, set the server LAN address and restrict access with a
  firewall/security group to the Prometheus IP.
* `verify_tls = false` matches your current working setup with an unverified
  HTTPS Loki. For anything beyond dev set `verify_tls = true` and
  `ca_bundle` to your CA certificate.
* Auth: `username`/`password` (Basic) or `bearer_token`. For multi-tenant Loki
  use `extra_headers` with `X-Scope-OrgID: <tenant>`.

---

## 5. Prometheus

Snippet: [`prometheus/prometheus-scrape.yml`](prometheus/prometheus-scrape.yml)

```yaml
scrape_configs:
  - job_name: wso2-endpoint-status
    scrape_interval: 30s
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:9187"]
```

Example alerts: [`prometheus/alerts.yml`](prometheus/alerts.yml) -
`Wso2EndpointSuspended`, `Wso2EndpointExporterStale`,
`Wso2EndpointExporterNoData`, `Wso2EndpointFlapping`.

Useful PromQL:

```promql
# endpoints suspended right now
wso2_endpoint_suspended == 1

# suspension activity per hour
sum by (endpoint) (increase(wso2_endpoint_suspension_events_total[1h]))

# table: name + last suspension time
wso2_endpoint_last_suspended_timestamp_seconds > 0
```

---

## 6. Grafana

1. **Dashboards -> New -> Import** -> upload
   [`grafana/wso2-endpoint-status-dashboard.json`](grafana/wso2-endpoint-status-dashboard.json),
   select your Prometheus datasource when prompted.
2. Panels:
   * **Endpoints SUSPENDED now** - red as soon as something is suspended;
   * **Endpoint status** - the table (ACTIVE/SUSPENDED per endpoint);
   * **Suspension timeline** - binary state over time, step line per endpoint;
   * **Suspension events per hour** - failure activity;
   * **Last suspension time** - when each endpoint failed the last time;
   * stats **Exporter poll OK** / **Data age** - so you notice when the data
     itself is stale instead of trusting a silent zero.

The dashboard uses only the three `wso2_endpoint_*` metrics, so it also works
if you renamed nothing in `config.ini`.

---

## 7. Tests

Pure `unittest`, no extra packages:

```bash
cd wso2_endpoint_exporter
python3 -m unittest discover -s tests -v
```

The suite starts a fake Loki (`http.server`) and covers parsing of real WSO2
log lines, window/state semantics, deduplication, label escaping, state-file
round-trip, HTTP endpoints and failure handling.

---

## 8. Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `/metrics` shows no `wso2_endpoint_suspended{...}` samples | no endpoint seen yet - add `known_endpoints` or let `history_hours` cover the period; check `/state.json` |
| gauge stuck at 0 | wrong LogQL filter - run the same `query` in Grafana Explore; check `wso2_exporter_poll_success` |
| gauge stuck at 1 in `state` mode | no recovery lines matched - configure `resume_query` or rely on `state_ttl_seconds` |
| `unsupported Loki resultType` in the log | the LogQL query aggregates (e.g. `count_over_time`); use a raw stream query |
| truncation warning in the log | raise `[loki] limit` |
| Prometheus target down | exporter bound to `127.0.0.1` while Prometheus is remote - change `listen_host` |

Manual check from the Prometheus host:

```bash
curl -s http://127.0.0.1:9187/health
curl -s http://127.0.0.1:9187/metrics | head
```
"# wso2_endpoint_exporter" 
