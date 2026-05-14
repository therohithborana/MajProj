from __future__ import annotations

from collections import defaultdict, deque
from copy import deepcopy
from datetime import datetime, timezone
from threading import Lock
from time import perf_counter

from models import serialize_document

try:
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult

    OTEL_AVAILABLE = True
except Exception:  # pragma: no cover - fallback for environments without OTel installed
    OTEL_AVAILABLE = False
    Resource = None
    TracerProvider = None
    SimpleSpanProcessor = None
    SpanExporter = object

    class SpanExportResult:
        SUCCESS = "success"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_metrics():
    return {
        "events_received": 0,
        "event_type_counts": {
            "access": 0,
            "auth": 0,
            "network": 0,
        },
        "failed_auth_events": 0,
        "detection_runs": 0,
        "incidents_detected": 0,
        "tool_executions": 0,
        "last_ingest_at": None,
        "last_detection_at": None,
        "last_alert_at": None,
        "last_attack_id": None,
    }


def _default_channels():
    return {
        "application_logs": 0,
        "authentication_logs": 0,
        "network_logs": 0,
    }


def _summarize_state(state: dict | None) -> dict:
    state = state or {}
    simulation = state.get("simulation") or {}
    anomaly = state.get("anomaly") or {}
    classification = state.get("classification") or {}
    attack = classification.get("attack") or {}
    policy_decision = state.get("policy_decision") or {}
    return serialize_document(
        {
            "current_stage": state.get("current_stage"),
            "attack_id": simulation.get("attack_id"),
            "anomaly_detected": bool(anomaly.get("detected")),
            "predicted_class": classification.get("predicted_class"),
            "severity": attack.get("severity"),
            "risk_score": classification.get("risk_score"),
            "policy_mode": policy_decision.get("mode"),
        }
    )


class _InMemorySpanExporter(SpanExporter):
    def __init__(self, sink: "OpenTelemetryRuntime"):
        self.sink = sink

    def export(self, spans):
        for span in spans:
            self.sink.record_finished_span(span)
        return SpanExportResult.SUCCESS

    def shutdown(self):
        return None


class OpenTelemetryRuntime:
    def __init__(self):
        self.enabled = OTEL_AVAILABLE
        self._lock = Lock()
        self._spans = defaultdict(lambda: deque(maxlen=80))
        self._alerts = defaultdict(lambda: deque(maxlen=20))
        self._metrics = defaultdict(_default_metrics)
        self._latest_tool = defaultdict(dict)
        if self.enabled:
            resource = Resource.create(
                {
                    "service.name": "cyberagent-backend",
                    "service.namespace": "cyberagent",
                    "deployment.environment": "development",
                }
            )
            self.provider = TracerProvider(resource=resource)
            self.provider.add_span_processor(SimpleSpanProcessor(_InMemorySpanExporter(self)))
            self.tracer = self.provider.get_tracer("cyberagent.observability", "1.0.0")
        else:
            self.provider = None
            self.tracer = None

    def _website_id_from_state(self, state: dict) -> str:
        return (
            state.get("website_id")
            or (state.get("website") or {}).get("_id")
            or "unknown"
        )

    def record_finished_span(self, span):
        attributes = dict(span.attributes or {})
        website_id = str(
            attributes.get("cyberagent.website_id")
            or attributes.get("website.id")
            or "unknown"
        )
        start_time = getattr(span, "start_time", 0) or 0
        end_time = getattr(span, "end_time", 0) or 0
        duration_ms = round(max(end_time - start_time, 0) / 1_000_000, 2)
        record = {
            "name": span.name,
            "kind": str(getattr(span, "kind", "INTERNAL")),
            "start_time": datetime.fromtimestamp(start_time / 1_000_000_000, timezone.utc).isoformat() if start_time else _utc_now_iso(),
            "duration_ms": duration_ms,
            "status": str(getattr(getattr(span, "status", None), "status_code", "UNSET")),
            "attributes": serialize_document(attributes),
        }
        with self._lock:
            self._spans[website_id].appendleft(record)

    def record_collector_ingest(self, website_id: str, source_label: str | None, events: list[dict], run_detection: bool):
        if self.enabled:
            with self.tracer.start_as_current_span("collector.ingest") as span:
                span.set_attribute("cyberagent.website_id", website_id)
                span.set_attribute("cyberagent.source_label", source_label or "customer_website")
                span.set_attribute("cyberagent.event_count", len(events))
                span.set_attribute("cyberagent.run_detection", run_detection)
                span.set_attribute("cyberagent.channels", ",".join(sorted({event.get("event_type", "unknown") for event in events})))
        failed_auth = sum(1 for event in events if event.get("event_type") == "auth" and str(event.get("result", "")).upper() == "FAILED")
        with self._lock:
            metrics = self._metrics[website_id]
            metrics["events_received"] += len(events)
            metrics["failed_auth_events"] += failed_auth
            metrics["last_ingest_at"] = _utc_now_iso()
            channels = _default_channels()
            for event in events:
                event_type = event.get("event_type")
                if event_type in metrics["event_type_counts"]:
                    metrics["event_type_counts"][event_type] += 1
                if event_type == "access":
                    channels["application_logs"] += 1
                elif event_type == "auth":
                    channels["authentication_logs"] += 1
                elif event_type == "network":
                    channels["network_logs"] += 1
            self._latest_tool[website_id]["last_ingest_channels"] = channels

    def trace_tool_execution(self, tool_name: str, owner_agent: str, state: dict, handler):
        website_id = self._website_id_from_state(state)
        attack_id = (state.get("simulation") or {}).get("attack_id")
        if not self.enabled:
            next_state = handler(state)
            self._update_after_tool(website_id, tool_name, owner_agent, state, next_state, 0.0, attack_id)
            return next_state

        with self.tracer.start_as_current_span(f"agent.{tool_name}") as span:
            span.set_attribute("cyberagent.website_id", website_id)
            span.set_attribute("cyberagent.attack_id", attack_id or "")
            span.set_attribute("cyberagent.tool_name", tool_name)
            span.set_attribute("cyberagent.owner_agent", owner_agent)
            span.set_attribute("cyberagent.stage_before", state.get("current_stage") or "collector_ingested")
            started = perf_counter()
            next_state = handler(state)
            duration_ms = round((perf_counter() - started) * 1000, 2)
            span.set_attribute("cyberagent.duration_ms", duration_ms)
            span.set_attribute("cyberagent.stage_after", next_state.get("current_stage") or "unknown")
            span.set_attribute("cyberagent.predicted_class", (next_state.get("classification") or {}).get("predicted_class") or "")
            anomaly = next_state.get("anomaly") or {}
            span.set_attribute("cyberagent.anomaly_detected", bool(anomaly.get("detected")))
            self._update_after_tool(website_id, tool_name, owner_agent, state, next_state, duration_ms, attack_id)
            return next_state

    def _update_after_tool(
        self,
        website_id: str,
        tool_name: str,
        owner_agent: str,
        state_before: dict,
        state_after: dict,
        duration_ms: float,
        attack_id: str | None,
    ):
        anomaly = state_after.get("anomaly") or {}
        classification = state_after.get("classification") or {}
        policy_decision = state_after.get("policy_decision") or {}
        detected = bool(anomaly.get("detected"))
        alert = None
        with self._lock:
            metrics = self._metrics[website_id]
            metrics["tool_executions"] += 1
            if tool_name == "telemetry.detect_threats":
                metrics["detection_runs"] += 1
                metrics["last_detection_at"] = _utc_now_iso()
            if detected and tool_name == "telemetry.detect_threats":
                metrics["incidents_detected"] += 1
                metrics["last_alert_at"] = _utc_now_iso()
                metrics["last_attack_id"] = attack_id
                alert = {
                    "timestamp": _utc_now_iso(),
                    "tool": tool_name,
                    "agent": owner_agent,
                    "attack_id": attack_id,
                    "message": anomaly.get("summary") or classification.get("predicted_class") or "Suspicious activity detected.",
                    "severity": (classification.get("attack") or {}).get("severity") or "MEDIUM",
                }
                self._alerts[website_id].appendleft(alert)
            self._latest_tool[website_id] = {
                "tool_name": tool_name,
                "owner_agent": owner_agent,
                "duration_ms": duration_ms,
                "input_summary": _summarize_state(state_before),
                "output_summary": _summarize_state(state_after),
                "policy_mode": policy_decision.get("mode"),
            }

    def snapshot(self, website_id: str) -> dict:
        with self._lock:
            metrics = deepcopy(self._metrics[website_id])
            spans = list(self._spans[website_id])
            alerts = list(self._alerts[website_id])
            latest_tool = deepcopy(self._latest_tool[website_id])
            last_ingest_channels = latest_tool.pop("last_ingest_channels", _default_channels())
        return {
            "enabled": self.enabled,
            "transport": "custom_security_events_plus_opentelemetry",
            "service_name": "cyberagent-backend",
            "website_id": website_id,
            "metrics": metrics,
            "channels": {
                "application_logs": {
                    "label": "Application logs",
                    "events_seen": metrics["event_type_counts"]["access"],
                },
                "authentication_logs": {
                    "label": "Authentication logs",
                    "events_seen": metrics["event_type_counts"]["auth"],
                },
                "network_logs": {
                    "label": "Network logs",
                    "events_seen": metrics["event_type_counts"]["network"],
                },
            },
            "latest_ingest_channels": last_ingest_channels,
            "latest_tool": latest_tool,
            "recent_spans": spans[:12],
            "recent_alerts": alerts[:8],
        }


otel_runtime = OpenTelemetryRuntime()
