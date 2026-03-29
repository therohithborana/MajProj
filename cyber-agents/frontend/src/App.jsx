import React, { useEffect, useMemo, useRef, useState } from "react";

const API_BASE = "http://localhost:8000";
const WS_URL = "ws://localhost:8000/ws";
const TOKEN_KEY = "cyberagent_token";

const colors = {
  background: "#f7f7f5",
  panel: "#ffffff",
  panelAlt: "#fbfbfa",
  border: "#e6e6e1",
  text: "#191919",
  muted: "#6b6b67",
  subtle: "#8d8d88",
  green: "#0f9d58",
  red: "#d14343",
  amber: "#b7791f",
  blue: "#2f76ff",
  gray: "#787774",
};

const stageMeta = {
  red_team_attacking: "Red team generated telemetry",
  log_monitoring: "Monitoring logs",
  anomaly_detected: "Anomaly detected",
  classified: "Incident classified",
  awaiting_approval: "Awaiting approval",
  action_executing: "Executing response",
  mitigated: "Mitigated",
  manual_queue: "Manual queue",
};

const severityColors = {
  CRITICAL: colors.red,
  HIGH: "#d9730d",
  MEDIUM: colors.amber,
  LOW: colors.green,
};

function authHeaders(token) {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function apiFetch(path, options = {}, token) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
      ...authHeaders(token),
    },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || "Request failed");
  }
  return data;
}

function StatusPill({ color, children }) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "6px 10px",
        borderRadius: 999,
        border: `1px solid ${color}`,
        background: `${color}12`,
        color,
        fontSize: 12,
        fontWeight: 600,
      }}
    >
      {children}
    </span>
  );
}

function Section({ title, eyebrow, children }) {
  return (
    <section style={sectionStyle}>
      <div style={{ marginBottom: 16 }}>
        {eyebrow ? <div style={eyebrowStyle}>{eyebrow}</div> : null}
        <div style={{ fontSize: 18, fontWeight: 650 }}>{title}</div>
      </div>
      {children}
    </section>
  );
}

function Field({ label, value, accent }) {
  return (
    <div>
      <div style={eyebrowStyle}>{label}</div>
      <div style={{ color: accent || colors.text, fontWeight: 600, lineHeight: 1.5 }}>{value}</div>
    </div>
  );
}

function LogBlock({ title, lines }) {
  if (!lines || !lines.length) {
    return null;
  }
  return (
    <div style={{ marginTop: 14 }}>
      <div style={eyebrowStyle}>{title}</div>
      <div style={monoBoxStyle}>
        {lines.map((line, index) => (
          <div key={`${title}-${index}`} style={{ marginBottom: index === lines.length - 1 ? 0 : 8 }}>
            {line}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const [mode, setMode] = useState("login");
  const [token, setToken] = useState(localStorage.getItem(TOKEN_KEY) || "");
  const [user, setUser] = useState(null);
  const [websites, setWebsites] = useState([]);
  const [selectedWebsiteId, setSelectedWebsiteId] = useState("");
  const [incidents, setIncidents] = useState({});
  const [selectedIncidentId, setSelectedIncidentId] = useState("");
  const [feed, setFeed] = useState([]);
  const [connected, setConnected] = useState(false);
  const [autoRunning, setAutoRunning] = useState(false);
  const [decisionLoading, setDecisionLoading] = useState({});
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const reconnectRef = useRef(null);

  const [authForm, setAuthForm] = useState({
    name: "",
    email: "",
    password: "",
  });
  const [websiteForm, setWebsiteForm] = useState({
    name: "",
    domain: "",
    environment: "development",
  });

  useEffect(() => {
    if (!token) {
      setUser(null);
      setWebsites([]);
      setSelectedWebsiteId("");
      return;
    }

    let cancelled = false;
    async function bootstrap() {
      try {
        setLoading(true);
        const me = await apiFetch("/auth/me", {}, token);
        const websiteList = await apiFetch("/websites", {}, token);
        if (cancelled) {
          return;
        }
        setUser(me.user);
        setWebsites(websiteList);
        const firstWebsite = websiteList[0]?._id || "";
        setSelectedWebsiteId((current) => current || firstWebsite);
      } catch (err) {
        localStorage.removeItem(TOKEN_KEY);
        setToken("");
        setError(err.message);
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }
    bootstrap();
    return () => {
      cancelled = true;
    };
  }, [token]);

  useEffect(() => {
    let socket;
    const connect = () => {
      socket = new WebSocket(WS_URL);
      socket.onopen = () => setConnected(true);
      socket.onmessage = (event) => {
        const payload = JSON.parse(event.data);
        const entry = {
          id: `${Date.now()}-${Math.random()}`,
          timestamp: new Date().toISOString(),
          type: payload.type,
          data: payload.data,
        };
        setFeed((current) => [entry, ...current].slice(0, 50));

        if (payload.type === "init") {
          const mapped = {};
          (payload.data.incidents || []).forEach((incident) => {
            mapped[incident.attack_id] = incident;
          });
          setIncidents(mapped);
          setAutoRunning(Boolean(payload.data.running));
        }

        if (payload.type === "red_team_attack" || payload.type === "agent_update" || payload.type === "incident_resolved") {
          setIncidents((current) => {
            const existing = current[payload.data.attack_id] || {};
            return {
              ...current,
              [payload.data.attack_id]: {
                ...existing,
                ...payload.data,
                simulation: payload.data.simulation || existing.simulation,
              },
            };
          });
          if (payload.data.website_id === selectedWebsiteId) {
            setSelectedIncidentId(payload.data.attack_id);
          }
        }
      };
      socket.onclose = () => {
        setConnected(false);
        reconnectRef.current = window.setTimeout(connect, 3000);
      };
      socket.onerror = () => socket.close();
    };

    connect();
    return () => {
      if (reconnectRef.current) {
        window.clearTimeout(reconnectRef.current);
      }
      if (socket) {
        socket.close();
      }
    };
  }, [selectedWebsiteId]);

  useEffect(() => {
    if (!token || !selectedWebsiteId) {
      return;
    }
    let cancelled = false;
    async function loadIncidents() {
      try {
        const websiteIncidents = await apiFetch(`/websites/${selectedWebsiteId}/incidents`, {}, token);
        if (cancelled) {
          return;
        }
        setIncidents((current) => {
          const next = { ...current };
          websiteIncidents.forEach((incident) => {
            next[incident.attack_id] = incident;
          });
          return next;
        });
        setSelectedIncidentId((current) => current || websiteIncidents[0]?.attack_id || "");
      } catch (err) {
        setError(err.message);
      }
    }
    loadIncidents();
    return () => {
      cancelled = true;
    };
  }, [selectedWebsiteId, token]);

  const selectedWebsite = websites.find((website) => website._id === selectedWebsiteId) || null;
  const websiteIncidents = useMemo(
    () =>
      Object.values(incidents)
        .filter((incident) => incident.website_id === selectedWebsiteId)
        .sort((a, b) => (b.simulation?.timestamp || "").localeCompare(a.simulation?.timestamp || "")),
    [incidents, selectedWebsiteId]
  );
  const selectedIncident =
    websiteIncidents.find((incident) => incident.attack_id === selectedIncidentId) || websiteIncidents[0] || null;
  const selectedAttack = selectedIncident?.classification?.attack;

  const stats = useMemo(() => {
    return {
      total: websiteIncidents.length,
      pending: websiteIncidents.filter((incident) => incident.approval_status === "pending").length,
      mitigated: websiteIncidents.filter((incident) => incident.action_result?.status === "MITIGATED").length,
      critical: websiteIncidents.filter((incident) => incident.classification?.attack?.severity === "CRITICAL").length,
    };
  }, [websiteIncidents]);

  async function submitAuth(targetMode) {
    try {
      setLoading(true);
      setError("");
      const payload =
        targetMode === "signup"
          ? { name: authForm.name, email: authForm.email, password: authForm.password }
          : { email: authForm.email, password: authForm.password };
      const path = targetMode === "signup" ? "/auth/signup" : "/auth/login";
      const data = await apiFetch(path, { method: "POST", body: JSON.stringify(payload) });
      localStorage.setItem(TOKEN_KEY, data.token);
      setToken(data.token);
      setAuthForm({ name: "", email: "", password: "" });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function createWebsite() {
    try {
      setLoading(true);
      setError("");
      const website = await apiFetch(
        "/websites",
        {
          method: "POST",
          body: JSON.stringify({
            ...websiteForm,
            use_demo: true,
            web_server: "nginx",
          }),
        },
        token
      );
      setWebsites((current) => [...current, website]);
      setSelectedWebsiteId(website._id);
      setWebsiteForm({ name: "", domain: "", environment: "development" });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function connectDemo(websiteId) {
    try {
      setLoading(true);
      const website = await apiFetch(`/websites/${websiteId}/connect-demo`, { method: "POST" }, token);
      setWebsites((current) => current.map((item) => (item._id === websiteId ? website : item)));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function simulateAttack() {
    if (!selectedWebsiteId) {
      return;
    }
    try {
      setError("");
      await apiFetch(`/websites/${selectedWebsiteId}/simulate`, { method: "POST" }, token);
    } catch (err) {
      setError(err.message);
    }
  }

  async function toggleAuto() {
    if (!selectedWebsiteId) {
      return;
    }
    try {
      const endpoint = autoRunning ? `/websites/${selectedWebsiteId}/monitor/stop` : `/websites/${selectedWebsiteId}/monitor/start`;
      const data = await apiFetch(endpoint, { method: "POST" }, token);
      setAutoRunning(Boolean(data.running));
    } catch (err) {
      setError(err.message);
    }
  }

  async function approveIncident(decision) {
    if (!selectedIncident) {
      return;
    }
    try {
      setDecisionLoading((current) => ({ ...current, [selectedIncident.attack_id]: true }));
      const updated = await apiFetch(
        `/incidents/${selectedIncident.attack_id}/approve`,
        { method: "POST", body: JSON.stringify({ decision }) },
        token
      );
      setIncidents((current) => ({ ...current, [updated.simulation.attack_id]: updated }));
    } catch (err) {
      setError(err.message);
    } finally {
      setDecisionLoading((current) => ({ ...current, [selectedIncident.attack_id]: false }));
    }
  }

  function logout() {
    localStorage.removeItem(TOKEN_KEY);
    setToken("");
    setUser(null);
    setWebsites([]);
    setSelectedWebsiteId("");
    setSelectedIncidentId("");
    setIncidents({});
  }

  if (!user) {
    return (
      <div style={pageStyle}>
        <div style={heroWrapStyle}>
          <div style={{ maxWidth: 560 }}>
            <div style={eyebrowStyle}>CyberAgent</div>
            <div style={{ fontSize: 42, fontWeight: 700, letterSpacing: -1, marginBottom: 14 }}>
              Multi-agent website security, with a demo site you can plug in now.
            </div>
            <div style={{ color: colors.muted, fontSize: 16, lineHeight: 1.7 }}>
              Sign up, connect a website project, and watch CyberAgent monitor telemetry, detect incidents, generate
              mitigation plans, and walk you through approval-gated response.
            </div>
          </div>

          <div style={authCardStyle}>
            <div style={{ display: "flex", gap: 10, marginBottom: 18 }}>
              <button onClick={() => setMode("login")} style={mode === "login" ? primaryButtonStyle : secondaryButtonStyle}>
                Log in
              </button>
              <button onClick={() => setMode("signup")} style={mode === "signup" ? primaryButtonStyle : secondaryButtonStyle}>
                Sign up
              </button>
            </div>
            {mode === "signup" ? (
              <input
                value={authForm.name}
                onChange={(event) => setAuthForm((current) => ({ ...current, name: event.target.value }))}
                placeholder="Name"
                style={inputStyle}
              />
            ) : null}
            <input
              value={authForm.email}
              onChange={(event) => setAuthForm((current) => ({ ...current, email: event.target.value }))}
              placeholder="Email"
              style={inputStyle}
            />
            <input
              type="password"
              value={authForm.password}
              onChange={(event) => setAuthForm((current) => ({ ...current, password: event.target.value }))}
              placeholder="Password"
              style={inputStyle}
            />
            {error ? <div style={errorStyle}>{error}</div> : null}
            <button onClick={() => submitAuth(mode)} style={primaryButtonStyle} disabled={loading}>
              {loading ? "Working..." : mode === "signup" ? "Create account" : "Log in"}
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!websites.length) {
    return (
      <div style={pageStyle}>
        <div style={topBarStyle}>
          <div>
            <div style={eyebrowStyle}>Welcome</div>
            <div style={{ fontSize: 30, fontWeight: 700 }}>{user.name}</div>
          </div>
          <button onClick={logout} style={secondaryButtonStyle}>
            Log out
          </button>
        </div>

        <div style={setupCardStyle}>
          <div style={eyebrowStyle}>Connect website</div>
          <div style={{ fontSize: 28, fontWeight: 700, marginBottom: 10 }}>Create your first monitored website</div>
          <div style={{ color: colors.muted, lineHeight: 1.7, marginBottom: 18 }}>
            Phase 1 connects a demo website automatically. We’ll use this project to scope incidents, telemetry, and
            monitoring to your account.
          </div>
          <div style={formGridStyle}>
            <input
              value={websiteForm.name}
              onChange={(event) => setWebsiteForm((current) => ({ ...current, name: event.target.value }))}
              placeholder="Website name"
              style={inputStyle}
            />
            <input
              value={websiteForm.domain}
              onChange={(event) => setWebsiteForm((current) => ({ ...current, domain: event.target.value }))}
              placeholder="Website domain"
              style={inputStyle}
            />
            <input
              value={websiteForm.environment}
              onChange={(event) => setWebsiteForm((current) => ({ ...current, environment: event.target.value }))}
              placeholder="Environment"
              style={inputStyle}
            />
          </div>
          {error ? <div style={errorStyle}>{error}</div> : null}
          <button onClick={createWebsite} style={primaryButtonStyle} disabled={loading}>
            {loading ? "Creating..." : "Create and connect demo website"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={pageStyle}>
      <div style={topBarStyle}>
        <div>
          <div style={eyebrowStyle}>CyberAgent Dashboard</div>
          <div style={{ fontSize: 30, fontWeight: 700, marginBottom: 6 }}>Welcome back, {user.name}</div>
          <div style={{ color: colors.muted }}>Manage websites, monitor telemetry, and review incidents.</div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <StatusPill color={connected ? colors.green : colors.red}>{connected ? "Live" : "Offline"}</StatusPill>
          <button onClick={logout} style={secondaryButtonStyle}>
            Log out
          </button>
        </div>
      </div>

      {error ? <div style={errorStyle}>{error}</div> : null}

      <div style={mainGridStyle}>
        <aside style={sidebarStyle}>
          <Section title="Your websites" eyebrow="Connected projects">
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {websites.map((website) => (
                <button
                  key={website._id}
                  onClick={() => setSelectedWebsiteId(website._id)}
                  style={{
                    ...websiteButtonStyle,
                    background: selectedWebsiteId === website._id ? colors.panelAlt : colors.panel,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
                    <div style={{ fontWeight: 650 }}>{website.name}</div>
                    <StatusPill color={website.status === "connected" ? colors.green : colors.amber}>
                      {website.status}
                    </StatusPill>
                  </div>
                  <div style={{ color: colors.muted, fontSize: 13 }}>{website.domain}</div>
                  <div style={{ color: colors.subtle, fontSize: 12, marginTop: 4 }}>{website.environment}</div>
                </button>
              ))}
            </div>
          </Section>

          <Section title="Live feed" eyebrow="Realtime agent events">
            <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 360, overflowY: "auto" }}>
              {feed
                .filter((entry) => !selectedWebsiteId || entry.data.website_id === selectedWebsiteId || entry.type === "init")
                .map((entry) => (
                  <div key={entry.id} style={feedCardStyle}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 10, marginBottom: 6 }}>
                      <div style={{ fontSize: 12, fontWeight: 600 }}>{entry.type}</div>
                      <div style={{ fontSize: 11, color: colors.subtle }}>{new Date(entry.timestamp).toLocaleTimeString()}</div>
                    </div>
                    <div style={{ color: colors.muted, fontSize: 12, lineHeight: 1.5 }}>
                      {entry.data.message || entry.data.current_stage || "Event received"}
                    </div>
                  </div>
                ))}
            </div>
          </Section>
        </aside>

        <main style={{ minWidth: 0 }}>
          {selectedWebsite ? (
            <>
              <Section title={selectedWebsite.name} eyebrow="Connected website">
                <div style={statsGridStyle}>
                  <Field label="Domain" value={selectedWebsite.domain} />
                  <Field label="Environment" value={selectedWebsite.environment} />
                  <Field label="Connection type" value={selectedWebsite.connection_type} />
                  <Field label="Status" value={selectedWebsite.status} accent={selectedWebsite.status === "connected" ? colors.green : colors.amber} />
                </div>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 18 }}>
                  {selectedWebsite.status !== "connected" ? (
                    <button onClick={() => connectDemo(selectedWebsite._id)} style={primaryButtonStyle}>
                      Connect demo website
                    </button>
                  ) : null}
                  <button onClick={simulateAttack} style={primaryButtonStyle}>
                    Simulate attack
                  </button>
                  <button onClick={toggleAuto} style={secondaryButtonStyle}>
                    {autoRunning ? "Stop auto monitor" : "Start auto monitor"}
                  </button>
                </div>
              </Section>

              <div style={miniStatsGridStyle}>
                <StatCard label="Total incidents" value={stats.total} />
                <StatCard label="Pending approval" value={stats.pending} />
                <StatCard label="Mitigated" value={stats.mitigated} />
                <StatCard label="Critical" value={stats.critical} />
              </div>

              <Section title="Incidents" eyebrow="Website incident queue">
                <div style={{ display: "grid", gridTemplateColumns: "320px minmax(0, 1fr)", gap: 16 }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {websiteIncidents.map((incident) => (
                      <button
                        key={incident.attack_id}
                        onClick={() => setSelectedIncidentId(incident.attack_id)}
                        style={{
                          ...websiteButtonStyle,
                          background: selectedIncident?.attack_id === incident.attack_id ? colors.panelAlt : colors.panel,
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
                          <div style={{ fontWeight: 650 }}>{incident.attack_id}</div>
                          {incident.classification?.attack?.severity ? (
                            <StatusPill color={severityColors[incident.classification.attack.severity]}>
                              {incident.classification.attack.severity}
                            </StatusPill>
                          ) : null}
                        </div>
                        <div style={{ fontSize: 13, color: colors.muted, marginBottom: 4 }}>
                          {incident.classification?.predicted_class || incident.simulation?.attack_profile?.attack_type || "Pending"}
                        </div>
                        <div style={{ fontSize: 12, color: colors.subtle }}>
                          {stageMeta[incident.current_stage] || incident.current_stage}
                        </div>
                      </button>
                    ))}
                    {!websiteIncidents.length ? (
                      <div style={{ color: colors.muted }}>No incidents yet for this website.</div>
                    ) : null}
                  </div>

                  <div>
                    {!selectedIncident ? (
                      <div style={emptyStateStyle}>Select an incident to inspect its flow.</div>
                    ) : (
                      <>
                        <Section title="Red Team Agent" eyebrow="Generated telemetry">
                          <div style={statsGridStyle}>
                            <Field label="Scenario" value={selectedIncident.simulation.attack_profile.attack_type} />
                            <Field label="Primary source" value={selectedIncident.simulation.attack_profile.primary_src_ip} />
                            <Field
                              label="Target"
                              value={`${selectedIncident.simulation.attack_profile.target_ip}:${selectedIncident.simulation.attack_profile.target_port}`}
                            />
                            <Field label="Expected rate" value={`${selectedIncident.simulation.attack_profile.packet_rate}/sec`} />
                          </div>
                          <div style={{ color: colors.muted, lineHeight: 1.7, marginTop: 14 }}>
                            {selectedIncident.simulation.description}
                          </div>
                          <LogBlock title="Access logs" lines={selectedIncident.simulation.telemetry.generated_logs.access} />
                          <LogBlock title="Auth logs" lines={selectedIncident.simulation.telemetry.generated_logs.auth} />
                          <LogBlock title="Network logs" lines={selectedIncident.simulation.telemetry.generated_logs.network} />
                        </Section>

                        {selectedIncident.telemetry ? (
                          <Section title="Log Monitor Agent" eyebrow="Telemetry ingestion">
                            <div style={statsGridStyle}>
                              <Field label="Observed logs" value={selectedIncident.telemetry.total_logs_observed} />
                              <Field label="Access" value={selectedIncident.telemetry.log_counts.access} />
                              <Field label="Auth" value={selectedIncident.telemetry.log_counts.auth} />
                              <Field label="Network" value={selectedIncident.telemetry.log_counts.network} />
                            </div>
                          </Section>
                        ) : null}

                        {selectedIncident.anomaly ? (
                          <Section title="Anomaly Detection Agent" eyebrow="Detection evidence">
                            <div style={statsGridStyle}>
                              <Field label="Anomaly type" value={selectedIncident.anomaly.anomaly_type} />
                              <Field label="Primary source" value={selectedIncident.anomaly.primary_src_ip} />
                              <Field
                                label="Target"
                                value={`${selectedIncident.anomaly.target_ip}:${selectedIncident.anomaly.target_port}`}
                              />
                              <Field label="Severity" value={selectedIncident.anomaly.severity} accent={severityColors[selectedIncident.anomaly.severity]} />
                            </div>
                            <div style={{ color: colors.muted, lineHeight: 1.7, marginTop: 14 }}>
                              {selectedIncident.anomaly.summary}
                            </div>
                          </Section>
                        ) : null}

                        {selectedIncident.classification && selectedAttack ? (
                          <Section title="Classification Agent" eyebrow="Incident context">
                            <div style={statsGridStyle}>
                              <Field label="Attack type" value={selectedIncident.classification.predicted_class} />
                              <Field label="Confidence" value={`${(selectedIncident.classification.confidence * 100).toFixed(1)}%`} />
                              <Field label="Risk score" value={selectedIncident.classification.risk_score} accent={colors.amber} />
                              <Field label="Target" value={`${selectedAttack.target_ip}:${selectedAttack.target_port}`} />
                            </div>
                            <div style={{ marginTop: 14, color: colors.muted, lineHeight: 1.7 }}>
                              {selectedIncident.classification.key_indicators.map((item) => (
                                <div key={item} style={{ marginBottom: 6 }}>
                                  • {item}
                                </div>
                              ))}
                            </div>
                          </Section>
                        ) : null}

                        {selectedIncident.mitigation_plan ? (
                          <Section title="Response Planning Agent" eyebrow="Approval gated">
                            <div style={statsGridStyle}>
                              <Field label="Strategy" value={selectedIncident.mitigation_plan.strategy} />
                              <Field label="Estimated time" value={selectedIncident.mitigation_plan.estimated_mitigation_time} />
                              <Field label="Collateral risk" value={selectedIncident.mitigation_plan.collateral_risk} accent={colors.amber} />
                              <Field label="Status" value={selectedIncident.approval_status || "pending"} />
                            </div>
                            <div style={{ display: "grid", gap: 10, marginTop: 14 }}>
                              {selectedIncident.mitigation_plan.steps.map((step) => (
                                <div key={`${step.step}-${step.action}`} style={feedCardStyle}>
                                  <div style={{ fontWeight: 650, marginBottom: 8 }}>
                                    {step.step}. {step.action}
                                  </div>
                                  <div style={monoBoxStyle}>{step.command}</div>
                                  <div style={{ color: colors.muted, marginTop: 10 }}>{step.impact}</div>
                                </div>
                              ))}
                            </div>
                            {selectedIncident.approval_status === "pending" ? (
                              <div style={{ display: "flex", gap: 10, marginTop: 14 }}>
                                <button
                                  onClick={() => approveIncident("approved")}
                                  style={primaryButtonStyle}
                                  disabled={decisionLoading[selectedIncident.attack_id]}
                                >
                                  Approve
                                </button>
                                <button
                                  onClick={() => approveIncident("rejected")}
                                  style={secondaryButtonStyle}
                                  disabled={decisionLoading[selectedIncident.attack_id]}
                                >
                                  Reject
                                </button>
                              </div>
                            ) : null}
                          </Section>
                        ) : null}

                        {selectedIncident.action_result ? (
                          <Section title="Action Agent" eyebrow="Execution result">
                            <div style={statsGridStyle}>
                              <Field label="Status" value={selectedIncident.action_result.status} accent={selectedIncident.action_result.status === "MITIGATED" ? colors.green : colors.gray} />
                              {selectedIncident.action_result.total_execution_time_ms ? (
                                <Field label="Execution time" value={`${selectedIncident.action_result.total_execution_time_ms} ms`} />
                              ) : null}
                              {selectedIncident.action_result.ticket_id ? (
                                <Field label="Ticket" value={selectedIncident.action_result.ticket_id} />
                              ) : null}
                            </div>
                          </Section>
                        ) : null}

                        {selectedIncident.incident_report ? (
                          <Section title="Reporting Agent" eyebrow="Final report">
                            <div style={{ color: colors.muted, lineHeight: 1.7 }}>
                              {selectedIncident.incident_report.executive_summary}
                            </div>
                          </Section>
                        ) : null}
                      </>
                    )}
                  </div>
                </div>
              </Section>
            </>
          ) : (
            <div style={emptyStateStyle}>Select a website to continue.</div>
          )}
        </main>
      </div>
    </div>
  );
}

function StatCard({ label, value }) {
  return (
    <div style={statCardStyle}>
      <div style={eyebrowStyle}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700 }}>{value}</div>
    </div>
  );
}

const pageStyle = {
  minHeight: "100vh",
  background: colors.background,
  color: colors.text,
  fontFamily: 'ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif',
  padding: 24,
  boxSizing: "border-box",
};

const heroWrapStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1fr) 380px",
  gap: 24,
  maxWidth: 1180,
  margin: "80px auto",
  alignItems: "center",
};

const authCardStyle = {
  background: colors.panel,
  border: `1px solid ${colors.border}`,
  borderRadius: 14,
  padding: 24,
  display: "flex",
  flexDirection: "column",
  gap: 12,
};

const topBarStyle = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start",
  gap: 16,
  maxWidth: 1480,
  margin: "0 auto 20px",
  flexWrap: "wrap",
};

const mainGridStyle = {
  display: "grid",
  gridTemplateColumns: "320px minmax(0, 1fr)",
  gap: 20,
  maxWidth: 1480,
  margin: "0 auto",
};

const sidebarStyle = {
  display: "flex",
  flexDirection: "column",
  gap: 16,
};

const sectionStyle = {
  background: colors.panel,
  border: `1px solid ${colors.border}`,
  borderRadius: 12,
  padding: 20,
  marginBottom: 16,
};

const inputStyle = {
  width: "100%",
  padding: "12px 14px",
  borderRadius: 10,
  border: `1px solid ${colors.border}`,
  outline: "none",
  fontSize: 14,
  boxSizing: "border-box",
};

const primaryButtonStyle = {
  border: "none",
  borderRadius: 10,
  padding: "11px 14px",
  background: colors.text,
  color: "#ffffff",
  fontWeight: 600,
  cursor: "pointer",
};

const secondaryButtonStyle = {
  border: `1px solid ${colors.border}`,
  borderRadius: 10,
  padding: "11px 14px",
  background: colors.panel,
  color: colors.text,
  fontWeight: 600,
  cursor: "pointer",
};

const errorStyle = {
  background: "#fff1f1",
  border: `1px solid #f1d1d1`,
  color: colors.red,
  padding: "10px 12px",
  borderRadius: 10,
};

const setupCardStyle = {
  maxWidth: 760,
  margin: "40px auto",
  background: colors.panel,
  border: `1px solid ${colors.border}`,
  borderRadius: 14,
  padding: 24,
};

const formGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
  gap: 12,
  marginBottom: 16,
};

const websiteButtonStyle = {
  textAlign: "left",
  border: `1px solid ${colors.border}`,
  borderRadius: 10,
  padding: 12,
  cursor: "pointer",
};

const feedCardStyle = {
  background: colors.panelAlt,
  border: `1px solid ${colors.border}`,
  borderRadius: 10,
  padding: 12,
};

const statsGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
  gap: 14,
};

const miniStatsGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
  gap: 12,
  marginBottom: 16,
};

const statCardStyle = {
  background: colors.panel,
  border: `1px solid ${colors.border}`,
  borderRadius: 12,
  padding: "16px 18px",
};

const eyebrowStyle = {
  color: colors.subtle,
  fontSize: 12,
  fontWeight: 600,
  marginBottom: 6,
};

const monoBoxStyle = {
  background: "#fafaf9",
  border: `1px solid ${colors.border}`,
  borderRadius: 10,
  padding: 12,
  fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", monospace',
  color: colors.text,
  overflowX: "auto",
  fontSize: 13,
  lineHeight: 1.6,
};

const emptyStateStyle = {
  background: colors.panel,
  border: `1px solid ${colors.border}`,
  borderRadius: 12,
  padding: 30,
  color: colors.muted,
  textAlign: "center",
};
