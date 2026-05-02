import React, { useEffect, useMemo, useRef, useState } from "react";

const API_BASE = "http://localhost:8000";
const WS_URL = "ws://localhost:8000/ws";
const TOKEN_KEY = "cyberagent_token";

const colors = {
  background: "#f3efe7",
  canvas: "#fffdf8",
  panel: "#ffffff",
  panelAlt: "#f7f0e3",
  border: "#ded4c3",
  text: "#1f1b16",
  muted: "#6a6256",
  subtle: "#8b8376",
  green: "#198754",
  red: "#c5422f",
  amber: "#b7791f",
  blue: "#1f5eff",
  gold: "#a06b11",
  ink: "#11213b",
};

const severityColors = {
  CRITICAL: colors.red,
  HIGH: "#d9730d",
  MEDIUM: colors.amber,
  LOW: colors.green,
};

const policyColors = {
  auto_execute: colors.green,
  approval_required: colors.amber,
  manual_escalation: colors.red,
};

function isoNow() {
  return new Date().toISOString();
}

function accessEvent(srcIp, path, method = "GET", statusCode = 200, userAgent = "novacart-browser", bytes = 512) {
  const timestamp = isoNow();
  return {
    event_type: "access",
    timestamp,
    src_ip: srcIp,
    path,
    method,
    status_code: statusCode,
    bytes_sent: bytes,
    user_agent: userAgent,
    message: `${timestamp} ACCESS src=${srcIp} method=${method} path=${path} status=${statusCode} bytes=${bytes} user_agent=${userAgent}`,
  };
}

function authEvent(srcIp, username, result, port = 22) {
  const timestamp = isoNow();
  return {
    event_type: "auth",
    timestamp,
    src_ip: srcIp,
    username,
    result,
    port,
    message: `${timestamp} AUTH service=sshd src=${srcIp} user=${username} result=${result} port=${port}`,
  };
}

function networkEvent(srcIp, dstIp, port, packets, bytes, flags = "ACK") {
  const timestamp = isoNow();
  return {
    event_type: "network",
    timestamp,
    src_ip: srcIp,
    dst_ip: dstIp,
    port,
    protocol: "TCP",
    packets,
    bytes_sent: bytes,
    flags,
    message: `${timestamp} NETFLOW src=${srcIp} dst=${dstIp}:${port} proto=TCP packets=${packets} bytes=${bytes} flags=${flags}`,
  };
}

function buildCollectorScenarioPayload(kind, website) {
  const sourceLabel = `${website?.name || "NovaCart"} demo website collector`;
  const targetIp = "10.0.0.12";
  const customerIp = "198.51.100.24";

  if (kind === "normal") {
    return {
      source_label: sourceLabel,
      run_detection: false,
      events: [
        accessEvent(customerIp, "/"),
        accessEvent(customerIp, "/products"),
        accessEvent(customerIp, "/checkout", "POST", 200, "novacart-browser", 920),
      ],
    };
  }

  if (kind === "bruteforce") {
    return {
      source_label: sourceLabel,
      run_detection: true,
      events: [
        ...Array.from({ length: 12 }, () => authEvent(customerIp, "admin", "FAILED", 22)),
        ...Array.from({ length: 8 }, () => networkEvent(customerIp, targetIp, 22, 130, 4600, "ACK")),
        accessEvent(customerIp, "/admin/login", "POST", 401, "credential-checker", 742),
      ],
    };
  }

  if (kind === "recon") {
    const paths = ["/admin", "/admin/login", "/.env", "/config.php", "/server-status", "/backup.zip", "/wp-admin"];
    return {
      source_label: sourceLabel,
      run_detection: true,
      events: [
        ...paths.map((path) => accessEvent(customerIp, path, "GET", 403, "recon-bot", 228)),
        ...paths.map(() => networkEvent(customerIp, targetIp, 443, 16, 920, "SYN")),
      ],
    };
  }

  return {
    source_label: sourceLabel,
    run_detection: true,
    events: [
      ...Array.from({ length: 28 }, (_, index) =>
        accessEvent(`203.0.113.${20 + (index % 10)}`, ["/", "/products", "/login", "/api/search"][index % 4], "GET", 200, "loadbot", 1400)
      ),
      ...Array.from({ length: 28 }, (_, index) =>
        networkEvent(`203.0.113.${20 + (index % 10)}`, targetIp, 443, 6000 + index * 100, 280000 + index * 1000, "SYN")
      ),
    ],
  };
}

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
        padding: "7px 12px",
        borderRadius: 999,
        border: `1px solid ${color}`,
        background: `${color}12`,
        color,
        fontSize: 12,
        fontWeight: 700,
        textTransform: "capitalize",
      }}
    >
      {children}
    </span>
  );
}

function Section({ title, eyebrow, right, children }) {
  return (
    <section style={sectionStyle}>
      <div style={sectionHeaderStyle}>
        <div>
          {eyebrow ? <div style={eyebrowStyle}>{eyebrow}</div> : null}
          <div style={{ fontSize: 20, fontWeight: 700 }}>{title}</div>
        </div>
        {right}
      </div>
      {children}
    </section>
  );
}

function StatCard({ label, value, hint }) {
  return (
    <div style={statCardStyle}>
      <div style={eyebrowStyle}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, margin: "6px 0 4px" }}>{value}</div>
      <div style={{ color: colors.subtle, fontSize: 12 }}>{hint}</div>
    </div>
  );
}

function Field({ label, value, accent }) {
  return (
    <div>
      <div style={eyebrowStyle}>{label}</div>
      <div style={{ color: accent || colors.text, fontWeight: 600, lineHeight: 1.5, wordBreak: "break-word" }}>
        {value || "—"}
      </div>
    </div>
  );
}

function EmptyState({ title, body }) {
  return (
    <div style={{ padding: 20, border: `1px dashed ${colors.border}`, borderRadius: 20, color: colors.muted }}>
      <div style={{ fontWeight: 700, marginBottom: 6 }}>{title}</div>
      <div style={{ lineHeight: 1.6 }}>{body}</div>
    </div>
  );
}

function App() {
  const [mode, setMode] = useState("login");
  const [token, setToken] = useState(localStorage.getItem(TOKEN_KEY) || "");
  const [user, setUser] = useState(null);
  const [websites, setWebsites] = useState([]);
  const [selectedWebsiteId, setSelectedWebsiteId] = useState("");
  const [incidents, setIncidents] = useState({});
  const [selectedIncidentId, setSelectedIncidentId] = useState("");
  const [feed, setFeed] = useState([]);
  const [telemetry, setTelemetry] = useState({ total_events: 0, counts: {}, recent_events: [] });
  const [integration, setIntegration] = useState(null);
  const [connected, setConnected] = useState(false);
  const [autoRunning, setAutoRunning] = useState(false);
  const [decisionLoading, setDecisionLoading] = useState({});
  const [collectorLoading, setCollectorLoading] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const reconnectRef = useRef(null);

  const [authForm, setAuthForm] = useState({ name: "", email: "", password: "" });
  const [websiteForm, setWebsiteForm] = useState({ name: "", domain: "", environment: "production" });

  useEffect(() => {
    if (!token) {
      setUser(null);
      setWebsites([]);
      setSelectedWebsiteId("");
      setTelemetry({ total_events: 0, counts: {}, recent_events: [] });
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
        setSelectedWebsiteId((current) => current || websiteList[0]?._id || "");
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
        setFeed((current) => [entry, ...current].slice(0, 80));

        if (payload.type === "init") {
          const mapped = {};
          (payload.data.incidents || []).forEach((incident) => {
            mapped[incident.attack_id] = incident;
          });
          setIncidents(mapped);
          setAutoRunning(Boolean(payload.data.running));
        }

        if (payload.data?.attack_id) {
          setIncidents((current) => {
            const existing = current[payload.data.attack_id] || {};
            return {
              ...current,
              [payload.data.attack_id]: {
                ...existing,
                ...payload.data,
                attack_id: payload.data.attack_id,
                simulation: payload.data.simulation || existing.simulation,
                telemetry: payload.data.telemetry || existing.telemetry,
                anomaly: payload.data.anomaly || existing.anomaly,
                correlation: payload.data.correlation || existing.correlation,
                classification: payload.data.classification || existing.classification,
                investigation: payload.data.investigation || existing.investigation,
                mitigation_plan: payload.data.mitigation_plan || existing.mitigation_plan,
                policy_decision: payload.data.policy_decision || existing.policy_decision,
                action_result: payload.data.action_result || existing.action_result,
                incident_report: payload.data.incident_report || existing.incident_report,
                agent_trace: payload.data.agent_trace || existing.agent_trace,
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

    async function loadWebsiteData() {
      try {
        const [websiteIncidents, telemetryData, integrationData] = await Promise.all([
          apiFetch(`/websites/${selectedWebsiteId}/incidents`, {}, token),
          apiFetch(`/websites/${selectedWebsiteId}/telemetry`, {}, token),
          apiFetch(`/websites/${selectedWebsiteId}/integration`, {}, token),
        ]);
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
        setTelemetry(telemetryData);
        setIntegration(integrationData);
        setSelectedIncidentId((current) => current || websiteIncidents[0]?.attack_id || "");
      } catch (err) {
        setError(err.message);
      }
    }

    loadWebsiteData();
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

  const stats = useMemo(
    () => ({
      incidents: websiteIncidents.length,
      autoExecuted: websiteIncidents.filter((incident) => incident.action_result?.execution_mode === "AUTONOMOUS").length,
      approvals: websiteIncidents.filter((incident) => incident.policy_decision?.mode === "approval_required").length,
      critical: websiteIncidents.filter((incident) => incident.classification?.attack?.severity === "CRITICAL").length,
    }),
    [websiteIncidents]
  );

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
      setWebsiteForm({ name: "", domain: "", environment: "production" });
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
      const telemetryData = await apiFetch(`/websites/${selectedWebsiteId}/telemetry`, {}, token);
      setTelemetry(telemetryData);
    } catch (err) {
      setError(err.message);
    }
  }

  async function refreshWebsiteData() {
    if (!token || !selectedWebsiteId) {
      return;
    }
    const [websiteIncidents, telemetryData, integrationData] = await Promise.all([
      apiFetch(`/websites/${selectedWebsiteId}/incidents`, {}, token),
      apiFetch(`/websites/${selectedWebsiteId}/telemetry`, {}, token),
      apiFetch(`/websites/${selectedWebsiteId}/integration`, {}, token),
    ]);
    setIncidents((current) => {
      const next = { ...current };
      websiteIncidents.forEach((incident) => {
        next[incident.attack_id] = incident;
      });
      return next;
    });
    setTelemetry(telemetryData);
    setIntegration(integrationData);
    setSelectedIncidentId((current) => current || websiteIncidents[0]?.attack_id || "");
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

  async function decideIncident(decision) {
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

  async function runCollectorScenario(kind) {
    if (!selectedWebsite?.collector?.ingest_token) {
      return;
    }
    try {
      setCollectorLoading(kind);
      setError("");
      const payload = buildCollectorScenarioPayload(kind, selectedWebsite);
      const response = await fetch(`${API_BASE}/collector/ingest`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Collector-Token": selectedWebsite.collector.ingest_token,
        },
        body: JSON.stringify(payload),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.detail || "Collector ingestion failed");
      }
      await refreshWebsiteData();
    } catch (err) {
      setError(err.message);
    } finally {
      setCollectorLoading("");
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
    setFeed([]);
    setIntegration(null);
  }

  if (!user) {
    return (
      <div style={pageStyle}>
        <div style={heroWrapStyle}>
          <div style={{ maxWidth: 620 }}>
            <div style={eyebrowStyle}>Autonomous AI SOC</div>
            <div style={heroTitleStyle}>Multi-agent cyber defense for startups with 70% automated response.</div>
            <div style={heroBodyStyle}>
              Connect application, authentication, and network telemetry. Watch cooperating AI agents normalize,
              detect, investigate, classify, plan, and either auto-contain threats or escalate them for approval.
            </div>
            <div style={heroBadgeRowStyle}>
              <StatusPill color={colors.green}>Collector-driven telemetry</StatusPill>
              <StatusPill color={colors.blue}>Agent traceable investigations</StatusPill>
              <StatusPill color={colors.amber}>Human oversight for risky actions</StatusPill>
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
              {loading ? "Working..." : mode === "signup" ? "Create workspace" : "Log in"}
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
            <div style={eyebrowStyle}>Workspace</div>
            <div style={{ fontSize: 30, fontWeight: 700 }}>{user.name}</div>
          </div>
          <button onClick={logout} style={secondaryButtonStyle}>
            Log out
          </button>
        </div>
        <div style={setupCardStyle}>
          <div style={eyebrowStyle}>Protected project</div>
          <div style={{ fontSize: 30, fontWeight: 700, marginBottom: 10 }}>Create your first monitored startup app</div>
          <div style={{ color: colors.muted, lineHeight: 1.7, marginBottom: 18 }}>
            This creates a tenant-scoped project, collector token, telemetry store, and autonomous agent workflow so
            you can demo the complete SaaS flow right away.
          </div>
          <div style={formGridStyle}>
            <input
              value={websiteForm.name}
              onChange={(event) => setWebsiteForm((current) => ({ ...current, name: event.target.value }))}
              placeholder="Project name"
              style={inputStyle}
            />
            <input
              value={websiteForm.domain}
              onChange={(event) => setWebsiteForm((current) => ({ ...current, domain: event.target.value }))}
              placeholder="Domain"
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
            {loading ? "Creating..." : "Create protected project"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={pageStyle}>
      <div style={topBarStyle}>
        <div>
          <div style={eyebrowStyle}>CyberAgent Command</div>
          <div style={{ fontSize: 32, fontWeight: 800 }}>Autonomous AI SOC</div>
          <div style={{ color: colors.muted, marginTop: 6 }}>
            AI agents handle ingestion, triage, investigation, policy, and response while humans stay in the loop for risky actions.
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <StatusPill color={connected ? colors.green : colors.red}>
            {connected ? "Realtime connected" : "Live stream disconnected"}
          </StatusPill>
          <button onClick={logout} style={secondaryButtonStyle}>
            Log out
          </button>
        </div>
      </div>

      {error ? <div style={errorStyle}>{error}</div> : null}

      <div style={dashboardLayoutStyle}>
        <aside style={sidebarStyle}>
          <Section title="Protected projects" eyebrow="Multi-tenant workspaces">
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {websites.map((website) => (
                <button
                  key={website._id}
                  onClick={() => setSelectedWebsiteId(website._id)}
                  style={{
                    ...projectCardStyle,
                    background: selectedWebsiteId === website._id ? colors.panelAlt : colors.panel,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 10, marginBottom: 8 }}>
                    <div style={{ fontWeight: 700 }}>{website.name}</div>
                    <StatusPill color={website.status === "connected" ? colors.green : colors.amber}>{website.status}</StatusPill>
                  </div>
                  <div style={{ color: colors.muted, fontSize: 13 }}>{website.domain}</div>
                  <div style={{ color: colors.subtle, fontSize: 12, marginTop: 6 }}>{website.environment}</div>
                </button>
              ))}
            </div>
          </Section>

          <Section title="Agent activity" eyebrow="Live orchestration feed">
            <div style={{ display: "flex", flexDirection: "column", gap: 10, maxHeight: 420, overflowY: "auto" }}>
              {feed
                .filter((entry) => !selectedWebsiteId || entry.data.website_id === selectedWebsiteId || entry.type === "init")
                .map((entry) => (
                  <div key={entry.id} style={feedCardStyle}>
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 10, marginBottom: 6 }}>
                      <div style={{ fontSize: 12, fontWeight: 700 }}>{entry.data.agent_trace_entry?.agent || entry.type}</div>
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

        <main style={{ minWidth: 0, display: "flex", flexDirection: "column", gap: 20 }}>
          {selectedWebsite ? (
            <>
              <Section
                title={selectedWebsite.name}
                eyebrow="Protected application"
                right={
                  <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                    <button onClick={simulateAttack} style={primaryButtonStyle}>
                      Simulate attack
                    </button>
                    <button onClick={toggleAuto} style={secondaryButtonStyle}>
                      {autoRunning ? "Stop auto monitor" : "Start auto monitor"}
                    </button>
                  </div>
                }
              >
                <div style={heroPanelStyle}>
                  <div style={metaGridStyle}>
                    <Field label="Domain" value={selectedWebsite.domain} />
                    <Field label="Environment" value={selectedWebsite.environment} />
                    <Field label="Collector mode" value={selectedWebsite.collector?.mode || "agent"} />
                    <Field label="Project status" value={selectedWebsite.status} accent={colors.green} />
                  </div>
                  <div style={collectorCardStyle}>
                    <div>
                      <div style={eyebrowStyle}>Collector token</div>
                      <div style={tokenStyle}>{selectedWebsite.collector?.ingest_token || "Unavailable"}</div>
                    </div>
                    <div style={{ color: colors.muted, lineHeight: 1.6, fontSize: 14 }}>
                      Customer-side collector posts batched events to `POST /collector/ingest` with `X-Collector-Token`.
                    </div>
                  </div>
                </div>
              </Section>

              <Section title="Integration lab" eyebrow="Collector setup and customer onboarding">
                <div style={integrationGridStyle}>
                  <div style={integrationPanelStyle}>
                    <div style={eyebrowStyle}>How it connects</div>
                    <div style={{ fontSize: 24, fontWeight: 800, marginBottom: 10 }}>
                      {selectedWebsite.demo_site?.name || "NovaCart"} sends telemetry with the collector token.
                    </div>
                    <div style={{ color: colors.muted, lineHeight: 1.7, marginBottom: 16 }}>
                      In a real deployment, a small collector runs beside the customer website, reads app, auth, and
                      network events, and posts them to your backend with the project token in the header.
                    </div>
                    <div style={tableWrapStyle}>
                      <div style={tableRowStyle}>
                        <div style={{ fontWeight: 700, minWidth: 130 }}>Step 1</div>
                        <div style={{ color: colors.muted }}>Create the protected project and copy its collector token.</div>
                      </div>
                      <div style={tableRowStyle}>
                        <div style={{ fontWeight: 700, minWidth: 130 }}>Step 2</div>
                        <div style={{ color: colors.muted }}>
                          Paste the token into the customer-side collector as `CYBERAGENT_COLLECTOR_TOKEN`.
                        </div>
                      </div>
                      <div style={tableRowStyle}>
                        <div style={{ fontWeight: 700, minWidth: 130 }}>Step 3</div>
                        <div style={{ color: colors.muted }}>
                          The collector sends batched events to `/collector/ingest` using `X-Collector-Token`.
                        </div>
                      </div>
                    </div>
                  </div>

                  <div style={codePanelStyle}>
                    <div style={eyebrowStyle}>Collector request</div>
                    <pre style={codeBlockStyle}>
{`POST ${integration?.ingest_url || `${API_BASE}/collector/ingest`}
Header: ${integration?.token_header || "X-Collector-Token"}: ${selectedWebsite.collector?.ingest_token || ""}
Body: {
  "source_label": "${selectedWebsite.name} web collector",
  "run_detection": true,
  "events": [...]
}`}
                    </pre>
                    <div style={{ color: colors.subtle, fontSize: 13, lineHeight: 1.6 }}>
                      Sample collector file: `backend/collector_agent.py`
                    </div>
                  </div>
                </div>
              </Section>

              <Section title="Dummy customer website" eyebrow="Live integration demo">
                <div style={dummySiteShellStyle}>
                  <div style={dummyNavStyle}>
                    <div>
                      <div style={{ fontWeight: 800, fontSize: 22 }}>{selectedWebsite.demo_site?.name || "NovaCart"}</div>
                      <div style={{ color: "#b7c7ec", fontSize: 13 }}>A protected startup storefront integrated with CyberAgent</div>
                    </div>
                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                      <StatusPill color="#9ed0ff">Collector installed</StatusPill>
                      <StatusPill color="#8de1b0">Project token active</StatusPill>
                    </div>
                  </div>

                  <div style={dummyHeroGridStyle}>
                    <div>
                      <div style={{ color: "#ffe8a3", fontSize: 12, fontWeight: 800, letterSpacing: 1.2, textTransform: "uppercase" }}>
                        Demo storefront
                      </div>
                      <div style={{ fontSize: 36, lineHeight: 1.05, fontWeight: 800, margin: "10px 0 12px" }}>
                        Payments, logins, and customer traffic that your AI SOC can actually monitor.
                      </div>
                      <div style={{ color: "#d8e4ff", lineHeight: 1.7, maxWidth: 560 }}>
                        Use these actions to simulate what happens on a startup website. Each button sends real
                        collector telemetry into the platform using the token above.
                      </div>
                      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 20 }}>
                        <button
                          onClick={() => runCollectorScenario("normal")}
                          style={sitePrimaryButtonStyle}
                          disabled={Boolean(collectorLoading)}
                        >
                          {collectorLoading === "normal" ? "Sending..." : "Browse products"}
                        </button>
                        <button
                          onClick={() => runCollectorScenario("bruteforce")}
                          style={siteSecondaryButtonStyle}
                          disabled={Boolean(collectorLoading)}
                        >
                          {collectorLoading === "bruteforce" ? "Sending..." : "Simulate failed logins"}
                        </button>
                        <button
                          onClick={() => runCollectorScenario("recon")}
                          style={siteSecondaryButtonStyle}
                          disabled={Boolean(collectorLoading)}
                        >
                          {collectorLoading === "recon" ? "Sending..." : "Simulate recon scan"}
                        </button>
                        <button
                          onClick={() => runCollectorScenario("traffic")}
                          style={siteAlertButtonStyle}
                          disabled={Boolean(collectorLoading)}
                        >
                          {collectorLoading === "traffic" ? "Sending..." : "Simulate traffic spike"}
                        </button>
                      </div>
                    </div>

                    <div style={siteInfoPanelStyle}>
                      <div style={eyebrowStyle}>What each action does</div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                        <div style={siteInfoCardStyle}>
                          <div style={{ fontWeight: 700 }}>Browse products</div>
                          <div style={{ color: "#c8d6f2", fontSize: 13 }}>Normal access events only. Useful to show healthy telemetry.</div>
                        </div>
                        <div style={siteInfoCardStyle}>
                          <div style={{ fontWeight: 700 }}>Failed logins</div>
                          <div style={{ color: "#c8d6f2", fontSize: 13 }}>Creates a brute-force style auth burst and opens an incident.</div>
                        </div>
                        <div style={siteInfoCardStyle}>
                          <div style={{ fontWeight: 700 }}>Recon scan</div>
                          <div style={{ color: "#c8d6f2", fontSize: 13 }}>Probes sensitive paths like `/admin` and `/.env`.</div>
                        </div>
                        <div style={siteInfoCardStyle}>
                          <div style={{ fontWeight: 700 }}>Traffic spike</div>
                          <div style={{ color: "#c8d6f2", fontSize: 13 }}>Generates a DDoS-like burst with many access and network events.</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </Section>

              <div style={statsGridStyle}>
                <StatCard label="Total telemetry events" value={telemetry.total_events || 0} hint="Collector-fed access, auth, and network data" />
                <StatCard label="Incidents" value={stats.incidents} hint="Detected across this protected project" />
                <StatCard label="Auto-executed" value={stats.autoExecuted} hint="Resolved autonomously by policy" />
                <StatCard label="Approval-gated" value={stats.approvals} hint="Queued for human decision" />
              </div>

              <Section title="Telemetry overview" eyebrow="Normalized event streams">
                <div style={statsGridStyle}>
                  <StatCard label="Access events" value={telemetry.counts?.access || 0} hint="Application requests" />
                  <StatCard label="Auth events" value={telemetry.counts?.auth || 0} hint="Identity and login activity" />
                  <StatCard label="Network events" value={telemetry.counts?.network || 0} hint="Connection and flow telemetry" />
                </div>
                <div style={tableWrapStyle}>
                  {(telemetry.recent_events || []).slice(0, 8).map((event, index) => (
                    <div key={`${event.attack_id || "event"}-${index}`} style={tableRowStyle}>
                      <div style={{ fontWeight: 700, minWidth: 90 }}>{event.event_type}</div>
                      <div style={{ color: colors.muted, flex: 1 }}>{event.message}</div>
                    </div>
                  ))}
                </div>
              </Section>

              <Section title="Incident queue" eyebrow="AI-driven detections">
                <div style={incidentLayoutStyle}>
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {websiteIncidents.length ? (
                      websiteIncidents.map((incident) => {
                        const severity = incident.classification?.attack?.severity || "LOW";
                        const policyMode = incident.policy_decision?.mode || "approval_required";
                        return (
                          <button
                            key={incident.attack_id}
                            onClick={() => setSelectedIncidentId(incident.attack_id)}
                            style={{
                              ...projectCardStyle,
                              background: selectedIncident?.attack_id === incident.attack_id ? colors.panelAlt : colors.panel,
                            }}
                          >
                            <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 10 }}>
                              <div style={{ fontWeight: 700 }}>{incident.classification?.predicted_class || incident.attack_id}</div>
                              <StatusPill color={severityColors[severity] || colors.amber}>{severity}</StatusPill>
                            </div>
                            <div style={{ color: colors.muted, fontSize: 13, marginBottom: 8 }}>
                              {incident.simulation?.description || "Investigation in progress"}
                            </div>
                            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                              <StatusPill color={policyColors[policyMode] || colors.blue}>{policyMode.replaceAll("_", " ")}</StatusPill>
                              {incident.action_result?.execution_mode ? (
                                <StatusPill color={colors.blue}>{incident.action_result.execution_mode.replaceAll("_", " ")}</StatusPill>
                              ) : null}
                            </div>
                          </button>
                        );
                      })
                    ) : (
                      <EmptyState title="No incidents yet" body="Run the simulator or start auto-monitoring to generate collector-fed threat telemetry." />
                    )}
                  </div>

                  <div>
                    {selectedIncident ? (
                      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                        <div style={detailHeroStyle}>
                          <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
                            <div>
                              <div style={eyebrowStyle}>Incident</div>
                              <div style={{ fontSize: 28, fontWeight: 800 }}>
                                {selectedIncident.classification?.predicted_class || selectedIncident.attack_id}
                              </div>
                            </div>
                            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                              <StatusPill
                                color={severityColors[selectedIncident.classification?.attack?.severity || "MEDIUM"] || colors.amber}
                              >
                                {selectedIncident.classification?.attack?.severity || "MEDIUM"}
                              </StatusPill>
                              <StatusPill
                                color={policyColors[selectedIncident.policy_decision?.mode || "approval_required"] || colors.blue}
                              >
                                {(selectedIncident.policy_decision?.mode || "approval_required").replaceAll("_", " ")}
                              </StatusPill>
                            </div>
                          </div>
                          <div style={{ color: colors.muted, lineHeight: 1.6, marginTop: 12 }}>
                            {selectedIncident.anomaly?.summary || selectedIncident.simulation?.description}
                          </div>
                        </div>

                        <div style={metaGridStyle}>
                          <Field label="Primary source" value={selectedIncident.classification?.attack?.primary_src_ip} />
                          <Field
                            label="Target"
                            value={
                              selectedIncident.classification?.attack
                                ? `${selectedIncident.classification.attack.target_ip}:${selectedIncident.classification.attack.target_port}`
                                : "—"
                            }
                          />
                          <Field
                            label="Confidence"
                            value={
                              selectedIncident.classification?.confidence
                                ? `${Math.round(selectedIncident.classification.confidence * 100)}%`
                                : "—"
                            }
                          />
                          <Field label="Risk score" value={selectedIncident.classification?.risk_score} />
                        </div>

                        <Section title="Automation decision" eyebrow="Policy agent">
                          <div style={tableWrapStyle}>
                            <Field label="Policy mode" value={selectedIncident.policy_decision?.mode?.replaceAll("_", " ")} />
                            <Field label="Reason" value={selectedIncident.policy_decision?.reason} />
                            <Field
                              label="Execution status"
                              value={selectedIncident.action_result?.execution_mode?.replaceAll("_", " ") || "Awaiting action"}
                            />
                          </div>
                          {selectedIncident.approval_status === "pending" ? (
                            <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 16 }}>
                              <button
                                onClick={() => decideIncident("approved")}
                                style={primaryButtonStyle}
                                disabled={decisionLoading[selectedIncident.attack_id]}
                              >
                                {decisionLoading[selectedIncident.attack_id] ? "Applying..." : "Approve containment"}
                              </button>
                              <button
                                onClick={() => decideIncident("rejected")}
                                style={dangerButtonStyle}
                                disabled={decisionLoading[selectedIncident.attack_id]}
                              >
                                Reject to manual queue
                              </button>
                            </div>
                          ) : null}
                        </Section>

                        <Section title="Agent trace" eyebrow="Explainable orchestration">
                          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                            {(selectedIncident.agent_trace || []).map((entry, index) => (
                              <div key={`${entry.agent}-${index}`} style={traceCardStyle}>
                                <div style={{ display: "flex", justifyContent: "space-between", gap: 10, marginBottom: 6 }}>
                                  <div style={{ fontWeight: 700 }}>{entry.agent}</div>
                                  <div style={{ color: colors.subtle, fontSize: 12 }}>{entry.stage}</div>
                                </div>
                                <div style={{ color: colors.muted, lineHeight: 1.5 }}>{entry.summary}</div>
                              </div>
                            ))}
                          </div>
                        </Section>

                        <Section title="Evidence and playbook" eyebrow="Investigation output">
                          <div style={metaGridStyle}>
                            <Field
                              label="Affected assets"
                              value={(selectedIncident.investigation?.affected_assets || []).join(", ")}
                            />
                            <Field
                              label="Flagged paths"
                              value={(selectedIncident.anomaly?.flagged_paths || []).join(", ")}
                            />
                          </div>
                          <div style={tableWrapStyle}>
                            {(selectedIncident.mitigation_plan?.steps || []).map((step) => (
                              <div key={step.step} style={tableRowStyle}>
                                <div style={{ fontWeight: 700, minWidth: 88 }}>Step {step.step}</div>
                                <div style={{ flex: 1 }}>
                                  <div style={{ fontWeight: 700 }}>{step.action}</div>
                                  <div style={{ color: colors.muted, fontSize: 13, marginTop: 4 }}>{step.command}</div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </Section>

                        <Section title="Final report" eyebrow="Reporting agent">
                          {selectedIncident.incident_report ? (
                            <>
                              <div style={{ color: colors.muted, lineHeight: 1.7, marginBottom: 16 }}>
                                {selectedIncident.incident_report.executive_summary}
                              </div>
                              <div style={metaGridStyle}>
                                <Field label="Response" value={selectedIncident.incident_report.response} />
                                <Field label="Policy mode" value={selectedIncident.incident_report.automation?.policy_mode} />
                                <Field label="Execution mode" value={selectedIncident.incident_report.automation?.execution_mode} />
                              </div>
                            </>
                          ) : (
                            <EmptyState title="Report pending" body="The final report appears after the response path completes." />
                          )}
                        </Section>
                      </div>
                    ) : (
                      <EmptyState title="Choose an incident" body="Select an incident from the queue to inspect its agent trace, evidence, and automation policy." />
                    )}
                  </div>
                </div>
              </Section>
            </>
          ) : null}
        </main>
      </div>
    </div>
  );
}

const pageStyle = {
  minHeight: "100vh",
  background: "radial-gradient(circle at top left, #fff7ea 0%, #f3efe7 45%, #ece6da 100%)",
  color: colors.text,
  padding: "28px 28px 40px",
  fontFamily: '"Avenir Next", "Segoe UI", sans-serif',
};

const heroWrapStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1.2fr) minmax(360px, 420px)",
  gap: 24,
  alignItems: "center",
  maxWidth: 1180,
  margin: "40px auto",
};

const heroTitleStyle = {
  fontSize: 54,
  lineHeight: 1.05,
  fontWeight: 800,
  letterSpacing: -1.6,
  marginBottom: 16,
};

const heroBodyStyle = {
  color: colors.muted,
  fontSize: 18,
  lineHeight: 1.8,
  maxWidth: 620,
};

const heroBadgeRowStyle = {
  display: "flex",
  gap: 10,
  flexWrap: "wrap",
  marginTop: 24,
};

const topBarStyle = {
  display: "flex",
  justifyContent: "space-between",
  gap: 20,
  alignItems: "flex-start",
  marginBottom: 24,
  flexWrap: "wrap",
};

const dashboardLayoutStyle = {
  display: "grid",
  gridTemplateColumns: "320px minmax(0, 1fr)",
  gap: 20,
  alignItems: "start",
};

const sidebarStyle = {
  display: "flex",
  flexDirection: "column",
  gap: 20,
};

const sectionStyle = {
  background: "rgba(255,255,255,0.9)",
  border: `1px solid ${colors.border}`,
  borderRadius: 28,
  padding: 22,
  boxShadow: "0 18px 50px rgba(31,27,22,0.06)",
};

const sectionHeaderStyle = {
  display: "flex",
  justifyContent: "space-between",
  gap: 12,
  alignItems: "flex-start",
  marginBottom: 16,
  flexWrap: "wrap",
};

const eyebrowStyle = {
  color: colors.gold,
  fontSize: 11,
  fontWeight: 800,
  letterSpacing: 1.2,
  textTransform: "uppercase",
  marginBottom: 6,
};

const authCardStyle = {
  background: "linear-gradient(180deg, rgba(255,255,255,0.97), rgba(249,243,231,0.98))",
  border: `1px solid ${colors.border}`,
  borderRadius: 30,
  padding: 24,
  boxShadow: "0 20px 60px rgba(31,27,22,0.08)",
  display: "flex",
  flexDirection: "column",
  gap: 12,
};

const setupCardStyle = {
  maxWidth: 920,
  margin: "20px auto",
  background: "rgba(255,255,255,0.94)",
  border: `1px solid ${colors.border}`,
  borderRadius: 28,
  padding: 28,
  boxShadow: "0 18px 50px rgba(31,27,22,0.06)",
};

const inputStyle = {
  width: "100%",
  padding: "14px 16px",
  borderRadius: 16,
  border: `1px solid ${colors.border}`,
  outline: "none",
  fontSize: 15,
  background: colors.canvas,
  boxSizing: "border-box",
};

const formGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
  gap: 12,
  marginBottom: 16,
};

const primaryButtonStyle = {
  padding: "12px 18px",
  borderRadius: 16,
  border: "none",
  background: "linear-gradient(135deg, #1f5eff 0%, #123bb0 100%)",
  color: "#fff",
  fontWeight: 700,
  cursor: "pointer",
};

const secondaryButtonStyle = {
  padding: "12px 18px",
  borderRadius: 16,
  border: `1px solid ${colors.border}`,
  background: colors.panel,
  color: colors.text,
  fontWeight: 700,
  cursor: "pointer",
};

const dangerButtonStyle = {
  padding: "12px 18px",
  borderRadius: 16,
  border: "none",
  background: "linear-gradient(135deg, #d74d38 0%, #a82f26 100%)",
  color: "#fff",
  fontWeight: 700,
  cursor: "pointer",
};

const errorStyle = {
  marginBottom: 18,
  borderRadius: 16,
  border: `1px solid ${colors.red}`,
  background: `${colors.red}14`,
  padding: "12px 14px",
  color: colors.red,
};

const projectCardStyle = {
  width: "100%",
  borderRadius: 20,
  border: `1px solid ${colors.border}`,
  padding: 16,
  textAlign: "left",
  cursor: "pointer",
};

const feedCardStyle = {
  borderRadius: 18,
  border: `1px solid ${colors.border}`,
  padding: 14,
  background: colors.canvas,
};

const statsGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
  gap: 14,
};

const statCardStyle = {
  background: "rgba(255,255,255,0.92)",
  border: `1px solid ${colors.border}`,
  borderRadius: 22,
  padding: 18,
};

const heroPanelStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1fr) minmax(320px, 380px)",
  gap: 18,
  alignItems: "start",
};

const collectorCardStyle = {
  background: "linear-gradient(135deg, rgba(17,33,59,0.96), rgba(31,94,255,0.92))",
  color: "#fff",
  borderRadius: 22,
  padding: 18,
  minHeight: 120,
  display: "flex",
  flexDirection: "column",
  gap: 12,
};

const integrationGridStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1.15fr) minmax(320px, 0.85fr)",
  gap: 16,
  alignItems: "start",
};

const integrationPanelStyle = {
  borderRadius: 24,
  border: `1px solid ${colors.border}`,
  background: colors.canvas,
  padding: 20,
};

const codePanelStyle = {
  borderRadius: 24,
  padding: 20,
  background: "linear-gradient(180deg, #14233e, #0c1630)",
  color: "#edf4ff",
  border: "1px solid rgba(255,255,255,0.08)",
};

const codeBlockStyle = {
  margin: 0,
  whiteSpace: "pre-wrap",
  wordBreak: "break-word",
  fontSize: 13,
  lineHeight: 1.7,
  fontFamily: '"SFMono-Regular", Consolas, monospace',
};

const tokenStyle = {
  fontFamily: '"SFMono-Regular", Consolas, monospace',
  fontSize: 13,
  lineHeight: 1.7,
  background: "rgba(255,255,255,0.14)",
  borderRadius: 14,
  padding: "10px 12px",
  wordBreak: "break-all",
};

const tableWrapStyle = {
  display: "flex",
  flexDirection: "column",
  gap: 10,
};

const tableRowStyle = {
  display: "flex",
  gap: 12,
  alignItems: "flex-start",
  padding: 14,
  borderRadius: 18,
  background: colors.canvas,
  border: `1px solid ${colors.border}`,
};

const incidentLayoutStyle = {
  display: "grid",
  gridTemplateColumns: "320px minmax(0, 1fr)",
  gap: 16,
  alignItems: "start",
};

const detailHeroStyle = {
  padding: 20,
  borderRadius: 24,
  background: "linear-gradient(135deg, rgba(255,248,230,0.95), rgba(255,255,255,0.95))",
  border: `1px solid ${colors.border}`,
};

const dummySiteShellStyle = {
  borderRadius: 28,
  overflow: "hidden",
  background: "linear-gradient(180deg, #132440 0%, #0f1730 100%)",
  color: "#fff",
  border: "1px solid rgba(16,33,59,0.12)",
};

const dummyNavStyle = {
  padding: "18px 20px",
  borderBottom: "1px solid rgba(255,255,255,0.08)",
  display: "flex",
  justifyContent: "space-between",
  gap: 16,
  alignItems: "center",
  flexWrap: "wrap",
};

const dummyHeroGridStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1.2fr) minmax(280px, 0.8fr)",
  gap: 18,
  padding: 22,
  alignItems: "start",
};

const sitePrimaryButtonStyle = {
  padding: "12px 18px",
  borderRadius: 16,
  border: "none",
  background: "linear-gradient(135deg, #ffd166 0%, #e89d1b 100%)",
  color: "#1c1b16",
  fontWeight: 800,
  cursor: "pointer",
};

const siteSecondaryButtonStyle = {
  padding: "12px 18px",
  borderRadius: 16,
  border: "1px solid rgba(255,255,255,0.18)",
  background: "rgba(255,255,255,0.08)",
  color: "#fff",
  fontWeight: 700,
  cursor: "pointer",
};

const siteAlertButtonStyle = {
  padding: "12px 18px",
  borderRadius: 16,
  border: "none",
  background: "linear-gradient(135deg, #ff7a59 0%, #d94a34 100%)",
  color: "#fff",
  fontWeight: 800,
  cursor: "pointer",
};

const siteInfoPanelStyle = {
  borderRadius: 22,
  background: "rgba(255,255,255,0.06)",
  border: "1px solid rgba(255,255,255,0.08)",
  padding: 18,
};

const siteInfoCardStyle = {
  borderRadius: 16,
  background: "rgba(255,255,255,0.06)",
  padding: 14,
};

const traceCardStyle = {
  borderRadius: 18,
  border: `1px solid ${colors.border}`,
  padding: 14,
  background: colors.canvas,
};

const metaGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
  gap: 14,
};

export default App;
