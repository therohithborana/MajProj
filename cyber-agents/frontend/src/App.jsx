import React, { useEffect, useMemo, useRef, useState } from "react";
import { LayoutDashboard, ShieldAlert, Activity, Settings, Bell, Search, PanelLeftClose, PanelLeftOpen } from "lucide-react";

const API_BASE = "http://localhost:8000";
const WS_URL = "ws://localhost:8000/ws";
const TOKEN_KEY = "cyberagent_token";

const colors = {
  background: "#0c0c0d",
  canvas: "#131314",
  panel: "#131314",
  panelAlt: "#1a1a1b",
  border: "#232326",
  text: "#f4f4f5",
  muted: "#a1a1aa",
  subtle: "#71717a",
  green: "#34d399",
  red: "#f87171",
  amber: "#f59e0b",
  blue: "#8b5cf6",
  gold: "#a78bfa",
  ink: "#09090b",
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

function IconButton({ onClick, children, active = false, title }) {
  return (
    <button
      onClick={onClick}
      title={title}
      style={{
        width: 38,
        height: 38,
        borderRadius: 14,
        border: `1px solid ${active ? "#3b2a47" : colors.border}`,
        background: active ? "rgba(167, 139, 250, 0.12)" : colors.panelAlt,
        color: active ? colors.text : colors.muted,
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        cursor: "pointer",
      }}
    >
      {children}
    </button>
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
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const reconnectRef = useRef(null);
  const notificationsRef = useRef(null);
  const profileMenuRef = useRef(null);

  const [authForm, setAuthForm] = useState({ name: "", email: "", password: "" });
  const [websiteForm, setWebsiteForm] = useState({ name: "", domain: "", environment: "production" });
  const [currentTab, setCurrentTab] = useState("dashboard");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfileMenu, setShowProfileMenu] = useState(false);

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
        if (payload.type === "init") {
          const mapped = {};
          (payload.data.incidents || []).forEach((incident) => {
            mapped[incident.attack_id] = incident;
          });
          setIncidents(mapped);
          setAutoRunning(Boolean(payload.data.running));
          return;
        }

        const entry = {
          id: `${Date.now()}-${Math.random()}`,
          timestamp: new Date().toISOString(),
          type: payload.type,
          data: payload.data,
        };
        setFeed((current) => [entry, ...current].slice(0, 80));

        if (payload.type === "telemetry_update" && payload.data?.website_id === selectedWebsiteId && payload.data?.telemetry) {
          setTelemetry(payload.data.telemetry);
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

  useEffect(() => {
    function handlePointerDown(event) {
      if (showNotifications && notificationsRef.current && !notificationsRef.current.contains(event.target)) {
        setShowNotifications(false);
      }
      if (showProfileMenu && profileMenuRef.current && !profileMenuRef.current.contains(event.target)) {
        setShowProfileMenu(false);
      }
    }

    document.addEventListener("mousedown", handlePointerDown);
    return () => document.removeEventListener("mousedown", handlePointerDown);
  }, [showNotifications, showProfileMenu]);

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

  const notificationItems = useMemo(() => {
    const items = [];
    const pending = websiteIncidents.filter((incident) => incident.approval_status === "pending").length;
    if (pending) {
      items.push({
        title: `${pending} pending approval${pending > 1 ? "s" : ""}`,
        detail: "Containment is waiting for analyst approval.",
      });
    }
    feed.slice(0, 4).forEach((entry) => {
      items.push({
        title: entry.data.agent_trace_entry?.agent || entry.type,
        detail: entry.data.message || entry.data.current_stage || "New orchestration activity.",
      });
    });
    return items.slice(0, 5);
  }, [feed, websiteIncidents]);

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
    setShowNotifications(false);
    setShowProfileMenu(false);
  }

  if (!user) {
    return (
      <div style={pageStyle}>
        <div style={landingGlowWrapStyle}>
          <div style={landingGlowPrimaryStyle} />
          <div style={landingGlowSecondaryStyle} />
        </div>

        <div style={landingShellStyle}>
          <header style={landingHeaderStyle}>
            <div style={landingBrandStyle}>
              <div style={landingBrandMarkStyle}>C</div>
              <div>
                <div style={landingBrandNameStyle}>CyberAgent</div>
                <div style={landingBrandSubStyle}>Autonomous AI SOC for startups</div>
              </div>
            </div>
            <nav style={landingNavStyle}>
              <span>How it works</span>
              <span>Features</span>
              <span>Security</span>
              <span>Reviews</span>
            </nav>
          </header>

          <div style={heroWrapStyle}>
            <div style={{ maxWidth: 700 }}>
              <div style={landingBadgeStyle}>Featured architecture: hybrid AI + SOC automation</div>
              <div style={heroTitleStyle}>
                Multi-agent cyber defense for modern startups and customer-facing applications.
              </div>
              <div style={heroBodyStyle}>
                Ingest application, authentication, and network telemetry into one autonomous platform that
                detects threats, coordinates specialist agents, and keeps humans in control only when response
                risk is high.
              </div>
              <div style={heroBadgeRowStyle}>
                <StatusPill color={colors.green}>Collector-based onboarding</StatusPill>
                <StatusPill color={colors.blue}>Agent-to-agent handoffs</StatusPill>
                <StatusPill color={colors.amber}>70% automation, 30% oversight</StatusPill>
              </div>
              <div style={landingStatRowStyle}>
                <div style={landingStatStyle}>
                  <div style={landingStatValueStyle}>3</div>
                  <div style={landingStatLabelStyle}>Telemetry channels</div>
                </div>
                <div style={landingStatStyle}>
                  <div style={landingStatValueStyle}>9</div>
                  <div style={landingStatLabelStyle}>Agent stages</div>
                </div>
                <div style={landingStatStyle}>
                  <div style={landingStatValueStyle}>Live</div>
                  <div style={landingStatLabelStyle}>SOC dashboard</div>
                </div>
              </div>
            </div>

            <div style={authCardStyle}>
              <div style={authCardHeaderStyle}>
                <div style={{ display: "flex", gap: 10 }}>
                  <button onClick={() => setMode("login")} style={mode === "login" ? primaryButtonStyle : secondaryButtonStyle}>
                    Log in
                  </button>
                  <button onClick={() => setMode("signup")} style={mode === "signup" ? primaryButtonStyle : secondaryButtonStyle}>
                    Sign up
                  </button>
                </div>
                <div style={authCardSubStyle}>
                  {mode === "signup" ? "Create your protected workspace" : "Access your SOC workspace"}
                </div>
              </div>
              {mode === "signup" ? (
                <input
                  value={authForm.name}
                  onChange={(event) => setAuthForm((current) => ({ ...current, name: event.target.value }))}
                  placeholder="Full name"
                  style={inputStyle}
                />
              ) : null}
              <input
                value={authForm.email}
                onChange={(event) => setAuthForm((current) => ({ ...current, email: event.target.value }))}
                placeholder="Work email"
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
                {loading ? "Working..." : mode === "signup" ? "Create workspace" : "Enter dashboard"}
              </button>
            </div>
          </div>

          <footer style={landingFooterStyle}>
            <span>Integrates with startup web apps, auth services, collector agents, and network telemetry pipelines</span>
          </footer>
        </div>
      </div>
    );
  }

  if (!websites.length) {
    return (
      <div style={pageStyle}>
        <div style={landingGlowWrapStyle}>
          <div style={landingGlowPrimaryStyle} />
          <div style={landingGlowSecondaryStyle} />
        </div>
        <div style={topBarStyle}>
          <div>
            <div style={eyebrowStyle}>Workspace setup</div>
            <div style={{ fontSize: 30, fontWeight: 700 }}>{user.name}</div>
          </div>
          <button onClick={logout} style={secondaryButtonStyle}>
            Log out
          </button>
        </div>
        <div style={setupSplitStyle}>
          <div style={setupIntroStyle}>
            <div style={landingBadgeStyle}>Protected project onboarding</div>
            <div style={{ fontSize: 48, lineHeight: 1.05, fontWeight: 800, marginBottom: 16 }}>
              Create the first monitored application in your SOC workspace.
            </div>
            <div style={{ color: colors.muted, lineHeight: 1.8, fontSize: 17 }}>
              We’ll provision a tenant-scoped project, generate a collector token, enable telemetry ingestion,
              and prepare the full multi-agent response workflow for live incidents.
            </div>
          </div>
          <div style={setupCardStyle}>
            <div style={eyebrowStyle}>Protected project</div>
            <div style={{ fontSize: 28, fontWeight: 700, marginBottom: 12 }}>Project details</div>
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
      </div>
    );
  }

  return (
    <div className="dashboard-layout">
      <aside className={`sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
        <div className="sidebar-header">
          <ShieldAlert className="sidebar-logo" size={28} />
          {!sidebarCollapsed && <div className="sidebar-title">CyberAgent SOC</div>}
        </div>
        <div className="sidebar-nav">
          <button className={`nav-item ${currentTab === 'dashboard' ? 'active' : ''}`} onClick={() => setCurrentTab('dashboard')}>
            <LayoutDashboard className="nav-item-icon" size={20} />
            {!sidebarCollapsed && <span>Dashboard</span>}
          </button>
          <button className={`nav-item ${currentTab === 'telemetry' ? 'active' : ''}`} onClick={() => setCurrentTab('telemetry')}>
            <Activity className="nav-item-icon" size={20} />
            {!sidebarCollapsed && <span>Telemetry & Lab</span>}
          </button>
          <button className={`nav-item ${currentTab === 'incidents' ? 'active' : ''}`} onClick={() => setCurrentTab('incidents')}>
            <ShieldAlert className="nav-item-icon" size={20} />
            {!sidebarCollapsed && <span>Threat Detection</span>}
          </button>
        </div>
        <div className="sidebar-footer">
          <button className="nav-item" onClick={() => setCurrentTab('telemetry')}>
            <Settings className="nav-item-icon" size={20} />
            {!sidebarCollapsed && <span>Workspace Settings</span>}
          </button>
        </div>
      </aside>

      <main className="main-content">
        <div className="topbar">
          <div className="flex-gap">
            <button className="btn btn-secondary" style={{padding: '8px', border: 'none'}} onClick={() => setSidebarCollapsed(!sidebarCollapsed)}>
              {sidebarCollapsed ? <PanelLeftOpen size={20} /> : <PanelLeftClose size={20} />}
            </button>
            <div className="topbar-search">
              <Search size={18} color="var(--text-subtle)" />
              <input type="text" placeholder="Search incidents, IPs, policies..." />
            </div>
          </div>
          <div className="flex-gap" style={{position: 'relative'}}>
            <StatusPill color={connected ? "var(--color-green)" : "var(--color-red)"}>
              {connected ? "Realtime Active" : "Disconnected"}
            </StatusPill>
            <div style={{position: 'relative'}} ref={notificationsRef}>
              <IconButton
                onClick={() => {
                  setShowNotifications((current) => !current);
                  setShowProfileMenu(false);
                }}
                active={showNotifications}
                title="Notifications"
              >
                <Bell size={18} />
              </IconButton>
              {showNotifications ? (
                <div style={menuPanelStyle}>
                  <div style={menuPanelHeaderStyle}>Notifications</div>
                  {notificationItems.length ? (
                    notificationItems.map((item, index) => (
                      <div key={`${item.title}-${index}`} style={menuItemStyle}>
                        <div style={{fontWeight: 600, fontSize: 13, color: colors.text, marginBottom: 4}}>{item.title}</div>
                        <div style={{fontSize: 12, color: colors.muted, lineHeight: 1.5}}>{item.detail}</div>
                      </div>
                    ))
                  ) : (
                    <div style={menuEmptyStyle}>No new notifications</div>
                  )}
                </div>
              ) : null}
            </div>
            <div style={{position: 'relative'}} ref={profileMenuRef}>
              <button
                onClick={() => {
                  setShowProfileMenu((current) => !current);
                  setShowNotifications(false);
                }}
                style={profileButtonStyle}
                title="Profile menu"
              >
                {user?.name?.charAt(0)?.toUpperCase() || 'A'}
              </button>
              {showProfileMenu ? (
                <div style={{...menuPanelStyle, right: 0, width: 220}}>
                  <div style={menuPanelHeaderStyle}>Signed in as</div>
                  <div style={{padding: "0 14px 14px"}}>
                    <div style={{fontWeight: 700, color: colors.text}}>{user?.name || "Analyst"}</div>
                    <div style={{fontSize: 12, color: colors.muted, marginTop: 4}}>{user?.email || ""}</div>
                  </div>
                  <button style={menuActionButtonStyle} onClick={logout}>
                    Log out
                  </button>
                </div>
              ) : null}
            </div>
          </div>
        </div>

        <div className="content-scrollable">
          {error ? <div style={errorStyle}>{error}</div> : null}
          {selectedWebsite ? (
            <>
              {currentTab === 'dashboard' && (
                <div>
                  <div className="flex-between" style={{marginBottom: 24}}>
                    <div>
                      <div className="card-title" style={{fontSize: 24}}>{selectedWebsite.name}</div>
                      <div style={{color: 'var(--text-muted)'}}>{selectedWebsite.domain} • {selectedWebsite.environment}</div>
                    </div>
                    <div className="flex-gap">
                      <button onClick={simulateAttack} className="btn btn-primary">Simulate Attack</button>
                      <button onClick={toggleAuto} className={`btn ${autoRunning ? 'btn-danger' : 'btn-secondary'}`}>
                        {autoRunning ? "Stop Monitor" : "Start Monitor"}
                      </button>
                    </div>
                  </div>

                  <div className="grid-metrics">
                    <div className="card">
                      <div className="card-header">
                        <div className="card-title">Total Events</div>
                        <Activity size={20} color={colors.gold} />
                      </div>
                      <div className="card-value">{telemetry.total_events || 0}</div>
                      <div style={{color: 'var(--text-subtle)', fontSize: 13}}>Collector-fed data</div>
                    </div>
                    <div className="card">
                      <div className="card-header">
                        <div className="card-title">Incidents</div>
                        <ShieldAlert size={20} color={colors.amber} />
                      </div>
                      <div className="card-value">{stats.incidents}</div>
                      <div style={{color: 'var(--text-subtle)', fontSize: 13}}>Detected across project</div>
                    </div>
                    <div className="card">
                      <div className="card-header">
                        <div className="card-title">Auto-executed</div>
                        <Settings size={20} color={colors.green} />
                      </div>
                      <div className="card-value">{stats.autoExecuted}</div>
                      <div style={{color: 'var(--text-subtle)', fontSize: 13}}>Resolved autonomously</div>
                    </div>
                    <div className="card">
                      <div className="card-header">
                        <div className="card-title">Pending Approvals</div>
                        <Bell size={20} color={colors.red} />
                      </div>
                      <div className="card-value">{stats.approvals}</div>
                      <div style={{color: 'var(--text-subtle)', fontSize: 13}}>Queued for decision</div>
                    </div>
                  </div>

                  <div className="grid-layout">
                    <div className="card">
                      <div className="card-title" style={{marginBottom: 16}}>Live Orchestration Feed</div>
                      <div style={{display: 'flex', flexDirection: 'column', gap: 12, maxHeight: 400, overflowY: 'auto'}}>
                        {feed.filter(e => !selectedWebsiteId || e.data.website_id === selectedWebsiteId).map(entry => (
                          <div key={entry.id} style={{padding: 12, background: 'rgba(255,255,255,0.03)', borderRadius: 8, borderLeft: `3px solid ${colors.gold}`}}>
                            <div className="flex-between" style={{marginBottom: 6}}>
                              <span style={{fontSize: 13, fontWeight: 600}}>{entry.data.agent_trace_entry?.agent || entry.type}</span>
                              <span style={{fontSize: 11, color: 'var(--text-subtle)'}}>{new Date(entry.timestamp).toLocaleTimeString()}</span>
                            </div>
                            <div style={{fontSize: 13, color: 'var(--text-muted)'}}>{entry.data.message || entry.data.current_stage || "Event"}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="card">
                      <div className="card-title" style={{marginBottom: 16}}>Projects</div>
                      <div style={{display: 'flex', flexDirection: 'column', gap: 10}}>
                        {websites.map(w => (
                          <div key={w._id} className={`table-row-clickable ${selectedWebsiteId === w._id ? 'active' : ''}`} onClick={() => setSelectedWebsiteId(w._id)} style={{padding: 12, border: '1px solid var(--border-color)', borderRadius: 8, background: selectedWebsiteId === w._id ? 'var(--panel-alt)' : 'transparent'}}>
                            <div className="flex-between" style={{marginBottom: 4}}>
                              <span style={{fontWeight: 600}}>{w.name}</span>
                              <StatusPill color={w.status === 'connected' ? 'var(--color-green)' : 'var(--color-amber)'}>{w.status}</StatusPill>
                            </div>
                            <div style={{fontSize: 12, color: 'var(--text-subtle)'}}>{w.domain}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {currentTab === 'telemetry' && (
                <div>
                  <div className="card" style={{marginBottom: 24}}>
                    <div className="card-title" style={{marginBottom: 16}}>Collector Setup</div>
                    <div className="grid-layout">
                      <div>
                        <div style={{marginBottom: 16, color: 'var(--text-muted)'}}>
                          Customer-side collector posts batched events to <code>POST /collector/ingest</code> with <code>X-Collector-Token</code>.
                        </div>
                        <div style={{background: 'var(--bg-canvas)', padding: 16, borderRadius: 8, border: '1px solid var(--border-color)', marginBottom: 16}}>
                          <div style={{fontSize: 12, color: 'var(--color-gold)', marginBottom: 8, fontWeight: 'bold'}}>COLLECTOR TOKEN</div>
                          <div style={tokenStyle}>{selectedWebsite.collector?.ingest_token || "Unavailable"}</div>
                        </div>
                      </div>
                      <div style={codePanelStyle}>
                        <div style={eyebrowStyle}>Collector Request Example</div>
                        <pre style={codeBlockStyle}>{`POST ${integration?.ingest_url || API_BASE + '/collector/ingest'}
Header: ${integration?.token_header || "X-Collector-Token"}: ${selectedWebsite.collector?.ingest_token || ""}
Body: {
  "source_label": "${selectedWebsite.name} web collector",
  "run_detection": true,
  "events": [...]
}`}</pre>
                      </div>
                    </div>
                  </div>

                  <div className="card" style={{marginBottom: 24}}>
                    <div className="card-title" style={{marginBottom: 16}}>Agent Protocol Surface</div>
                    <div className="grid-layout">
                      <div style={integrationPanelStyle}>
                        <div style={eyebrowStyle}>A2A Discovery</div>
                        <div style={{display: 'grid', gap: 12}}>
                          <div>
                            <div style={{fontSize: 12, color: 'var(--text-subtle)', marginBottom: 4}}>Agent Registry</div>
                            <div style={tokenStyle}>{integration?.protocols?.a2a_registry_url || `${API_BASE}/a2a/agents`}</div>
                          </div>
                          <div>
                            <div style={{fontSize: 12, color: 'var(--text-subtle)', marginBottom: 4}}>Root Agent Card</div>
                            <div style={tokenStyle}>{integration?.protocols?.a2a_root_agent_card || `${API_BASE}/a2a/soc_coordinator/agent-card.json`}</div>
                          </div>
                          <div style={{fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6}}>
                            The SOC coordinator exposes named agents for normalization, detection, correlation, classification,
                            investigation, response planning, policy, action, and reporting through A2A-style invoke contracts.
                          </div>
                          <div style={{fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6}}>
                            Stage 2 runtime: {integration?.protocols?.stage2?.enabled ? 'Google ADK native reasoning enabled.' : 'Stage 2 runtime unavailable.'}
                          </div>
                        </div>
                      </div>
                      <div style={codePanelStyle}>
                        <div style={eyebrowStyle}>AG-UI Run Endpoint</div>
                        <pre style={codeBlockStyle}>{`POST ${integration?.protocols?.agui_run_url || `${API_BASE}/agui/runs`}
Body: {
  "incident_id": "<incident-id>",
  "thread_id": "cyberagent-soc-thread"
}

Streams:
- RUN_STARTED
- STATE_SNAPSHOT / STATE_DELTA
- TOOL_CALL_START / TOOL_CALL_RESULT
- TEXT_MESSAGE_CONTENT
- RUN_FINISHED`}</pre>
                      </div>
                    </div>
                  </div>

                  {integration?.protocols?.stage2?.a2a_agents?.length ? (
                    <div className="card" style={{marginBottom: 24}}>
                      <div className="card-title" style={{marginBottom: 16}}>Stage 2 ADK Agents</div>
                      <div style={{display: 'grid', gap: 12}}>
                        {integration.protocols.stage2.a2a_agents.map((agent) => (
                          <div key={agent.name} style={traceCardStyle}>
                            <div className="flex-between" style={{marginBottom: 8}}>
                              <span style={{fontWeight: 600, fontSize: 13}}>{agent.name}</span>
                              <span style={{fontSize: 12, color: 'var(--color-gold)'}}>ADK + A2A</span>
                            </div>
                            <div style={{fontSize: 13, color: 'var(--text-muted)', marginBottom: 8}}>{agent.description}</div>
                            <div style={tokenStyle}>{agent.agent_card_url || agent.base_url}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  
                  <div className="card">
                    <div className="card-title" style={{marginBottom: 16}}>Normalized Event Streams</div>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Event Type</th>
                          <th>Message Details</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(telemetry.recent_events || []).slice(0, 10).map((event, i) => (
                          <tr key={i}>
                            <td style={{fontWeight: 600, textTransform: 'capitalize'}}>{event.event_type}</td>
                            <td>{event.message}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {currentTab === 'incidents' && (
                <div className="grid-layout">
                  <div className="card" style={{padding: '16px 0'}}>
                    <div className="card-title" style={{padding: '0 16px', marginBottom: 12}}>Incident Queue</div>
                    <div style={{display: 'flex', flexDirection: 'column'}}>
                      {websiteIncidents.length ? websiteIncidents.map(incident => {
                        const severity = incident.classification?.attack?.severity || "LOW";
                        const policyMode = incident.policy_decision?.mode || "approval_required";
                        return (
                          <div key={incident.attack_id} className={`table-row-clickable ${selectedIncidentId === incident.attack_id ? 'active' : ''}`} onClick={() => setSelectedIncidentId(incident.attack_id)} style={{padding: '16px', borderBottom: '1px solid var(--border-color)', background: selectedIncidentId === incident.attack_id ? 'var(--panel-alt)' : 'transparent'}}>
                            <div className="flex-between" style={{marginBottom: 8}}>
                              <span style={{fontWeight: 600}}>{incident.classification?.predicted_class || incident.attack_id}</span>
                              <span className={`status-pill badge-${severity === 'CRITICAL' ? 'red' : severity === 'HIGH' ? 'amber' : 'amber'}`}>{severity}</span>
                            </div>
                            <div style={{fontSize: 13, color: 'var(--text-muted)', marginBottom: 12}}>
                              {incident.simulation?.description || "Investigation in progress"}
                            </div>
                            <div className="flex-gap">
                              <span className="status-pill badge-blue">{policyMode.replace('_', ' ')}</span>
                            </div>
                          </div>
                        )
                      }) : <div style={{padding: 24, textAlign: 'center', color: 'var(--text-muted)'}}>No incidents found.</div>}
                    </div>
                  </div>
                  
                  <div>
                    {selectedIncident ? (
                      <div className="card">
                        <div className="flex-between" style={{marginBottom: 16}}>
                          <div>
                            <div style={{fontSize: 12, color: 'var(--color-gold)', fontWeight: 600, marginBottom: 4}}>INCIDENT DETAILS</div>
                            <div className="card-title" style={{fontSize: 20}}>{selectedIncident.classification?.predicted_class || selectedIncident.attack_id}</div>
                          </div>
                        </div>
                        <div style={{color: 'var(--text-muted)', fontSize: 14, lineHeight: 1.6, marginBottom: 24}}>
                          {selectedIncident.anomaly?.summary || selectedIncident.simulation?.description}
                        </div>
                        
                        <div className="grid-metrics" style={{gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24}}>
                          <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>PRIMARY SOURCE</div>
                            <div style={{fontWeight: 600, fontSize: 13}}>{selectedIncident.classification?.attack?.primary_src_ip || '—'}</div>
                          </div>
                          <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>TARGET</div>
                            <div style={{fontWeight: 600, fontSize: 13}}>{selectedIncident.classification?.attack ? `${selectedIncident.classification.attack.target_ip}:${selectedIncident.classification.attack.target_port}` : '—'}</div>
                          </div>
                          <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>CONFIDENCE</div>
                            <div style={{fontWeight: 600, fontSize: 13}}>{selectedIncident.classification?.confidence ? `${Math.round(selectedIncident.classification.confidence * 100)}%` : '—'}</div>
                          </div>
                          <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>RISK SCORE</div>
                            <div style={{fontWeight: 600, fontSize: 13}}>{selectedIncident.classification?.risk_score || '—'}</div>
                          </div>
                          <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>CLASSIFIER RUNTIME</div>
                            <div style={{fontWeight: 600, fontSize: 13}}>{selectedIncident.llm_usage?.["Threat Classification Agent"]?.runtime || '—'}</div>
                          </div>
                        </div>

                        {selectedIncident.approval_status === "pending" && (
                          <div style={{padding: 16, background: 'rgba(212, 167, 44, 0.1)', border: '1px solid rgba(212, 167, 44, 0.3)', borderRadius: 12, marginBottom: 24}}>
                            <div style={{fontWeight: 600, marginBottom: 12, color: 'var(--color-amber)'}}>Human Approval Required</div>
                            <div className="flex-gap">
                              <button className="btn btn-primary" disabled={decisionLoading[selectedIncident.attack_id]} onClick={() => decideIncident("approved")}>Approve Containment</button>
                              <button className="btn btn-danger" disabled={decisionLoading[selectedIncident.attack_id]} onClick={() => decideIncident("rejected")}>Reject to Manual</button>
                            </div>
                          </div>
                        )}

                        <div className="card-title" style={{marginBottom: 12, fontSize: 14, color: 'var(--color-gold)'}}>AGENT TRACE</div>
                        <div style={{display: 'flex', flexDirection: 'column', gap: 12}}>
                          {(selectedIncident.agent_trace || []).map((entry, idx) => (
                            <div key={idx} style={{padding: 12, background: 'var(--bg-canvas)', borderRadius: 8, border: '1px solid var(--border-color)'}}>
                              <div className="flex-between" style={{marginBottom: 6}}>
                                <span style={{fontWeight: 600, fontSize: 13}}>{entry.agent}</span>
                                <span style={{fontSize: 12, color: 'var(--text-subtle)'}}>{entry.stage}</span>
                              </div>
                              <div style={{fontSize: 13, color: 'var(--text-muted)'}}>{entry.summary}</div>
                            </div>
                          ))}
                        </div>

                        {(selectedIncident.protocol_trace || []).length ? (
                          <>
                            <div className="card-title" style={{marginTop: 24, marginBottom: 12, fontSize: 14, color: 'var(--color-gold)'}}>A2A INVOCATION TRACE</div>
                            <div style={{display: 'flex', flexDirection: 'column', gap: 12}}>
                              {(selectedIncident.protocol_trace || []).map((entry, idx) => (
                                <div key={idx} style={{padding: 12, background: 'var(--bg-canvas)', borderRadius: 8, border: '1px solid var(--border-color)'}}>
                                  <div className="flex-between" style={{marginBottom: 8}}>
                                    <span style={{fontWeight: 600, fontSize: 13}}>{entry.from_agent} → {entry.to_agent}</span>
                                    <span style={{fontSize: 12, color: 'var(--text-subtle)'}}>{entry.protocol}</span>
                                  </div>
                                  <div style={{fontSize: 13, color: 'var(--text-muted)', marginBottom: 8}}>
                                    Runtime: {entry.runtime} • Task ID: {entry.task_id}
                                  </div>
                                  <div style={{fontSize: 12, color: 'var(--text-subtle)', lineHeight: 1.6}}>
                                    Stage: {entry.output_summary?.current_stage || "n/a"} • Approval: {entry.output_summary?.approval_status || "n/a"}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </>
                        ) : null}
                      </div>
                    ) : (
                      <div className="card" style={{display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 400, color: 'var(--text-muted)'}}>
                        Select an incident to view details
                      </div>
                    )}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div style={{padding: 40, textAlign: 'center', color: 'var(--text-muted)'}}>
              Select a project from the sidebar to view metrics.
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

const pageStyle = {
  minHeight: "100vh",
  background: "linear-gradient(180deg, #09090b 0%, #0c0c0d 55%, #111114 100%)",
  color: colors.text,
  padding: "28px 28px 40px",
  fontFamily: '"Plus Jakarta Sans", "Inter", "Segoe UI", sans-serif',
  position: "relative",
  overflow: "hidden",
};

const landingGlowWrapStyle = {
  position: "absolute",
  inset: 0,
  overflow: "hidden",
  pointerEvents: "none",
};

const landingGlowPrimaryStyle = {
  position: "absolute",
  top: "-8%",
  right: "-6%",
  width: 520,
  height: 520,
  borderRadius: "50%",
  background: "rgba(139, 92, 246, 0.12)",
  filter: "blur(120px)",
};

const landingGlowSecondaryStyle = {
  position: "absolute",
  bottom: "8%",
  left: "-10%",
  width: 560,
  height: 560,
  borderRadius: "50%",
  background: "rgba(37, 99, 235, 0.08)",
  filter: "blur(130px)",
};

const landingShellStyle = {
  position: "relative",
  maxWidth: 1380,
  margin: "0 auto",
  display: "flex",
  flexDirection: "column",
  minHeight: "calc(100vh - 68px)",
};

const landingHeaderStyle = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 24,
  padding: "8px 0 18px",
  flexWrap: "wrap",
};

const landingBrandStyle = {
  display: "flex",
  alignItems: "center",
  gap: 14,
};

const landingBrandMarkStyle = {
  width: 42,
  height: 42,
  borderRadius: 12,
  display: "grid",
  placeItems: "center",
  background: "linear-gradient(135deg, #8b5cf6 0%, #4f46e5 100%)",
  color: "#ffffff",
  fontWeight: 800,
  fontSize: 18,
  boxShadow: "0 0 24px rgba(139, 92, 246, 0.28)",
};

const landingBrandNameStyle = {
  fontSize: 22,
  fontWeight: 800,
  letterSpacing: -0.4,
};

const landingBrandSubStyle = {
  color: colors.muted,
  fontSize: 13,
};

const landingNavStyle = {
  display: "flex",
  gap: 28,
  flexWrap: "wrap",
  color: colors.muted,
  fontSize: 14,
};

const landingBadgeStyle = {
  display: "inline-flex",
  alignItems: "center",
  gap: 8,
  padding: "8px 14px",
  borderRadius: 999,
  border: "1px solid rgba(139, 92, 246, 0.24)",
  background: "rgba(139, 92, 246, 0.1)",
  color: "#d8ccff",
  fontSize: 13,
  fontWeight: 600,
  marginBottom: 22,
};

const heroWrapStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1.2fr) minmax(380px, 430px)",
  gap: 36,
  alignItems: "center",
  width: "100%",
  flex: 1,
  padding: "48px 0 24px",
};

const heroTitleStyle = {
  fontSize: 62,
  lineHeight: 1.02,
  fontWeight: 800,
  letterSpacing: -2,
  marginBottom: 18,
  maxWidth: 760,
};

const heroBodyStyle = {
  color: colors.muted,
  fontSize: 18,
  lineHeight: 1.9,
  maxWidth: 680,
};

const heroBadgeRowStyle = {
  display: "flex",
  gap: 10,
  flexWrap: "wrap",
  marginTop: 24,
};

const landingStatRowStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(3, minmax(0, 180px))",
  gap: 14,
  marginTop: 28,
};

const landingStatStyle = {
  padding: "18px 18px 16px",
  borderRadius: 24,
  border: `1px solid ${colors.border}`,
  background: "rgba(19, 19, 20, 0.78)",
  backdropFilter: "blur(12px)",
};

const landingStatValueStyle = {
  fontSize: 24,
  fontWeight: 800,
  marginBottom: 6,
};

const landingStatLabelStyle = {
  fontSize: 13,
  color: colors.muted,
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
  background: "linear-gradient(180deg, rgba(19,19,20,0.98), rgba(26,26,27,0.98))",
  border: `1px solid ${colors.border}`,
  borderRadius: 32,
  padding: 22,
  boxShadow: "0 22px 42px -24px rgba(0,0,0,0.65)",
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
  background: "linear-gradient(180deg, rgba(19,19,20,0.98), rgba(26,26,27,0.98))",
  border: `1px solid ${colors.border}`,
  borderRadius: 36,
  padding: 26,
  boxShadow: "0 24px 70px rgba(0,0,0,0.45)",
  display: "flex",
  flexDirection: "column",
  gap: 12,
  backdropFilter: "blur(14px)",
};

const authCardHeaderStyle = {
  display: "flex",
  flexDirection: "column",
  gap: 12,
  marginBottom: 8,
};

const authCardSubStyle = {
  color: colors.muted,
  fontSize: 14,
};

const setupCardStyle = {
  width: "100%",
  background: "linear-gradient(180deg, rgba(19,19,20,0.98), rgba(26,26,27,0.98))",
  border: `1px solid ${colors.border}`,
  borderRadius: 36,
  padding: 28,
  boxShadow: "0 22px 60px rgba(0,0,0,0.45)",
  backdropFilter: "blur(14px)",
};

const setupSplitStyle = {
  position: "relative",
  display: "grid",
  gridTemplateColumns: "minmax(0, 1fr) minmax(420px, 520px)",
  gap: 32,
  alignItems: "center",
  maxWidth: 1320,
  margin: "36px auto 0",
};

const setupIntroStyle = {
  maxWidth: 700,
};

const landingFooterStyle = {
  marginTop: "auto",
  paddingTop: 24,
  borderTop: "1px solid rgba(255,255,255,0.06)",
  color: colors.subtle,
  fontSize: 12,
  letterSpacing: 0.3,
};

const inputStyle = {
  width: "100%",
  padding: "14px 16px",
  borderRadius: 18,
  border: `1px solid ${colors.border}`,
  outline: "none",
  fontSize: 15,
  background: "#1a1a1b",
  color: colors.text,
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
  borderRadius: 999,
  border: "none",
  background: "linear-gradient(135deg, #7c3aed 0%, #4f46e5 100%)",
  color: "#fff",
  fontWeight: 700,
  cursor: "pointer",
};

const secondaryButtonStyle = {
  padding: "12px 18px",
  borderRadius: 999,
  border: `1px solid ${colors.border}`,
  background: "#1a1a1b",
  color: colors.text,
  fontWeight: 700,
  cursor: "pointer",
};

const dangerButtonStyle = {
  padding: "12px 18px",
  borderRadius: 999,
  border: "none",
  background: "linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)",
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
  borderRadius: 24,
  border: `1px solid ${colors.border}`,
  padding: 16,
  textAlign: "left",
  cursor: "pointer",
  color: colors.text,
};

const feedCardStyle = {
  borderRadius: 22,
  border: `1px solid ${colors.border}`,
  padding: 14,
  background: colors.panelAlt,
};

const statsGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
  gap: 14,
};

const statCardStyle = {
  background: "linear-gradient(180deg, rgba(19,19,20,0.98), rgba(26,26,27,0.98))",
  border: `1px solid ${colors.border}`,
  borderRadius: 24,
  padding: 18,
};

const heroPanelStyle = {
  display: "grid",
  gridTemplateColumns: "minmax(0, 1fr) minmax(320px, 380px)",
  gap: 18,
  alignItems: "start",
};

const collectorCardStyle = {
  background: "linear-gradient(135deg, rgba(36,26,54,0.98), rgba(76,29,149,0.96))",
  color: "#fff",
  borderRadius: 24,
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
  background: colors.panelAlt,
  padding: 20,
};

const codePanelStyle = {
  borderRadius: 24,
  padding: 20,
  background: "linear-gradient(180deg, #19131f, #121215)",
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

const menuPanelStyle = {
  position: "absolute",
  top: "calc(100% + 10px)",
  right: 0,
  width: 300,
  borderRadius: 24,
  border: `1px solid ${colors.border}`,
  background: "rgba(19,19,20,0.98)",
  boxShadow: "0 24px 60px rgba(0,0,0,0.45)",
  overflow: "hidden",
  zIndex: 30,
  backdropFilter: "blur(18px)",
};

const menuPanelHeaderStyle = {
  padding: "14px 14px 10px",
  color: colors.gold,
  fontSize: 11,
  fontWeight: 800,
  letterSpacing: 1.1,
  textTransform: "uppercase",
};

const menuItemStyle = {
  padding: "12px 14px",
  borderTop: `1px solid ${colors.border}`,
  background: "rgba(255,255,255,0.015)",
};

const menuEmptyStyle = {
  padding: "18px 14px 20px",
  color: colors.muted,
  fontSize: 13,
  borderTop: `1px solid ${colors.border}`,
};

const menuActionButtonStyle = {
  width: "calc(100% - 28px)",
  margin: "0 14px 14px",
  padding: "11px 14px",
  borderRadius: 14,
  border: `1px solid ${colors.border}`,
  background: colors.panelAlt,
  color: colors.text,
  fontWeight: 700,
  cursor: "pointer",
};

const profileButtonStyle = {
  width: 40,
  height: 40,
  borderRadius: 999,
  border: `1px solid rgba(198, 163, 111, 0.28)`,
  background: "linear-gradient(135deg, rgba(198,163,111,0.22), rgba(104,81,48,0.3))",
  color: colors.text,
  fontWeight: 800,
  fontSize: 14,
  cursor: "pointer",
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
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
  borderRadius: 20,
  background: colors.panelAlt,
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
  background: "linear-gradient(135deg, rgba(19,19,20,0.98), rgba(26,26,27,0.98))",
  border: `1px solid ${colors.border}`,
};

const traceCardStyle = {
  borderRadius: 20,
  border: `1px solid ${colors.border}`,
  padding: 14,
  background: colors.panelAlt,
};

const metaGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
  gap: 14,
};

export default App;
