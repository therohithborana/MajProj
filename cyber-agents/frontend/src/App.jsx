import React, { useEffect, useMemo, useRef, useState } from "react";
import { LayoutDashboard, ShieldAlert, Activity, Settings, Bell, Search, PanelLeftClose, PanelLeftOpen, FileText, X } from "lucide-react";

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

function dedupeDiscussionEntries(entries = []) {
  const seen = new Set();
  return entries.filter((entry) => {
    const key = `${entry.speaker || ""}|${entry.audience || ""}|${entry.stage || ""}|${entry.message || ""}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
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
  const [telemetry, setTelemetry] = useState({ total_events: 0, counts: {}, recent_events: [], recent_by_type: {} });
  const [observability, setObservability] = useState({
    enabled: false,
    metrics: { event_type_counts: {}, failed_auth_events: 0, tool_executions: 0, incidents_detected: 0 },
    recent_spans: [],
    recent_alerts: [],
    latest_tool: {},
  });
  const [analytics, setAnalytics] = useState({ totals: {}, by_class: {}, by_severity: {}, by_status: {} });
  const [jobs, setJobs] = useState([]);
  const [integration, setIntegration] = useState(null);
  const [connected, setConnected] = useState(false);
  const [decisionLoading, setDecisionLoading] = useState({});
  const [copyFeedback, setCopyFeedback] = useState("");
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
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [approvalFilter, setApprovalFilter] = useState("all");
  const [noteDraft, setNoteDraft] = useState("");
  const [notesSaving, setNotesSaving] = useState(false);
  const [assigneeDraft, setAssigneeDraft] = useState("");
  const [assigning, setAssigning] = useState(false);
  const [incidentDetailTab, setIncidentDetailTab] = useState("discussion");

  useEffect(() => {
    if (!token) {
      setUser(null);
      setWebsites([]);
      setSelectedWebsiteId("");
      setTelemetry({ total_events: 0, counts: {}, recent_events: [], recent_by_type: {} });
      setAnalytics({ totals: {}, by_class: {}, by_severity: {}, by_status: {} });
      setJobs([]);
      setObservability({
        enabled: false,
        metrics: { event_type_counts: {}, failed_auth_events: 0, tool_executions: 0, incidents_detected: 0 },
        recent_spans: [],
        recent_alerts: [],
        latest_tool: {},
      });
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

  async function loadSelectedWebsiteData(websiteId, activeToken) {
    if (!websiteId || !activeToken) {
      return null;
    }
    const [websiteIncidents, telemetryData, observabilityData, integrationData, analyticsData, jobsData] = await Promise.all([
      apiFetch(`/websites/${websiteId}/incidents`, {}, activeToken),
      apiFetch(`/websites/${websiteId}/telemetry`, {}, activeToken),
      apiFetch(`/websites/${websiteId}/observability`, {}, activeToken),
      apiFetch(`/websites/${websiteId}/integration`, {}, activeToken),
      apiFetch(`/websites/${websiteId}/analytics`, {}, activeToken),
      apiFetch(`/websites/${websiteId}/jobs`, {}, activeToken),
    ]);
    setIncidents((current) => {
      const next = { ...current };
      websiteIncidents.forEach((incident) => {
        next[incident.attack_id] = incident;
      });
      return next;
    });
    setTelemetry(telemetryData);
    setObservability(observabilityData);
    setIntegration(integrationData);
    setAnalytics(analyticsData);
    setJobs(jobsData);
    setSelectedIncidentId((current) => current || websiteIncidents[0]?.attack_id || "");
    return { websiteIncidents, telemetryData, observabilityData, integrationData, analyticsData, jobsData };
  }

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
          if (payload.data.observability) {
            setObservability(payload.data.observability);
          }
        }

        if (payload.type === "observability_update" && payload.data?.website_id === selectedWebsiteId && payload.data?.observability) {
          setObservability(payload.data.observability);
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
                challenge_review: payload.data.challenge_review || existing.challenge_review,
                investigation: payload.data.investigation || existing.investigation,
                mitigation_plan: payload.data.mitigation_plan || existing.mitigation_plan,
                policy_decision: payload.data.policy_decision || existing.policy_decision,
                approval_status: payload.data.approval_status || existing.approval_status,
                assignee: payload.data.assignee || existing.assignee,
                notes: payload.data.notes || existing.notes,
                action_result: payload.data.action_result || existing.action_result,
                incident_report: payload.data.incident_report || existing.incident_report,
                agent_trace: payload.data.agent_trace || existing.agent_trace,
                agent_messages: payload.data.agent_messages || existing.agent_messages,
                agent_discussion: payload.data.agent_discussion || existing.agent_discussion,
                protocol_trace: payload.data.protocol_trace || existing.protocol_trace,
                tool_trace: payload.data.tool_trace || existing.tool_trace,
                runtime_metadata: payload.data.runtime_metadata || existing.runtime_metadata,
                llm_usage: payload.data.llm_usage || existing.llm_usage,
                current_stage: payload.data.current_stage || existing.current_stage,
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
        const result = await loadSelectedWebsiteData(selectedWebsiteId, token);
        if (cancelled) {
          return;
        }
        if (!result) {
          return;
        }
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
        .filter((incident) => severityFilter === "all" || incident.classification?.attack?.severity === severityFilter)
        .filter((incident) => approvalFilter === "all" || incident.approval_status === approvalFilter)
        .filter((incident) => {
          if (!searchTerm.trim()) {
            return true;
          }
          const haystack = JSON.stringify({
            attackId: incident.attack_id,
            attackClass: incident.classification?.predicted_class,
            source: incident.classification?.attack?.primary_src_ip,
            target: incident.classification?.attack?.target_ip,
            description: incident.simulation?.description,
          }).toLowerCase();
          return haystack.includes(searchTerm.trim().toLowerCase());
        })
        .sort((a, b) => (b.simulation?.timestamp || "").localeCompare(a.simulation?.timestamp || "")),
    [incidents, selectedWebsiteId, severityFilter, approvalFilter, searchTerm]
  );
  const selectedIncident =
    websiteIncidents.find((incident) => incident.attack_id === selectedIncidentId) || null;

  useEffect(() => {
    setAssigneeDraft(selectedIncident?.assignee?.name || "");
  }, [selectedIncident?.attack_id, selectedIncident?.assignee?.name]);

  useEffect(() => {
    setIncidentDetailTab("discussion");
  }, [selectedIncident?.attack_id]);

  useEffect(() => {
    if (selectedIncidentId && !websiteIncidents.some((incident) => incident.attack_id === selectedIncidentId)) {
      setSelectedIncidentId("");
    }
  }, [selectedIncidentId, websiteIncidents]);

  useEffect(() => {
    function handleEscape(event) {
      if (event.key === "Escape") {
        setSelectedIncidentId("");
      }
    }
    if (selectedIncident) {
      document.addEventListener("keydown", handleEscape);
      return () => document.removeEventListener("keydown", handleEscape);
    }
    return undefined;
  }, [selectedIncident]);

  const visibleAgentTrace = useMemo(() => {
    if (!selectedIncident) {
      return [];
    }
    if ((selectedIncident.agent_trace || []).length) {
      return selectedIncident.agent_trace;
    }
    return (selectedIncident.tool_trace || []).map((entry) => ({
      agent: entry.llm_agent || entry.agent,
      stage: entry.output_summary?.current_stage || entry.tool,
      summary: entry.llm_used
        ? `${entry.llm_agent || entry.agent} used ${entry.tool} with Gemini-backed reasoning.`
        : `${entry.agent} executed ${entry.tool} through the MCP tool runtime.`,
      details: {
        tool: entry.tool,
        llm_runtime: entry.llm_runtime,
      },
    }));
  }, [selectedIncident]);

  const visibleAgentMessages = useMemo(() => {
    if (!selectedIncident) {
      return [];
    }
    if ((selectedIncident.agent_messages || []).length) {
      return selectedIncident.agent_messages;
    }
    return (selectedIncident.tool_trace || []).map((entry, index, items) => {
      const next = items[index + 1];
      return {
        from: entry.llm_agent || entry.agent,
        to: next ? next.llm_agent || next.agent : "Dashboard",
        subject: entry.prompt_profile?.purpose || "Agent handoff",
        content: entry.llm_used
          ? `${entry.llm_agent || entry.agent} completed a Gemini-backed reasoning step and passed the updated incident state forward.`
          : `${entry.agent} finished ${entry.tool} and passed the structured result to the next stage.`,
        artifacts: {
          tool: entry.tool,
          current_stage: entry.output_summary?.current_stage,
        },
      };
    });
  }, [selectedIncident]);

  const visibleDiscussion = useMemo(() => {
    if (!selectedIncident) {
      return [];
    }
    if ((selectedIncident.agent_discussion || []).length) {
      return selectedIncident.agent_discussion;
    }
    const discussion = [];
    (selectedIncident.agent_trace || []).forEach((entry) => {
      discussion.push({
        speaker: entry.agent,
        audience: null,
        message: entry.summary,
        stage: entry.stage,
        kind: "statement",
      });
    });
    if (!discussion.length) {
      (selectedIncident.tool_trace || []).forEach((entry, index, items) => {
        const next = items[index + 1];
        discussion.push({
          speaker: entry.llm_agent || entry.agent,
          audience: next ? next.llm_agent || next.agent : "SOC Dashboard",
          message: entry.llm_used
            ? `I completed ${entry.tool} using Gemini-backed reasoning. Please take the updated state and continue the investigation.`
            : `I completed ${entry.tool} using deterministic logic. Please continue with the updated incident state.`,
          stage: entry.output_summary?.current_stage || entry.tool,
          kind: "handoff",
        });
      });
    }
    return dedupeDiscussionEntries(discussion);
  }, [selectedIncident]);

  const stats = useMemo(
    () => ({
      incidents: websiteIncidents.length,
      autoExecuted: websiteIncidents.filter((incident) => incident.action_result?.execution_mode === "AUTONOMOUS").length,
      approvals: websiteIncidents.filter((incident) => incident.policy_decision?.mode === "approval_required").length,
      critical: websiteIncidents.filter((incident) => incident.classification?.attack?.severity === "CRITICAL").length,
    }),
    [websiteIncidents]
  );

  const topAttackClasses = useMemo(
    () =>
      Object.entries(analytics.by_class || {})
        .sort((a, b) => b[1] - a[1])
        .slice(0, 4),
    [analytics]
  );

  const recentJobs = useMemo(() => (jobs || []).slice(0, 5), [jobs]);
  const reportIncidents = useMemo(
    () => websiteIncidents.filter((incident) => incident.incident_report?.report_id),
    [websiteIncidents]
  );
  const accessEvents = useMemo(
    () => (telemetry.recent_by_type?.access || (telemetry.recent_events || []).filter((event) => event.event_type === "access")).slice(0, 6),
    [telemetry]
  );
  const authEvents = useMemo(
    () => (telemetry.recent_by_type?.auth || (telemetry.recent_events || []).filter((event) => event.event_type === "auth")).slice(0, 6),
    [telemetry]
  );
  const networkEvents = useMemo(
    () => (telemetry.recent_by_type?.network || (telemetry.recent_events || []).filter((event) => event.event_type === "network")).slice(0, 6),
    [telemetry]
  );
  const channelCounts = useMemo(
    () => ({
      access: Math.max(observability.channels?.application_logs?.events_seen || 0, telemetry.counts?.access || 0),
      auth: Math.max(observability.channels?.authentication_logs?.events_seen || 0, telemetry.counts?.auth || 0),
      network: Math.max(observability.channels?.network_logs?.events_seen || 0, telemetry.counts?.network || 0),
    }),
    [observability, telemetry]
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

  const liveDiscussionFeed = useMemo(
    () =>
      feed.filter((entry) => entry.data?.agent_discussion_entry && (!selectedWebsiteId || entry.data.website_id === selectedWebsiteId)),
    [feed, selectedWebsiteId]
  );

  const uniqueLiveDiscussionFeed = useMemo(
    () =>
      dedupeDiscussionEntries(
        liveDiscussionFeed.map((entry) => ({
          ...entry.data.agent_discussion_entry,
          _feedId: entry.id,
          _timestamp: entry.timestamp,
        }))
      ),
    [liveDiscussionFeed]
  );

  const pageMeta = useMemo(
    () => ({
      dashboard: {
        eyebrow: "Executive view",
        title: selectedWebsite ? `${selectedWebsite.name} command center` : "SOC dashboard",
        description: "Watch live agent activity, triage health, and active detections without wading through raw telemetry.",
      },
      telemetry: {
        eyebrow: "Telemetry workspace",
        title: "Telemetry & observability",
        description: "Review collector setup, live channels, and normalized application, authentication, and network logs.",
      },
      incidents: {
        eyebrow: "Response operations",
        title: "Threat detection",
        description: "Track incidents, inspect agent reasoning, approve actions, and review the execution chain.",
      },
      reports: {
        eyebrow: "Reporting",
        title: "Generated reports",
        description: "Browse executive summaries, completed writeups, and reporting-agent outputs across the workspace.",
      },
      settings: {
        eyebrow: "Workspace",
        title: "Workspace settings",
        description: "Manage project connection details, collector configuration, and tenant-level operating context.",
      },
    }),
    [selectedWebsite]
  );
  const currentPageMeta = pageMeta[currentTab] || pageMeta.dashboard;

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
      await loadSelectedWebsiteData(selectedWebsiteId, token);
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
      await loadSelectedWebsiteData(selectedWebsiteId, token);
    } catch (err) {
      setError(err.message);
    } finally {
      setDecisionLoading((current) => ({ ...current, [selectedIncident.attack_id]: false }));
    }
  }

  async function addIncidentNote() {
    if (!selectedIncident || !noteDraft.trim()) {
      return;
    }
    try {
      setNotesSaving(true);
      const notes = await apiFetch(
        `/incidents/${selectedIncident.attack_id}/notes`,
        { method: "POST", body: JSON.stringify({ note: noteDraft.trim() }) },
        token
      );
      setIncidents((current) => ({
        ...current,
        [selectedIncident.attack_id]: {
          ...(current[selectedIncident.attack_id] || {}),
          notes,
        },
      }));
      await loadSelectedWebsiteData(selectedWebsiteId, token);
      setNoteDraft("");
    } catch (err) {
      setError(err.message);
    } finally {
      setNotesSaving(false);
    }
  }

  async function assignIncident() {
    if (!selectedIncident || !assigneeDraft.trim()) {
      return;
    }
    try {
      setAssigning(true);
      const updated = await apiFetch(
        `/incidents/${selectedIncident.attack_id}/assign`,
        { method: "POST", body: JSON.stringify({ assignee: assigneeDraft.trim() }) },
        token
      );
      setIncidents((current) => ({ ...current, [selectedIncident.attack_id]: updated }));
      await loadSelectedWebsiteData(selectedWebsiteId, token);
    } catch (err) {
      setError(err.message);
    } finally {
      setAssigning(false);
    }
  }

  async function copyCollectorToken() {
    const tokenToCopy = selectedWebsite?.collector?.ingest_token;
    if (!tokenToCopy) {
      return;
    }
    try {
      await navigator.clipboard.writeText(tokenToCopy);
      setCopyFeedback("Copied");
      window.setTimeout(() => setCopyFeedback(""), 1800);
    } catch (_error) {
      setCopyFeedback("Copy failed");
      window.setTimeout(() => setCopyFeedback(""), 1800);
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
    setAnalytics({ totals: {}, by_class: {}, by_severity: {}, by_status: {} });
    setJobs([]);
    setObservability({
      enabled: false,
      metrics: { event_type_counts: {}, failed_auth_events: 0, tool_executions: 0, incidents_detected: 0 },
      recent_spans: [],
      recent_alerts: [],
      latest_tool: {},
    });
    setIntegration(null);
    setShowNotifications(false);
    setShowProfileMenu(false);
  }

  function scrollLandingSection(sectionId) {
    const target = document.getElementById(sectionId);
    if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
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
                <div style={landingBrandSubStyle}>Security operations workspace</div>
              </div>
            </div>
            <nav style={landingNavStyle}>
              <button style={landingNavButtonStyle} onClick={() => scrollLandingSection("how-it-works")}>How it works</button>
              <button style={landingNavButtonStyle} onClick={() => scrollLandingSection("features")}>Features</button>
              <button style={landingNavButtonStyle} onClick={() => scrollLandingSection("security")}>Security</button>
              <button style={landingNavButtonStyle} onClick={() => scrollLandingSection("reviews")}>Reviews</button>
            </nav>
          </header>

          <div style={heroWrapStyle}>
            <div style={{ maxWidth: 700 }}>
              <div style={landingBadgeStyle}>Featured architecture: hybrid AI + SOC automation</div>
              <div style={heroTitleStyle}>
                Multi-agent security operations for monitored web and network environments.
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

          <section id="how-it-works" style={landingSectionStyle}>
            <div style={landingSectionIntroStyle}>
              <div style={landingSectionEyebrowStyle}>How it works</div>
              <div style={landingSectionTitleStyle}>A structured incident workflow from telemetry to response.</div>
              <div style={landingSectionBodyStyle}>
                Security events are ingested, normalized, analyzed by specialist agents, and escalated into coordinated response steps with analyst oversight where needed.
              </div>
            </div>
            <div style={landingFeatureGridStyle}>
              <div style={landingFeatureCardStyle}>
                <div style={landingFeatureStepStyle}>01</div>
                <div style={landingFeatureTitleStyle}>Collect</div>
                <div style={landingFeatureBodyStyle}>Application, authentication, and network signals are streamed into the monitoring pipeline.</div>
              </div>
              <div style={landingFeatureCardStyle}>
                <div style={landingFeatureStepStyle}>02</div>
                <div style={landingFeatureTitleStyle}>Analyze</div>
                <div style={landingFeatureBodyStyle}>Detection, correlation, classification, and challenge-review agents evaluate the evidence.</div>
              </div>
              <div style={landingFeatureCardStyle}>
                <div style={landingFeatureStepStyle}>03</div>
                <div style={landingFeatureTitleStyle}>Respond</div>
                <div style={landingFeatureBodyStyle}>Policy, mitigation, reporting, and approval workflows keep response controlled and auditable.</div>
              </div>
            </div>
          </section>

          <section id="features" style={landingSectionStyle}>
            <div style={landingSectionIntroStyle}>
              <div style={landingSectionEyebrowStyle}>Features</div>
              <div style={landingSectionTitleStyle}>Built for continuous monitoring and analyst visibility.</div>
            </div>
            <div style={landingFeatureGridStyle}>
              <div style={landingFeatureCardStyle}>
                <div style={landingFeatureTitleStyle}>Live telemetry workspace</div>
                <div style={landingFeatureBodyStyle}>Review separated application, authentication, and network activity in one operator view.</div>
              </div>
              <div style={landingFeatureCardStyle}>
                <div style={landingFeatureTitleStyle}>Multi-agent investigation</div>
                <div style={landingFeatureBodyStyle}>Inspect discussion, handoffs, coordinator planning, and tool usage for each incident.</div>
              </div>
              <div style={landingFeatureCardStyle}>
                <div style={landingFeatureTitleStyle}>Report generation</div>
                <div style={landingFeatureBodyStyle}>Produce executive summaries, analyst notes, and response documentation from the same workflow.</div>
              </div>
            </div>
          </section>

          <section id="security" style={landingSectionStyle}>
            <div style={landingSectionIntroStyle}>
              <div style={landingSectionEyebrowStyle}>Security</div>
              <div style={landingSectionTitleStyle}>Controlled automation with traceable decisions.</div>
            </div>
            <div style={landingSecurityGridStyle}>
              <div style={landingSecurityCardStyle}>
                <div style={landingFeatureTitleStyle}>Approval-aware execution</div>
                <div style={landingFeatureBodyStyle}>Response actions can pause for analyst approval before any higher-risk containment step.</div>
              </div>
              <div style={landingSecurityCardStyle}>
                <div style={landingFeatureTitleStyle}>Traceable reasoning</div>
                <div style={landingFeatureBodyStyle}>Agent discussions, tool traces, and planner decisions remain visible across the incident lifecycle.</div>
              </div>
            </div>
          </section>

          <section id="reviews" style={landingSectionStyle}>
            <div style={landingSectionIntroStyle}>
              <div style={landingSectionEyebrowStyle}>Reviews</div>
              <div style={landingSectionTitleStyle}>Operational value focused on visibility and response discipline.</div>
            </div>
            <div style={landingFeatureGridStyle}>
              <div style={landingQuoteCardStyle}>
                “The incident workflow is readable enough for analysts and structured enough for automation.”
              </div>
              <div style={landingQuoteCardStyle}>
                “Useful separation between telemetry review, response operations, and report generation.”
              </div>
              <div style={landingQuoteCardStyle}>
                “A practical operator experience rather than a generic AI demo surface.”
              </div>
            </div>
          </section>

          <footer style={landingFooterStyle}>
            <span>Integrates with monitored applications, identity services, collector agents, and network telemetry pipelines</span>
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
          {!sidebarCollapsed && (
            <div>
              <div className="sidebar-title">CyberAgent SOC</div>
              <div className="sidebar-subtitle">Autonomous response workspace</div>
            </div>
          )}
        </div>
        {!sidebarCollapsed ? (
          <div className="sidebar-workspace">
            <div className="sidebar-workspace-label">Active project</div>
            <select value={selectedWebsiteId} onChange={(event) => setSelectedWebsiteId(event.target.value)} className="sidebar-select">
              {websites.map((website) => (
                <option key={website._id} value={website._id}>
                  {website.name}
                </option>
              ))}
            </select>
            {selectedWebsite ? (
              <div className="sidebar-workspace-meta">
                <span>{selectedWebsite.domain}</span>
                <span>{selectedWebsite.environment}</span>
              </div>
            ) : null}
          </div>
        ) : null}
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
          <button className={`nav-item ${currentTab === 'reports' ? 'active' : ''}`} onClick={() => setCurrentTab('reports')}>
            <FileText className="nav-item-icon" size={20} />
            {!sidebarCollapsed && <span>Reports</span>}
          </button>
        </div>
        <div className="sidebar-footer">
          <button className={`nav-item ${currentTab === 'settings' ? 'active' : ''}`} onClick={() => setCurrentTab('settings')}>
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
              <input type="text" placeholder="Search incidents, IPs, policies..." value={searchTerm} onChange={(event) => setSearchTerm(event.target.value)} />
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
                    <div style={{fontSize: 12, color: colors.subtle, marginTop: 8, textTransform: "capitalize"}}>
                      Role: {user?.role || "owner"}
                    </div>
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
              <div className="page-hero">
                <div>
                  <div className="page-eyebrow">{currentPageMeta.eyebrow}</div>
                  <div className="page-title">{currentPageMeta.title}</div>
                  <div className="page-description">{currentPageMeta.description}</div>
                </div>
                <div className="page-hero-actions">
                  <StatusPill color={selectedWebsite.status === "connected" ? colors.green : colors.amber}>
                    {selectedWebsite.status}
                  </StatusPill>
                  {currentTab !== "reports" ? (
                    <button onClick={simulateAttack} className="btn btn-primary">Simulate Attack</button>
                  ) : null}
                </div>
              </div>

              {currentTab === 'dashboard' && (
                <div>
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

                  <div className="page-grid page-grid-dashboard" style={{marginTop: 24}}>
                    <div className="page-stack">
                      <div className="card">
                        <div className="card-title" style={{marginBottom: 16}}>Live orchestration feed</div>
                        <div style={{display: 'flex', flexDirection: 'column', gap: 12, maxHeight: 360, overflowY: 'auto'}}>
                          {feed.filter(e => !selectedWebsiteId || e.data.website_id === selectedWebsiteId).map(entry => (
                            <div key={entry.id} style={{padding: 12, background: 'rgba(255,255,255,0.03)', borderRadius: 12, borderLeft: `3px solid ${colors.gold}`}}>
                              <div className="flex-between" style={{marginBottom: 6}}>
                                <span style={{fontSize: 13, fontWeight: 600}}>{entry.data.agent_trace_entry?.agent || entry.type}</span>
                                <span style={{fontSize: 11, color: 'var(--text-subtle)'}}>{new Date(entry.timestamp).toLocaleTimeString()}</span>
                              </div>
                              <div style={{fontSize: 13, color: 'var(--text-muted)'}}>{entry.data.message || entry.data.current_stage || "Event"}</div>
                            </div>
                          ))}
                          {!feed.filter(e => !selectedWebsiteId || e.data.website_id === selectedWebsiteId).length ? (
                            <div style={{fontSize: 13, color: 'var(--text-muted)'}}>Agent activity, approvals, and reporting steps will stream here live.</div>
                          ) : null}
                        </div>
                      </div>

                      <div className="card">
                        <div className="card-title" style={{marginBottom: 16}}>Live agent conversation</div>
                        <div style={{display: 'flex', flexDirection: 'column', gap: 12, maxHeight: 320, overflowY: 'auto'}}>
                          {uniqueLiveDiscussionFeed.map((discussion, index) => {
                            return (
                              <div key={`${discussion.speaker}-${discussion.stage}-${index}`} style={{padding: 14, background: 'rgba(139, 92, 246, 0.08)', borderRadius: 14, border: '1px solid var(--border-color)'}}>
                                <div className="flex-between" style={{marginBottom: 8, gap: 12}}>
                                  <span style={{fontWeight: 700, fontSize: 13}}>
                                    {discussion.speaker}
                                    {discussion.audience ? (
                                      <span style={{fontWeight: 500, color: 'var(--text-subtle)', marginLeft: 8}}>→ {discussion.audience}</span>
                                    ) : null}
                                  </span>
                                  <span style={{fontSize: 12, color: 'var(--text-subtle)', textTransform: 'capitalize'}}>
                                    {discussion.source === 'gemini' ? 'Gemini' : 'Fallback'}
                                  </span>
                                </div>
                                <div style={{fontSize: 14, color: 'var(--text-muted)', lineHeight: 1.7}}>
                                  {discussion.message}
                                </div>
                              </div>
                            );
                          })}
                          {!uniqueLiveDiscussionFeed.length ? (
                            <div style={{fontSize: 13, color: 'var(--text-muted)'}}>
                              Start a new incident to watch the agents discuss it live stage by stage.
                            </div>
                          ) : null}
                        </div>
                      </div>
                    </div>

                    <div className="page-stack">
                      <div className="card">
                        <div className="card-title" style={{marginBottom: 16}}>Operations snapshot</div>
                        <div style={{display: 'grid', gap: 12}}>
                          {topAttackClasses.length ? topAttackClasses.map(([label, count]) => (
                            <div key={label} className="metric-list-item">
                              <span style={{fontWeight: 600, fontSize: 13}}>{label}</span>
                              <span style={{fontSize: 13, color: 'var(--text-muted)'}}>{count} cases</span>
                            </div>
                          )) : (
                            <div style={{color: 'var(--text-muted)', fontSize: 13}}>Attack-class analytics will appear once incidents accumulate.</div>
                          )}
                        </div>
                      </div>

                      <div className="card">
                        <div className="card-title" style={{marginBottom: 16}}>Recent pipeline jobs</div>
                        <div style={{display: 'grid', gap: 12}}>
                          {recentJobs.length ? recentJobs.map((job) => (
                            <div key={job._id} className="metric-list-item metric-list-item-block">
                              <div className="flex-between" style={{marginBottom: 6}}>
                                <span style={{fontWeight: 600, fontSize: 13}}>{job.job_type.replace(/_/g, ' ')}</span>
                                <span className={`status-pill ${job.status === 'completed' ? 'badge-green' : job.status === 'failed' ? 'badge-red' : job.status === 'awaiting_approval' ? 'badge-blue' : 'badge-amber'}`}>
                                  {job.status.replace(/_/g, ' ')}
                                </span>
                              </div>
                              <div style={{fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6}}>
                                Attack: {job.metadata?.attack_id || 'n/a'} • Phase: {job.metadata?.phase || 'queued'}
                              </div>
                            </div>
                          )) : (
                            <div style={{color: 'var(--text-muted)', fontSize: 13}}>Jobs will appear as collector ingests and incident workflows run.</div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="grid-layout" style={{marginTop: 24}}>
                    <div className="card">
                      <div className="card-title" style={{marginBottom: 16}}>Incident Analytics</div>
                      <div className="grid-metrics" style={{gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 12, marginBottom: 16}}>
                        <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                          <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>TOTAL INCIDENTS</div>
                          <div style={{fontWeight: 700, fontSize: 18}}>{analytics.totals?.incidents || 0}</div>
                        </div>
                        <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                          <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>ANALYST NOTES</div>
                          <div style={{fontWeight: 700, fontSize: 18}}>{analytics.totals?.notes || 0}</div>
                        </div>
                        <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                          <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>CRITICAL CASES</div>
                          <div style={{fontWeight: 700, fontSize: 18}}>{analytics.by_severity?.CRITICAL || 0}</div>
                        </div>
                      </div>
                      <div style={{display: 'grid', gap: 12}}>
                        {topAttackClasses.length ? topAttackClasses.map(([label, count]) => (
                          <div key={label} className="flex-between" style={{padding: 12, background: 'var(--bg-canvas)', borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <span style={{fontWeight: 600, fontSize: 13}}>{label}</span>
                            <span style={{fontSize: 13, color: 'var(--text-muted)'}}>{count} cases</span>
                          </div>
                        )) : (
                          <div style={{color: 'var(--text-muted)', fontSize: 13}}>Attack-class analytics will appear once incidents accumulate.</div>
                        )}
                      </div>
                    </div>

                    <div className="card">
                      <div className="card-title" style={{marginBottom: 16}}>Pipeline Jobs</div>
                      <div style={{display: 'grid', gap: 12}}>
                        {recentJobs.length ? recentJobs.map((job) => (
                          <div key={job._id} style={{padding: 12, background: 'var(--bg-canvas)', borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div className="flex-between" style={{marginBottom: 6}}>
                              <span style={{fontWeight: 600, fontSize: 13}}>{job.job_type.replace(/_/g, ' ')}</span>
                              <span className={`status-pill ${job.status === 'completed' ? 'badge-green' : job.status === 'failed' ? 'badge-red' : job.status === 'awaiting_approval' ? 'badge-blue' : 'badge-amber'}`}>
                                {job.status.replace(/_/g, ' ')}
                              </span>
                            </div>
                            <div style={{fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6}}>
                              Attack: {job.metadata?.attack_id || 'n/a'} • Phase: {job.metadata?.phase || 'queued'}
                            </div>
                            <div style={{fontSize: 12, color: 'var(--text-subtle)', marginTop: 6}}>
                              Retries: {job.retry_count || 0} • Updated: {job.updated_at ? new Date(job.updated_at).toLocaleTimeString() : 'n/a'}
                            </div>
                            {job.error ? (
                              <div style={{fontSize: 12, color: colors.red, marginTop: 6}}>{job.error}</div>
                            ) : null}
                          </div>
                        )) : (
                          <div style={{color: 'var(--text-muted)', fontSize: 13}}>Jobs will appear as collector ingests and incident workflows run.</div>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="grid-layout" style={{marginTop: 24}}>
                    <div className="card">
                      <div className="card-title" style={{marginBottom: 16}}>OpenTelemetry Monitor</div>
                      <div className="grid-metrics" style={{gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 12, marginBottom: 16}}>
                        <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                          <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>APP LOGS</div>
                          <div style={{fontWeight: 700, fontSize: 16}}>{channelCounts.access}</div>
                        </div>
                        <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                          <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>AUTH LOGS</div>
                          <div style={{fontWeight: 700, fontSize: 16}}>{channelCounts.auth}</div>
                        </div>
                        <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                          <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>NETWORK LOGS</div>
                          <div style={{fontWeight: 700, fontSize: 16}}>{channelCounts.network}</div>
                        </div>
                        <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                          <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>FAILED AUTH SIGNALS</div>
                          <div style={{fontWeight: 700, fontSize: 16}}>{observability.metrics?.failed_auth_events || 0}</div>
                        </div>
                      </div>
                      <div style={{display: 'grid', gap: 12}}>
                        {(observability.recent_events || []).slice(0, 6).map((event, index) => (
                          <div key={`${event.timestamp}-${index}`} style={{padding: 12, background: 'var(--bg-canvas)', borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div className="flex-between" style={{marginBottom: 6}}>
                              <span style={{fontWeight: 600, fontSize: 13}}>{event.title}</span>
                              <span style={{fontSize: 12, color: 'var(--text-subtle)'}}>{new Date(event.timestamp).toLocaleTimeString()}</span>
                            </div>
                            <div style={{fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6}}>
                              {event.detail}
                            </div>
                            {event.agent || event.tool ? (
                              <div style={{fontSize: 12, color: 'var(--text-subtle)', marginTop: 6}}>
                                {event.agent ? `Agent: ${event.agent}` : ""}
                                {event.agent && event.tool ? " • " : ""}
                                {event.tool ? `Tool: ${event.tool}` : ""}
                              </div>
                            ) : null}
                          </div>
                        ))}
                        {!observability.recent_events?.length ? (
                          <div style={{color: 'var(--text-muted)', fontSize: 13}}>OpenTelemetry spans will appear here as soon as the collector or agents run.</div>
                        ) : null}
                      </div>
                    </div>
                    <div className="card">
                      <div className="card-title" style={{marginBottom: 16}}>Detection Highlights</div>
                      <div style={{display: 'grid', gap: 12}}>
                        {(observability.recent_alerts || []).slice(0, 6).map((alert, index) => (
                          <div key={`${alert.timestamp}-${index}`} style={{padding: 12, background: 'var(--bg-canvas)', borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div className="flex-between" style={{marginBottom: 6}}>
                              <span style={{fontWeight: 600, fontSize: 13}}>{alert.agent}</span>
                              <span className={`status-pill badge-${alert.severity === 'CRITICAL' ? 'red' : 'amber'}`}>{alert.severity}</span>
                            </div>
                            <div style={{fontSize: 13, color: 'var(--text-muted)', marginBottom: 6}}>{alert.message}</div>
                            <div style={{fontSize: 12, color: 'var(--text-subtle)'}}>Incident: {alert.attack_id || 'n/a'} • Tool: {alert.tool}</div>
                          </div>
                        ))}
                        {!observability.recent_alerts?.length ? (
                          <div style={{color: 'var(--text-muted)', fontSize: 13}}>
                            Normal telemetry is flowing. When repeated failed logins or recon starts, the detection agent will flag it here.
                          </div>
                        ) : null}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {currentTab === 'telemetry' && (
                <div>
                  <div className="page-grid page-grid-telemetry" style={{marginBottom: 24}}>
                    <div className="card">
                      <div className="card-title" style={{marginBottom: 16}}>Collector setup</div>
                      <div>
                        <div style={{marginBottom: 16, color: 'var(--text-muted)'}}>
                          Use this project token in the dummy storefront so browsing, login activity, and suspicious behavior map into the correct protected application.
                        </div>
                        <div style={{background: 'var(--bg-canvas)', padding: 16, borderRadius: 8, border: '1px solid var(--border-color)', marginBottom: 16}}>
                          <div className="flex-between" style={{gap: 12, marginBottom: 8}}>
                            <div style={{fontSize: 12, color: 'var(--color-gold)', fontWeight: 'bold'}}>COLLECTOR TOKEN</div>
                            <button className="btn btn-secondary" style={{padding: '8px 12px'}} onClick={copyCollectorToken}>
                              {copyFeedback || "Copy token"}
                            </button>
                          </div>
                          <div style={tokenStyle}>{selectedWebsite.collector?.ingest_token || "Unavailable"}</div>
                        </div>
                        <div style={{display: 'grid', gap: 12}}>
                          <div style={{padding: 14, background: 'var(--bg-canvas)', borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div style={{fontSize: 12, color: 'var(--text-subtle)', marginBottom: 6}}>How to use it</div>
                            <div style={{fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.7}}>
                              Paste this token into NovaCart on <code>localhost:3001</code>. The storefront will begin syncing healthy application activity every few seconds and will send attack scenarios when you simulate failed logins, recon, or traffic spikes.
                            </div>
                          </div>
                          <div style={{padding: 14, background: 'var(--bg-canvas)', borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div style={{fontSize: 12, color: 'var(--text-subtle)', marginBottom: 6}}>Connection status</div>
                            <div style={{fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.7}}>
                              Recent activity should appear below as normalized application, authentication, and network events. Malicious behavior will also trigger the incident workflow in the threat-detection tab.
                            </div>
                          </div>
                        </div>
                      </div>
                      </div>
                      <div className="card telemetry-summary-card">
                        <div className="card-title" style={{marginBottom: 16}}>OpenTelemetry Monitor</div>
                        <div className="grid-metrics" style={{gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 12, marginBottom: 16}}>
                          <div style={{background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>APPLICATION LOGS</div>
                            <div style={{fontWeight: 700, fontSize: 18}}>{channelCounts.access}</div>
                          </div>
                          <div style={{background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>AUTHENTICATION LOGS</div>
                            <div style={{fontWeight: 700, fontSize: 18}}>{channelCounts.auth}</div>
                          </div>
                          <div style={{background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>NETWORK LOGS</div>
                            <div style={{fontWeight: 700, fontSize: 18}}>{channelCounts.network}</div>
                          </div>
                          <div style={{background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>FAILED LOGIN SIGNALS</div>
                            <div style={{fontWeight: 700, fontSize: 18}}>{observability.metrics?.failed_auth_events || 0}</div>
                          </div>
                        </div>
                        <div style={{fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.7}}>
                          The monitoring layer is capturing live application, authentication, and network activity from the storefront. When failed logins or suspicious scans start, those same signals feed the detection chain.
                        </div>
                      </div>
                  </div>
                  
                  <div className="card">
                    <div className="card-title" style={{marginBottom: 16}}>Normalized Event Streams</div>
                    <div className="grid-layout">
                      {[
                        { title: 'Application Logs', events: accessEvents, empty: 'Application events will appear here.' },
                        { title: 'Authentication Logs', events: authEvents, empty: 'Authentication events will appear here.' },
                        { title: 'Network Logs', events: networkEvents, empty: 'Network events will appear here.' },
                      ].map((group) => (
                        <div key={group.title} style={{background: 'var(--bg-canvas)', borderRadius: 12, border: '1px solid var(--border-color)', padding: 14}}>
                          <div style={{fontSize: 13, fontWeight: 700, marginBottom: 10}}>{group.title}</div>
                          <div style={{display: 'grid', gap: 8}}>
                            {group.events.length ? group.events.map((event, i) => (
                              <div key={`${group.title}-${i}`} style={{padding: 10, borderRadius: 10, background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border-color)'}}>
                                <div style={{fontSize: 12, color: 'var(--text-subtle)', marginBottom: 4}}>{new Date(event.timestamp).toLocaleTimeString()}</div>
                                <div style={{fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6}}>{event.message}</div>
                              </div>
                            )) : (
                              <div style={{fontSize: 12, color: 'var(--text-muted)'}}>{group.empty}</div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {currentTab === 'reports' && (
                <div>
                  <div className="flex-between" style={{marginBottom: 24}}>
                    <div>
                      <div className="card-title" style={{fontSize: 24}}>Reports</div>
                      <div style={{color: 'var(--text-muted)'}}>Reporting Agent outputs, executive summaries, and completed case writeups.</div>
                    </div>
                  </div>

                  <div className="grid-layout">
                    <div className="card">
                      <div className="card-title" style={{marginBottom: 16}}>Generated Reports</div>
                      <div style={{display: 'grid', gap: 12}}>
                        {reportIncidents.length ? reportIncidents.map((incident) => (
                          <div key={incident.attack_id} style={{padding: 14, background: 'var(--bg-canvas)', borderRadius: 14, border: '1px solid var(--border-color)'}}>
                            <div className="flex-between" style={{marginBottom: 8}}>
                              <span style={{fontWeight: 700, fontSize: 13}}>{incident.incident_report?.report_id || incident.attack_id}</span>
                              <span style={{fontSize: 12, color: 'var(--text-subtle)'}}>{incident.classification?.predicted_class || 'Incident'}</span>
                            </div>
                            <div style={{fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.7, marginBottom: 10}}>
                              {incident.incident_report?.executive_summary || 'Report pending.'}
                            </div>
                            <div style={{fontSize: 12, color: 'var(--text-subtle)', marginBottom: 10}}>
                              Severity: {incident.classification?.attack?.severity || '—'} • Confidence: {incident.classification?.confidence ? `${Math.round(incident.classification.confidence * 100)}%` : '—'}
                            </div>
                            <button className="btn btn-secondary" style={{padding: '8px 12px'}} onClick={() => { setCurrentTab('incidents'); setSelectedIncidentId(incident.attack_id); setIncidentDetailTab('report'); }}>
                              Open incident report
                            </button>
                          </div>
                        )) : (
                          <div style={{fontSize: 13, color: 'var(--text-muted)'}}>Reports will appear here once the reporting agent completes an incident workflow.</div>
                        )}
                      </div>
                    </div>

                    <div className="card">
                      <div className="card-title" style={{marginBottom: 16}}>Report Coverage</div>
                      <div className="grid-metrics" style={{gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 12}}>
                        <div style={{background: 'var(--bg-canvas)', padding: 14, borderRadius: 12, border: '1px solid var(--border-color)'}}>
                          <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>TOTAL REPORTS</div>
                          <div style={{fontWeight: 700, fontSize: 20}}>{reportIncidents.length}</div>
                        </div>
                        <div style={{background: 'var(--bg-canvas)', padding: 14, borderRadius: 12, border: '1px solid var(--border-color)'}}>
                          <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>PENDING WRITEUP</div>
                          <div style={{fontWeight: 700, fontSize: 20}}>{websiteIncidents.filter((incident) => !incident.incident_report?.report_id).length}</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {currentTab === 'incidents' && (
                <div>
                  <div className="card" style={{padding: '16px 0'}}>
                    <div className="card-title" style={{padding: '0 16px', marginBottom: 12}}>Incident Queue</div>
                    <div style={{display: 'flex', gap: 8, padding: '0 16px 12px', flexWrap: 'wrap'}}>
                      <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)} style={{...inputStyle, width: 160, marginBottom: 0}}>
                        <option value="all">All severities</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                      </select>
                      <select value={approvalFilter} onChange={(event) => setApprovalFilter(event.target.value)} style={{...inputStyle, width: 180, marginBottom: 0}}>
                        <option value="all">All statuses</option>
                        <option value="pending">Pending approval</option>
                        <option value="approved">Approved</option>
                        <option value="rejected">Rejected</option>
                        <option value="auto_approved">Auto approved</option>
                        <option value="manual_required">Manual required</option>
                      </select>
                    </div>
                    <div style={{display: 'flex', flexDirection: 'column'}}>
                      {websiteIncidents.length ? websiteIncidents.map(incident => {
                        const severity = incident.classification?.attack?.severity || "LOW";
                        const policyMode = incident.policy_decision?.mode || "approval_required";
                        return (
                          <div key={incident.attack_id} className={`table-row-clickable ${selectedIncidentId === incident.attack_id ? 'active' : ''}`} onClick={() => setSelectedIncidentId(incident.attack_id)} style={{padding: '18px 16px', borderBottom: '1px solid var(--border-color)', background: selectedIncidentId === incident.attack_id ? 'var(--panel-alt)' : 'transparent', cursor: 'pointer'}}>
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

                  {selectedIncident ? (
                    <div
                      onClick={() => setSelectedIncidentId("")}
                      style={{
                        position: 'fixed',
                        inset: 0,
                        zIndex: 80,
                        background: 'rgba(7, 7, 10, 0.72)',
                        backdropFilter: 'blur(10px)',
                        display: 'flex',
                        justifyContent: 'center',
                        alignItems: 'center',
                        padding: 20,
                      }}
                    >
                      <div
                        className="card"
                        onClick={(event) => event.stopPropagation()}
                        style={{
                          width: 'min(960px, calc(100vw - 48px))',
                          maxWidth: '100%',
                          height: 'min(88vh, 980px)',
                          overflowY: 'auto',
                          borderRadius: 28,
                          padding: 24,
                          boxShadow: '0 24px 80px rgba(0,0,0,0.45)',
                        }}
                      >
                        <div className="flex-between" style={{marginBottom: 16}}>
                          <div>
                            <div style={{fontSize: 12, color: 'var(--color-gold)', fontWeight: 600, marginBottom: 4}}>INCIDENT DETAILS</div>
                            <div className="card-title" style={{fontSize: 20}}>{selectedIncident.classification?.predicted_class || selectedIncident.attack_id}</div>
                          </div>
                          <button className="btn btn-secondary" style={{padding: 10, minWidth: 42}} onClick={() => setSelectedIncidentId("")}>
                            <X size={18} />
                          </button>
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
                            <div style={{fontWeight: 600, fontSize: 13}}>{selectedIncident.runtime_metadata?.active_runtime || selectedIncident.llm_usage?.["Threat Classification Agent"]?.runtime || '—'}</div>
                          </div>
                          <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>CONFIDENCE SOURCE</div>
                            <div style={{fontWeight: 600, fontSize: 13}}>{selectedIncident.classification?.confidence_source || '—'}</div>
                          </div>
                          <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>MODEL VERSION</div>
                            <div style={{fontWeight: 600, fontSize: 13}}>{selectedIncident.classification?.model_prediction?.model_version || '—'}</div>
                          </div>
                          <div style={{background: 'var(--bg-canvas)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                            <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>ASSIGNEE</div>
                            <div style={{fontWeight: 600, fontSize: 13}}>{selectedIncident.assignee?.name || 'Unassigned'}</div>
                          </div>
                        </div>

                        <div className="flex-gap" style={{marginBottom: 16, flexWrap: 'wrap'}}>
                          <button className={`btn ${incidentDetailTab === 'overview' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setIncidentDetailTab('overview')}>
                            Overview
                          </button>
                          <button className={`btn ${incidentDetailTab === 'discussion' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setIncidentDetailTab('discussion')}>
                            Agent Discussion
                          </button>
                          <button className={`btn ${incidentDetailTab === 'analysis' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setIncidentDetailTab('analysis')}>
                            Analysis Trace
                          </button>
                          <button className={`btn ${incidentDetailTab === 'report' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setIncidentDetailTab('report')}>
                            Report
                          </button>
                        </div>

                        {incidentDetailTab === 'overview' ? (
                          <>
                        <div style={{padding: 16, background: 'var(--bg-canvas)', border: '1px solid var(--border-color)', borderRadius: 12, marginBottom: 24}}>
                          <div className="card-title" style={{marginBottom: 12, fontSize: 14, color: 'var(--color-gold)'}}>Ownership</div>
                          <div className="flex-gap" style={{alignItems: 'stretch', flexWrap: 'wrap'}}>
                            <input
                              value={assigneeDraft}
                              onChange={(event) => setAssigneeDraft(event.target.value)}
                              placeholder="Assign analyst or incident owner"
                              style={{...inputStyle, flex: '1 1 240px', marginBottom: 0}}
                            />
                            <button className="btn btn-secondary" onClick={assignIncident} disabled={assigning || !assigneeDraft.trim()}>
                              {assigning ? 'Assigning...' : 'Assign owner'}
                            </button>
                          </div>
                          {selectedIncident.assignee?.assigned_by ? (
                            <div style={{fontSize: 12, color: 'var(--text-subtle)', marginTop: 8}}>
                              Assigned by {selectedIncident.assignee.assigned_by} at {new Date(selectedIncident.assignee.assigned_at).toLocaleString()}
                            </div>
                          ) : null}
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

                        {selectedIncident.challenge_review ? (
                          <div style={{padding: 16, background: 'var(--bg-canvas)', border: '1px solid var(--border-color)', borderRadius: 12, marginBottom: 24}}>
                            <div className="card-title" style={{marginBottom: 12, fontSize: 14, color: 'var(--color-gold)'}}>Challenge Review</div>
                            <div className="grid-metrics" style={{gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 12, marginBottom: 12}}>
                              <div style={{background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                                <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>OUTCOME</div>
                                <div style={{fontWeight: 700, fontSize: 15, textTransform: 'capitalize'}}>{selectedIncident.challenge_review.challenge_outcome || 'support'}</div>
                              </div>
                              <div style={{background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                                <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>ALT CLASS</div>
                                <div style={{fontWeight: 700, fontSize: 15}}>{selectedIncident.challenge_review.alternative_class || '—'}</div>
                              </div>
                              <div style={{background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 8, border: '1px solid var(--border-color)'}}>
                                <div style={{fontSize: 11, color: 'var(--text-subtle)', marginBottom: 4}}>FALSE POSITIVE RISK</div>
                                <div style={{fontWeight: 700, fontSize: 15}}>{selectedIncident.challenge_review.false_positive_risk || '—'}</div>
                              </div>
                            </div>
                            <div style={{fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.7}}>
                              Confidence in primary verdict: {selectedIncident.challenge_review.confidence_in_primary ? `${Math.round(selectedIncident.challenge_review.confidence_in_primary * 100)}%` : 'n/a'}
                            </div>
                            {(selectedIncident.challenge_review.notes || []).length ? (
                              <div style={{marginTop: 10, display: 'grid', gap: 8}}>
                                {(selectedIncident.challenge_review.notes || []).map((note, idx) => (
                                  <div key={idx} style={{fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6}}>
                                    • {note}
                                  </div>
                                ))}
                              </div>
                            ) : null}
                          </div>
                        ) : null}

                          </>
                        ) : null}

                        {incidentDetailTab === 'discussion' ? (
                          <>
                            <div className="card-title" style={{marginBottom: 12, fontSize: 14, color: 'var(--color-gold)'}}>AGENT DISCUSSION</div>
                            <div style={{display: 'flex', flexDirection: 'column', gap: 12}}>
                              {visibleDiscussion.map((entry, idx) => (
                                <div key={idx} style={{padding: 14, background: idx % 2 === 0 ? 'rgba(139, 92, 246, 0.08)' : 'var(--bg-canvas)', borderRadius: 14, border: '1px solid var(--border-color)'}}>
                                  <div className="flex-between" style={{marginBottom: 8, gap: 12}}>
                                    <span style={{fontWeight: 700, fontSize: 13}}>
                                      {entry.speaker}
                                      {entry.audience ? (
                                        <span style={{fontWeight: 500, color: 'var(--text-subtle)', marginLeft: 8}}>→ {entry.audience}</span>
                                      ) : null}
                                    </span>
                                    <span style={{fontSize: 12, color: 'var(--text-subtle)', textTransform: 'capitalize'}}>{(entry.stage || entry.kind || 'discussion').replace(/_/g, ' ')}</span>
                                  </div>
                                  <div style={{fontSize: 14, color: 'var(--text-muted)', lineHeight: 1.7}}>
                                    {entry.message}
                                  </div>
                                  <div style={{fontSize: 12, color: 'var(--text-subtle)', marginTop: 8, textTransform: 'capitalize'}}>
                                    {entry.source === 'gemini' ? 'Generated with Gemini' : 'Local fallback'}
                                  </div>
                                </div>
                              ))}
                              {!visibleDiscussion.length ? (
                                <div style={{fontSize: 13, color: 'var(--text-muted)'}}>
                                  The agent conversation will appear here once the incident workflow begins.
                                </div>
                              ) : null}
                            </div>
                          </>
                        ) : null}

                        {incidentDetailTab === 'analysis' ? (
                          <>
                            <div className="card-title" style={{marginBottom: 12, fontSize: 14, color: 'var(--color-gold)'}}>AGENT TRACE</div>
                            <div style={{display: 'flex', flexDirection: 'column', gap: 12}}>
                              {visibleAgentTrace.map((entry, idx) => (
                                <div key={idx} style={{padding: 12, background: 'var(--bg-canvas)', borderRadius: 8, border: '1px solid var(--border-color)'}}>
                                  <div className="flex-between" style={{marginBottom: 6}}>
                                    <span style={{fontWeight: 600, fontSize: 13}}>{entry.agent}</span>
                                    <span style={{fontSize: 12, color: 'var(--text-subtle)'}}>{entry.stage}</span>
                                  </div>
                                  <div style={{fontSize: 13, color: 'var(--text-muted)'}}>{entry.summary}</div>
                                  {entry.details?.tool || entry.details?.llm_runtime ? (
                                    <div style={{fontSize: 12, color: 'var(--text-subtle)', marginTop: 6}}>
                                      {entry.details?.tool ? `Tool: ${entry.details.tool}` : ""}
                                      {entry.details?.tool && entry.details?.llm_runtime ? " • " : ""}
                                      {entry.details?.llm_runtime ? `Runtime: ${entry.details.llm_runtime}` : ""}
                                    </div>
                                  ) : null}
                                </div>
                              ))}
                              {!visibleAgentTrace.length ? (
                                <div style={{fontSize: 13, color: 'var(--text-muted)'}}>
                                  Agent trace will appear here once the multi-agent coordinator publishes the incident workflow.
                                </div>
                              ) : null}
                            </div>

                            {visibleAgentMessages.length ? (
                              <>
                                <div className="card-title" style={{marginTop: 24, marginBottom: 12, fontSize: 14, color: 'var(--color-gold)'}}>AGENT HANDOFFS</div>
                                <div style={{display: 'flex', flexDirection: 'column', gap: 12}}>
                                  {visibleAgentMessages.map((entry, idx) => (
                                    <div key={idx} style={{padding: 12, background: 'var(--bg-canvas)', borderRadius: 8, border: '1px solid var(--border-color)'}}>
                                      <div className="flex-between" style={{marginBottom: 6}}>
                                        <span style={{fontWeight: 600, fontSize: 13}}>{entry.from} → {entry.to}</span>
                                        <span style={{fontSize: 12, color: 'var(--text-subtle)'}}>{entry.subject}</span>
                                      </div>
                                      <div style={{fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6}}>{entry.content}</div>
                                      {entry.artifacts?.tool || entry.artifacts?.current_stage ? (
                                        <div style={{fontSize: 12, color: 'var(--text-subtle)', marginTop: 6}}>
                                          {entry.artifacts?.tool ? `Tool: ${entry.artifacts.tool}` : ""}
                                          {entry.artifacts?.tool && entry.artifacts?.current_stage ? " • " : ""}
                                          {entry.artifacts?.current_stage ? `Stage: ${entry.artifacts.current_stage}` : ""}
                                        </div>
                                      ) : null}
                                    </div>
                                  ))}
                                </div>
                              </>
                            ) : null}

                            {(selectedIncident.runtime_metadata?.planner_trace || []).length ? (
                              <>
                                <div className="card-title" style={{marginTop: 24, marginBottom: 12, fontSize: 14, color: 'var(--color-gold)'}}>COORDINATOR PLAN</div>
                                <div style={{display: 'flex', flexDirection: 'column', gap: 12}}>
                                  {(selectedIncident.runtime_metadata?.planner_trace || []).map((entry, idx) => (
                                    <div key={idx} style={{padding: 12, background: 'var(--bg-canvas)', borderRadius: 8, border: '1px solid var(--border-color)'}}>
                                      <div className="flex-between" style={{marginBottom: 8}}>
                                        <span style={{fontWeight: 600, fontSize: 13}}>{entry.phase} phase</span>
                                        <span style={{fontSize: 12, color: 'var(--text-subtle)'}}>{entry.tool}</span>
                                      </div>
                                      <div style={{fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6}}>
                                        {entry.reason}
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              </>
                            ) : null}

                            {(selectedIncident.tool_trace || []).length ? (
                              <>
                                <div className="card-title" style={{marginTop: 24, marginBottom: 12, fontSize: 14, color: 'var(--color-gold)'}}>MCP TOOL TRACE</div>
                                <div style={{display: 'flex', flexDirection: 'column', gap: 12}}>
                                  {(selectedIncident.tool_trace || []).map((entry, idx) => (
                                    <div key={idx} style={{padding: 12, background: 'var(--bg-canvas)', borderRadius: 8, border: '1px solid var(--border-color)'}}>
                                      <div className="flex-between" style={{marginBottom: 8}}>
                                        <span style={{fontWeight: 600, fontSize: 13}}>{entry.agent}</span>
                                        <span style={{fontSize: 12, color: 'var(--text-subtle)'}}>{entry.tool}</span>
                                      </div>
                                      <div style={{fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6}}>
                                        Output stage: {entry.output_summary?.current_stage || 'n/a'} • Approval: {entry.output_summary?.approval_status || 'n/a'}
                                      </div>
                                      {entry.llm_agent ? (
                                        <div style={{fontSize: 12, color: 'var(--text-subtle)', marginTop: 6}}>
                                          {entry.llm_agent} {entry.llm_used ? `used ${entry.llm_runtime || 'Gemini'}` : 'fell back to heuristic logic'}.
                                        </div>
                                      ) : null}
                                      {entry.prompt_profile?.purpose ? (
                                        <div style={{fontSize: 12, color: 'var(--text-subtle)', marginTop: 6}}>
                                          Purpose: {entry.prompt_profile.purpose}
                                        </div>
                                      ) : null}
                                      {entry.planner_reason ? (
                                        <div style={{fontSize: 12, color: 'var(--text-subtle)', marginTop: 6}}>
                                          Coordinator: {entry.planner_reason}
                                        </div>
                                      ) : null}
                                    </div>
                                  ))}
                                </div>
                              </>
                            ) : null}
                          </>
                        ) : null}

                        {incidentDetailTab === 'report' ? (
                          <>
                        <div style={{padding: 16, background: 'var(--bg-canvas)', border: '1px solid var(--border-color)', borderRadius: 12, marginBottom: 24}}>
                          <div className="card-title" style={{marginBottom: 12, fontSize: 14, color: 'var(--color-gold)'}}>Reporting Agent Summary</div>
                          {selectedIncident.incident_report ? (
                            <div style={{display: 'grid', gap: 12}}>
                              <div style={{fontSize: 12, color: 'var(--text-subtle)'}}>{selectedIncident.incident_report.report_id}</div>
                              <div style={{fontSize: 14, color: 'var(--text-muted)', lineHeight: 1.8}}>
                                {selectedIncident.incident_report.executive_summary}
                              </div>
                              {(selectedIncident.incident_report.recommendations || []).length ? (
                                <div style={{display: 'grid', gap: 8}}>
                                  {(selectedIncident.incident_report.recommendations || []).map((item, idx) => (
                                    <div key={idx} style={{fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6}}>• {item}</div>
                                  ))}
                                </div>
                              ) : null}
                            </div>
                          ) : (
                            <div style={{fontSize: 13, color: 'var(--text-muted)'}}>The reporting agent will publish the final incident summary here after resolution.</div>
                          )}
                        </div>

                        <div className="card-title" style={{marginTop: 24, marginBottom: 12, fontSize: 14, color: 'var(--color-gold)'}}>CASE NOTES</div>
                        <div style={{display: 'flex', flexDirection: 'column', gap: 12}}>
                          {((selectedIncident.notes || []).length ? selectedIncident.notes : []).map((note, idx) => (
                            <div key={idx} style={{padding: 12, background: 'var(--bg-canvas)', borderRadius: 8, border: '1px solid var(--border-color)'}}>
                              <div className="flex-between" style={{marginBottom: 6}}>
                                <span style={{fontWeight: 600, fontSize: 13}}>
                                  {note.author}
                                  {note.author_role ? (
                                    <span style={{fontWeight: 500, color: 'var(--text-subtle)', marginLeft: 8, textTransform: 'capitalize'}}>
                                      {note.author_role}
                                    </span>
                                  ) : null}
                                </span>
                                <span style={{fontSize: 12, color: 'var(--text-subtle)'}}>{new Date(note.created_at).toLocaleString()}</span>
                              </div>
                              <div style={{fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.6}}>{note.note}</div>
                            </div>
                          ))}
                          {!(selectedIncident.notes || []).length ? (
                            <div style={{fontSize: 13, color: 'var(--text-muted)'}}>No analyst notes yet.</div>
                          ) : null}
                          <textarea
                            value={noteDraft}
                            onChange={(event) => setNoteDraft(event.target.value)}
                            placeholder="Add an analyst note, investigation update, or escalation comment..."
                            style={{...inputStyle, minHeight: 110, resize: 'vertical'}}
                          />
                          <div>
                            <button className="btn btn-secondary" onClick={addIncidentNote} disabled={notesSaving || !noteDraft.trim()}>
                              {notesSaving ? 'Saving note...' : 'Add note'}
                            </button>
                          </div>
                        </div>
                          </>
                        ) : null}
                      </div>
                    </div>
                  ) : null}
                </div>
              )}

              {currentTab === 'settings' && (
                <div className="page-grid page-grid-settings">
                  <div className="card">
                    <div className="card-title" style={{marginBottom: 16}}>Workspace profile</div>
                    <div className="settings-grid">
                      <div className="settings-key">Project</div>
                      <div className="settings-value">{selectedWebsite.name}</div>
                      <div className="settings-key">Domain</div>
                      <div className="settings-value">{selectedWebsite.domain}</div>
                      <div className="settings-key">Environment</div>
                      <div className="settings-value">{selectedWebsite.environment}</div>
                      <div className="settings-key">Connection type</div>
                      <div className="settings-value">{selectedWebsite.connection_type}</div>
                      <div className="settings-key">Collector mode</div>
                      <div className="settings-value">{selectedWebsite.collector?.mode || "agent"}</div>
                    </div>
                  </div>

                  <div className="card">
                    <div className="card-title" style={{marginBottom: 16}}>Collector identity</div>
                    <div style={{background: 'var(--bg-canvas)', padding: 16, borderRadius: 12, border: '1px solid var(--border-color)', marginBottom: 16}}>
                      <div style={{fontSize: 12, color: 'var(--color-gold)', fontWeight: 700, marginBottom: 8}}>INGEST TOKEN</div>
                      <div style={tokenStyle}>{selectedWebsite.collector?.ingest_token || "Unavailable"}</div>
                    </div>
                    <div style={{fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.7}}>
                      Keep this token bound to the storefront or collector process that belongs to this workspace. Rotating tokens is not exposed yet, so treat it like an environment secret.
                    </div>
                  </div>

                  <div className="card">
                    <div className="card-title" style={{marginBottom: 16}}>Runtime endpoints</div>
                    <div className="settings-grid">
                      <div className="settings-key">Collector ingest</div>
                      <div className="settings-value">{integration?.ingest_url || `${API_BASE}/collector/ingest`}</div>
                      <div className="settings-key">MCP endpoint</div>
                      <div className="settings-value">{integration?.protocols?.mcp_endpoint || `${API_BASE}/mcp`}</div>
                      <div className="settings-key">Tool registry</div>
                      <div className="settings-value">{integration?.protocols?.mcp_tools_url || `${API_BASE}/mcp/tools`}</div>
                      <div className="settings-key">Observability</div>
                      <div className="settings-value">{integration?.protocols?.observability_url || `${API_BASE}/websites/${selectedWebsiteId}/observability`}</div>
                    </div>
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

const landingNavButtonStyle = {
  background: "transparent",
  border: "none",
  color: colors.muted,
  fontSize: 14,
  padding: 0,
  cursor: "pointer",
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

const landingSectionStyle = {
  padding: "28px 0 0",
  marginTop: 28,
};

const landingSectionIntroStyle = {
  maxWidth: 780,
  marginBottom: 20,
};

const landingSectionEyebrowStyle = {
  color: colors.gold,
  fontSize: 12,
  fontWeight: 800,
  letterSpacing: 1.4,
  textTransform: "uppercase",
  marginBottom: 12,
};

const landingSectionTitleStyle = {
  fontSize: 34,
  lineHeight: 1.15,
  fontWeight: 800,
  letterSpacing: -0.8,
  marginBottom: 12,
};

const landingSectionBodyStyle = {
  fontSize: 16,
  lineHeight: 1.8,
  color: colors.muted,
};

const landingFeatureGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
  gap: 18,
};

const landingFeatureCardStyle = {
  background: "rgba(19, 19, 20, 0.78)",
  border: `1px solid ${colors.border}`,
  borderRadius: 24,
  padding: 22,
  backdropFilter: "blur(12px)",
};

const landingFeatureStepStyle = {
  color: colors.gold,
  fontSize: 12,
  fontWeight: 800,
  letterSpacing: 1.4,
  marginBottom: 12,
};

const landingFeatureTitleStyle = {
  fontSize: 18,
  fontWeight: 700,
  marginBottom: 10,
};

const landingFeatureBodyStyle = {
  fontSize: 14,
  lineHeight: 1.7,
  color: colors.muted,
};

const landingSecurityGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
  gap: 18,
};

const landingSecurityCardStyle = {
  background: "linear-gradient(180deg, rgba(139, 92, 246, 0.08), rgba(19, 19, 20, 0.82))",
  border: `1px solid ${colors.border}`,
  borderRadius: 24,
  padding: 22,
};

const landingQuoteCardStyle = {
  background: "rgba(19, 19, 20, 0.78)",
  border: `1px solid ${colors.border}`,
  borderRadius: 24,
  padding: 22,
  color: colors.text,
  fontSize: 16,
  lineHeight: 1.8,
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
