import React, { useEffect, useMemo, useRef, useState } from "react";

const API_BASE = "http://localhost:8000";
const WS_URL = "ws://localhost:8000/ws";

const colors = {
  background: "#f7f7f5",
  page: "#fbfbfa",
  card: "#ffffff",
  mutedCard: "#f3f3f1",
  border: "#e6e6e1",
  text: "#191919",
  secondaryText: "#6b6b67",
  subtleText: "#8d8d88",
  accent: "#2f76ff",
  green: "#0f9d58",
  red: "#d14343",
  amber: "#b7791f",
  purple: "#7c5cff",
  gray: "#787774",
};

const severityColors = {
  CRITICAL: "#d14343",
  HIGH: "#d9730d",
  MEDIUM: "#b7791f",
  LOW: "#0f9d58",
};

const stageMeta = {
  red_team_attacking: { icon: "●", label: "Under attack" },
  threat_detection: { icon: "●", label: "Detecting" },
  threat_detected: { icon: "●", label: "Detecting" },
  classified: { icon: "●", label: "Classified" },
  awaiting_approval: { icon: "●", label: "Awaiting approval" },
  action_executing: { icon: "●", label: "Executing" },
  mitigated: { icon: "●", label: "Mitigated" },
  manual_queue: { icon: "●", label: "Manual queue" },
};

function formatTime(value) {
  return new Date(value || Date.now()).toLocaleTimeString();
}

function Section({ title, children, eyebrow }) {
  return (
    <section
      style={{
        background: colors.card,
        border: `1px solid ${colors.border}`,
        borderRadius: 12,
        padding: 20,
        marginBottom: 16,
      }}
    >
      <div style={{ marginBottom: 16 }}>
        {eyebrow ? (
          <div style={{ color: colors.subtleText, fontSize: 12, marginBottom: 6, fontWeight: 600 }}>{eyebrow}</div>
        ) : null}
        <div style={{ color: colors.text, fontSize: 18, fontWeight: 650 }}>{title}</div>
      </div>
      {children}
    </section>
  );
}

function StatCard({ label, value }) {
  return (
    <div
      style={{
        background: colors.card,
        border: `1px solid ${colors.border}`,
        borderRadius: 12,
        padding: "16px 18px",
      }}
    >
      <div style={{ color: colors.subtleText, fontSize: 12, fontWeight: 600 }}>{label}</div>
      <div style={{ color: colors.text, fontSize: 28, fontWeight: 700, marginTop: 8 }}>{value}</div>
    </div>
  );
}

function Detail({ label, value, accent }) {
  return (
    <div style={{ minWidth: 180 }}>
      <div style={{ color: colors.subtleText, fontSize: 12, marginBottom: 4, fontWeight: 600 }}>{label}</div>
      <div style={{ color: accent || colors.text, fontWeight: 600, lineHeight: 1.5 }}>{value}</div>
    </div>
  );
}

function StatusPill({ color, children, subtle }) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "6px 10px",
        borderRadius: 999,
        border: `1px solid ${subtle ? colors.border : color}`,
        background: subtle ? colors.mutedCard : `${color}12`,
        color: subtle ? colors.secondaryText : color,
        fontSize: 12,
        fontWeight: 600,
      }}
    >
      {children}
    </span>
  );
}

export default function App() {
  const [incidents, setIncidents] = useState({});
  const [selectedId, setSelectedId] = useState(null);
  const [feed, setFeed] = useState([]);
  const [connected, setConnected] = useState(false);
  const [autoRunning, setAutoRunning] = useState(false);
  const [decisionLoading, setDecisionLoading] = useState({});
  const reconnectRef = useRef(null);

  useEffect(() => {
    let socket;

    const connect = () => {
      socket = new WebSocket(WS_URL);

      socket.onopen = () => {
        setConnected(true);
      };

      socket.onmessage = (event) => {
        const payload = JSON.parse(event.data);
        const entry = {
          id: `${Date.now()}-${Math.random()}`,
          type: payload.type,
          data: payload.data,
          timestamp: new Date().toISOString(),
        };
        setFeed((current) => [entry, ...current].slice(0, 50));

        if (payload.type === "init") {
          const mapped = {};
          (payload.data.incidents || []).forEach((incident) => {
            mapped[incident.attack.attack_id] = incident;
          });
          setIncidents(mapped);
          setAutoRunning(Boolean(payload.data.running));
          const firstId = Object.keys(mapped)[0];
          if (firstId) {
            setSelectedId((current) => current || firstId);
          }
        }

        if (payload.type === "red_team_attack") {
          setIncidents((current) => ({
            ...current,
            [payload.data.attack.attack_id]: payload.data,
          }));
          setSelectedId(payload.data.attack.attack_id);
        }

        if (payload.type === "agent_update" || payload.type === "incident_resolved") {
          setIncidents((current) => {
            const existing = current[payload.data.attack_id] || {};
            return {
              ...current,
              [payload.data.attack_id]: {
                ...existing,
                ...payload.data,
                attack: existing.attack,
              },
            };
          });
        }
      };

      socket.onclose = () => {
        setConnected(false);
        reconnectRef.current = window.setTimeout(connect, 3000);
      };

      socket.onerror = () => {
        socket.close();
      };
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
  }, []);

  const incidentList = useMemo(
    () =>
      Object.values(incidents).sort((a, b) => {
        const left = a.attack?.timestamp || "";
        const right = b.attack?.timestamp || "";
        return right.localeCompare(left);
      }),
    [incidents]
  );

  const selected = selectedId ? incidents[selectedId] : null;
  const stats = useMemo(() => {
    const values = Object.values(incidents);
    return {
      total: values.length,
      pending: values.filter((incident) => incident.approval_status === "pending").length,
      mitigated: values.filter((incident) => incident.action_result?.status === "MITIGATED").length,
      critical: values.filter((incident) => incident.attack?.severity === "CRITICAL").length,
    };
  }, [incidents]);

  async function simulateAttack() {
    await fetch(`${API_BASE}/simulate`, { method: "POST" });
  }

  async function toggleAuto() {
    const endpoint = autoRunning ? "/auto-simulate/stop" : "/auto-simulate";
    const response = await fetch(`${API_BASE}${endpoint}`, { method: "POST" });
    const data = await response.json();
    setAutoRunning(Boolean(data.running));
  }

  async function submitDecision(incidentId, decision) {
    setDecisionLoading((current) => ({ ...current, [incidentId]: true }));
    try {
      const response = await fetch(`${API_BASE}/incidents/${incidentId}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision }),
      });
      const data = await response.json();
      setIncidents((current) => ({
        ...current,
        [incidentId]: data,
      }));
    } finally {
      setDecisionLoading((current) => ({ ...current, [incidentId]: false }));
    }
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        background: colors.background,
        color: colors.text,
        fontFamily:
          'ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif',
        padding: 24,
        boxSizing: "border-box",
      }}
    >
      <div style={{ maxWidth: 1480, margin: "0 auto" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            gap: 16,
            flexWrap: "wrap",
            marginBottom: 20,
          }}
        >
          <div>
            <div style={{ color: colors.subtleText, fontSize: 13, fontWeight: 600, marginBottom: 8 }}>Dashboard</div>
            <div style={{ fontSize: 34, fontWeight: 700, letterSpacing: -0.8, marginBottom: 6 }}>CyberAgent</div>
            <div style={{ color: colors.secondaryText, maxWidth: 640, lineHeight: 1.6 }}>
              Multi-agent incident orchestration with simulated attacks, model classification, approval gates, and
              report generation.
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <StatusPill color={connected ? colors.green : colors.red}>
              <span style={{ fontSize: 10 }}>{connected ? "●" : "●"}</span>
              {connected ? "Live" : "Offline"}
            </StatusPill>
            <button onClick={simulateAttack} style={primaryButtonStyle}>
              Simulate attack
            </button>
            <button onClick={toggleAuto} style={secondaryButtonStyle}>
              {autoRunning ? "Stop auto" : "Auto demo"}
            </button>
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
            gap: 12,
            marginBottom: 20,
          }}
        >
          <StatCard label="Total incidents" value={stats.total} />
          <StatCard label="Pending approval" value={stats.pending} />
          <StatCard label="Mitigated" value={stats.mitigated} />
          <StatCard label="Critical" value={stats.critical} />
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "320px minmax(0, 1fr)",
            gap: 20,
            minHeight: "calc(100vh - 210px)",
          }}
        >
          <aside
            style={{
              background: colors.page,
              border: `1px solid ${colors.border}`,
              borderRadius: 12,
              padding: 14,
              display: "flex",
              flexDirection: "column",
              gap: 14,
              minHeight: 0,
            }}
          >
            <div style={{ minHeight: 0, flex: 1, display: "flex", flexDirection: "column" }}>
              <div style={sidebarTitleStyle}>Live feed</div>
              <div style={{ overflowY: "auto", display: "flex", flexDirection: "column", gap: 8, paddingRight: 2 }}>
                {feed.map((entry) => (
                  <div
                    key={entry.id}
                    style={{
                      background: colors.card,
                      border: `1px solid ${colors.border}`,
                      borderRadius: 10,
                      padding: 12,
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 6 }}>
                      <span style={{ color: colors.text, fontSize: 12, fontWeight: 600 }}>{entry.type}</span>
                      <span style={{ color: colors.subtleText, fontSize: 11 }}>{formatTime(entry.timestamp)}</span>
                    </div>
                    <div style={{ color: colors.secondaryText, fontSize: 12, lineHeight: 1.5 }}>
                      {entry.data.message || entry.data.current_stage || "Pipeline event received"}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ minHeight: 0, flex: 1, display: "flex", flexDirection: "column" }}>
              <div style={sidebarTitleStyle}>Incidents</div>
              <div style={{ overflowY: "auto", display: "flex", flexDirection: "column", gap: 8, paddingRight: 2 }}>
                {incidentList.map((incident) => {
                  const attack = incident.attack || {};
                  const meta = stageMeta[incident.current_stage] || stageMeta.red_team_attacking;
                  return (
                    <button
                      key={attack.attack_id}
                      onClick={() => setSelectedId(attack.attack_id)}
                      style={{
                        textAlign: "left",
                        border: `1px solid ${selectedId === attack.attack_id ? "#d8d8d2" : colors.border}`,
                        borderRadius: 10,
                        padding: 12,
                        cursor: "pointer",
                        background: selectedId === attack.attack_id ? colors.mutedCard : colors.card,
                        color: colors.text,
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
                        <div style={{ fontWeight: 650 }}>{attack.attack_id}</div>
                        <StatusPill color={severityColors[attack.severity] || colors.gray}>
                          {attack.severity}
                        </StatusPill>
                      </div>
                      <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 6 }}>{attack.attack_type}</div>
                      <div style={{ color: colors.secondaryText, fontSize: 12, marginBottom: 4 }}>
                        {meta.icon} {meta.label}
                      </div>
                      <div style={{ color: colors.subtleText, fontSize: 12 }}>{attack.primary_src_ip}</div>
                    </button>
                  );
                })}
              </div>
            </div>
          </aside>

          <main style={{ minWidth: 0 }}>
            {!selected ? (
              <div
                style={{
                  minHeight: "100%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  border: `1px solid ${colors.border}`,
                  borderRadius: 12,
                  background: colors.page,
                }}
              >
                <div style={{ textAlign: "center" }}>
                  <div style={{ color: colors.subtleText, fontSize: 14, marginBottom: 8 }}>No incident selected</div>
                  <div style={{ fontSize: 28, fontWeight: 650 }}>Choose an incident from the sidebar</div>
                </div>
              </div>
            ) : (
              <>
                <Section title={selected.attack.attack_type} eyebrow="Red Team Agent">
                  <div style={detailGridStyle}>
                    <Detail label="Attack type" value={selected.attack.attack_type} />
                    <Detail label="Target" value={`${selected.attack.target_ip}:${selected.attack.target_port}`} />
                    <Detail label="Packet rate" value={`${selected.attack.packet_rate}/sec`} />
                    <Detail label="Protocol" value={selected.attack.protocol} />
                  </div>
                  <div style={bodyRowStyle}>
                    <span style={bodyLabelStyle}>Source IPs</span>
                    <span>{selected.attack.src_ips.join(", ")}</span>
                  </div>
                  <div style={bodyRowStyle}>
                    <span style={bodyLabelStyle}>Description</span>
                    <span>{selected.attack.description}</span>
                  </div>
                  <div style={monoBoxStyle}>{selected.attack.raw_log}</div>
                </Section>

                {selected.classification && (
                  <Section title="Threat Detection Agent" eyebrow="Classification">
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        gap: 18,
                        flexWrap: "wrap",
                        marginBottom: 18,
                      }}
                    >
                      <div>
                        <div style={{ color: colors.subtleText, fontSize: 12, fontWeight: 600, marginBottom: 4 }}>
                          Predicted class
                        </div>
                        <div style={{ color: colors.text, fontSize: 28, fontWeight: 700 }}>
                          {selected.classification.predicted_class}
                        </div>
                      </div>
                      <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
                        <Detail label="Model" value={selected.classification.model} />
                        <Detail label="Features used" value={selected.classification.features_used} />
                        <Detail label="Risk score" value={selected.classification.risk_score} accent={colors.amber} />
                      </div>
                    </div>

                    <div style={{ display: "grid", gap: 12, marginBottom: 18 }}>
                      {Object.entries(selected.classification.confidence_scores).map(([label, value]) => (
                        <div key={label}>
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                            <span style={{ fontSize: 14, fontWeight: 600 }}>{label}</span>
                            <span style={{ color: colors.secondaryText, fontSize: 13 }}>{(value * 100).toFixed(1)}%</span>
                          </div>
                          <div
                            style={{
                              background: colors.mutedCard,
                              borderRadius: 999,
                              height: 8,
                              overflow: "hidden",
                            }}
                          >
                            <div
                              style={{
                                width: `${value * 100}%`,
                                height: "100%",
                                background:
                                  label === selected.classification.predicted_class ? colors.text : "#cfcfca",
                              }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>

                    <div style={{ color: colors.secondaryText, lineHeight: 1.7 }}>
                      {selected.classification.key_indicators.map((item) => (
                        <div key={item} style={{ marginBottom: 8 }}>
                          • {item}
                        </div>
                      ))}
                    </div>
                  </Section>
                )}

                {selected.mitigation_plan && (
                  <Section title="Threat Resolve Agent" eyebrow="Gemini generated plan">
                    <div style={detailGridStyle}>
                      <Detail label="Strategy" value={selected.mitigation_plan.strategy} />
                      <Detail
                        label="Estimated mitigation time"
                        value={selected.mitigation_plan.estimated_mitigation_time}
                      />
                      <Detail label="Collateral risk" value={selected.mitigation_plan.collateral_risk} accent={colors.amber} />
                    </div>

                    <div style={{ display: "grid", gap: 12, marginTop: 18 }}>
                      {selected.mitigation_plan.steps.map((step) => (
                        <div
                          key={`${step.step}-${step.action}`}
                          style={{
                            border: `1px solid ${colors.border}`,
                            borderRadius: 10,
                            padding: 14,
                            background: colors.page,
                          }}
                        >
                          <div
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              gap: 12,
                              flexWrap: "wrap",
                              marginBottom: 10,
                            }}
                          >
                            <div style={{ fontWeight: 650 }}>
                              {step.step}. {step.action}
                            </div>
                            <StatusPill color={step.reversible ? colors.green : colors.red}>
                              {step.reversible ? "Reversible" : "Permanent"}
                            </StatusPill>
                          </div>
                          <div style={monoBoxStyle}>{step.command}</div>
                          <div style={{ color: colors.secondaryText, lineHeight: 1.6, marginTop: 12 }}>{step.impact}</div>
                        </div>
                      ))}
                    </div>

                    {selected.approval_status === "pending" && (
                      <div
                        style={{
                          marginTop: 18,
                          border: `1px solid ${colors.border}`,
                          borderRadius: 10,
                          padding: 14,
                          background: colors.mutedCard,
                        }}
                      >
                        <div style={{ color: colors.text, fontWeight: 600, marginBottom: 12 }}>
                          Awaiting administrator approval before execution.
                        </div>
                        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                          <button
                            disabled={decisionLoading[selected.attack.attack_id]}
                            onClick={() => submitDecision(selected.attack.attack_id, "approved")}
                            style={approveButtonStyle(decisionLoading[selected.attack.attack_id])}
                          >
                            Approve
                          </button>
                          <button
                            disabled={decisionLoading[selected.attack.attack_id]}
                            onClick={() => submitDecision(selected.attack.attack_id, "rejected")}
                            style={rejectButtonStyle(decisionLoading[selected.attack.attack_id])}
                          >
                            Reject
                          </button>
                        </div>
                      </div>
                    )}
                  </Section>
                )}

                {selected.action_result && (
                  <Section title="Action Agent" eyebrow="Execution">
                    <div style={{ marginBottom: 16 }}>
                      <StatusPill
                        color={selected.action_result.status === "MITIGATED" ? colors.green : colors.gray}
                      >
                        {selected.action_result.status}
                      </StatusPill>
                    </div>

                    {selected.action_result.status === "MITIGATED" ? (
                      <div style={detailGridStyle}>
                        <Detail label="Steps executed" value={selected.action_result.steps_executed.length} />
                        <Detail
                          label="Total execution time"
                          value={`${selected.action_result.total_execution_time_ms} ms`}
                        />
                        <Detail label="Blocked IPs" value={selected.action_result.blocked_ips.join(", ")} />
                      </div>
                    ) : (
                      <div style={detailGridStyle}>
                        <Detail label="Ticket ID" value={selected.action_result.ticket_id} />
                        <Detail label="Assigned to" value={selected.action_result.assigned_to} />
                      </div>
                    )}
                  </Section>
                )}

                {selected.incident_report && (
                  <Section title="Incident Report" eyebrow="Gemini generated">
                    <div
                      style={{
                        border: `1px solid ${colors.border}`,
                        borderRadius: 10,
                        padding: 16,
                        background: colors.page,
                        lineHeight: 1.7,
                        marginBottom: 18,
                      }}
                    >
                      {selected.incident_report.executive_summary}
                    </div>

                    <div style={{ marginBottom: 18 }}>
                      <div style={subsectionTitleStyle}>Attack summary</div>
                      <div style={{ display: "grid", gap: 8 }}>
                        {Object.entries(selected.incident_report.attack_summary).map(([label, value]) => (
                          <div key={label} style={tableRowStyle}>
                            <div style={tableLabelStyle}>{label.replace("_", " ")}</div>
                            <div>{String(value)}</div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div style={{ marginBottom: 18 }}>
                      <div style={subsectionTitleStyle}>Recommendations</div>
                      <ol style={{ margin: "0 0 0 20px", lineHeight: 1.8, color: colors.secondaryText }}>
                        {selected.incident_report.recommendations.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ol>
                    </div>

                    <div>
                      <div style={subsectionTitleStyle}>Timeline</div>
                      <div style={{ display: "grid", gap: 8 }}>
                        {Object.entries(selected.incident_report.timeline).map(([label, value]) => (
                          <div key={label} style={tableRowStyle}>
                            <div style={tableLabelStyle}>{label}</div>
                            <div>{String(value)}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </Section>
                )}
              </>
            )}
          </main>
        </div>
      </div>
    </div>
  );
}

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
  background: colors.card,
  color: colors.text,
  fontWeight: 600,
  cursor: "pointer",
};

function approveButtonStyle(disabled) {
  return {
    border: "none",
    borderRadius: 10,
    padding: "10px 14px",
    background: colors.text,
    color: "#ffffff",
    fontWeight: 600,
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.55 : 1,
  };
}

function rejectButtonStyle(disabled) {
  return {
    border: `1px solid ${colors.border}`,
    borderRadius: 10,
    padding: "10px 14px",
    background: colors.card,
    color: colors.text,
    fontWeight: 600,
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.55 : 1,
  };
}

const sidebarTitleStyle = {
  color: colors.text,
  fontWeight: 650,
  marginBottom: 10,
};

const detailGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
  gap: 16,
};

const bodyRowStyle = {
  display: "grid",
  gridTemplateColumns: "140px 1fr",
  gap: 16,
  marginTop: 14,
  color: colors.secondaryText,
  lineHeight: 1.6,
};

const bodyLabelStyle = {
  color: colors.subtleText,
  fontWeight: 600,
};

const monoBoxStyle = {
  marginTop: 14,
  background: "#fafaf9",
  border: `1px solid ${colors.border}`,
  borderRadius: 10,
  padding: 14,
  fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", monospace',
  color: colors.text,
  overflowX: "auto",
  fontSize: 13,
  lineHeight: 1.6,
};

const subsectionTitleStyle = {
  color: colors.text,
  fontWeight: 650,
  marginBottom: 10,
};

const tableRowStyle = {
  display: "grid",
  gridTemplateColumns: "160px 1fr",
  gap: 12,
  padding: "10px 12px",
  borderRadius: 10,
  background: colors.page,
  border: `1px solid ${colors.border}`,
};

const tableLabelStyle = {
  color: colors.subtleText,
  textTransform: "capitalize",
  fontWeight: 600,
};
