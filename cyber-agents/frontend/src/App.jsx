import React, { useEffect, useMemo, useRef, useState } from "react";

const API_BASE = "http://localhost:8000";
const WS_URL = "ws://localhost:8000/ws";

const colors = {
  background: "#0a0e1a",
  accent: "#00d4ff",
  green: "#00ff88",
  red: "#ff4444",
  purple: "#aa44ff",
  amber: "#ffcc00",
  text: "#e0e6f0",
  panel: "#0d1b2e",
  border: "#1e3a5f",
  sidebar: "#080c18",
  muted: "#7f95b5",
  gray: "#9ba6ba",
};

const severityColors = {
  CRITICAL: "#ff4444",
  HIGH: "#ff8800",
  MEDIUM: "#ffcc00",
  LOW: "#00ff88",
};

const stageMeta = {
  red_team_attacking: { icon: "🔴", label: "Under Attack" },
  threat_detection: { icon: "🔵", label: "Detecting..." },
  threat_detected: { icon: "🔵", label: "Detecting..." },
  classified: { icon: "🤖", label: "Classified" },
  awaiting_approval: { icon: "⏳", label: "Awaiting Approval" },
  action_executing: { icon: "⚡", label: "Executing..." },
  mitigated: { icon: "🛡️", label: "Mitigated" },
  manual_queue: { icon: "📋", label: "Manual Queue" },
};

function formatTime(value) {
  return new Date(value || Date.now()).toLocaleTimeString();
}

function StatCard({ label, value, color }) {
  return (
    <div
      style={{
        background: "linear-gradient(135deg, rgba(13,27,46,0.95), rgba(8,12,24,0.95))",
        border: `1px solid ${colors.border}`,
        borderRadius: 14,
        padding: "16px 18px",
        boxShadow: "0 0 24px rgba(0, 212, 255, 0.08)",
      }}
    >
      <div style={{ color: colors.muted, fontSize: 12, letterSpacing: 1.2 }}>{label}</div>
      <div style={{ color: color || colors.text, fontSize: 28, fontWeight: 700, marginTop: 8 }}>{value}</div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div
      style={{
        background: "linear-gradient(180deg, rgba(13,27,46,0.98), rgba(9,18,32,0.98))",
        border: `1px solid ${colors.border}`,
        borderRadius: 18,
        padding: 20,
        marginBottom: 18,
        boxShadow: "0 0 30px rgba(0, 0, 0, 0.24)",
      }}
    >
      <div style={{ color: colors.accent, fontWeight: 700, letterSpacing: 1.4, marginBottom: 16 }}>{title}</div>
      {children}
    </div>
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
        background:
          "radial-gradient(circle at top left, rgba(0, 212, 255, 0.12), transparent 28%), radial-gradient(circle at top right, rgba(170, 68, 255, 0.16), transparent 22%), linear-gradient(180deg, #060914, #0a0e1a 35%, #09111f)",
        color: colors.text,
        fontFamily: '"Segoe UI", "Helvetica Neue", sans-serif',
        padding: 20,
        boxSizing: "border-box",
      }}
    >
      <div style={{ maxWidth: 1600, margin: "0 auto" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: 16,
            marginBottom: 18,
            flexWrap: "wrap",
          }}
        >
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ fontSize: 30 }}>🛡️</div>
              <div>
                <div style={{ fontSize: 28, fontWeight: 800, letterSpacing: 2 }}>CYBERAGENT</div>
                <div style={{ color: colors.muted, fontSize: 12, letterSpacing: 2 }}>
                  MULTI-AGENT SECURITY ORCHESTRATION
                </div>
              </div>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "10px 14px",
                border: `1px solid ${colors.border}`,
                borderRadius: 999,
                background: "rgba(8,12,24,0.8)",
              }}
            >
              <div
                style={{
                  width: 10,
                  height: 10,
                  borderRadius: "50%",
                  background: connected ? colors.green : colors.red,
                  boxShadow: `0 0 12px ${connected ? colors.green : colors.red}`,
                }}
              />
              <span style={{ fontSize: 12 }}>{connected ? "Live" : "Offline"}</span>
            </div>
            <button onClick={simulateAttack} style={buttonStyle(colors.accent, "#02151d")}>
              SIMULATE ATTACK
            </button>
            <button onClick={toggleAuto} style={buttonStyle(autoRunning ? colors.red : colors.purple, "#f7f8fb")}>
              {autoRunning ? "STOP AUTO" : "AUTO DEMO"}
            </button>
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
            gap: 12,
            marginBottom: 18,
          }}
        >
          <StatCard label="TOTAL INCIDENTS" value={stats.total} color={colors.accent} />
          <StatCard label="PENDING APPROVAL" value={stats.pending} color={colors.amber} />
          <StatCard label="MITIGATED" value={stats.mitigated} color={colors.green} />
          <StatCard label="CRITICAL" value={stats.critical} color={colors.red} />
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "340px minmax(0, 1fr)",
            gap: 18,
            minHeight: "calc(100vh - 220px)",
          }}
        >
          <div
            style={{
              background: "linear-gradient(180deg, rgba(8,12,24,0.98), rgba(7,10,20,0.96))",
              border: `1px solid ${colors.border}`,
              borderRadius: 18,
              padding: 16,
              display: "flex",
              flexDirection: "column",
              gap: 16,
              minHeight: 0,
            }}
          >
            <div style={{ minHeight: 0, flex: 1, display: "flex", flexDirection: "column" }}>
              <div style={sidebarTitleStyle}>LIVE FEED</div>
              <div style={{ overflowY: "auto", display: "flex", flexDirection: "column", gap: 10, paddingRight: 4 }}>
                {feed.map((entry) => (
                  <div
                    key={entry.id}
                    style={{
                      border: `1px solid ${colors.border}`,
                      borderRadius: 12,
                      padding: 12,
                      background: "rgba(13,27,46,0.72)",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                      <span style={{ color: colors.accent, fontSize: 12, fontWeight: 700 }}>{entry.type}</span>
                      <span style={{ color: colors.muted, fontSize: 11 }}>{formatTime(entry.timestamp)}</span>
                    </div>
                    <div style={{ color: colors.gray, fontSize: 12 }}>
                      {entry.data.message || entry.data.current_stage || "Pipeline event received"}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ minHeight: 0, flex: 1, display: "flex", flexDirection: "column" }}>
              <div style={sidebarTitleStyle}>INCIDENTS</div>
              <div style={{ overflowY: "auto", display: "flex", flexDirection: "column", gap: 10, paddingRight: 4 }}>
                {incidentList.map((incident) => {
                  const attack = incident.attack || {};
                  const meta = stageMeta[incident.current_stage] || stageMeta.red_team_attacking;
                  return (
                    <button
                      key={attack.attack_id}
                      onClick={() => setSelectedId(attack.attack_id)}
                      style={{
                        textAlign: "left",
                        border: `1px solid ${selectedId === attack.attack_id ? colors.accent : colors.border}`,
                        borderRadius: 14,
                        padding: 14,
                        cursor: "pointer",
                        background:
                          selectedId === attack.attack_id
                            ? "linear-gradient(135deg, rgba(0,212,255,0.16), rgba(13,27,46,0.92))"
                            : "rgba(13,27,46,0.7)",
                        color: colors.text,
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8, gap: 8 }}>
                        <span style={{ fontWeight: 700 }}>{attack.attack_id}</span>
                        <span
                          style={{
                            color: severityColors[attack.severity] || colors.text,
                            fontWeight: 700,
                            fontSize: 12,
                          }}
                        >
                          {attack.severity}
                        </span>
                      </div>
                      <div style={{ color: colors.text, fontSize: 14, marginBottom: 6 }}>{attack.attack_type}</div>
                      <div style={{ color: colors.gray, fontSize: 12, marginBottom: 6 }}>
                        {meta.icon} {meta.label}
                      </div>
                      <div style={{ color: colors.muted, fontSize: 12 }}>{attack.primary_src_ip}</div>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          <div style={{ minWidth: 0 }}>
            {!selected ? (
              <div
                style={{
                  minHeight: "100%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  border: `1px solid ${colors.border}`,
                  borderRadius: 18,
                  background: "rgba(13,27,46,0.72)",
                }}
              >
                <div style={{ textAlign: "center" }}>
                  <div style={{ fontSize: 56, marginBottom: 18 }}>🛡️</div>
                  <div style={{ fontSize: 24, fontWeight: 700 }}>No incident selected</div>
                </div>
              </div>
            ) : (
              <>
                <Section title="RED TEAM AGENT">
                  <div style={detailGridStyle}>
                    <Detail label="Attack Type" value={selected.attack.attack_type} accent={colors.red} />
                    <Detail label="Target" value={`${selected.attack.target_ip}:${selected.attack.target_port}`} />
                    <Detail label="Packet Rate" value={`${selected.attack.packet_rate}/sec`} />
                    <Detail label="Protocol" value={selected.attack.protocol} />
                  </div>
                  <div style={{ marginTop: 14, color: colors.gray }}>
                    <strong style={{ color: colors.text }}>Source IPs:</strong> {selected.attack.src_ips.join(", ")}
                  </div>
                  <div style={{ marginTop: 10, color: colors.gray }}>{selected.attack.description}</div>
                  <div style={monoBoxStyle}>{selected.attack.raw_log}</div>
                </Section>

                {selected.classification && (
                  <Section title="THREAT DETECTION AGENT">
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
                      <div>
                        <div style={{ color: colors.muted, fontSize: 12 }}>PREDICTED CLASS</div>
                        <div style={{ color: colors.purple, fontSize: 30, fontWeight: 800 }}>
                          {selected.classification.predicted_class}
                        </div>
                      </div>
                      <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
                        <Detail label="Model" value={selected.classification.model} />
                        <Detail label="Features Used" value={selected.classification.features_used} />
                        <Detail label="Risk Score" value={selected.classification.risk_score} accent={colors.amber} />
                      </div>
                    </div>

                    <div style={{ marginTop: 18 }}>
                      {Object.entries(selected.classification.confidence_scores).map(([label, value]) => (
                        <div key={label} style={{ marginBottom: 12 }}>
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                            <span style={{ color: colors.text }}>{label}</span>
                            <span style={{ color: colors.gray }}>{(value * 100).toFixed(1)}%</span>
                          </div>
                          <div style={{ background: "#09111d", borderRadius: 999, height: 12, overflow: "hidden" }}>
                            <div
                              style={{
                                width: `${value * 100}%`,
                                height: "100%",
                                background:
                                  label === selected.classification.predicted_class ? colors.purple : "#24364f",
                              }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>

                    <ul style={{ margin: "16px 0 0 18px", color: colors.gray, lineHeight: 1.7 }}>
                      {selected.classification.key_indicators.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ul>
                  </Section>
                )}

                {selected.mitigation_plan && (
                  <Section title="📋 THREAT RESOLVE AGENT — GEMINI GENERATED PLAN">
                    <div style={detailGridStyle}>
                      <Detail label="Strategy" value={selected.mitigation_plan.strategy} accent={colors.accent} />
                      <Detail
                        label="Estimated Mitigation Time"
                        value={selected.mitigation_plan.estimated_mitigation_time}
                      />
                      <Detail label="Collateral Risk" value={selected.mitigation_plan.collateral_risk} accent={colors.amber} />
                    </div>

                    <div style={{ display: "grid", gap: 14, marginTop: 18 }}>
                      {selected.mitigation_plan.steps.map((step) => (
                        <div
                          key={`${step.step}-${step.action}`}
                          style={{
                            border: `1px solid ${colors.border}`,
                            borderRadius: 14,
                            padding: 16,
                            background: "rgba(9,18,32,0.85)",
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
                            <div style={{ color: colors.text, fontWeight: 700 }}>
                              Step {step.step}: {step.action}
                            </div>
                            <div
                              style={{
                                color: step.reversible ? colors.green : colors.red,
                                fontSize: 12,
                                fontWeight: 700,
                              }}
                            >
                              {step.reversible ? "REVERSIBLE" : "PERMANENT"}
                            </div>
                          </div>
                          <div style={monoBoxStyle}>{step.command}</div>
                          <div style={{ color: colors.gray }}>{step.impact}</div>
                        </div>
                      ))}
                    </div>

                    {selected.approval_status === "pending" && (
                      <div
                        style={{
                          marginTop: 18,
                          border: `1px solid ${colors.amber}`,
                          borderRadius: 14,
                          padding: 16,
                          background: "rgba(255, 204, 0, 0.08)",
                        }}
                      >
                        <div style={{ color: colors.amber, fontWeight: 700, marginBottom: 12 }}>
                          Awaiting administrator approval before executing controls.
                        </div>
                        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                          <button
                            disabled={decisionLoading[selected.attack.attack_id]}
                            onClick={() => submitDecision(selected.attack.attack_id, "approved")}
                            style={buttonStyle(colors.green, "#04120b", decisionLoading[selected.attack.attack_id])}
                          >
                            APPROVE
                          </button>
                          <button
                            disabled={decisionLoading[selected.attack.attack_id]}
                            onClick={() => submitDecision(selected.attack.attack_id, "rejected")}
                            style={buttonStyle(colors.red, "#170607", decisionLoading[selected.attack.attack_id])}
                          >
                            REJECT
                          </button>
                        </div>
                      </div>
                    )}
                  </Section>
                )}

                {selected.action_result && (
                  <Section title="ACTION AGENT">
                    <div
                      style={{
                        color:
                          selected.action_result.status === "MITIGATED" ? colors.green : colors.gray,
                        fontSize: 26,
                        fontWeight: 800,
                        marginBottom: 16,
                      }}
                    >
                      {selected.action_result.status}
                    </div>
                    {selected.action_result.status === "MITIGATED" ? (
                      <div style={detailGridStyle}>
                        <Detail label="Steps Executed" value={selected.action_result.steps_executed.length} />
                        <Detail
                          label="Total Execution Time"
                          value={`${selected.action_result.total_execution_time_ms} ms`}
                        />
                        <Detail
                          label="Blocked IPs"
                          value={selected.action_result.blocked_ips.join(", ")}
                          accent={colors.green}
                        />
                      </div>
                    ) : (
                      <div style={detailGridStyle}>
                        <Detail label="Ticket ID" value={selected.action_result.ticket_id} accent={colors.amber} />
                        <Detail label="Assigned To" value={selected.action_result.assigned_to} />
                      </div>
                    )}
                  </Section>
                )}

                {selected.incident_report && (
                  <Section title="📄 INCIDENT REPORT — GEMINI GENERATED">
                    <div
                      style={{
                        border: `1px solid ${colors.purple}`,
                        borderRadius: 16,
                        padding: 18,
                        background: "linear-gradient(135deg, rgba(170,68,255,0.16), rgba(13,27,46,0.88))",
                        marginBottom: 18,
                        lineHeight: 1.7,
                      }}
                    >
                      {selected.incident_report.executive_summary}
                    </div>

                    <div style={{ display: "grid", gap: 8, marginBottom: 18 }}>
                      {Object.entries(selected.incident_report.attack_summary).map(([label, value]) => (
                        <div
                          key={label}
                          style={{
                            display: "grid",
                            gridTemplateColumns: "160px 1fr",
                            gap: 12,
                            padding: "10px 12px",
                            borderRadius: 10,
                            background: "rgba(9,18,32,0.78)",
                            border: `1px solid ${colors.border}`,
                          }}
                        >
                          <div style={{ color: colors.muted, textTransform: "capitalize" }}>{label.replace("_", " ")}</div>
                          <div>{String(value)}</div>
                        </div>
                      ))}
                    </div>

                    <div style={{ marginBottom: 18 }}>
                      <div style={{ color: colors.accent, marginBottom: 10, fontWeight: 700 }}>Recommendations</div>
                      <ol style={{ margin: "0 0 0 20px", lineHeight: 1.8 }}>
                        {selected.incident_report.recommendations.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ol>
                    </div>

                    <div>
                      <div style={{ color: colors.accent, marginBottom: 10, fontWeight: 700 }}>Timeline</div>
                      <div style={{ display: "grid", gap: 8 }}>
                        {Object.entries(selected.incident_report.timeline).map(([label, value]) => (
                          <div
                            key={label}
                            style={{
                              display: "grid",
                              gridTemplateColumns: "160px 1fr",
                              gap: 12,
                              padding: "10px 12px",
                              borderRadius: 10,
                              background: "rgba(9,18,32,0.78)",
                              border: `1px solid ${colors.border}`,
                            }}
                          >
                            <div style={{ color: colors.muted, textTransform: "capitalize" }}>{label}</div>
                            <div>{String(value)}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </Section>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Detail({ label, value, accent }) {
  return (
    <div style={{ minWidth: 180 }}>
      <div style={{ color: colors.muted, fontSize: 12, marginBottom: 4, letterSpacing: 1 }}>{label}</div>
      <div style={{ color: accent || colors.text, fontWeight: 700, lineHeight: 1.5 }}>{value}</div>
    </div>
  );
}

function buttonStyle(background, color, disabled) {
  return {
    border: "none",
    borderRadius: 12,
    padding: "12px 16px",
    background,
    color,
    fontWeight: 800,
    letterSpacing: 0.8,
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.6 : 1,
    boxShadow: `0 0 18px ${background}33`,
  };
}

const sidebarTitleStyle = {
  color: colors.accent,
  fontWeight: 700,
  letterSpacing: 1.4,
  marginBottom: 12,
};

const detailGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
  gap: 16,
};

const monoBoxStyle = {
  marginTop: 12,
  background: "#06101b",
  border: `1px solid ${colors.border}`,
  borderRadius: 12,
  padding: 14,
  fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", monospace',
  color: colors.green,
  overflowX: "auto",
};
