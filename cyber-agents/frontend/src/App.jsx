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
  green: "#0f9d58",
  red: "#d14343",
  amber: "#b7791f",
  gray: "#787774",
};

const severityColors = {
  CRITICAL: "#d14343",
  HIGH: "#d9730d",
  MEDIUM: "#b7791f",
  LOW: "#0f9d58",
};

const stageMeta = {
  red_team_attacking: { icon: "●", label: "Red team generated telemetry" },
  log_monitoring: { icon: "●", label: "Monitoring logs" },
  anomaly_detected: { icon: "●", label: "Anomaly detected" },
  classified: { icon: "●", label: "Incident classified" },
  awaiting_approval: { icon: "●", label: "Awaiting approval" },
  action_executing: { icon: "●", label: "Executing response" },
  mitigated: { icon: "●", label: "Mitigated" },
  manual_queue: { icon: "●", label: "Manual queue" },
};

function formatTime(value) {
  return new Date(value || Date.now()).toLocaleTimeString();
}

function Section({ title, eyebrow, children }) {
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
        {eyebrow ? <div style={eyebrowStyle}>{eyebrow}</div> : null}
        <div style={{ color: colors.text, fontSize: 18, fontWeight: 650 }}>{title}</div>
      </div>
      {children}
    </section>
  );
}

function StatCard({ label, value }) {
  return (
    <div style={statCardStyle}>
      <div style={eyebrowStyle}>{label}</div>
      <div style={{ color: colors.text, fontSize: 28, fontWeight: 700, marginTop: 8 }}>{value}</div>
    </div>
  );
}

function Detail({ label, value, accent }) {
  return (
    <div style={{ minWidth: 180 }}>
      <div style={eyebrowStyle}>{label}</div>
      <div style={{ color: accent || colors.text, fontWeight: 600, lineHeight: 1.5 }}>{value}</div>
    </div>
  );
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

function LogBlock({ title, lines }) {
  if (!lines || !lines.length) {
    return null;
  }
  return (
    <div style={{ marginTop: 14 }}>
      <div style={subsectionTitleStyle}>{title}</div>
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

      socket.onopen = () => setConnected(true);

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
            mapped[incident.simulation.attack_id] = incident;
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
            [payload.data.attack_id]: {
              ...(current[payload.data.attack_id] || {}),
              ...payload.data,
            },
          }));
          setSelectedId(payload.data.attack_id);
        }

        if (payload.type === "agent_update" || payload.type === "incident_resolved") {
          setIncidents((current) => {
            const existing = current[payload.data.attack_id] || {};
            return {
              ...current,
              [payload.data.attack_id]: {
                ...existing,
                ...payload.data,
                simulation: existing.simulation,
              },
            };
          });
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
  }, []);

  const incidentList = useMemo(
    () =>
      Object.values(incidents).sort((a, b) => {
        const left = a.simulation?.timestamp || "";
        const right = b.simulation?.timestamp || "";
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
      critical: values.filter((incident) => incident.classification?.attack?.severity === "CRITICAL").length,
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

  const attack = selected?.classification?.attack;

  return (
    <div style={pageStyle}>
      <div style={{ maxWidth: 1480, margin: "0 auto" }}>
        <div style={headerStyle}>
          <div>
            <div style={eyebrowStyle}>Dashboard</div>
            <div style={{ fontSize: 34, fontWeight: 700, letterSpacing: -0.8, marginBottom: 6 }}>CyberAgent</div>
            <div style={{ color: colors.secondaryText, maxWidth: 760, lineHeight: 1.6 }}>
              Log-driven red team and blue team workflow with monitoring, anomaly detection, classification, planning,
              execution, and reporting.
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
            <StatusPill color={connected ? colors.green : colors.red}>
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

        <div style={statsGridStyle}>
          <StatCard label="Total incidents" value={stats.total} />
          <StatCard label="Pending approval" value={stats.pending} />
          <StatCard label="Mitigated" value={stats.mitigated} />
          <StatCard label="Critical" value={stats.critical} />
        </div>

        <div style={mainGridStyle}>
          <aside style={sidebarStyle}>
            <div style={sidebarPanelStyle}>
              <div style={sidebarTitleStyle}>Live feed</div>
              <div style={scrollListStyle}>
                {feed.map((entry) => (
                  <div key={entry.id} style={feedCardStyle}>
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

            <div style={sidebarPanelStyle}>
              <div style={sidebarTitleStyle}>Incidents</div>
              <div style={scrollListStyle}>
                {incidentList.map((incident) => {
                  const simulation = incident.simulation || {};
                  const meta = stageMeta[incident.current_stage] || stageMeta.red_team_attacking;
                  const severity = incident.classification?.attack?.severity || simulation.attack_profile?.severity;
                  return (
                    <button
                      key={simulation.attack_id}
                      onClick={() => setSelectedId(simulation.attack_id)}
                      style={{
                        ...incidentCardStyle,
                        background: selectedId === simulation.attack_id ? colors.mutedCard : colors.card,
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
                        <div style={{ fontWeight: 650 }}>{simulation.attack_id}</div>
                        {severity ? (
                          <StatusPill color={severityColors[severity] || colors.gray}>{severity}</StatusPill>
                        ) : null}
                      </div>
                      <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 6 }}>
                        {incident.classification?.predicted_class || simulation.attack_profile?.attack_type || "Pending"}
                      </div>
                      <div style={{ color: colors.secondaryText, fontSize: 12, marginBottom: 4 }}>
                        {meta.icon} {meta.label}
                      </div>
                      <div style={{ color: colors.subtleText, fontSize: 12 }}>
                        {incident.anomaly?.primary_src_ip || simulation.attack_profile?.primary_src_ip || "Waiting"}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          </aside>

          <main style={{ minWidth: 0 }}>
            {!selected ? (
              <div style={emptyStateStyle}>
                <div style={{ color: colors.subtleText, fontSize: 14, marginBottom: 8 }}>No incident selected</div>
                <div style={{ fontSize: 28, fontWeight: 650 }}>Choose an incident from the sidebar</div>
              </div>
            ) : (
              <>
                <Section title="Red Team Agent" eyebrow="Raw telemetry generation">
                  <div style={detailGridStyle}>
                    <Detail label="Scenario" value={selected.simulation.attack_profile.attack_type} />
                    <Detail label="Primary source" value={selected.simulation.attack_profile.primary_src_ip} />
                    <Detail
                      label="Target"
                      value={`${selected.simulation.attack_profile.target_ip}:${selected.simulation.attack_profile.target_port}`}
                    />
                    <Detail label="Expected rate" value={`${selected.simulation.attack_profile.packet_rate}/sec`} />
                  </div>
                  <div style={bodyRowStyle}>
                    <span style={bodyLabelStyle}>Description</span>
                    <span>{selected.simulation.description}</span>
                  </div>
                  <LogBlock title="Access log samples" lines={selected.simulation.telemetry.generated_logs.access} />
                  <LogBlock title="Auth log samples" lines={selected.simulation.telemetry.generated_logs.auth} />
                  <LogBlock title="Network log samples" lines={selected.simulation.telemetry.generated_logs.network} />
                </Section>

                {selected.telemetry && (
                  <Section title="Log Monitor Agent" eyebrow="Continuous monitoring">
                    <div style={detailGridStyle}>
                      <Detail label="Total logs observed" value={selected.telemetry.total_logs_observed} />
                      <Detail label="Access logs" value={selected.telemetry.log_counts.access} />
                      <Detail label="Auth logs" value={selected.telemetry.log_counts.auth} />
                      <Detail label="Network logs" value={selected.telemetry.log_counts.network} />
                    </div>
                    <div style={{ marginTop: 16 }}>
                      <div style={subsectionTitleStyle}>Monitored log files</div>
                      {Object.entries(selected.telemetry.log_paths).map(([name, path]) => (
                        <div key={name} style={tableRowStyle}>
                          <div style={tableLabelStyle}>{name}</div>
                          <div>{path}</div>
                        </div>
                      ))}
                    </div>
                  </Section>
                )}

                {selected.anomaly && (
                  <Section title="Anomaly Detection Agent" eyebrow="Evidence from telemetry">
                    <div style={detailGridStyle}>
                      <Detail label="Anomaly type" value={selected.anomaly.anomaly_type} />
                      <Detail label="Primary source" value={selected.anomaly.primary_src_ip} />
                      <Detail
                        label="Target"
                        value={`${selected.anomaly.target_ip}:${selected.anomaly.target_port}`}
                      />
                      <Detail label="Severity" value={selected.anomaly.severity} accent={severityColors[selected.anomaly.severity]} />
                    </div>
                    <div style={bodyRowStyle}>
                      <span style={bodyLabelStyle}>Summary</span>
                      <span>{selected.anomaly.summary}</span>
                    </div>
                    <div style={detailGridStyleWithMargin}>
                      <Detail label="Request burst" value={selected.anomaly.request_burst} />
                      <Detail label="Failed auth attempts" value={selected.anomaly.failed_auth_attempts} />
                      <Detail label="Ports touched" value={selected.anomaly.port_span} />
                      <Detail label="Packets observed" value={selected.anomaly.total_packets_observed} />
                    </div>
                    <LogBlock title="Sample access telemetry" lines={selected.anomaly.sample_logs.access} />
                    <LogBlock title="Sample auth telemetry" lines={selected.anomaly.sample_logs.auth} />
                    <LogBlock title="Sample network telemetry" lines={selected.anomaly.sample_logs.network} />
                  </Section>
                )}

                {selected.classification && attack && (
                  <Section title="Classification Agent" eyebrow="Incident structuring">
                    <div style={{ display: "flex", justifyContent: "space-between", gap: 18, flexWrap: "wrap", marginBottom: 18 }}>
                      <div>
                        <div style={eyebrowStyle}>Predicted attack type</div>
                        <div style={{ color: colors.text, fontSize: 28, fontWeight: 700 }}>{selected.classification.predicted_class}</div>
                      </div>
                      <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
                        <Detail label="Confidence" value={`${(selected.classification.confidence * 100).toFixed(1)}%`} />
                        <Detail label="Risk score" value={selected.classification.risk_score} accent={colors.amber} />
                        <Detail label="Correlated sources" value={attack.src_ips.length} />
                      </div>
                    </div>

                    <div style={{ display: "grid", gap: 12, marginBottom: 18 }}>
                      {Object.entries(selected.classification.confidence_scores).map(([label, value]) => (
                        <div key={label}>
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                            <span style={{ fontSize: 14, fontWeight: 600 }}>{label}</span>
                            <span style={{ color: colors.secondaryText, fontSize: 13 }}>{(value * 100).toFixed(1)}%</span>
                          </div>
                          <div style={barTrackStyle}>
                            <div
                              style={{
                                width: `${value * 100}%`,
                                height: "100%",
                                background: label === selected.classification.predicted_class ? colors.text : "#cfcfca",
                              }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>

                    <div style={detailGridStyle}>
                      <Detail label="Primary source" value={attack.primary_src_ip} />
                      <Detail label="Target" value={`${attack.target_ip}:${attack.target_port}`} />
                      <Detail label="Protocol" value={attack.protocol} />
                      <Detail label="Estimated packet rate" value={`${attack.packet_rate}/sec`} />
                    </div>

                    <div style={{ color: colors.secondaryText, lineHeight: 1.7, marginTop: 16 }}>
                      {selected.classification.key_indicators.map((item) => (
                        <div key={item} style={{ marginBottom: 8 }}>
                          • {item}
                        </div>
                      ))}
                    </div>
                  </Section>
                )}

                {selected.mitigation_plan && (
                  <Section title="Response Planning Agent" eyebrow="Gemini generated plan">
                    <div style={detailGridStyle}>
                      <Detail label="Strategy" value={selected.mitigation_plan.strategy} />
                      <Detail label="Estimated time" value={selected.mitigation_plan.estimated_mitigation_time} />
                      <Detail label="Collateral risk" value={selected.mitigation_plan.collateral_risk} accent={colors.amber} />
                    </div>

                    <div style={{ display: "grid", gap: 12, marginTop: 18 }}>
                      {selected.mitigation_plan.steps.map((step) => (
                        <div key={`${step.step}-${step.action}`} style={stepCardStyle}>
                          <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
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
                      <div style={approvalBoxStyle}>
                        <div style={{ color: colors.text, fontWeight: 600, marginBottom: 12 }}>
                          Awaiting administrator approval before execution.
                        </div>
                        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                          <button
                            disabled={decisionLoading[selected.simulation.attack_id]}
                            onClick={() => submitDecision(selected.simulation.attack_id, "approved")}
                            style={approveButtonStyle(decisionLoading[selected.simulation.attack_id])}
                          >
                            Approve
                          </button>
                          <button
                            disabled={decisionLoading[selected.simulation.attack_id]}
                            onClick={() => submitDecision(selected.simulation.attack_id, "rejected")}
                            style={rejectButtonStyle(decisionLoading[selected.simulation.attack_id])}
                          >
                            Reject
                          </button>
                        </div>
                      </div>
                    )}
                  </Section>
                )}

                {selected.action_result && (
                  <Section title="Action Agent" eyebrow="Execution result">
                    <div style={{ marginBottom: 16 }}>
                      <StatusPill color={selected.action_result.status === "MITIGATED" ? colors.green : colors.gray}>
                        {selected.action_result.status}
                      </StatusPill>
                    </div>
                    {selected.action_result.status === "MITIGATED" ? (
                      <div style={detailGridStyle}>
                        <Detail label="Steps executed" value={selected.action_result.steps_executed.length} />
                        <Detail label="Execution time" value={`${selected.action_result.total_execution_time_ms} ms`} />
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
                  <Section title="Reporting Agent" eyebrow="Gemini generated report">
                    <div style={reportSummaryStyle}>{selected.incident_report.executive_summary}</div>

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

const pageStyle = {
  minHeight: "100vh",
  background: colors.background,
  color: colors.text,
  fontFamily: 'ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif',
  padding: 24,
  boxSizing: "border-box",
};

const headerStyle = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start",
  gap: 16,
  flexWrap: "wrap",
  marginBottom: 20,
};

const statsGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
  gap: 12,
  marginBottom: 20,
};

const mainGridStyle = {
  display: "grid",
  gridTemplateColumns: "320px minmax(0, 1fr)",
  gap: 20,
  minHeight: "calc(100vh - 210px)",
};

const sidebarStyle = {
  display: "flex",
  flexDirection: "column",
  gap: 14,
  minHeight: 0,
};

const sidebarPanelStyle = {
  background: colors.page,
  border: `1px solid ${colors.border}`,
  borderRadius: 12,
  padding: 14,
  display: "flex",
  flexDirection: "column",
  minHeight: 0,
  flex: 1,
};

const scrollListStyle = {
  overflowY: "auto",
  display: "flex",
  flexDirection: "column",
  gap: 8,
  paddingRight: 2,
};

const feedCardStyle = {
  background: colors.card,
  border: `1px solid ${colors.border}`,
  borderRadius: 10,
  padding: 12,
};

const incidentCardStyle = {
  textAlign: "left",
  border: `1px solid ${colors.border}`,
  borderRadius: 10,
  padding: 12,
  cursor: "pointer",
  color: colors.text,
};

const emptyStateStyle = {
  minHeight: "100%",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  border: `1px solid ${colors.border}`,
  borderRadius: 12,
  background: colors.page,
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

const statCardStyle = {
  background: colors.card,
  border: `1px solid ${colors.border}`,
  borderRadius: 12,
  padding: "16px 18px",
};

const sidebarTitleStyle = {
  color: colors.text,
  fontWeight: 650,
  marginBottom: 10,
};

const eyebrowStyle = {
  color: colors.subtleText,
  fontSize: 12,
  fontWeight: 600,
  marginBottom: 6,
};

const detailGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
  gap: 16,
};

const detailGridStyleWithMargin = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
  gap: 16,
  marginTop: 16,
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
  marginTop: 10,
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

const barTrackStyle = {
  background: colors.mutedCard,
  borderRadius: 999,
  height: 8,
  overflow: "hidden",
};

const stepCardStyle = {
  border: `1px solid ${colors.border}`,
  borderRadius: 10,
  padding: 14,
  background: colors.page,
};

const approvalBoxStyle = {
  marginTop: 18,
  border: `1px solid ${colors.border}`,
  borderRadius: 10,
  padding: 14,
  background: colors.mutedCard,
};

const reportSummaryStyle = {
  border: `1px solid ${colors.border}`,
  borderRadius: 10,
  padding: 16,
  background: colors.page,
  lineHeight: 1.7,
  marginBottom: 18,
};
