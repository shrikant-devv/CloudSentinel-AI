import { useState, useEffect, useCallback } from "react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function App() {
  // Security event form
  const [event, setEvent] = useState({
    event_type: "failed_login_attempts",
    source_ip: "203.0.113.25",
    failed_attempts: 25,
    time_window: "2 minutes",
    target: "test-iam-user",
    mfa_enabled: false,
  });

  // Application states
  const [analysis, setAnalysis] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(true);
  const [updatingStatusId, setUpdatingStatusId] = useState(null);
  const [error, setError] = useState("");

  // History search and filters
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [riskFilter, setRiskFilter] = useState("All");

  // Fetch permanent history from PostgreSQL
  const fetchHistory = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/history`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Unable to load threat history"
        );
      }

      const formattedHistory = (data.history || []).map((record) => ({
        id: record.id,
        event: record.event_data || {},
        analysis: record.analysis_data || {},
        timestamp: record.created_at
          ? new Date(record.created_at).toLocaleString()
          : "Unknown date",
        status: record.status || "Open",
      }));

      setHistory(formattedHistory);
      setError("");
    } catch (err) {
      console.error("History fetch error:", err);
      setError(err.message);
    } finally {
      setLoadingHistory(false);
    }
  }, []);

  // Load history when dashboard opens
  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  // Dashboard statistics
  const totalEvents = history.length;

  const threatsDetected = history.filter(
    (item) =>
      item.analysis?.threat ||
      item.analysis?.threat_type
  ).length;

  const highRiskAlerts = history.filter(
    (item) =>
      String(item.analysis?.risk_level || "").toLowerCase() === "high"
  ).length;

  // Search and filter incident history
  const filteredHistory = history.filter((item) => {
    const search = searchTerm.trim().toLowerCase();

    const threatName =
      item.analysis?.threat ||
      item.analysis?.threat_type ||
      "";

    const sourceIP = item.event?.source_ip || "";
    const target = item.event?.target || "";
    const eventType = item.event?.event_type || "";

    const matchesSearch =
      String(threatName).toLowerCase().includes(search) ||
      String(sourceIP).toLowerCase().includes(search) ||
      String(target).toLowerCase().includes(search) ||
      String(eventType).toLowerCase().includes(search);

    const matchesStatus =
      statusFilter === "All" ||
      item.status === statusFilter;

    const matchesRisk =
      riskFilter === "All" ||
      String(item.analysis?.risk_level || "").toLowerCase() ===
        riskFilter.toLowerCase();

    return matchesSearch && matchesStatus && matchesRisk;
  });

  // Analyze a security event using AWS Bedrock
  const analyzeThreat = async () => {
    setLoading(true);
    setError("");
    setAnalysis(null);

    try {
      const response = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(event),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Threat analysis failed"
        );
      }

      setAnalysis(data.analysis);

      // Refresh permanent PostgreSQL history
      await fetchHistory();
    } catch (err) {
      console.error("Analysis error:", err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Update incident status in PostgreSQL
  const updateIncidentStatus = async (incidentId, newStatus) => {
    setUpdatingStatusId(incidentId);
    setError("");

    try {
      const response = await fetch(
        `${API_URL}/incidents/${incidentId}/status`,
        {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            status: newStatus,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Unable to update incident status"
        );
      }

      // Update displayed history
      setHistory((previousHistory) =>
        previousHistory.map((item) =>
          item.id === incidentId
            ? {
                ...item,
                status: data.status || newStatus,
              }
            : item
        )
      );
    } catch (err) {
      console.error("Status update error:", err);
      setError(err.message);
    } finally {
      setUpdatingStatusId(null);
    }
  };

  return (
    <div className="dashboard">

      {/* Sidebar */}
      <aside className="sidebar">
        <h2>🛡️ CloudSentinel</h2>
        <p className="sidebar-subtitle">
          AI SECURITY PLATFORM
        </p>

        <nav>
          <a href="#overview">
            ◈ Overview
          </a>

          <a href="#analyzer">
            ⌕ Threat Analyzer
          </a>

          <a href="#results">
            ⚠ Security Reports
          </a>

          <a href="#history">
            ▤ Incident History
          </a>
        </nav>

        <div className="sidebar-bottom">
          <span className="online-dot"></span>
          AWS Bedrock Connected
          <p>Amazon Nova Lite</p>
        </div>
      </aside>

      {/* Main Dashboard */}
      <main className="main-content">

        {/* Header */}
        <header className="topbar">
          <div>
            <h1>Security Overview</h1>
            <p>
              AI-powered cloud threat detection and analysis
            </p>
          </div>

          <span className="status">
            ● SYSTEM ONLINE
          </span>
        </header>

        {/* Dashboard Statistics */}
        <section id="overview" className="stats-grid">

          <div className="stat-card">
            <span>Total Events</span>
            <h2>{totalEvents}</h2>
            <small>Analyzed security events</small>
          </div>

          <div className="stat-card">
            <span>Threats Detected</span>
            <h2>{threatsDetected}</h2>
            <small>AI analysis results</small>
          </div>

          <div className="stat-card">
            <span>High Risk Alerts</span>
            <h2 className="danger-text">
              {highRiskAlerts}
            </h2>
            <small>Requires investigation</small>
          </div>

          <div className="stat-card">
            <span>AI Engine</span>
            <h2 className="success-text">Active</h2>
            <small>Amazon Nova Lite</small>
          </div>

        </section>

        {/* Threat Analyzer */}
        <section id="analyzer" className="panel">

          <div className="panel-heading">
            <div>
              <h2>AI Threat Analyzer</h2>
              <p>
                Submit a security event for intelligent analysis
              </p>
            </div>

            <span className="ai-tag">
              ✦ POWERED BY AI
            </span>
          </div>

          <div className="form-grid">

            <label>
              Event Type
              <input
                type="text"
                value={event.event_type}
                onChange={(e) =>
                  setEvent({
                    ...event,
                    event_type: e.target.value,
                  })
                }
              />
            </label>

            <label>
              Source IP
              <input
                type="text"
                value={event.source_ip}
                onChange={(e) =>
                  setEvent({
                    ...event,
                    source_ip: e.target.value,
                  })
                }
              />
            </label>

            <label>
              Failed Attempts
              <input
                type="number"
                min="0"
                value={event.failed_attempts}
                onChange={(e) =>
                  setEvent({
                    ...event,
                    failed_attempts: Number(e.target.value),
                  })
                }
              />
            </label>

            <label>
              Time Window
              <input
                type="text"
                value={event.time_window}
                onChange={(e) =>
                  setEvent({
                    ...event,
                    time_window: e.target.value,
                  })
                }
              />
            </label>

            <label>
              Target User
              <input
                type="text"
                value={event.target}
                onChange={(e) =>
                  setEvent({
                    ...event,
                    target: e.target.value,
                  })
                }
              />
            </label>

            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={event.mfa_enabled}
                onChange={(e) =>
                  setEvent({
                    ...event,
                    mfa_enabled: e.target.checked,
                  })
                }
              />
              MFA Enabled
            </label>

          </div>

          <button
            className="analyze-button"
            onClick={analyzeThreat}
            disabled={loading}
          >
            {loading
              ? "Analyzing Security Event..."
              : "✦ Analyze Threat with AI"}
          </button>

          {error && (
            <p className="error-message">{error}</p>
          )}

        </section>

        {/* Security Reports - Always Visible */}
        <section
          id="results"
          className="panel results-panel"
        >

          <div className="panel-heading">
            <div>
              <h2>AI Security Reports</h2>
              <p>
                Threat analysis generated by Amazon Nova Lite
              </p>
            </div>

            {analysis && (
              <span
                className={
                  String(analysis.risk_level || "").toLowerCase() === "high"
                    ? "risk high"
                    : "risk"
                }
              >
                {analysis.risk_level || "Unknown"} RISK
              </span>
            )}
          </div>

          {analysis ? (
            <>
              <h3>
                {analysis.threat ||
                  analysis.threat_type ||
                  "Unknown Threat"}
              </h3>

              <p className="reason">
                {analysis.reason || "No explanation provided."}
              </p>

              <div className="result-grid">

                <div>
                  <h3>Recommendations</h3>

                  {Array.isArray(analysis.recommendations) &&
                  analysis.recommendations.length > 0 ? (
                    <ul>
                      {analysis.recommendations.map(
                        (item, index) => (
                          <li key={index}>{item}</li>
                        )
                      )}
                    </ul>
                  ) : (
                    <p className="reason">
                      No recommendations available.
                    </p>
                  )}
                </div>

                <div>
                  <h3>Response Steps</h3>

                  {Array.isArray(analysis.response_steps) &&
                  analysis.response_steps.length > 0 ? (
                    <ol>
                      {analysis.response_steps.map(
                        (item, index) => (
                          <li key={index}>{item}</li>
                        )
                      )}
                    </ol>
                  ) : (
                    <p className="reason">
                      No response steps available.
                    </p>
                  )}
                </div>

              </div>
            </>
          ) : (
            <p className="reason">
              No security report generated yet.
              Go to Threat Analyzer, submit a security event,
              and click Analyze Threat with AI.
              Your latest AI-generated report will appear here.
            </p>
          )}

        </section>

        {/* Permanent Security Event History */}
        <section
          id="history"
          className="panel history-panel"
        >

          <div className="panel-heading">
            <div>
              <h2>Security Event History</h2>
              <p>
                Incidents saved permanently in PostgreSQL
              </p>
            </div>

            <span className="ai-tag">
              {history.length} EVENTS
            </span>
          </div>

          {/* Search and Filter Controls */}
          <div className="history-filters">

            <input
              type="text"
              placeholder="Search threat, IP, target..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="All">All Statuses</option>
              <option value="Open">Open</option>
              <option value="Investigating">Investigating</option>
              <option value="Resolved">Resolved</option>
            </select>

            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
            >
              <option value="All">All Risk Levels</option>
              <option value="high">High Risk</option>
              <option value="medium">Medium Risk</option>
              <option value="low">Low Risk</option>
            </select>

          </div>

          {/* History Content */}
          {loadingHistory ? (
            <p className="reason">
              Loading threat history...
            </p>
          ) : history.length === 0 ? (
            <p className="reason">
              No security events analyzed yet.
            </p>
          ) : filteredHistory.length === 0 ? (
            <p className="reason">
              No incidents match your search or selected filters.
            </p>
          ) : (

            <div className="history-list">

              {filteredHistory.map((item) => (

                <div
                  className="history-item"
                  key={item.id}
                >

                  <div className="history-details">
                    <h3>
                      {item.analysis?.threat ||
                        item.analysis?.threat_type ||
                        "Unknown Threat"}
                    </h3>

                    <p>
                      Source IP:{" "}
                      {item.event?.source_ip || "Unknown"}
                    </p>

                    <p>
                      Target:{" "}
                      {item.event?.target || "Unknown"}
                    </p>

                    <small>{item.timestamp}</small>
                  </div>

                  <div className="incident-actions">

                    <span
                      className={
                        String(item.analysis?.risk_level || "").toLowerCase() === "high"
                          ? "risk high"
                          : "risk"
                      }
                    >
                      {item.analysis?.risk_level || "Unknown"} RISK
                    </span>

                    <label className="status-control">
                      Incident Status

                      <select
                        className="status-select"
                        value={item.status}
                        disabled={updatingStatusId === item.id}
                        onChange={(e) =>
                          updateIncidentStatus(
                            item.id,
                            e.target.value
                          )
                        }
                      >
                        <option value="Open">Open</option>
                        <option value="Investigating">
                          Investigating
                        </option>
                        <option value="Resolved">Resolved</option>
                      </select>
                    </label>

                    {updatingStatusId === item.id && (
                      <small>Updating status...</small>
                    )}

                  </div>

                </div>

              ))}

            </div>
          )}

        </section>

        {/* Footer */}
        <footer>
          CloudSentinel AI · Built with React, FastAPI & AWS Bedrock
        </footer>

      </main>
    </div>
  );
}

export default App;

