import { useState, useEffect, useCallback } from "react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, CartesianGrid } from "recharts";

// ── API ──────────────────────────────────────────────────────────────────────
const API = "/api";
async function api(path, opts = {}) {
  const r = await fetch(`${API}${path}`, { headers: { "Content-Type": "application/json", ...opts.headers }, ...opts });
  if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
  return r.json();
}
const apiGet = (p) => api(p);
const apiPost = (p, b) => api(p, { method: "POST", body: JSON.stringify(b) });
const apiDelete = (p) => api(p, { method: "DELETE" });

// ── Constants ────────────────────────────────────────────────────────────────
const SEV = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6", info: "#6b7280" };
const SEV_BG = { critical: "rgba(239,68,68,.12)", high: "rgba(249,115,22,.12)", medium: "rgba(234,179,8,.10)", low: "rgba(59,130,246,.10)", info: "rgba(107,114,128,.10)" };
const STAT_C = { open: "#ef4444", confirmed: "#f97316", false_positive: "#6b7280", remediated: "#22c55e" };
const PH = { initializing: "Init", nuclei_scan: "Nuclei", zap_scan: "ZAP Scan", deduplication: "Dedup", storing_findings: "Storing", ai_analysis: "GPT-4o", poc_generation: "PoC Gen", done: "Done", error: "Error" };
const PH_ORDER = ["initializing", "nuclei_scan", "zap_scan", "deduplication", "storing_findings", "ai_analysis", "poc_generation", "done"];
const ENGINE_COLORS = { nuclei: "#8b5cf6", zap: "#f97316", both: "#10b981" };

// ── Components ───────────────────────────────────────────────────────────────
const SevBadge = ({ s }) => <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 10px", borderRadius: 6, fontSize: 11, fontWeight: 700, letterSpacing: .5, textTransform: "uppercase", color: SEV[s], background: SEV_BG[s], border: `1px solid ${SEV[s]}22` }}><span style={{ width: 6, height: 6, borderRadius: "50%", background: SEV[s] }} />{s}</span>;
const StatusBadge = ({ s }) => <span style={{ padding: "2px 8px", borderRadius: 6, fontSize: 11, fontWeight: 600, color: STAT_C[s] || "#888", background: `${STAT_C[s] || "#888"}18` }}>{(s || "").replace("_", " ")}</span>;
const EngineBadge = ({ e }) => <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700, textTransform: "uppercase", color: ENGINE_COLORS[e] || "#6b7280", background: `${ENGINE_COLORS[e] || "#6b7280"}18`, border: `1px solid ${ENGINE_COLORS[e] || "#6b7280"}30` }}>{e === "both" ? "Nuclei+ZAP" : e}</span>;
const SourceBadge = ({ s }) => <span style={{ padding: "1px 6px", borderRadius: 4, fontSize: 9, fontWeight: 700, textTransform: "uppercase", color: s === "zap" ? "#f97316" : "#8b5cf6", background: s === "zap" ? "#f9731615" : "#8b5cf615" }}>{s || "nuclei"}</span>;
const Card = ({ children, style, ...p }) => <div style={{ background: "#111318", border: "1px solid #1e2028", borderRadius: 12, padding: 20, ...style }} {...p}>{children}</div>;
const MetricCard = ({ label, value, sub, accent }) => <Card style={{ display: "flex", flexDirection: "column", gap: 4 }}><span style={{ fontSize: 12, color: "#6b7280", fontWeight: 500, letterSpacing: .5, textTransform: "uppercase" }}>{label}</span><span style={{ fontSize: 32, fontWeight: 800, color: accent || "#f0f0f0", fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.1 }}>{value}</span>{sub && <span style={{ fontSize: 12, color: "#4b5563" }}>{sub}</span>}</Card>;
const Spinner = () => <div style={{ display: "flex", alignItems: "center", gap: 8, color: "#6b7280", fontSize: 13 }}><div style={{ width: 16, height: 16, border: "2px solid #2d3040", borderTopColor: "#10b981", borderRadius: "50%", animation: "spin .8s linear infinite" }} />Loading...<style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style></div>;
const Empty = ({ msg }) => <Card style={{ textAlign: "center", padding: 40, color: "#4b5563" }}><div style={{ fontSize: 32, marginBottom: 8, opacity: .3 }}>⬡</div><div style={{ fontSize: 14 }}>{msg}</div></Card>;
const ErrorBox = ({ error, onRetry }) => <Card style={{ borderColor: "#ef444440" }}><div style={{ color: "#ef4444", fontSize: 13, fontWeight: 600, marginBottom: 4 }}>Error</div><div style={{ color: "#9ca3af", fontSize: 12, fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all" }}>{error}</div>{onRetry && <button onClick={onRetry} style={{ marginTop: 10, padding: "6px 14px", borderRadius: 6, border: "1px solid #2d3040", background: "transparent", color: "#9ca3af", fontSize: 12, cursor: "pointer" }}>Retry</button>}</Card>;
const Input = ({ label, ...p }) => <div style={{ display: "flex", flexDirection: "column", gap: 4 }}><label style={{ fontSize: 11, color: "#6b7280", fontWeight: 600, textTransform: "uppercase", letterSpacing: .5 }}>{label}</label><input style={{ padding: "10px 12px", borderRadius: 8, border: "1px solid #2d3040", background: "#0d0f13", color: "#e5e7eb", fontSize: 13, outline: "none", fontFamily: "'JetBrains Mono', monospace" }} {...p} /></div>;
const Select = ({ label, children, ...p }) => <div style={{ display: "flex", flexDirection: "column", gap: 4 }}><label style={{ fontSize: 11, color: "#6b7280", fontWeight: 600, textTransform: "uppercase", letterSpacing: .5 }}>{label}</label><select style={{ padding: "10px 12px", borderRadius: 8, border: "1px solid #2d3040", background: "#0d0f13", color: "#e5e7eb", fontSize: 13, outline: "none" }} {...p}>{children}</select></div>;
const Tab = ({ active, onClick, children }) => <button onClick={onClick} style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "8px 16px", border: "none", borderBottom: active ? "2px solid #10b981" : "2px solid transparent", background: "transparent", color: active ? "#f0f0f0" : "#6b7280", fontSize: 13, fontWeight: active ? 700 : 500, cursor: "pointer", fontFamily: "inherit" }}>{children}</button>;

const ProgressBar = ({ phase }) => {
  const idx = PH_ORDER.indexOf(phase);
  const pct = phase === "done" ? 100 : phase === "error" ? 100 : Math.max(8, ((idx + 1) / PH_ORDER.length) * 100);
  return <div style={{ display: "flex", flexDirection: "column", gap: 4 }}><div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "#9ca3af" }}><span>{PH[phase] || phase}</span><span>{phase === "error" ? "Failed" : `${Math.round(pct)}%`}</span></div><div style={{ height: 4, borderRadius: 2, background: "#1e2028", overflow: "hidden" }}><div style={{ height: "100%", width: `${pct}%`, borderRadius: 2, background: phase === "error" ? "#ef4444" : phase === "done" ? "#10b981" : "linear-gradient(90deg, #10b981, #059669)", transition: "width .5s" }} /></div></div>;
};

// ── Auth Config Panel ────────────────────────────────────────────────────────
const AuthPanel = ({ auth, setAuth }) => {
  const up = (k, v) => setAuth({ ...auth, [k]: v });
  const t = auth.auth_type;
  return (
    <Card style={{ border: "1px solid #f9731640", marginTop: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb" }}>Authentication Config</span>
        <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: "#f9731618", color: "#f97316" }}>ZAP</span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <Select label="Auth Type" value={t} onChange={e => up("auth_type", e.target.value)}>
          <option value="none">None (Unauthenticated)</option>
          <option value="form">Form-Based Login</option>
          <option value="bearer">Bearer Token</option>
          <option value="cookie">Cookie Session</option>
          <option value="header">Custom Header</option>
        </Select>
        {t !== "none" && <Input label="Logged-In Indicator (regex)" placeholder="Logout|Dashboard|Welcome" value={auth.logged_in_indicator || ""} onChange={e => up("logged_in_indicator", e.target.value)} />}
      </div>

      {t === "form" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 12 }}>
          <Input label="Login URL *" placeholder="https://app.com/login" value={auth.login_url || ""} onChange={e => up("login_url", e.target.value)} />
          <div />
          <Input label="Username Field Name" placeholder="username" value={auth.username_field || "username"} onChange={e => up("username_field", e.target.value)} />
          <Input label="Password Field Name" placeholder="password" value={auth.password_field || "password"} onChange={e => up("password_field", e.target.value)} />
          <Input label="Username *" placeholder="admin" value={auth.username || ""} onChange={e => up("username", e.target.value)} />
          <Input label="Password *" type="password" placeholder="••••••••" value={auth.password || ""} onChange={e => up("password", e.target.value)} />
          <Input label="Logged-Out Indicator (regex)" placeholder="Login|Sign in" value={auth.logged_out_indicator || ""} onChange={e => up("logged_out_indicator", e.target.value)} />
        </div>
      )}

      {t === "bearer" && (
        <div style={{ marginTop: 12 }}>
          <Input label="Bearer Token *" placeholder="eyJhbGciOiJIUzI1NiIs..." value={auth.token || ""} onChange={e => up("token", e.target.value)} />
        </div>
      )}

      {t === "cookie" && (
        <div style={{ marginTop: 12 }}>
          <Input label="Cookie String *" placeholder="session=abc123; CSRF-Token=xyz" value={auth.cookies || ""} onChange={e => up("cookies", e.target.value)} />
        </div>
      )}

      {t === "header" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 12, marginTop: 12 }}>
          <Input label="Header Name *" placeholder="X-API-Key" value={auth.header_name || "Authorization"} onChange={e => up("header_name", e.target.value)} />
          <Input label="Header Value *" placeholder="your-api-key-here" value={auth.header_value || ""} onChange={e => up("header_value", e.target.value)} />
        </div>
      )}

      {t !== "none" && (
        <div style={{ marginTop: 12 }}>
          <Input label="Exclude URLs (comma-separated regex)" placeholder=".*logout.*, .*reset-password.*" value={(auth.exclude_urls || []).join(", ")} onChange={e => up("exclude_urls", e.target.value.split(",").map(s => s.trim()).filter(Boolean))} />
        </div>
      )}
    </Card>
  );
};

// ── Dashboard View ───────────────────────────────────────────────────────────
const DashboardView = () => {
  const [stats, setStats] = useState(null);
  const [trend, setTrend] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const load = useCallback(async () => {
    try { setError(null);
      const [s, t] = await Promise.all([apiGet("/dashboard/stats"), apiGet("/dashboard/severity-trend")]);
      setStats(s);
      const bd = {}; (t || []).forEach(r => { if (!bd[r.day]) bd[r.day] = { day: r.day, critical: 0, high: 0, medium: 0, low: 0, info: 0 }; bd[r.day][r.severity] = r.count; }); setTrend(Object.values(bd));
    } catch (e) { setError(e.message); } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); const iv = setInterval(load, 15000); return () => clearInterval(iv); }, [load]);
  if (loading && !stats) return <Spinner />;
  if (error && !stats) return <ErrorBox error={error} onRetry={load} />;
  if (!stats) return <Empty msg="No data yet. Launch a scan." />;
  const sd = stats.severity_distribution || {};
  const pie = Object.entries(sd).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value }));
  const ed = stats.engine_distribution || {};
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 14 }}>
        <MetricCard label="Total Scans" value={stats.total_scans} sub={`${stats.targets_scanned} targets`} />
        <MetricCard label="Active" value={stats.active_scans} accent="#10b981" />
        <MetricCard label="Open Findings" value={stats.open_findings} accent="#ef4444" sub={`of ${stats.total_findings}`} />
        <MetricCard label="Critical (7d)" value={stats.critical_last_7d} accent="#ef4444" />
      </div>
      {(ed.nuclei || ed.zap) && (
        <div style={{ display: "flex", gap: 12 }}>
          {ed.nuclei && <Card style={{ flex: 1, display: "flex", alignItems: "center", gap: 10 }}><span style={{ width: 10, height: 10, borderRadius: 2, background: "#8b5cf6" }} /><span style={{ fontSize: 13, color: "#d1d5db" }}>Nuclei: <strong>{ed.nuclei}</strong> findings</span></Card>}
          {ed.zap && <Card style={{ flex: 1, display: "flex", alignItems: "center", gap: 10 }}><span style={{ width: 10, height: 10, borderRadius: 2, background: "#f97316" }} /><span style={{ fontSize: 13, color: "#d1d5db" }}>ZAP: <strong>{ed.zap}</strong> findings</span></Card>}
        </div>
      )}
      <div style={{ display: "grid", gridTemplateColumns: trend.length ? "2fr 1fr" : "1fr", gap: 14 }}>
        {trend.length > 0 && <Card><div style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb", marginBottom: 16 }}>SEVERITY TREND</div><ResponsiveContainer width="100%" height={240}><AreaChart data={trend}><defs>{Object.entries(SEV).map(([k, c]) => <linearGradient key={k} id={`g-${k}`} x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={c} stopOpacity={.3} /><stop offset="95%" stopColor={c} stopOpacity={0} /></linearGradient>)}</defs><CartesianGrid strokeDasharray="3 3" stroke="#1e2028" /><XAxis dataKey="day" tick={{ fill: "#6b7280", fontSize: 11 }} axisLine={{ stroke: "#1e2028" }} /><YAxis tick={{ fill: "#6b7280", fontSize: 11 }} axisLine={{ stroke: "#1e2028" }} /><Tooltip contentStyle={{ background: "#1a1d24", border: "1px solid #2d3040", borderRadius: 8, fontSize: 12 }} /><Area type="monotone" dataKey="critical" stroke={SEV.critical} fill="url(#g-critical)" strokeWidth={2} /><Area type="monotone" dataKey="high" stroke={SEV.high} fill="url(#g-high)" strokeWidth={2} /><Area type="monotone" dataKey="medium" stroke={SEV.medium} fill="url(#g-medium)" strokeWidth={1.5} /></AreaChart></ResponsiveContainer></Card>}
        {pie.length > 0 && <Card><div style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb", marginBottom: 16 }}>BREAKDOWN</div><ResponsiveContainer width="100%" height={200}><PieChart><Pie data={pie} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3} dataKey="value" stroke="none">{pie.map(e => <Cell key={e.name} fill={SEV[e.name]} />)}</Pie><Tooltip contentStyle={{ background: "#1a1d24", border: "1px solid #2d3040", borderRadius: 8, fontSize: 12 }} /></PieChart></ResponsiveContainer><div style={{ display: "flex", flexWrap: "wrap", gap: 8, justifyContent: "center" }}>{pie.map(e => <span key={e.name} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "#9ca3af" }}><span style={{ width: 8, height: 8, borderRadius: 2, background: SEV[e.name] }} />{e.name}: {e.value}</span>)}</div></Card>}
        {!trend.length && !pie.length && <Empty msg="No findings data yet." />}
      </div>
    </div>
  );
};

// ── Scans View ───────────────────────────────────────────────────────────────
const DEFAULT_AUTH = { auth_type: "none", login_url: "", username_field: "username", password_field: "password", username: "", password: "", logged_in_indicator: "", logged_out_indicator: "", token: "", header_name: "Authorization", header_value: "", cookies: "", exclude_urls: [] };

const ScansView = ({ onViewFindings }) => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("full");
  const [engine, setEngine] = useState("nuclei");
  const [doAI, setDoAI] = useState(true);
  const [doPoC, setDoPoC] = useState(true);
  const [auth, setAuth] = useState({ ...DEFAULT_AUTH });
  const [submitting, setSubmitting] = useState(false);

  const loadScans = useCallback(async () => {
    try { setError(null); setScans(await apiGet("/scans?limit=50")); } catch (e) { setError(e.message); } finally { setLoading(false); }
  }, []);
  useEffect(() => { loadScans(); const iv = setInterval(loadScans, 5000); return () => clearInterval(iv); }, [loadScans]);

  const submit = async () => {
    if (!target.trim()) return;
    try {
      setSubmitting(true); setError(null);
      const body = {
        target: target.trim(), scan_type: scanType, scanner_engine: engine,
        severity_filter: ["critical", "high", "medium", "low", "info"],
        ai_analysis: doAI, generate_poc: doPoC,
      };
      if ((engine === "zap" || engine === "both") && auth.auth_type !== "none") {
        body.auth_config = auth;
      }
      await apiPost("/scans", body);
      setTarget(""); setShowForm(false); setAuth({ ...DEFAULT_AUTH }); await loadScans();
    } catch (e) { setError(e.message); } finally { setSubmitting(false); }
  };

  if (loading) return <Spinner />;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {error && <ErrorBox error={error} />}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ color: "#9ca3af", fontSize: 13 }}>{scans.length} scans</span>
        <button onClick={() => setShowForm(!showForm)} style={{ padding: "8px 18px", borderRadius: 8, border: "none", background: "linear-gradient(135deg, #10b981, #059669)", color: "#fff", fontSize: 13, fontWeight: 700, cursor: "pointer" }}>+ New Scan</button>
      </div>

      {showForm && (
        <Card style={{ border: "1px solid #10b98140" }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: "#e5e7eb", marginBottom: 14 }}>Launch New Scan</div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
            <Input label="Target *" placeholder="https://example.com" value={target} onChange={e => setTarget(e.target.value)} onKeyDown={e => e.key === "Enter" && submit()} />
            <Select label="Scan Type" value={scanType} onChange={e => setScanType(e.target.value)}>
              <option value="quick">Quick</option>
              <option value="full">Full</option>
              <option value="deep">Deep (Slow)</option>
            </Select>
            <Select label="Scanner Engine" value={engine} onChange={e => setEngine(e.target.value)}>
              <option value="nuclei">Nuclei (Fast Vuln Scan)</option>
              <option value="zap">ZAP (Authenticated DAST)</option>
              <option value="both">Both (Nuclei + ZAP)</option>
            </Select>
          </div>
          <div style={{ display: "flex", gap: 16, marginTop: 12 }}>
            <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "#9ca3af", cursor: "pointer" }}><input type="checkbox" checked={doAI} onChange={e => setDoAI(e.target.checked)} style={{ accentColor: "#10b981" }} /> GPT-4o Analysis</label>
            <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "#9ca3af", cursor: "pointer" }}><input type="checkbox" checked={doPoC} onChange={e => setDoPoC(e.target.checked)} style={{ accentColor: "#10b981" }} /> Generate PoC</label>
          </div>

          {(engine === "zap" || engine === "both") && <AuthPanel auth={auth} setAuth={setAuth} />}

          <button onClick={submit} disabled={submitting || !target.trim()} style={{ marginTop: 14, padding: "10px 24px", borderRadius: 8, border: "none", background: submitting ? "#4b5563" : "#10b981", color: "#fff", fontSize: 13, fontWeight: 700, cursor: submitting ? "wait" : "pointer", opacity: !target.trim() ? .5 : 1 }}>
            {submitting ? "Launching..." : `Launch ${engine === "both" ? "Nuclei + ZAP" : engine === "zap" ? "ZAP" : "Nuclei"} Scan`}
          </button>
        </Card>
      )}

      {scans.length === 0 && <Empty msg="No scans yet. Click '+ New Scan' to start." />}

      {scans.map(sc => (
        <Card key={sc.scan_id} style={{ cursor: sc.status === "completed" ? "pointer" : "default" }} onClick={() => sc.status === "completed" && onViewFindings(sc.scan_id)}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4, flexWrap: "wrap" }}>
                <span style={{ fontSize: 14, fontWeight: 700, color: "#e5e7eb", fontFamily: "'JetBrains Mono', monospace" }}>{sc.target}</span>
                <EngineBadge e={sc.scanner_engine || "nuclei"} />
                <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700, textTransform: "uppercase",
                  background: sc.status === "completed" ? "#10b98118" : sc.status === "failed" ? "#ef444418" : sc.status === "scanning" ? "#eab30818" : "#6b728018",
                  color: sc.status === "completed" ? "#10b981" : sc.status === "failed" ? "#ef4444" : sc.status === "scanning" ? "#eab308" : "#6b7280" }}>
                  {sc.status}
                </span>
                {sc.auth_config && JSON.parse(sc.auth_config || "{}").auth_type !== "none" && (
                  <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: "#f9731618", color: "#f97316" }}>AUTH</span>
                )}
              </div>
              <div style={{ display: "flex", gap: 16, fontSize: 12, color: "#6b7280", marginTop: 6 }}>
                <span>Type: {sc.scan_type}</span>
                <span>Raw: {sc.raw_finding_count || 0}</span>
                <span>Unique: {sc.unique_finding_count || 0}</span>
              </div>
              {sc.error && <div style={{ fontSize: 11, color: "#ef4444", marginTop: 6, fontFamily: "'JetBrains Mono', monospace" }}>{sc.error}</div>}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{ textAlign: "right", fontSize: 11, color: "#4b5563" }}>
                <div>{new Date(sc.created_at).toLocaleString()}</div>
                {sc.completed_at && <div style={{ color: "#10b981" }}>Done {Math.round((new Date(sc.completed_at) - new Date(sc.created_at)) / 60000)}m</div>}
              </div>
              {sc.status === "completed" && (
                <button
                  onClick={e => {
                    e.stopPropagation();
                    const link = document.createElement("a");
                    link.href = `/api/scans/${sc.scan_id}/report/pdf`;
                    link.download = `report_${sc.scan_id}.pdf`;
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                  }}
                  title="Download PDF Report"
                  style={{ padding: "4px 8px", borderRadius: 4, border: "1px solid #22c55e", background: "#10b98115", color: "#10b981", fontSize: 11, cursor: "pointer", fontWeight: 600 }}>
                  ↓ PDF
                </button>
              )}
              <button onClick={e => { e.stopPropagation(); apiDelete(`/scans/${sc.scan_id}`).then(loadScans); }} style={{ padding: "4px 8px", borderRadius: 4, border: "1px solid #2d3040", background: "transparent", color: "#6b7280", fontSize: 11, cursor: "pointer" }}>✕</button>
            </div>
          </div>
          {sc.status === "scanning" && <div style={{ marginTop: 10 }}><ProgressBar phase={sc.phase} /></div>}
        </Card>
      ))}
    </div>
  );
};

// ── Findings View ────────────────────────────────────────────────────────────
const FindingsView = ({ scanFilter, onViewFinding }) => {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sevFilter, setSevFilter] = useState("all");
  const loadFindings = useCallback(async () => {
    try { setError(null); setFindings(await apiGet(scanFilter ? `/scans/${scanFilter}/findings` : "/findings?limit=200")); } catch (e) { setError(e.message); } finally { setLoading(false); }
  }, [scanFilter]);
  useEffect(() => { loadFindings(); }, [loadFindings]);
  if (loading) return <Spinner />;
  if (error) return <ErrorBox error={error} onRetry={loadFindings} />;
  if (!findings.length) return <Empty msg={scanFilter ? "No findings for this scan." : "No findings yet."} />;
  const filtered = sevFilter === "all" ? findings : findings.filter(f => f.severity === sevFilter);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        {["all", "critical", "high", "medium", "low", "info"].map(s => (
          <button key={s} onClick={() => setSevFilter(s)} style={{ padding: "4px 10px", borderRadius: 6, border: sevFilter === s ? `1px solid ${SEV[s] || "#10b981"}` : "1px solid #1e2028", background: sevFilter === s ? `${SEV[s] || "#10b981"}15` : "transparent", color: sevFilter === s ? SEV[s] || "#10b981" : "#6b7280", fontSize: 11, fontWeight: 600, cursor: "pointer", textTransform: "uppercase" }}>
            {s} ({s === "all" ? findings.length : findings.filter(f => f.severity === s).length})
          </button>
        ))}
      </div>
      {filtered.map(f => (
        <Card key={f.id} style={{ cursor: "pointer" }} onClick={() => onViewFinding(f)}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
                <SevBadge s={f.severity} />
                <StatusBadge s={f.status} />
                <SourceBadge s={f.scanner_source} />
                {f.cve_id && <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: "#10b98115", color: "#34d399", fontFamily: "'JetBrains Mono', monospace" }}>{f.cve_id}</span>}
              </div>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#e5e7eb", marginBottom: 4 }}>{f.name}</div>
              <div style={{ fontSize: 12, color: "#6b7280", lineHeight: 1.5, maxWidth: 600 }}>{(f.description || "").slice(0, 150)}{(f.description || "").length > 150 ? "..." : ""}</div>
              <div style={{ display: "flex", gap: 12, marginTop: 8, fontSize: 11, color: "#4b5563" }}>
                <span style={{ fontFamily: "'JetBrains Mono', monospace" }}>{f.host}</span>
                {f.cvss_score > 0 && <span>CVSS: <span style={{ color: f.cvss_score >= 9 ? "#ef4444" : f.cvss_score >= 7 ? "#f97316" : "#eab308", fontWeight: 700 }}>{f.cvss_score}</span></span>}
              </div>
            </div>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 4 }}>
              {f.ai_analysis && <span style={{ fontSize: 10, color: "#34d399", background: "#10b98115", padding: "2px 6px", borderRadius: 4 }}>GPT-4o</span>}
              {f.poc_screenshot && <span style={{ fontSize: 10, color: "#22c55e", background: "#22c55e15", padding: "2px 6px", borderRadius: 4 }}>PoC</span>}
            </div>
          </div>
        </Card>
      ))}
    </div>
  );
};

// ── Finding Detail ───────────────────────────────────────────────────────────
const FindingDetail = ({ finding, onBack }) => {
  const [tab, setTab] = useState("overview");
  const [detail, setDetail] = useState(finding);
  useEffect(() => { apiGet(`/findings/${finding.id}`).then(setDetail).catch(() => {}); }, [finding.id]);
  const f = detail;
  let ai = f.ai_analysis; if (typeof ai === "string") { try { ai = JSON.parse(ai); } catch { ai = null; } }
  let tags = []; try { tags = typeof f.tags === "string" ? JSON.parse(f.tags) : (f.tags || []); } catch { tags = []; }
  let extracted = f.extracted_results; if (typeof extracted === "string") { try { extracted = JSON.parse(extracted); } catch { extracted = null; } }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <button onClick={onBack} style={{ alignSelf: "flex-start", padding: "6px 14px", borderRadius: 6, border: "1px solid #2d3040", background: "transparent", color: "#9ca3af", fontSize: 12, cursor: "pointer", fontFamily: "inherit" }}>← Back</button>
      <Card>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
          <SevBadge s={f.severity} /><StatusBadge s={f.status} /><SourceBadge s={f.scanner_source} />
          {f.cve_id && <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 700, background: "#10b98118", color: "#34d399", fontFamily: "'JetBrains Mono', monospace" }}>{f.cve_id}</span>}
          {f.cvss_score > 0 && <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 700, background: "#22c55e18", color: "#22c55e" }}>CVSS {f.cvss_score}</span>}
        </div>
        <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800, color: "#f0f0f0" }}>{f.name}</h2>
        <div style={{ fontSize: 12, color: "#6b7280", fontFamily: "'JetBrains Mono', monospace", marginTop: 6, wordBreak: "break-all" }}>{f.url || f.matched_at || f.host}</div>
      </Card>

      <div style={{ display: "flex", gap: 0, borderBottom: "1px solid #1e2028" }}>
        <Tab active={tab === "overview"} onClick={() => setTab("overview")}>Overview</Tab>
        {ai && <Tab active={tab === "ai"} onClick={() => setTab("ai")}>AI Analysis</Tab>}
        <Tab active={tab === "poc"} onClick={() => setTab("poc")}>PoC</Tab>
        {extracted && extracted.evidence && <Tab active={tab === "evidence"} onClick={() => setTab("evidence")}>ZAP Evidence</Tab>}
        {f.poc_screenshot && <Tab active={tab === "screenshot"} onClick={() => setTab("screenshot")}>Screenshot</Tab>}
      </div>

      {tab === "overview" && (
        <Card>
          <div style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb", marginBottom: 8 }}>Description</div>
          <p style={{ margin: 0, fontSize: 13, color: "#9ca3af", lineHeight: 1.7 }}>{f.description || "No description."}</p>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 20 }}>
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", textTransform: "uppercase", marginBottom: 6 }}>Details</div>
              {[["Host", f.host], ["Template", f.template_id], ["Scanner", f.scanner_source || "nuclei"], ["Matched At", f.matched_at || f.url], ["Matcher", f.matcher_name]].map(([k, v]) => v ? <div key={k} style={{ display: "flex", gap: 8, fontSize: 12, marginBottom: 4 }}><span style={{ color: "#4b5563", minWidth: 80 }}>{k}:</span><span style={{ color: "#d1d5db", fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all" }}>{v}</span></div> : null)}
            </div>
            {tags.length > 0 && <div><div style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", textTransform: "uppercase", marginBottom: 6 }}>Tags</div><div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>{tags.map(t => <span key={t} style={{ padding: "3px 8px", borderRadius: 4, fontSize: 11, background: "#1e2028", color: "#9ca3af" }}>{t}</span>)}</div></div>}
          </div>
          {f.curl_command && <div style={{ marginTop: 16 }}><div style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", textTransform: "uppercase", marginBottom: 6 }}>Curl Command</div><pre style={{ margin: 0, padding: 12, borderRadius: 8, background: "#0a0c10", border: "1px solid #1e2028", color: "#d1d5db", fontSize: 11, fontFamily: "'JetBrains Mono', monospace", overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{f.curl_command}</pre></div>}
          {f.reference && <div style={{ marginTop: 16 }}><div style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", textTransform: "uppercase", marginBottom: 6 }}>References</div><div style={{ fontSize: 12, color: "#9ca3af", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{f.reference}</div></div>}
        </Card>
      )}

      {tab === "ai" && ai && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <Card>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
              {[["Exploitability", ai.exploitability, ai.exploitability === "trivial" ? "#ef4444" : ai.exploitability === "easy" ? "#f97316" : "#eab308"],
                ["False Positive", ai.false_positive_likelihood, ai.false_positive_likelihood === "low" ? "#22c55e" : "#eab308"],
                ["CWE", ai.cwe_mapping || "—", "#34d399"]
              ].map(([l, v, c]) => <div key={l} style={{ textAlign: "center" }}><div style={{ fontSize: 11, color: "#6b7280", textTransform: "uppercase" }}>{l}</div><div style={{ fontSize: 16, fontWeight: 800, color: c, marginTop: 4 }}>{v}</div></div>)}
            </div>
          </Card>
          {ai.business_impact && <Card><div style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb", marginBottom: 8 }}>Business Impact</div><p style={{ margin: 0, fontSize: 13, color: "#d1d5db", lineHeight: 1.7, padding: 12, background: "#0d0f13", borderRadius: 8, borderLeft: "3px solid #ef4444" }}>{ai.business_impact}</p></Card>}
        </div>
      )}

      {tab === "poc" && <Card><div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}><span style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb" }}>PoC Script</span><button onClick={() => navigator.clipboard?.writeText(f.poc_script || "")} style={{ padding: "4px 12px", borderRadius: 6, border: "1px solid #2d3040", background: "transparent", color: "#9ca3af", fontSize: 11, cursor: "pointer" }}>Copy</button></div><pre style={{ margin: 0, padding: 16, borderRadius: 8, background: "#0a0c10", border: "1px solid #1e2028", color: "#d1d5db", fontSize: 12, lineHeight: 1.6, fontFamily: "'JetBrains Mono', monospace", overflow: "auto", maxHeight: 500, whiteSpace: "pre-wrap" }}>{f.poc_script || "No PoC generated."}</pre></Card>}

      {tab === "evidence" && extracted && (
        <Card>
          <div style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb", marginBottom: 12 }}>ZAP Evidence</div>
          {[["Evidence", extracted.evidence], ["Parameter", extracted.param], ["Attack Payload", extracted.attack], ["Other Info", extracted.other]].map(([label, val]) => val ? (
            <div key={label} style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", textTransform: "uppercase", marginBottom: 4 }}>{label}</div>
              <pre style={{ margin: 0, padding: 10, borderRadius: 6, background: "#0a0c10", border: "1px solid #1e2028", color: "#d1d5db", fontSize: 12, fontFamily: "'JetBrains Mono', monospace", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{val}</pre>
            </div>
          ) : null)}
        </Card>
      )}

      {tab === "screenshot" && f.poc_screenshot && <Card><div style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb", marginBottom: 12 }}>Screenshot</div><img src={f.poc_screenshot} alt="Evidence" style={{ width: "100%", borderRadius: 8, border: "1px solid #1e2028" }} onError={e => { e.target.style.display = "none"; }} /></Card>}
    </div>
  );
};

// ── Main App ─────────────────────────────────────────────────────────────────
export default function VulnerabilityScannerApp() {
  const [view, setView] = useState("dashboard");
  const [scanFilter, setScanFilter] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [health, setHealth] = useState(null);
  useEffect(() => { apiGet("/health").then(setHealth).catch(() => {}); }, []);

  const nav = [{ id: "dashboard", label: "Dashboard", icon: "◈" }, { id: "scans", label: "Scans", icon: "⟐" }, { id: "findings", label: "Findings", icon: "⬡" }];

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: "#0a0c10", color: "#e5e7eb", fontFamily: "'DM Sans', 'Segoe UI', system-ui, sans-serif" }}>
      <aside style={{ width: 220, background: "#0d0f13", borderRight: "1px solid #1e2028", padding: "20px 12px", display: "flex", flexDirection: "column", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 8px", marginBottom: 28 }}>
          <div style={{ width: 28, height: 28, borderRadius: 8, background: "linear-gradient(135deg, #10b981, #059669)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, fontWeight: 900, color: "#fff" }}>V</div>
          <span style={{ fontSize: 16, fontWeight: 800, letterSpacing: -.5 }}><span style={{ color: "#10b981" }}>Vulnerability</span><span style={{ color: "#e5e7eb" }}>Scanner</span></span>
        </div>
        <nav style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {nav.map(i => <button key={i.id} onClick={() => { setView(i.id); setSelectedFinding(null); setScanFilter(null); }} style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", borderRadius: 8, border: "none", background: view === i.id ? "#10b98115" : "transparent", color: view === i.id ? "#34d399" : "#6b7280", fontSize: 13, fontWeight: view === i.id ? 700 : 500, cursor: "pointer", textAlign: "left", fontFamily: "inherit" }}><span style={{ fontSize: 16, opacity: .8 }}>{i.icon}</span>{i.label}</button>)}
        </nav>
        <div style={{ marginTop: "auto", padding: "12px 8px", borderTop: "1px solid #1e2028", display: "flex", flexDirection: "column", gap: 8 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}><span style={{ width: 8, height: 8, borderRadius: "50%", background: health?.nuclei_available ? "#22c55e" : "#ef4444", boxShadow: `0 0 8px ${health?.nuclei_available ? "#22c55e" : "#ef4444"}60` }} /><span style={{ fontSize: 11, color: "#6b7280" }}>Nuclei {health?.nuclei_available ? "Online" : "Offline"}</span></div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}><span style={{ width: 8, height: 8, borderRadius: "50%", background: health?.zap_available ? "#22c55e" : "#ef4444", boxShadow: `0 0 8px ${health?.zap_available ? "#22c55e" : "#ef4444"}60` }} /><span style={{ fontSize: 11, color: "#6b7280" }}>ZAP {health?.zap_available ? "Online" : "Offline"}</span></div>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}><span style={{ width: 8, height: 8, borderRadius: "50%", background: health?.ai_enabled ? "#10b981" : "#6b7280", boxShadow: `0 0 8px ${health?.ai_enabled ? "#10b981" : "#6b7280"}60` }} /><span style={{ fontSize: 11, color: "#6b7280" }}>{health?.ai_enabled ? `${health.ai_model}` : "AI Off"}</span></div>
        </div>
      </aside>
      <main style={{ flex: 1, padding: 24, overflow: "auto", maxHeight: "100vh" }}>
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>
          <div style={{ marginBottom: 24 }}>
            <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800, letterSpacing: -.5 }}>{selectedFinding ? "Finding Details" : view === "dashboard" ? "Security Dashboard" : view === "scans" ? "Scan Management" : "Vulnerability Findings"}</h1>
            <p style={{ margin: "4px 0 0", fontSize: 12, color: "#4b5563" }}>{selectedFinding ? selectedFinding.name : view === "dashboard" ? "Nuclei + ZAP + GPT-4o" : view === "scans" ? "Launch and monitor scans" : scanFilter ? `Scan ${scanFilter.slice(0, 8)}...` : "All findings"}</p>
          </div>
          {selectedFinding ? <FindingDetail finding={selectedFinding} onBack={() => setSelectedFinding(null)} /> : view === "dashboard" ? <DashboardView /> : view === "scans" ? <ScansView onViewFindings={id => { setScanFilter(id); setView("findings"); }} /> : <FindingsView scanFilter={scanFilter} onViewFinding={setSelectedFinding} />}
        </div>
      </main>
    </div>
  );
}
