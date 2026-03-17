import { useState, useEffect, useCallback, useRef } from "react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, CartesianGrid } from "recharts";

// ── API ──────────────────────────────────────────────────────────────────────
const API = "/api";
async function api(path, opts = {}) {
  const r = await fetch(`${API}${path}`, { headers: { "Content-Type": "application/json", ...opts.headers }, ...opts });
  if (!r.ok) {
    const text = await r.text();
    let msg = `${r.status}: ${text}`;
    try { const j = JSON.parse(text); msg = j.detail || j.message || msg; } catch (e) { /* keep raw msg */ }
    throw new Error(msg);
  }
  const text = await r.text();
  try { return JSON.parse(text); } catch (e) { throw new Error(`API returned non-JSON: ${text.slice(0, 150)}`); }
}
async function apiSafeJson(response) {
  const text = await response.text();
  if (!response.ok) {
    let msg = `${response.status}: ${text}`;
    try { const j = JSON.parse(text); msg = j.detail || j.message || msg; } catch (e) { /* keep raw msg */ }
    throw new Error(msg);
  }
  try { return JSON.parse(text); } catch (e) { throw new Error(`Server returned non-JSON: ${text.slice(0, 150)}`); }
}
const apiGet = (p) => api(p);
const apiPost = (p, b) => api(p, { method: "POST", body: JSON.stringify(b) });
const apiPatch = (p, b) => api(p, { method: "PATCH", body: JSON.stringify(b) });
const apiDelete = (p) => api(p, { method: "DELETE" });

// ── Constants ────────────────────────────────────────────────────────────────
const SEV = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6", info: "#6b7280" };
const SEV_BG = { critical: "rgba(239,68,68,.12)", high: "rgba(249,115,22,.12)", medium: "rgba(234,179,8,.10)", low: "rgba(59,130,246,.10)", info: "rgba(107,114,128,.10)" };
const STAT_C = { open: "#ef4444", confirmed: "#f97316", false_positive: "#6b7280", remediated: "#22c55e" };
const PH = { initializing: "Init", template_update: "Template Update", nuclei_scan: "Nuclei", zap_scan: "ZAP Scan", zap_auth_check: "Auth Check", selenium_login: "Selenium Login", zap_session_injection: "Session Inject", zap_context_config: "ZAP Context", zap_spider: "Spider", dep_scan: "Dep Scan", ssl_scan: "SSL Scan", deduplication: "Dedup", consolidation: "Consolidate", fp_filtering: "FP Filter", ai_fp_scoring: "AI FP Score", storing_findings: "Storing", ai_analysis: "GPT-4o", evidence_capture: "Evidence", reauth: "Re-Auth", done: "Done", error: "Error" };
const PH_ORDER = ["initializing", "template_update", "nuclei_scan", "zap_scan", "zap_auth_check", "selenium_login", "zap_session_injection", "zap_context_config", "zap_spider", "dep_scan", "ssl_scan", "deduplication", "consolidation", "fp_filtering", "ai_fp_scoring", "storing_findings", "ai_analysis", "evidence_capture", "done"];
const ENGINE_COLORS = { nuclei: "#8b5cf6", zap: "#f97316", both: "#10b981" };

// ── Components ───────────────────────────────────────────────────────────────
const SevBadge = ({ s }) => <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 10px", borderRadius: 6, fontSize: 11, fontWeight: 700, letterSpacing: .5, textTransform: "uppercase", color: SEV[s], background: SEV_BG[s], border: `1px solid ${SEV[s]}22` }}><span style={{ width: 6, height: 6, borderRadius: "50%", background: SEV[s] }} />{s}</span>;
const StatusBadge = ({ s }) => <span style={{ padding: "2px 8px", borderRadius: 6, fontSize: 11, fontWeight: 600, color: STAT_C[s] || "#888", background: `${STAT_C[s] || "#888"}18` }}>{(s || "").replace("_", " ")}</span>;
const EngineBadge = ({ e }) => <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700, textTransform: "uppercase", color: ENGINE_COLORS[e] || "#6b7280", background: `${ENGINE_COLORS[e] || "#6b7280"}18`, border: `1px solid ${ENGINE_COLORS[e] || "#6b7280"}30` }}>{e === "both" ? "Nuclei+ZAP" : e}</span>;
const SOURCE_COLOR = { zap: "#f97316", nuclei: "#8b5cf6", "dep-scan": "#a855f7", "ssl-scan": "#06b6d4" };
const SOURCE_LABEL = { "dep-scan": "DEP", "ssl-scan": "SSL" };
const SourceBadge = ({ s }) => {
  const color = SOURCE_COLOR[s] || SOURCE_COLOR.nuclei;
  const label = SOURCE_LABEL[s] || (s || "nuclei").toUpperCase();
  return <span style={{ padding: "1px 6px", borderRadius: 4, fontSize: 9, fontWeight: 700, textTransform: "uppercase", color, background: `${color}18`, border: `1px solid ${color}30` }}>{label}</span>;
};
const Card = ({ children, style, ...p }) => <div style={{ background: "#111318", border: "1px solid #1e2028", borderRadius: 12, padding: 20, ...style }} {...p}>{children}</div>;
const MetricCard = ({ label, value, sub, accent }) => <Card style={{ display: "flex", flexDirection: "column", gap: 4 }}><span style={{ fontSize: 12, color: "#6b7280", fontWeight: 500, letterSpacing: .5, textTransform: "uppercase" }}>{label}</span><span style={{ fontSize: 32, fontWeight: 800, color: accent || "#f0f0f0", fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.1 }}>{value}</span>{sub && <span style={{ fontSize: 12, color: "#4b5563" }}>{sub}</span>}</Card>;
const Spinner = () => <div style={{ display: "flex", alignItems: "center", gap: 8, color: "#6b7280", fontSize: 13 }}><div style={{ width: 16, height: 16, border: "2px solid #2d3040", borderTopColor: "#10b981", borderRadius: "50%", animation: "spin .8s linear infinite" }} />Loading...<style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style></div>;
const Empty = ({ msg }) => <Card style={{ textAlign: "center", padding: 40, color: "#4b5563" }}><div style={{ fontSize: 32, marginBottom: 8, opacity: .3 }}>⬡</div><div style={{ fontSize: 14 }}>{msg}</div></Card>;
const ErrorBox = ({ error, onRetry }) => <Card style={{ borderColor: "#ef444440" }}><div style={{ color: "#ef4444", fontSize: 13, fontWeight: 600, marginBottom: 4 }}>Error</div><div style={{ color: "#9ca3af", fontSize: 12, fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all" }}>{error}</div>{onRetry && <button onClick={onRetry} style={{ marginTop: 10, padding: "6px 14px", borderRadius: 6, border: "1px solid #2d3040", background: "transparent", color: "#9ca3af", fontSize: 12, cursor: "pointer" }}>Retry</button>}</Card>;
const Input = ({ label, ...p }) => <div style={{ display: "flex", flexDirection: "column", gap: 4 }}><label style={{ fontSize: 11, color: "#6b7280", fontWeight: 600, textTransform: "uppercase", letterSpacing: .5 }}>{label}</label><input style={{ padding: "10px 12px", borderRadius: 8, border: "1px solid #2d3040", background: "#0d0f13", color: "#e5e7eb", fontSize: 13, outline: "none", fontFamily: "'JetBrains Mono', monospace" }} {...p} /></div>;
const Select = ({ label, children, ...p }) => <div style={{ display: "flex", flexDirection: "column", gap: 4 }}><label style={{ fontSize: 11, color: "#6b7280", fontWeight: 600, textTransform: "uppercase", letterSpacing: .5 }}>{label}</label><select style={{ padding: "10px 12px", borderRadius: 8, border: "1px solid #2d3040", background: "#0d0f13", color: "#e5e7eb", fontSize: 13, outline: "none" }} {...p}>{children}</select></div>;
const Tab = ({ active, onClick, children }) => <button onClick={onClick} style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "8px 16px", border: "none", borderBottom: active ? "2px solid #10b981" : "2px solid transparent", background: "transparent", color: active ? "#f0f0f0" : "#6b7280", fontSize: 13, fontWeight: active ? 700 : 500, cursor: "pointer", fontFamily: "inherit" }}>{children}</button>;

// ── Toast Notification System ─────────────────────────────────────────────
let _toastListeners = [];
const toast = {
  _id: 0,
  _emit(t) { _toastListeners.forEach(fn => fn(t)); },
  success(msg) { this._emit({ id: ++this._id, type: "success", msg }); },
  error(msg)   { this._emit({ id: ++this._id, type: "error",   msg }); },
  info(msg)    { this._emit({ id: ++this._id, type: "info",    msg }); },
};


const ProgressBar = ({ phase }) => {
  const idx = PH_ORDER.indexOf(phase);
  const pct = phase === "done" ? 100 : phase === "error" ? 100 : Math.max(8, ((idx + 1) / PH_ORDER.length) * 100);
  return <div style={{ display: "flex", flexDirection: "column", gap: 4 }}><div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "#9ca3af" }}><span>{PH[phase] || phase}</span><span>{phase === "error" ? "Failed" : `${Math.round(pct)}%`}</span></div><div style={{ height: 4, borderRadius: 2, background: "#1e2028", overflow: "hidden" }}><div style={{ height: "100%", width: `${pct}%`, borderRadius: 2, background: phase === "error" ? "#ef4444" : phase === "done" ? "#10b981" : "linear-gradient(90deg, #10b981, #059669)", transition: "width .5s" }} /></div></div>;
};

// ── Auth Config Panel ────────────────────────────────────────────────────────
const AuthPanel = ({ auth, setAuth, onModeChange }) => {
  const [sideLoading, setSideLoading] = useState(false);
  const [sideMsg, setSideMsg] = useState(null); // {ok: bool, text: str}
  const [scanMode, setScanMode] = useState("manual"); // "manual" | "side-file"
  const [sideFile, setSideFile] = useState(null);
  const [targetUrl, setTargetUrl] = useState("");
  const [runScan, setRunScan] = useState(false);
  const [integratedLoading, setIntegratedLoading] = useState(false);

  const handleSideUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setSideLoading(true);
    setSideMsg(null);
    try {
      const form = new FormData();
      form.append("file", file);
      const r = await fetch("/api/upload/selenium-test", { method: "POST", body: form });
      const body = await apiSafeJson(r);
      
      // Extract auth configuration from SIDE file
      const authConfig = body.auth_configuration;
      if (authConfig.login_url) {
        setAuth(prev => ({
          ...prev,
          auth_type: "form",
          login_url: authConfig.login_url,
          username_field: authConfig.username_field || "username",
          password_field: authConfig.password_field || "password",
          username: authConfig.username_value || "",
          password: authConfig.password_value || "",
          logged_in_indicator: authConfig.success_indicator || ""
        }));
        setSideMsg({ ok: true, text: `✓ Loaded Selenium IDE test: ${body.filename} (${body.tests_count} tests)` });
      } else {
        setSideMsg({ ok: false, text: "Could not extract login flow from test file" });
      }
    } catch (err) {
      setSideMsg({ ok: false, text: err.message });
    } finally {
      setSideLoading(false);
      e.target.value = "";
    }
  };

  const handleIntegratedSideUpload = async (e) => {
    const file = e.target.files[0];
    if (!file || !targetUrl.trim()) {
      setSideMsg({ ok: false, text: "Please select a .side file and enter target URL" });
      return;
    }
    setSideFile(file);
    setSideMsg({ ok: true, text: `✓ Selected: ${file.name} → ${targetUrl}` });
  };

  const launchIntegratedScan = async () => {
    if (!sideFile || !targetUrl.trim()) {
      setSideMsg({ ok: false, text: "Missing .side file or target URL" });
      return;
    }

    try {
      setIntegratedLoading(true);
      setSideMsg(null);

      const form = new FormData();
      form.append("file", sideFile);

      const params = new URLSearchParams({
        target: targetUrl.trim(),
        run_scan: runScan.toString(),
        timeout_minutes: "60"
      });

      const r = await fetch(`/api/scans/authenticated/integrated?${params}`, {
        method: "POST",
        body: form
      });

      const body = await apiSafeJson(r);

      setSideMsg({
        ok: true,
        text: `✓ Authenticated scan queued! Scan ID: ${body.scan_id.slice(0, 8)}... — check Scans tab for progress`
      });
      toast.info("Authenticated scan queued — authentication in progress...");

      // Reset form
      setSideFile(null);
      setTargetUrl("");
      setRunScan(false);
    } catch (err) {
      setSideMsg({ ok: false, text: `Error: ${err.message}` });
      toast.error(`Auth scan failed: ${err.message}`);
    } finally {
      setIntegratedLoading(false);
    }
  };

  const up = (k, v) => setAuth({ ...auth, [k]: v });
  const t = auth.auth_type;
  
  return (
    <Card style={{ border: "1px solid #f9731640", marginTop: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb" }}>Authentication Config</span>
        <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: "#f9731618", color: "#f97316" }}>ZAP + Selenium</span>
      </div>

      {/* Mode Selection */}
      <div style={{ display: "flex", gap: 12, marginBottom: 14, paddingBottom: 12, borderBottom: "1px solid #1e2028" }}>
        <button 
          onClick={() => { setScanMode("manual"); onModeChange && onModeChange("manual"); }}
          style={{ 
            padding: "6px 14px", 
            borderRadius: 6, 
            border: scanMode === "manual" ? "2px solid #10b981" : "1px solid #2d3040",
            background: scanMode === "manual" ? "#10b98115" : "transparent",
            color: scanMode === "manual" ? "#10b981" : "#6b7280",
            fontSize: 12, 
            fontWeight: 600,
            cursor: "pointer"
          }}>
          Manual Config
        </button>
        <button 
          onClick={() => { setScanMode("side-file"); onModeChange && onModeChange("side-file"); }}
          style={{ 
            padding: "6px 14px", 
            borderRadius: 6, 
            border: scanMode === "side-file" ? "2px solid #f97316" : "1px solid #2d3040",
            background: scanMode === "side-file" ? "#f9731615" : "transparent",
            color: scanMode === "side-file" ? "#f97316" : "#6b7280",
            fontSize: 12, 
            fontWeight: 600,
            cursor: "pointer"
          }}>
          .SIDE File (Direct Scan)
        </button>
      </div>

      {scanMode === "side-file" ? (
        <>
          {/* Integrated SIDE File Upload & Direct Scan */}
          <div style={{ marginBottom: 14, padding: "14px", borderRadius: 8, border: "1px dashed #f9731640", background: "#f9731608" }}>
            <div style={{ fontSize: 11, color: "#f97316", fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 12 }}>
              Direct Authenticated Scan
            </div>
            
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
              <div>
                <label style={{ fontSize: 10, color: "#6b7280", fontWeight: 600, textTransform: "uppercase", letterSpacing: .5, marginBottom: 6, display: "block" }}>
                  Target URL *
                </label>
                <input 
                  type="url"
                  placeholder="https://example.com"
                  value={targetUrl}
                  onChange={e => setTargetUrl(e.target.value)}
                  style={{ 
                    width: "100%",
                    padding: "10px 12px", 
                    borderRadius: 8, 
                    border: "1px solid #2d3040", 
                    background: "#0d0f13", 
                    color: "#e5e7eb", 
                    fontSize: 13, 
                    outline: "none",
                    fontFamily: "'JetBrains Mono', monospace"
                  }} 
                />
              </div>
              <div>
                <label style={{ fontSize: 10, color: "#6b7280", fontWeight: 600, textTransform: "uppercase", letterSpacing: .5, marginBottom: 6, display: "block" }}>
                  .SIDE File *
                </label>
                <label style={{ 
                  display: "flex", 
                  alignItems: "center", 
                  gap: 6, 
                  padding: "10px 12px", 
                  borderRadius: 8, 
                  border: "1px solid #2d3040", 
                  background: "#1a1d24", 
                  color: "#9ca3af", 
                  fontSize: 12, 
                  cursor: "pointer", 
                  fontWeight: 600 
                }}>
                  {sideFile ? `✓ ${sideFile.name}` : "Choose .side file"}
                  <input 
                    type="file" 
                    accept=".side"
                    onChange={handleIntegratedSideUpload}
                    style={{ display: "none" }} 
                  />
                </label>
              </div>
            </div>

            <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
              <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "#9ca3af", cursor: "pointer" }}>
                <input 
                  type="checkbox" 
                  checked={runScan} 
                  onChange={e => setRunScan(e.target.checked)}
                  style={{ accentColor: "#10b981" }} 
                />
                Run Spider + Active Scan (takes longer)
              </label>
            </div>

            <button 
              onClick={launchIntegratedScan}
              disabled={integratedLoading || !sideFile || !targetUrl.trim()}
              style={{ 
                padding: "10px 18px", 
                borderRadius: 6, 
                border: "none", 
                background: integratedLoading || !sideFile || !targetUrl.trim() ? "#4b5563" : "#f97316",
                color: "#fff", 
                fontSize: 12, 
                fontWeight: 700, 
                cursor: integratedLoading ? "wait" : "pointer",
                opacity: !sideFile || !targetUrl.trim() ? .5 : 1
              }}>
              {integratedLoading ? "Scanning..." : "Launch Authenticated Scan"}
            </button>
          </div>

          {sideMsg && (
            <div style={{ 
              padding: "10px 12px", 
              borderRadius: 8, 
              border: sideMsg.ok ? "1px solid #10b98140" : "1px solid #ef444440",
              background: sideMsg.ok ? "#10b98108" : "#ef444408",
              color: sideMsg.ok ? "#10b981" : "#ef4444", 
              fontSize: 12,
              fontFamily: "'JetBrains Mono', monospace",
              wordBreak: "break-all"
            }}>
              {sideMsg.ok ? "✓" : "✕"} {sideMsg.text}
            </div>
          )}
        </>
      ) : (
        <>
          {/* Manual SIDE (Selenium IDE) file import */}
          <div style={{ marginBottom: 14, padding: "10px 14px", borderRadius: 8, border: "1px dashed #2d3040", background: "#0d0f1320" }}>
            <div style={{ fontSize: 11, color: "#6b7280", fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8 }}>
              Import Selenium IDE Test <span style={{ color: "#4b5563", fontWeight: 400, textTransform: "none" }}>— .side (Browser automation)</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <label style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "6px 14px", borderRadius: 6, border: "1px solid #2d3040", background: "#1a1d24", color: sideLoading ? "#4b5563" : "#9ca3af", fontSize: 12, cursor: sideLoading ? "wait" : "pointer", fontWeight: 600, userSelect: "none" }}>
                {sideLoading ? "Parsing…" : "Choose .side file"}
                <input type="file" accept=".side" style={{ display: "none" }} onChange={handleSideUpload} disabled={sideLoading} />
              </label>
              {sideMsg && (
                <span style={{ fontSize: 12, color: sideMsg.ok ? "#10b981" : "#ef4444", maxWidth: 360, wordBreak: "break-word" }}>
                  {sideMsg.ok ? "✓" : "✕"} {sideMsg.text}
                </span>
              )}
            </div>
            <div style={{ fontSize: 10, color: "#374151", marginTop: 6 }}>
              Export from Selenium IDE Chrome extension · Automatically extracts login credentials and form fields
            </div>
          </div>

          {/* Manual authentication configuration */}
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
        </>
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

// Scan type label helper
const SCAN_TYPE_LABEL = { quick: "Quick", full: "Full", deep: "Deep", custom: "Custom", "integrated-auth": "Integrated Auth", auth: "Auth Scan" };
const AUTH_TYPE_LABEL = { form: "Form Login", token: "Token", header: "Header", selenium: "Selenium", none: null };

const ScanCard = ({ sc, scanProgress, scanLog, onViewFindings, onViewDeps, onRescan, onDelete, onToggleHistory, historyData, expandedHistory }) => {
  const live = scanProgress[sc.scan_id];
  const liveStatus = live ? live.status : sc.status;
  const livePhase  = live ? live.phase  : sc.phase;
  const liveRaw    = live ? live.raw_finding_count    : (sc.raw_finding_count    || 0);
  const liveUnique = live ? live.unique_finding_count : (sc.unique_finding_count || 0);
  const phaseLog   = scanLog[sc.scan_id] || [];

  // Per-source finding counts (loaded once scan is completed)
  const [srcCounts, setSrcCounts] = useState({});
  useEffect(() => {
    if (liveStatus !== "completed") return;
    apiGet(`/scans/${sc.scan_id}/findings?limit=500`).then(fs => {
      const counts = {};
      for (const f of fs) { const s = f.scanner_source || "nuclei"; counts[s] = (counts[s] || 0) + 1; }
      setSrcCounts(counts);
    }).catch(() => {});
  }, [sc.scan_id, liveStatus]);

  // Decode auth info
  let authCfg = null; try { authCfg = sc.auth_config ? JSON.parse(sc.auth_config) : null; } catch {}
  const hasAuth = authCfg && authCfg.auth_type && authCfg.auth_type !== "none";
  const authStatus = sc.auth_status;
  const isAuthOk = authStatus?.verified;

  // Scan origin badges
  const isRescan = !!sc.parent_scan_id;
  const isIncremental = sc.is_incremental === "1";

  const statusColor = { completed: "#10b981", failed: "#ef4444", scanning: "#eab308", authenticating: "#f97316", queued: "#6b7280" };
  const statusBg   = { completed: "#10b98118", failed: "#ef444418", scanning: "#eab30818", authenticating: "#f9731618", queued: "#6b728018" };

  return (
    <Card style={{ cursor: liveStatus === "completed" ? "pointer" : "default" }} onClick={() => liveStatus === "completed" && onViewFindings(sc.scan_id)}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
        {/* Left: target + badges + meta */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 5, flexWrap: "wrap" }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb", fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all" }}>{sc.target}</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", marginBottom: 6 }}>
            <EngineBadge e={sc.scanner_engine || "nuclei"} />
            {/* Scan type */}
            <span style={{ padding: "2px 7px", borderRadius: 4, fontSize: 10, fontWeight: 600, background: "#1e2028", color: "#9ca3af" }}>
              {SCAN_TYPE_LABEL[sc.scan_type] || sc.scan_type}
            </span>
            {/* Status */}
            <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700, textTransform: "uppercase", background: statusBg[liveStatus] || "#6b728018", color: statusColor[liveStatus] || "#6b7280" }}>
              {liveStatus}
            </span>
            {/* Auth badges */}
            {hasAuth && !authStatus && (
              <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: "#f9731618", color: "#f97316" }}>
                {AUTH_TYPE_LABEL[authCfg.auth_type] || "AUTH"}
              </span>
            )}
            {hasAuth && authStatus && (
              <>
                <span title={authStatus.message || ""} style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, cursor: "help", background: isAuthOk ? "#10b98118" : "#ef444418", color: isAuthOk ? "#10b981" : "#ef4444", border: `1px solid ${isAuthOk ? "#10b98140" : "#ef444440"}` }}>
                  {isAuthOk ? "✓" : "✗"} {AUTH_TYPE_LABEL[authCfg.auth_type] || "AUTH"} {isAuthOk ? "OK" : "FAIL"}
                </span>
                {isAuthOk && authStatus.auth_screenshot && (
                  <a href={`/screenshots/${authStatus.auth_screenshot}`} target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()}
                    style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: "#3b82f618", color: "#60a5fa", border: "1px solid #3b82f640", textDecoration: "none" }}>
                    📷 Proof
                  </a>
                )}
              </>
            )}
            {/* Origin badges */}
            {isRescan && <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 9, fontWeight: 700, background: "#3b82f618", color: "#60a5fa" }}>RESCAN</span>}
            {isIncremental && <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 9, fontWeight: 700, background: "#0ea5e918", color: "#38bdf8" }}>INCREMENTAL</span>}
          </div>
          <div style={{ display: "flex", gap: 16, fontSize: 11, color: "#6b7280", flexWrap: "wrap", alignItems: "center" }}>
            <span>Raw: <strong style={{ color: "#9ca3af" }}>{liveRaw}</strong></span>
            <span>Unique: <strong style={{ color: "#e5e7eb" }}>{liveUnique}</strong></span>
            {Object.entries(srcCounts).filter(([src]) => src !== "nuclei" && src !== "zap").map(([src, cnt]) => (
              <span key={src} style={{ padding: "1px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, color: SOURCE_COLOR[src] || "#6b7280", background: `${SOURCE_COLOR[src] || "#6b7280"}15`, border: `1px solid ${SOURCE_COLOR[src] || "#6b7280"}30` }}>
                {SOURCE_LABEL[src] || src.toUpperCase()} {cnt}
              </span>
            ))}
            <span>{new Date(sc.created_at).toLocaleString()}</span>
            {sc.completed_at && <span style={{ color: "#10b981" }}>⏱ {Math.round((new Date(sc.completed_at) - new Date(sc.created_at)) / 60000)}m</span>}
          </div>
          {sc.error && <div style={{ fontSize: 11, color: "#ef4444", marginTop: 5, fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all" }}>{sc.error}</div>}
        </div>

        {/* Right: action buttons */}
        <div style={{ display: "flex", flexDirection: "column", gap: 5, alignItems: "flex-end", flexShrink: 0 }}>
          <div style={{ display: "flex", gap: 5, flexWrap: "wrap", justifyContent: "flex-end" }}>
            {liveStatus === "completed" && srcCounts["dep-scan"] > 0 && (
              <button onClick={e => { e.stopPropagation(); onViewDeps(sc.scan_id); }}
                style={{ padding: "4px 8px", borderRadius: 4, border: "1px solid #a855f740", background: "#a855f615", color: "#c084fc", fontSize: 11, cursor: "pointer", fontWeight: 600 }}>
                📦 Deps
              </button>
            )}
            {liveStatus === "completed" && (
              <button onClick={e => { e.stopPropagation(); const l = document.createElement("a"); l.href = `/api/scans/${sc.scan_id}/report/pdf`; l.download = `report_${sc.scan_id}.pdf`; document.body.appendChild(l); l.click(); document.body.removeChild(l); }}
                style={{ padding: "4px 8px", borderRadius: 4, border: "1px solid #22c55e", background: "#10b98115", color: "#10b981", fontSize: 11, cursor: "pointer", fontWeight: 600 }}>
                ↓ PDF
              </button>
            )}
            {(liveStatus === "completed" || liveStatus === "failed") && (
              <button onClick={e => { e.stopPropagation(); onRescan(sc); }}
                title="Re-run with same configuration (incremental — skips already-scanned URLs)"
                style={{ padding: "4px 8px", borderRadius: 4, border: "1px solid #3b82f640", background: "#3b82f615", color: "#60a5fa", fontSize: 11, cursor: "pointer", fontWeight: 600 }}>
                ↺ Rescan
              </button>
            )}
            <button onClick={e => { e.stopPropagation(); onToggleHistory(sc); }}
              style={{ padding: "4px 8px", borderRadius: 4, border: `1px solid ${expandedHistory[sc.scan_id] ? "#a855f740" : "#2d3040"}`, background: expandedHistory[sc.scan_id] ? "#a855f615" : "transparent", color: expandedHistory[sc.scan_id] ? "#c084fc" : "#6b7280", fontSize: 11, cursor: "pointer" }}>
              ⏷ History
            </button>
            <button onClick={e => { e.stopPropagation(); onDelete(sc.scan_id); }}
              style={{ padding: "4px 8px", borderRadius: 4, border: "1px solid #2d3040", background: "transparent", color: "#6b7280", fontSize: 11, cursor: "pointer" }}>✕</button>
          </div>
        </div>
      </div>

      {/* Progress bar while scanning */}
      {(liveStatus === "scanning" || liveStatus === "authenticating") && (
        <div style={{ marginTop: 10 }}>
          <ProgressBar phase={livePhase} />
          {phaseLog.length > 1 && (
            <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 4 }}>
              {phaseLog.slice(-8).map((entry, i, arr) => {
                const isCurrent = i === arr.length - 1;
                return (
                  <span key={i} style={{ fontSize: 10, padding: "2px 7px", borderRadius: 10, background: isCurrent ? "#10b98122" : "#1e2028", color: isCurrent ? "#10b981" : "#4b5563", border: isCurrent ? "1px solid #10b98140" : "1px solid transparent", fontFamily: "'JetBrains Mono', monospace" }}>
                    {PH[entry.phase] || entry.phase}
                  </span>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* History panel */}
      {expandedHistory[sc.scan_id] && historyData[sc.scan_id] && (
        <div style={{ marginTop: 12, borderTop: "1px solid #1e2028", paddingTop: 12 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: "#6b7280", textTransform: "uppercase", marginBottom: 8, letterSpacing: 0.5 }}>
            History — {sc.target} &nbsp;·&nbsp; {historyData[sc.scan_id].length} run{historyData[sc.scan_id].length !== 1 ? "s" : ""}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
            {historyData[sc.scan_id].map((h, i) => {
              const isCurrent = h.scan_id === sc.scan_id;
              return (
                <div key={h.scan_id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", borderRadius: 6, background: isCurrent ? "#10b98108" : "#0a0c10", border: `1px solid ${isCurrent ? "#10b98130" : "#1e2028"}` }}>
                  <span style={{ fontSize: 10, color: "#4b5563", minWidth: 22, textAlign: "right", fontFamily: "'JetBrains Mono', monospace" }}>#{historyData[sc.scan_id].length - i}</span>
                  <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: "#4b5563" }}>{h.scan_id.slice(0, 8)}</span>
                  <span style={{ padding: "1px 5px", borderRadius: 3, fontSize: 9, fontWeight: 700, textTransform: "uppercase", background: statusBg[h.status] || "#6b728018", color: statusColor[h.status] || "#6b7280" }}>{h.status}</span>
                  {h.is_incremental === "1" && <span style={{ padding: "1px 5px", borderRadius: 3, fontSize: 9, fontWeight: 700, background: "#0ea5e918", color: "#38bdf8" }}>INCR</span>}
                  {h.parent_scan_id && <span style={{ padding: "1px 5px", borderRadius: 3, fontSize: 9, fontWeight: 700, background: "#3b82f618", color: "#60a5fa" }}>RESCAN</span>}
                  <EngineBadge e={h.scanner_engine || "nuclei"} />
                  <span style={{ fontSize: 10, color: "#9ca3af" }}>{SCAN_TYPE_LABEL[h.scan_type] || h.scan_type}</span>
                  <span style={{ fontSize: 11, color: "#e5e7eb", fontWeight: 600 }}>{h.unique_finding_count || 0} <span style={{ color: "#6b7280", fontWeight: 400 }}>findings</span></span>
                  <span style={{ fontSize: 10, color: "#4b5563", marginLeft: "auto" }}>{new Date(h.created_at).toLocaleString()}</span>
                  {h.completed_at && <span style={{ fontSize: 10, color: "#10b981" }}>⏱ {Math.round((new Date(h.completed_at) - new Date(h.created_at)) / 60000)}m</span>}
                  {h.status === "completed" && (
                    <button onClick={e => { e.stopPropagation(); onViewFindings(h.scan_id); }} style={{ padding: "2px 8px", borderRadius: 4, border: "1px solid #2d3040", background: "transparent", color: "#9ca3af", fontSize: 10, cursor: "pointer", flexShrink: 0 }}>View</button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </Card>
  );
};

const ScansView = ({ onViewFindings, onViewDeps }) => {
  const [activeTab, setActiveTab] = useState("scans"); // "scans" | "schedules"
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [engineFilter, setEngineFilter] = useState("all"); // all | nuclei | zap | both | auth
  const [showForm, setShowForm] = useState(false);
  // New scan form
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("full");
  const [engine, setEngine] = useState("nuclei");
  const [doAI, setDoAI] = useState(true);
  const [doPoC, setDoPoC] = useState(true);
  const [auth, setAuth] = useState({ ...DEFAULT_AUTH });
  const [authPanelMode, setAuthPanelMode] = useState("manual");
  const [submitting, setSubmitting] = useState(false);
  // History
  const [expandedHistory, setExpandedHistory] = useState({});
  const [historyData, setHistoryData] = useState({});
  // SSE
  const prevScans = useRef({});
  const [scanProgress, setScanProgress] = useState({});
  const [scanLog, setScanLog] = useState({});
  const sseConnections = useRef({});
  // Schedules
  const [schedules, setSchedules] = useState([]);
  const [showSchedForm, setShowSchedForm] = useState(false);
  const [schedTarget, setSchedTarget] = useState("");
  const [schedType, setSchedType] = useState("full");
  const [schedEngine, setSchedEngine] = useState("nuclei");
  const [schedInterval, setSchedInterval] = useState("weekly");
  const [schedAuth, setSchedAuth] = useState({ ...DEFAULT_AUTH });
  const [schedAuthMode, setSchedAuthMode] = useState("manual");
  const [schedSubmitting, setSchedSubmitting] = useState(false);

  const loadScans = useCallback(async () => {
    try {
      setError(null);
      const data = await apiGet("/scans?limit=100");
      setScans(data);
      data.forEach(sc => {
        const prev = prevScans.current[sc.scan_id] || {};
        const as = sc.auth_status;
        if (as && as.verified && !prev.auth_notified) {
          toast.success(`Auth verified for ${sc.target.slice(0, 50)}`);
          prevScans.current[sc.scan_id] = { ...prev, auth_notified: true };
        }
        if (sc.status === "completed" && prev.status !== "completed") {
          const n = sc.unique_finding_count || 0;
          toast.success(`Scan done: ${sc.target.slice(0, 40)} — ${n} finding${n !== 1 ? "s" : ""}`);
        }
        if (sc.status === "failed" && prev.status !== "failed") {
          toast.error(`Scan failed: ${sc.target.slice(0, 40)}`);
        }
        prevScans.current[sc.scan_id] = { ...prev, status: sc.status };
      });
    } catch (e) { setError(e.message); } finally { setLoading(false); }
  }, []);

  const loadSchedules = useCallback(async () => {
    try { setSchedules(await apiGet("/schedules")); } catch (_) {}
  }, []);

  useEffect(() => { loadScans(); loadSchedules(); const iv = setInterval(loadScans, 5000); return () => clearInterval(iv); }, [loadScans, loadSchedules]);

  // SSE connections
  useEffect(() => {
    scans.forEach(sc => {
      const isActive = sc.status === "scanning" || sc.status === "authenticating";
      if (isActive && !sseConnections.current[sc.scan_id]) {
        const es = new EventSource(`/api/scans/${sc.scan_id}/progress/stream`);
        sseConnections.current[sc.scan_id] = es;
        es.onmessage = (evt) => {
          try {
            const data = JSON.parse(evt.data);
            if (data.error) return;
            setScanProgress(prev => ({ ...prev, [data.scan_id]: data }));
            setScanLog(prev => {
              const log = prev[data.scan_id] || [];
              const last = log[log.length - 1];
              if (!last || last.phase !== data.phase) return { ...prev, [data.scan_id]: [...log, { phase: data.phase, ts: Date.now() }] };
              return prev;
            });
            if (data.status === "completed" || data.status === "failed") { es.close(); delete sseConnections.current[data.scan_id]; loadScans(); }
          } catch (_) {}
        };
        es.onerror = () => { es.close(); delete sseConnections.current[sc.scan_id]; };
      }
      if (!isActive && sseConnections.current[sc.scan_id]) { sseConnections.current[sc.scan_id].close(); delete sseConnections.current[sc.scan_id]; }
    });
    return () => { Object.values(sseConnections.current).forEach(es => es.close()); sseConnections.current = {}; };
  }, [scans, loadScans]);

  const submitScan = async () => {
    if (!target.trim()) return;
    try {
      setSubmitting(true); setError(null);
      const body = { target: target.trim(), scan_type: scanType, scanner_engine: engine, severity_filter: ["critical", "high", "medium", "low", "info"], ai_analysis: doAI, generate_poc: doPoC };
      if ((engine === "zap" || engine === "both") && auth.auth_type !== "none") body.auth_config = auth;
      await apiPost("/scans", body);
      setTarget(""); setShowForm(false); setAuth({ ...DEFAULT_AUTH }); await loadScans();
    } catch (e) { setError(e.message); } finally { setSubmitting(false); }
  };

  const submitSchedule = async () => {
    if (!schedTarget.trim()) return;
    try {
      setSchedSubmitting(true);
      const body = { target: schedTarget.trim(), scan_type: schedType, scanner_engine: schedEngine, interval: schedInterval };
      if ((schedEngine === "zap" || schedEngine === "both") && schedAuth.auth_type !== "none") {
        body.auth_config = schedAuth;
      }
      await apiPost("/schedules", body);
      setSchedTarget(""); setShowSchedForm(false); setSchedAuth({ ...DEFAULT_AUTH }); await loadSchedules();
      toast.success(`Scheduled ${schedInterval} scan for ${schedTarget.trim()}`);
    } catch (e) { toast.error(e.message); } finally { setSchedSubmitting(false); }
  };

  const handleToggleHistory = async (sc) => {
    const key = sc.scan_id;
    if (expandedHistory[key]) { setExpandedHistory(p => ({ ...p, [key]: false })); return; }
    try {
      const data = await apiGet(`/scans?target=${encodeURIComponent(sc.target)}`);
      setHistoryData(p => ({ ...p, [key]: data }));
      setExpandedHistory(p => ({ ...p, [key]: true }));
    } catch (_) {}
  };

  const handleRescan = async (sc) => {
    try {
      await apiPost(`/scans/${sc.scan_id}/rescan`, {});
      toast.success(`Rescan queued for ${sc.target.slice(0, 40)}`);
      await loadScans();
    } catch (e) { toast.error(e.message); }
  };

  const handleDelete = async (scan_id) => {
    await apiDelete(`/scans/${scan_id}`);
    loadScans();
  };

  // Filter scans
  const filteredScans = scans.filter(sc => {
    if (engineFilter === "all") return true;
    if (engineFilter === "auth") {
      try { const cfg = JSON.parse(sc.auth_config || "{}"); return cfg.auth_type && cfg.auth_type !== "none"; } catch { return false; }
    }
    return sc.scanner_engine === engineFilter;
  });

  const activeCnt = scans.filter(s => s.status === "scanning" || s.status === "queued").length;
  const INTERVAL_COLORS = { daily: "#3b82f6", weekly: "#10b981", monthly: "#a855f7" };

  if (loading) return <Spinner />;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {error && <ErrorBox error={error} />}

      {/* ── Tab bar ── */}
      <div style={{ display: "flex", gap: 0, borderBottom: "1px solid #1e2028" }}>
        {[
          { id: "scans", label: `Scans${activeCnt ? ` (${activeCnt} active)` : ` (${scans.length})`}` },
          { id: "schedules", label: `Schedules (${schedules.length})` },
        ].map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)} style={{ padding: "8px 18px", border: "none", borderBottom: activeTab === t.id ? "2px solid #10b981" : "2px solid transparent", background: "transparent", color: activeTab === t.id ? "#10b981" : "#6b7280", fontSize: 13, fontWeight: activeTab === t.id ? 700 : 500, cursor: "pointer", fontFamily: "inherit", marginBottom: -1 }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ══════════════ SCANS TAB ══════════════ */}
      {activeTab === "scans" && (
        <>
          {/* Top bar: filters + new scan button */}
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {[["all", "All"], ["nuclei", "Nuclei"], ["zap", "ZAP"], ["both", "Nuclei+ZAP"], ["auth", "Auth"]].map(([val, label]) => (
                <button key={val} onClick={() => setEngineFilter(val)}
                  style={{ padding: "4px 10px", borderRadius: 6, border: engineFilter === val ? "1px solid #10b98160" : "1px solid #1e2028", background: engineFilter === val ? "#10b98115" : "transparent", color: engineFilter === val ? "#10b981" : "#6b7280", fontSize: 11, fontWeight: 600, cursor: "pointer" }}>
                  {label} {val === "all" ? "" : `(${val === "auth" ? scans.filter(s => { try { const c = JSON.parse(s.auth_config || "{}"); return c.auth_type && c.auth_type !== "none"; } catch { return false; } }).length : scans.filter(s => s.scanner_engine === val).length})`}
                </button>
              ))}
            </div>
            <button onClick={() => setShowForm(!showForm)} style={{ padding: "8px 18px", borderRadius: 8, border: "none", background: "linear-gradient(135deg, #10b981, #059669)", color: "#fff", fontSize: 13, fontWeight: 700, cursor: "pointer" }}>
              + New Scan
            </button>
          </div>

          {/* New scan form */}
          {showForm && (
            <Card style={{ border: "1px solid #10b98140" }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#e5e7eb", marginBottom: 14 }}>Launch New Scan</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
                <Input label="Target *" placeholder="https://example.com" value={target} onChange={e => setTarget(e.target.value)} onKeyDown={e => e.key === "Enter" && submitScan()} />
                <Select label="Scan Type" value={scanType} onChange={e => setScanType(e.target.value)}>
                  <option value="quick">Quick — fast, all templates</option>
                  <option value="full">Full — standard depth</option>
                  <option value="deep">Deep — max depth (slow)</option>
                </Select>
                <Select label="Scanner Engine" value={engine} onChange={e => { setEngine(e.target.value); setAuthPanelMode("manual"); }}>
                  <option value="nuclei">Nuclei — fast vuln detection</option>
                  <option value="zap">ZAP — deep DAST + auth</option>
                  <option value="both">Both — Nuclei + ZAP</option>
                </Select>
              </div>
              <div style={{ display: "flex", gap: 16, marginTop: 12, flexWrap: "wrap" }}>
                <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "#9ca3af", cursor: "pointer" }}><input type="checkbox" checked={doAI} onChange={e => setDoAI(e.target.checked)} style={{ accentColor: "#10b981" }} /> GPT-4o Analysis</label>
                <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "#9ca3af", cursor: "pointer" }}><input type="checkbox" checked={doPoC} onChange={e => setDoPoC(e.target.checked)} style={{ accentColor: "#10b981" }} /> Generate PoC</label>
              </div>
              {(engine === "zap" || engine === "both") && <AuthPanel auth={auth} setAuth={setAuth} onModeChange={setAuthPanelMode} />}
              {authPanelMode !== "side-file" && (
                <button onClick={submitScan} disabled={submitting || !target.trim()} style={{ marginTop: 14, padding: "10px 24px", borderRadius: 8, border: "none", background: submitting ? "#4b5563" : "#10b981", color: "#fff", fontSize: 13, fontWeight: 700, cursor: submitting ? "wait" : "pointer", opacity: !target.trim() ? .5 : 1 }}>
                  {submitting ? "Launching..." : `Launch ${engine === "both" ? "Nuclei + ZAP" : engine === "zap" ? "ZAP" : "Nuclei"} Scan`}
                </button>
              )}
            </Card>
          )}

          {filteredScans.length === 0 && <Empty msg={engineFilter === "all" ? "No scans yet. Click '+ New Scan' to start." : `No ${engineFilter} scans found.`} />}

          {filteredScans.map(sc => (
            <ScanCard key={sc.scan_id} sc={sc} scanProgress={scanProgress} scanLog={scanLog}
              onViewFindings={onViewFindings} onViewDeps={onViewDeps} onRescan={handleRescan} onDelete={handleDelete}
              onToggleHistory={handleToggleHistory} historyData={historyData} expandedHistory={expandedHistory} />
          ))}
        </>
      )}

      {/* ══════════════ SCHEDULES TAB ══════════════ */}
      {activeTab === "schedules" && (
        <>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 12, color: "#6b7280" }}>Scans run automatically on schedule. Each run is incremental — only new/changed URLs are rescanned.</span>
            <button onClick={() => setShowSchedForm(!showSchedForm)} style={{ padding: "8px 18px", borderRadius: 8, border: "none", background: "linear-gradient(135deg, #8b5cf6, #6d28d9)", color: "#fff", fontSize: 13, fontWeight: 700, cursor: "pointer", flexShrink: 0 }}>
              + New Schedule
            </button>
          </div>

          {showSchedForm && (
            <Card style={{ border: "1px solid #8b5cf640" }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#e5e7eb", marginBottom: 14 }}>Schedule Recurring Scan</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 12 }}>
                <Input label="Target *" placeholder="https://example.com" value={schedTarget} onChange={e => setSchedTarget(e.target.value)} />
                <Select label="Scan Type" value={schedType} onChange={e => setSchedType(e.target.value)}>
                  <option value="quick">Quick</option>
                  <option value="full">Full</option>
                </Select>
                <Select label="Scanner Engine" value={schedEngine} onChange={e => { setSchedEngine(e.target.value); setSchedAuthMode("manual"); }}>
                  <option value="nuclei">Nuclei</option>
                  <option value="zap">ZAP</option>
                  <option value="both">Both</option>
                </Select>
                <Select label="Interval" value={schedInterval} onChange={e => setSchedInterval(e.target.value)}>
                  <option value="daily">Daily (every 24h)</option>
                  <option value="weekly">Weekly (every 7d)</option>
                  <option value="monthly">Monthly (every 30d)</option>
                </Select>
              </div>
              {(schedEngine === "zap" || schedEngine === "both") && (
                <AuthPanel auth={schedAuth} setAuth={setSchedAuth} onModeChange={setSchedAuthMode} />
              )}
              {schedAuthMode !== "side-file" && (
                <button onClick={submitSchedule} disabled={schedSubmitting || !schedTarget.trim()} style={{ marginTop: 14, padding: "10px 24px", borderRadius: 8, border: "none", background: schedSubmitting ? "#4b5563" : "#8b5cf6", color: "#fff", fontSize: 13, fontWeight: 700, cursor: schedSubmitting ? "wait" : "pointer", opacity: !schedTarget.trim() ? .5 : 1 }}>
                  {schedSubmitting ? "Saving..." : "Create Schedule"}
                </button>
              )}
            </Card>
          )}

          {schedules.length === 0 && !showSchedForm && <Empty msg="No schedules yet. Schedules automatically run scans at the configured interval." />}

          {schedules.map(s => {
            let sCfg = null; try { sCfg = JSON.parse(s.config); } catch {}
            const eng = sCfg?.scanner_engine || "nuclei";
            const sAuth = sCfg?.auth_config;
            const hasSchedAuth = sAuth && sAuth.auth_type && sAuth.auth_type !== "none";
            return (
              <Card key={s.id}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb", fontFamily: "'JetBrains Mono', monospace" }}>{s.target}</span>
                      <EngineBadge e={eng} />
                      <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: `${INTERVAL_COLORS[s.interval] || "#6b7280"}18`, color: INTERVAL_COLORS[s.interval] || "#6b7280" }}>
                        {s.interval.toUpperCase()}
                      </span>
                      <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: s.enabled ? "#10b98118" : "#6b728018", color: s.enabled ? "#10b981" : "#6b7280" }}>
                        {s.enabled ? "ENABLED" : "PAUSED"}
                      </span>
                      <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, background: "#1e2028", color: "#9ca3af" }}>
                        {SCAN_TYPE_LABEL[sCfg?.scan_type] || sCfg?.scan_type || "full"}
                      </span>
                      {hasSchedAuth && (
                        <span style={{ padding: "2px 6px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: "#f9731618", color: "#f97316" }}>
                          {AUTH_TYPE_LABEL[sAuth.auth_type] || "AUTH"}
                        </span>
                      )}
                    </div>
                    <div style={{ display: "flex", gap: 16, fontSize: 11, color: "#4b5563" }}>
                      <span>Next: <span style={{ color: "#e5e7eb" }}>{new Date(s.next_run).toLocaleString()}</span></span>
                      {s.last_run && <span>Last: {new Date(s.last_run).toLocaleString()}</span>}
                      {s.last_scan_id && <span>Last scan: <span style={{ color: "#60a5fa", fontFamily: "'JetBrains Mono', monospace", cursor: "pointer" }} onClick={() => { setActiveTab("scans"); }}>{s.last_scan_id.slice(0, 8)}</span></span>}
                      {hasSchedAuth && sAuth.login_url && <span>Login: <span style={{ color: "#9ca3af", fontFamily: "'JetBrains Mono', monospace" }}>{sAuth.login_url.slice(0, 50)}</span></span>}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button onClick={async () => { await apiPatch(`/schedules/${s.id}?enabled=${!s.enabled}`); loadSchedules(); }}
                      style={{ padding: "4px 10px", borderRadius: 4, border: `1px solid ${s.enabled ? "#f9731640" : "#10b98140"}`, background: "transparent", color: s.enabled ? "#f97316" : "#10b981", fontSize: 11, cursor: "pointer" }}>
                      {s.enabled ? "Pause" : "Enable"}
                    </button>
                    <button onClick={async () => { if (confirm(`Delete schedule for ${s.target}?`)) { await apiDelete(`/schedules/${s.id}`); loadSchedules(); } }}
                      style={{ padding: "4px 8px", borderRadius: 4, border: "1px solid #2d3040", background: "transparent", color: "#6b7280", fontSize: 11, cursor: "pointer" }}>✕</button>
                  </div>
                </div>
              </Card>
            );
          })}
        </>
      )}
    </div>
  );
};

// ── Dependencies View ─────────────────────────────────────────────────────────
// Helper: parse extracted_results safely
const _parseEx = f => { try { return typeof f.extracted_results === "string" ? JSON.parse(f.extracted_results) : (f.extracted_results || {}); } catch { return {}; } };

// Tech-type icon map (library name → emoji icon)
const TECH_ICONS = {
  jquery: "⚡", react: "⚛", vue: "💚", angular: "🔴", "next.js": "▲", "nuxt.js": "💚",
  svelte: "🔥", bootstrap: "🅱", "tailwind css": "🌊", webpack: "📦", lodash: "🔧",
  "moment.js": "⏰", axios: "📡", wordpress: "🌐", drupal: "💧", joomla: "🔵",
  nginx: "🟩", apache: "🪶", php: "🐘", django: "🎸", flask: "🫙", fastapi: "⚡",
  "ruby on rails": "💎", laravel: "🔴", symfony: "🎼", spring: "🌿", express: "🚂",
  grafana: "📊", jenkins: "🤖", gitlab: "🦊", tomcat: "🐱", openssl: "🔐",
};
const _techIcon = name => TECH_ICONS[(name || "").toLowerCase()] || "📦";

const DependenciesView = ({ onViewFinding, scanFilter }) => {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sevFilter, setSevFilter] = useState("all");
  const [expanded, setExpanded] = useState({});

  const load = useCallback(async () => {
    try {
      setError(null);
      const url = scanFilter
        ? `/scans/${scanFilter}/findings?scanner_source=dep-scan&limit=500`
        : "/findings?scanner_source=dep-scan&limit=500";
      const data = await apiGet(url);
      setFindings(data);
    } catch (e) { setError(e.message); } finally { setLoading(false); }
  }, [scanFilter]);
  useEffect(() => { load(); }, [load]);

  if (loading) return <Spinner />;
  if (error) return <ErrorBox error={error} onRetry={load} />;

  // Split into vulnerable vs. clean tech-stack detections
  const vulnFindings = findings.filter(f => f.vuln_type !== "Technology Detected" || (f.severity !== "info" && f.cve_id));
  const cleanFindings = findings.filter(f => f.vuln_type === "Technology Detected" && !f.cve_id);

  // Group vulnerable findings by library name
  const grouped = {};
  for (const f of vulnFindings) {
    const ex = _parseEx(f);
    const lib = ex.library || f.name || "Unknown";
    if (!grouped[lib]) grouped[lib] = { lib, findings: [], ex };
    grouped[lib].findings.push(f);
  }
  const libs = Object.values(grouped).sort((a, b) => {
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const worstA = Math.min(...a.findings.map(f => sevOrder[f.severity] ?? 4));
    const worstB = Math.min(...b.findings.map(f => sevOrder[f.severity] ?? 4));
    return worstA - worstB;
  });

  const filteredLibs = sevFilter === "all" ? libs : libs.filter(g => g.findings.some(f => f.severity === sevFilter));

  if (!findings.length) return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <Card style={{ textAlign: "center", padding: 48, color: "#4b5563" }}>
        <div style={{ fontSize: 36, marginBottom: 12, opacity: 0.3 }}>📦</div>
        <div style={{ fontSize: 15, fontWeight: 600, color: "#6b7280", marginBottom: 8 }}>No dependency data yet</div>
        <div style={{ fontSize: 13, color: "#4b5563" }}>Run a scan — Retire.js + Wappalyzer will detect all libraries, frameworks, and servers (vulnerable and clean).</div>
      </Card>
    </div>
  );

  const critHigh = vulnFindings.filter(f => f.severity === "critical" || f.severity === "high").length;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Summary strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
        {[
          ["Vulnerable Libraries", libs.length, "#ef4444"],
          ["Total CVEs", vulnFindings.length, "#f97316"],
          ["Critical / High", critHigh, "#f97316"],
          ["Clean Detections", cleanFindings.length, "#10b981"],
        ].map(([label, val, color]) => (
          <Card key={label} style={{ padding: "14px 16px" }}>
            <div style={{ fontSize: 11, color: "#6b7280", fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5 }}>{label}</div>
            <div style={{ fontSize: 28, fontWeight: 800, color, fontFamily: "'JetBrains Mono', monospace", marginTop: 4 }}>{val}</div>
          </Card>
        ))}
      </div>

      {/* ── Vulnerable section ─────────────────────────────────────────────── */}
      {libs.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: "#ef4444" }}>⚠ Vulnerable Libraries</span>
            <span style={{ fontSize: 11, color: "#6b7280" }}>{libs.length} with known CVEs</span>
            {/* Severity filter */}
            <div style={{ marginLeft: "auto", display: "flex", gap: 6, flexWrap: "wrap" }}>
              {["all", "critical", "high", "medium", "low"].map(s => (
                <button key={s} onClick={() => setSevFilter(s)} style={{ padding: "3px 8px", borderRadius: 5, border: sevFilter === s ? `1px solid ${SEV[s] || "#10b981"}` : "1px solid #1e2028", background: sevFilter === s ? `${SEV[s] || "#10b981"}15` : "transparent", color: sevFilter === s ? SEV[s] || "#10b981" : "#6b7280", fontSize: 10, fontWeight: 600, cursor: "pointer", textTransform: "uppercase" }}>
                  {s}
                </button>
              ))}
            </div>
          </div>

          {filteredLibs.map(({ lib, findings: fs, ex }) => {
            const isOpen = expanded[lib];
            const worst = fs.reduce((w, f) => { const o = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }; return (o[f.severity] ?? 4) < (o[w] ?? 4) ? f.severity : w; }, "info");
            const fixVer = (() => { for (const f of fs) { const e = _parseEx(f); if (e && e.fixed_version) return e.fixed_version; } return null; })();
            const detVer = ex.detected_version || null;
            const method = ex.detection_method || null;
            return (
              <Card key={lib} style={{ padding: 0, overflow: "hidden" }}>
                <div onClick={() => setExpanded(p => ({ ...p, [lib]: !p[lib] }))}
                  style={{ padding: "14px 16px", cursor: "pointer", display: "flex", alignItems: "center", gap: 12, borderBottom: isOpen ? "1px solid #1e2028" : "none" }}>
                  <span style={{ fontSize: 22 }}>{_techIcon(lib)}</span>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5, flexWrap: "wrap" }}>
                      <span style={{ fontSize: 14, fontWeight: 700, color: "#e5e7eb" }}>{lib}</span>
                      {detVer && <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#ef4444", background: "#ef444415", padding: "1px 6px", borderRadius: 4 }}>v{detVer}</span>}
                      {fixVer && <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#10b981", background: "#10b98115", padding: "1px 6px", borderRadius: 4 }}>→ fix: v{fixVer}</span>}
                      {method && <span style={{ fontSize: 10, color: "#6b7280", background: "#1e2028", padding: "1px 6px", borderRadius: 4 }}>{method}</span>}
                    </div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      <SevBadge s={worst} />
                      {["critical","high","medium","low"].map(s => {
                        const cnt = fs.filter(f => f.severity === s).length;
                        return cnt > 0 ? <span key={s} style={{ fontSize: 10, color: SEV[s], background: `${SEV[s]}12`, padding: "1px 6px", borderRadius: 4, fontWeight: 600 }}>{cnt} {s}</span> : null;
                      })}
                      <span style={{ fontSize: 10, color: "#6b7280" }}>{fs.length} CVE{fs.length !== 1 ? "s" : ""}</span>
                    </div>
                  </div>
                  <span style={{ color: "#4b5563", fontSize: 14 }}>{isOpen ? "▲" : "▼"}</span>
                </div>
                {isOpen && (
                  <div style={{ display: "flex", flexDirection: "column" }}>
                    {fs.map((f, i) => (
                      <div key={f.id} onClick={() => onViewFinding(f)}
                        style={{ padding: "10px 16px", cursor: "pointer", borderBottom: i < fs.length - 1 ? "1px solid #13151a" : "none", display: "flex", alignItems: "center", gap: 10, background: "#0d0f1380" }}
                        onMouseEnter={e => e.currentTarget.style.background = "#1a1d2480"}
                        onMouseLeave={e => e.currentTarget.style.background = "#0d0f1380"}>
                        <SevBadge s={f.severity} />
                        <div style={{ flex: 1 }}>
                          <div style={{ fontSize: 13, fontWeight: 600, color: "#d1d5db" }}>{f.name}</div>
                          <div style={{ fontSize: 11, color: "#6b7280", marginTop: 2 }}>{(f.description || "").slice(0, 120)}{(f.description || "").length > 120 ? "…" : ""}</div>
                        </div>
                        {f.cve_id && <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "#34d399", background: "#10b98115", padding: "2px 6px", borderRadius: 4, whiteSpace: "nowrap" }}>{f.cve_id}</span>}
                        {f.cvss_score > 0 && <span style={{ fontSize: 10, fontWeight: 700, color: f.cvss_score >= 9 ? "#ef4444" : f.cvss_score >= 7 ? "#f97316" : "#eab308" }}>CVSS {f.cvss_score}</span>}
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      )}

      {/* ── Tech Stack section (clean detections) ─────────────────────────── */}
      {cleanFindings.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: "#10b981" }}>✓ Tech Stack Detected</span>
            <span style={{ fontSize: 11, color: "#6b7280" }}>{cleanFindings.length} technologies, no known CVEs</span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 10 }}>
            {cleanFindings.map(f => {
              const ex = _parseEx(f);
              const lib = ex.library || f.name || "Unknown";
              const ver = ex.detected_version;
              const method = ex.detection_method;
              return (
                <div key={f.id} onClick={() => onViewFinding(f)}
                  style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", borderRadius: 10, background: "#111318", border: "1px solid #1e2028", cursor: "pointer", transition: "border-color .15s" }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = "#10b98140"}
                  onMouseLeave={e => e.currentTarget.style.borderColor = "#1e2028"}>
                  {/* Icon */}
                  <span style={{ fontSize: 20, flexShrink: 0 }}>{_techIcon(lib)}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{lib}</div>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 3, flexWrap: "wrap" }}>
                      {ver
                        ? <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: "#6b7280" }}>v{ver}</span>
                        : <span style={{ fontSize: 11, color: "#4b5563" }}>version unknown</span>}
                      {method && <span style={{ fontSize: 9, color: "#4b5563", background: "#1e2028", padding: "1px 5px", borderRadius: 3 }}>{method}</span>}
                    </div>
                  </div>
                  {/* Safe icon */}
                  <span title="No known CVEs" style={{ fontSize: 13, color: "#10b981", flexShrink: 0 }}>✓</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

// ── Findings View ────────────────────────────────────────────────────────────
const FindingsView = ({ scanFilter, onViewFinding }) => {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sevFilter, setSevFilter] = useState("all");
  const [srcFilter, setSrcFilter] = useState("all");
  const loadFindings = useCallback(async () => {
    try { setError(null); setFindings(await apiGet(scanFilter ? `/scans/${scanFilter}/findings?limit=500` : "/findings?limit=500")); } catch (e) { setError(e.message); } finally { setLoading(false); }
  }, [scanFilter]);
  useEffect(() => { loadFindings(); }, [loadFindings]);
  if (loading) return <Spinner />;
  if (error) return <ErrorBox error={error} onRetry={loadFindings} />;
  if (!findings.length) return <Empty msg={scanFilter ? "No findings for this scan." : "No findings yet."} />;
  const nonDepFindings = findings.filter(f => (f.scanner_source || "nuclei") !== "dep-scan");
  const srcFiltered = srcFilter === "all" ? nonDepFindings : nonDepFindings.filter(f => (f.scanner_source || "nuclei") === srcFilter);
  const filtered = sevFilter === "all" ? srcFiltered : srcFiltered.filter(f => f.severity === sevFilter);
  const SRC_OPTS = [
    ["all", "All", "#10b981"],
    ["nuclei", "Nuclei", SOURCE_COLOR.nuclei],
    ["zap", "ZAP", SOURCE_COLOR.zap],
    ["ssl-scan", "SSL", SOURCE_COLOR["ssl-scan"]],
  ];
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {/* Source filter */}
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        {SRC_OPTS.map(([val, label, color]) => {
          const cnt = val === "all" ? findings.length : findings.filter(f => (f.scanner_source || "nuclei") === val).length;
          if (val !== "all" && cnt === 0) return null;
          const active = srcFilter === val;
          return (
            <button key={val} onClick={() => setSrcFilter(val)} style={{ padding: "3px 10px", borderRadius: 6, border: active ? `1px solid ${color}` : "1px solid #1e2028", background: active ? `${color}18` : "transparent", color: active ? color : "#6b7280", fontSize: 11, fontWeight: 700, cursor: "pointer" }}>
              {label} {cnt}
            </button>
          );
        })}
      </div>
      {/* Severity filter */}
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        {["all", "critical", "high", "medium", "low", "info"].map(s => (
          <button key={s} onClick={() => setSevFilter(s)} style={{ padding: "4px 10px", borderRadius: 6, border: sevFilter === s ? `1px solid ${SEV[s] || "#10b981"}` : "1px solid #1e2028", background: sevFilter === s ? `${SEV[s] || "#10b981"}15` : "transparent", color: sevFilter === s ? SEV[s] || "#10b981" : "#6b7280", fontSize: 11, fontWeight: 600, cursor: "pointer", textTransform: "uppercase" }}>
            {s} ({s === "all" ? srcFiltered.length : srcFiltered.filter(f => f.severity === s).length})
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
              <div style={{ display: "flex", gap: 12, marginTop: 8, fontSize: 11, color: "#4b5563", flexWrap: "wrap" }}>
                <span style={{ fontFamily: "'JetBrains Mono', monospace" }}>{f.host}</span>
                {f.cvss_score > 0 && <span>CVSS: <span style={{ color: f.cvss_score >= 9 ? "#ef4444" : f.cvss_score >= 7 ? "#f97316" : "#eab308", fontWeight: 700 }}>{f.cvss_score}</span></span>}
                {f.scanner_source === "dep-scan" && (() => { try { const ex = typeof f.extracted_results === "string" ? JSON.parse(f.extracted_results) : f.extracted_results; if (ex && ex.detected_version) return <span style={{ color: "#a855f7", fontFamily: "'JetBrains Mono', monospace" }}>v{ex.detected_version}{ex.fixed_version ? ` → fix: v${ex.fixed_version}` : ""}</span>; } catch {} return null; })()}
                {(() => { try { const ex = typeof f.extracted_results === "string" ? JSON.parse(f.extracted_results) : f.extracted_results; if (ex && ex.is_consolidated_group) return <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: "#f9731618", color: "#f97316", letterSpacing: 0.5 }}>{ex.consolidated_from} INSTANCES</span>; } catch {} return null; })()}
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

      <div style={{ display: "flex", gap: 0, borderBottom: "1px solid #1e2028", flexWrap: "wrap" }}>
        <Tab active={tab === "overview"} onClick={() => setTab("overview")}>Overview</Tab>
        {f.scanner_source === "dep-scan" && <Tab active={tab === "dep"} onClick={() => setTab("dep")}>Dependency</Tab>}
        {f.scanner_source === "ssl-scan" && <Tab active={tab === "ssl"} onClick={() => setTab("ssl")}>SSL Details</Tab>}
        {extracted && extracted.is_consolidated_group && <Tab active={tab === "instances"} onClick={() => setTab("instances")}>Instances ({extracted.consolidated_from})</Tab>}
        {ai && <Tab active={tab === "ai"} onClick={() => setTab("ai")}>AI Analysis</Tab>}
        <Tab active={tab === "poc"} onClick={() => setTab("poc")}>PoC</Tab>
        {extracted && extracted.evidence && <Tab active={tab === "evidence"} onClick={() => setTab("evidence")}>ZAP Evidence</Tab>}
        {(f.http_request || f.http_response) && <Tab active={tab === "http"} onClick={() => setTab("http")}>HTTP</Tab>}
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

      {tab === "dep" && f.scanner_source === "dep-scan" && (() => {
        let ex = {}; try { ex = typeof f.extracted_results === "string" ? JSON.parse(f.extracted_results) : (f.extracted_results || {}); } catch {}
        const refs = ex.references || [];
        return (
          <Card>
            <div style={{ fontSize: 14, fontWeight: 700, color: "#e5e7eb", marginBottom: 16 }}>Dependency Details</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {[
                ["Library", ex.library],
                ["Detected Version", ex.detected_version ? `v${ex.detected_version}` : null],
                ["Fixed Version", ex.fixed_version ? `v${ex.fixed_version}` : "Not specified"],
                ["Detection Method", ex.detection_method],
                ["CVE Source", ex.vuln_source],
                ["Official Website", ex.website || null],
              ].filter(([, v]) => v).map(([k, v]) => (
                <div key={k}>
                  <div style={{ fontSize: 11, color: "#6b7280", fontWeight: 600, textTransform: "uppercase", marginBottom: 4 }}>{k}</div>
                  <div style={{ fontSize: 13, color: "#d1d5db", fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all" }}>{v}</div>
                </div>
              ))}
            </div>
            {ex.fixed_version && (
              <div style={{ marginTop: 16, padding: "10px 14px", borderRadius: 8, background: "#166534"+"18", border: "1px solid #166534"+"44" }}>
                <span style={{ fontSize: 12, color: "#4ade80", fontWeight: 600 }}>Remediation: </span>
                <span style={{ fontSize: 12, color: "#9ca3af" }}>Upgrade <strong style={{ color: "#d1d5db" }}>{ex.library}</strong> to version <strong style={{ color: "#4ade80" }}>{ex.fixed_version}</strong> or later.</span>
              </div>
            )}
            {refs.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 11, color: "#6b7280", fontWeight: 600, textTransform: "uppercase", marginBottom: 8 }}>References</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {refs.map((r, i) => <a key={i} href={r} target="_blank" rel="noreferrer" style={{ fontSize: 12, color: "#60a5fa", wordBreak: "break-all", textDecoration: "none" }}>{r}</a>)}
                </div>
              </div>
            )}
          </Card>
        );
      })()}

      {tab === "ssl" && f.scanner_source === "ssl-scan" && (() => {
        let ex = {}; try { ex = typeof f.extracted_results === "string" ? JSON.parse(f.extracted_results) : (f.extracted_results || {}); } catch {}
        const CHECK_INFO = {
          cert_expired:          { icon: "✕", label: "Certificate Expired",       color: "#ef4444" },
          cert_expiring:         { icon: "⚠", label: "Certificate Expiring Soon", color: "#eab308" },
          cert_untrusted:        { icon: "✕", label: "Untrusted Certificate",      color: "#ef4444" },
          cert_hostname_mismatch:{ icon: "✕", label: "Hostname Mismatch",          color: "#ef4444" },
          deprecated_protocol:   { icon: "✕", label: "Deprecated Protocol",        color: "#f97316" },
          weak_ciphers:          { icon: "⚠", label: "Weak Cipher Suites",         color: "#eab308" },
          heartbleed:            { icon: "✕", label: "Heartbleed",                 color: "#ef4444" },
          ccs_injection:         { icon: "✕", label: "CCS Injection",              color: "#ef4444" },
          robot:                 { icon: "✕", label: "ROBOT Attack",               color: "#ef4444" },
          renegotiation:         { icon: "⚠", label: "Insecure Renegotiation",     color: "#f97316" },
          hsts:                  { icon: "⚠", label: "Missing HSTS",               color: "#eab308" },
        };
        const info = CHECK_INFO[ex.check] || { icon: "ℹ", label: ex.check || "SSL Check", color: "#06b6d4" };
        return (
          <Card>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
              <span style={{ fontSize: 22, color: info.color }}>{info.icon}</span>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: info.color }}>{info.label}</div>
                <div style={{ fontSize: 12, color: "#6b7280", marginTop: 2 }}>{f.host}</div>
              </div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {[
                ["Check", ex.check],
                ["Protocol", ex.protocol || null],
                ["Days Remaining", ex.days_remaining != null ? `${ex.days_remaining} days` : null],
                ["Days Overdue", ex.days_overdue != null ? `${ex.days_overdue} days` : null],
                ["Expired At", ex.expired_at ? ex.expired_at.split("T")[0] : null],
                ["Expires At", ex.expires_at ? ex.expires_at.split("T")[0] : null],
                ["ROBOT Result", ex.robot_result || null],
              ].filter(([, v]) => v).map(([k, v]) => (
                <div key={k}>
                  <div style={{ fontSize: 11, color: "#6b7280", fontWeight: 600, textTransform: "uppercase", marginBottom: 4 }}>{k}</div>
                  <div style={{ fontSize: 13, color: "#d1d5db", fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all" }}>{v}</div>
                </div>
              ))}
            </div>
            {ex.weak_ciphers && ex.weak_ciphers.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 11, color: "#6b7280", fontWeight: 600, textTransform: "uppercase", marginBottom: 8 }}>Weak Cipher Suites</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {ex.weak_ciphers.map((c, i) => (
                    <div key={i} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#eab308", padding: "3px 8px", background: "#eab30810", borderRadius: 4, border: "1px solid #eab30830" }}>{c}</div>
                  ))}
                </div>
              </div>
            )}
            <div style={{ marginTop: 16, padding: "10px 14px", borderRadius: 8, background: "#06b6d410", border: "1px solid #06b6d430" }}>
              <span style={{ fontSize: 12, color: "#06b6d4", fontWeight: 600 }}>Remediation: </span>
              <span style={{ fontSize: 12, color: "#9ca3af" }}>{
                ex.check === "hsts" ? "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" :
                ex.check === "weak_ciphers" ? "Update your TLS configuration to disable RC4, DES, 3DES, EXPORT, NULL, and anonymous cipher suites." :
                ex.check === "deprecated_protocol" ? `Disable ${ex.protocol} in your web server / load balancer TLS configuration.` :
                ex.check === "heartbleed" ? "Upgrade OpenSSL to 1.0.1g or later and regenerate all private keys and certificates." :
                ex.check === "cert_expired" || ex.check === "cert_expiring" ? "Renew the certificate from your CA and deploy the new cert/key pair." :
                ex.check === "cert_untrusted" ? "Replace the self-signed certificate with one issued by a trusted CA (e.g. Let's Encrypt)." :
                ex.check === "cert_hostname_mismatch" ? "Ensure the certificate CN/SAN matches the hostname being served." :
                "Review your TLS/SSL configuration and apply security best practices."
              }</span>
            </div>
            {f.reference && (
              <div style={{ marginTop: 12 }}>
                <a href={f.reference} target="_blank" rel="noreferrer" style={{ fontSize: 12, color: "#60a5fa", textDecoration: "none" }}>{f.reference}</a>
              </div>
            )}
          </Card>
        );
      })()}

      {tab === "instances" && extracted && extracted.is_consolidated_group && (() => {
        const urls = extracted.vulnerable_urls || [];
        const params = extracted.instance_params || [];
        const attacks = extracted.instance_attacks || [];
        return (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <Card>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: "#e5e7eb" }}>Affected URLs</div>
                  <div style={{ fontSize: 11, color: "#6b7280", marginTop: 2 }}>{urls.length} confirmed vulnerable endpoint{urls.length !== 1 ? "s" : ""} — grouped key: <code style={{ color: "#9ca3af", fontSize: 10 }}>{extracted.group_key}</code></div>
                </div>
                <button onClick={() => navigator.clipboard?.writeText(urls.join("\n"))} style={{ padding: "4px 12px", borderRadius: 6, border: "1px solid #2d3040", background: "transparent", color: "#9ca3af", fontSize: 11, cursor: "pointer", fontFamily: "inherit" }}>Copy All</button>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {urls.map((url, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", borderRadius: 6, background: "#0a0c10", border: "1px solid #1e2028" }}>
                    <span style={{ fontSize: 10, fontWeight: 700, color: "#ef4444", background: "#ef444415", padding: "1px 6px", borderRadius: 3, minWidth: 28, textAlign: "center" }}>{i + 1}</span>
                    <a href={url} target="_blank" rel="noreferrer" style={{ fontSize: 12, color: "#60a5fa", fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all", textDecoration: "none", flex: 1 }}>{url}</a>
                    <button onClick={e => { e.stopPropagation(); navigator.clipboard?.writeText(url); }} style={{ padding: "2px 8px", borderRadius: 4, border: "1px solid #2d3040", background: "transparent", color: "#6b7280", fontSize: 10, cursor: "pointer", flexShrink: 0 }}>Copy</button>
                  </div>
                ))}
                {urls.length === 0 && <div style={{ fontSize: 12, color: "#4b5563", padding: 12 }}>No URLs recorded.</div>}
              </div>
            </Card>
            {params.length > 0 && (
              <Card>
                <div style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb", marginBottom: 12 }}>Vulnerable Parameters ({params.length})</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {params.map((p, i) => <span key={i} style={{ padding: "3px 10px", borderRadius: 4, fontSize: 11, fontFamily: "'JetBrains Mono', monospace", background: "#f97316" + "15", color: "#fdba74", border: "1px solid #f9731630" }}>{p}</span>)}
                </div>
              </Card>
            )}
            {attacks.length > 0 && (
              <Card>
                <div style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb", marginBottom: 12 }}>Attack Payloads ({attacks.length})</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {attacks.map((a, i) => <pre key={i} style={{ margin: 0, padding: "6px 10px", borderRadius: 6, background: "#0a0c10", border: "1px solid #1e2028", color: "#fca5a5", fontSize: 11, fontFamily: "'JetBrains Mono', monospace", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{a}</pre>)}
                </div>
              </Card>
            )}
          </div>
        );
      })()}

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

      {tab === "http" && (f.http_request || f.http_response) && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {f.http_request && (
            <Card>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: "#3b82f618", color: "#60a5fa", letterSpacing: 0.5 }}>REQUEST</span>
                  <span style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb" }}>HTTP Request</span>
                </div>
                <button onClick={() => navigator.clipboard?.writeText(f.http_request || "")} style={{ padding: "4px 12px", borderRadius: 6, border: "1px solid #2d3040", background: "transparent", color: "#9ca3af", fontSize: 11, cursor: "pointer", fontFamily: "inherit" }}>Copy</button>
              </div>
              <pre style={{ margin: 0, padding: 14, borderRadius: 8, background: "#0a0c10", border: "1px solid #1e2740", color: "#93c5fd", fontSize: 11, lineHeight: 1.6, fontFamily: "'JetBrains Mono', monospace", overflow: "auto", maxHeight: 400, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{f.http_request}</pre>
            </Card>
          )}
          {f.http_response && (
            <Card>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700, background: "#10b98118", color: "#34d399", letterSpacing: 0.5 }}>RESPONSE</span>
                  <span style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb" }}>HTTP Response</span>
                </div>
                <button onClick={() => navigator.clipboard?.writeText(f.http_response || "")} style={{ padding: "4px 12px", borderRadius: 6, border: "1px solid #2d3040", background: "transparent", color: "#9ca3af", fontSize: 11, cursor: "pointer", fontFamily: "inherit" }}>Copy</button>
              </div>
              <pre style={{ margin: 0, padding: 14, borderRadius: 8, background: "#0a0c10", border: "1px solid #1e2d1e", color: "#6ee7b7", fontSize: 11, lineHeight: 1.6, fontFamily: "'JetBrains Mono', monospace", overflow: "auto", maxHeight: 400, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{f.http_response}</pre>
            </Card>
          )}
        </div>
      )}

      {tab === "screenshot" && f.poc_screenshot && <Card><div style={{ fontSize: 13, fontWeight: 700, color: "#e5e7eb", marginBottom: 12 }}>Screenshot</div><img src={f.poc_screenshot} alt="Evidence" style={{ width: "100%", borderRadius: 8, border: "1px solid #1e2028" }} onError={e => { e.target.style.display = "none"; }} /></Card>}
    </div>
  );
};

// ── Main App ─────────────────────────────────────────────────────────────────
export default function VulnerabilityScannerApp() {
  const [view, setView] = useState("dashboard");
  const [scanFilter, setScanFilter] = useState(null);
  const [depScanFilter, setDepScanFilter] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [health, setHealth] = useState(null);
  useEffect(() => { apiGet("/health").then(setHealth).catch(() => {}); }, []);

  const nav = [{ id: "dashboard", label: "Dashboard", icon: "◈" }, { id: "scans", label: "Scans", icon: "⟐" }, { id: "findings", label: "Findings", icon: "⬡" }, { id: "dependencies", label: "Dependencies", icon: "📦" }];

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: "#0a0c10", color: "#e5e7eb", fontFamily: "'DM Sans', 'Segoe UI', system-ui, sans-serif" }}>
      <aside style={{ width: 220, background: "#0d0f13", borderRight: "1px solid #1e2028", padding: "20px 12px", display: "flex", flexDirection: "column", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 8px", marginBottom: 28 }}>
          <div style={{ width: 28, height: 28, borderRadius: 8, background: "linear-gradient(135deg, #10b981, #059669)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, fontWeight: 900, color: "#fff" }}>V</div>
          <span style={{ fontSize: 16, fontWeight: 800, letterSpacing: -.5 }}><span style={{ color: "#10b981" }}>Vulnerability</span><span style={{ color: "#e5e7eb" }}>Scanner</span></span>
        </div>
        <nav style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {nav.map(i => <button key={i.id} onClick={() => { setView(i.id); setSelectedFinding(null); setScanFilter(null); setDepScanFilter(null); }} style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", borderRadius: 8, border: "none", background: view === i.id ? "#10b98115" : "transparent", color: view === i.id ? "#34d399" : "#6b7280", fontSize: 13, fontWeight: view === i.id ? 700 : 500, cursor: "pointer", textAlign: "left", fontFamily: "inherit" }}><span style={{ fontSize: 16, opacity: .8 }}>{i.icon}</span>{i.label}</button>)}
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
            <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800, letterSpacing: -.5 }}>{selectedFinding ? "Finding Details" : view === "dashboard" ? "Security Dashboard" : view === "scans" ? "Scan Management" : view === "dependencies" ? "Dependency Findings" : "Vulnerability Findings"}</h1>
            <p style={{ margin: "4px 0 0", fontSize: 12, color: "#4b5563" }}>{selectedFinding ? selectedFinding.name : view === "dashboard" ? "Nuclei + ZAP + GPT-4o" : view === "scans" ? "Scans · History · Schedules · Rescan" : view === "dependencies" ? (depScanFilter ? `Scan ${depScanFilter.slice(0, 8)}... · Retire.js · Wappalyzer` : "Retire.js · Wappalyzer · OSV CVE lookup") : scanFilter ? `Scan ${scanFilter.slice(0, 8)}...` : "All findings"}</p>
          </div>
          {selectedFinding ? <FindingDetail finding={selectedFinding} onBack={() => setSelectedFinding(null)} /> : view === "dashboard" ? <DashboardView /> : view === "scans" ? <ScansView onViewFindings={id => { setScanFilter(id); setView("findings"); }} onViewDeps={id => { setDepScanFilter(id); setView("dependencies"); }} /> : view === "dependencies" ? <DependenciesView onViewFinding={setSelectedFinding} scanFilter={depScanFilter} /> : <FindingsView scanFilter={scanFilter} onViewFinding={setSelectedFinding} />}
        </div>
      </main>
    </div>
  );
}
