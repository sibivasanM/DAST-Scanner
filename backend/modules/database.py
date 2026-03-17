"""
Database layer — SQLite with WAL mode for the scan platform.
Supports Nuclei + ZAP scanner engines and auth configurations.
"""

import json
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional


class Database:
    def __init__(self, db_path: str = "vulnforge.db"):
        self.db_path = db_path
        self._local = threading.local()

    @property
    def conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def initialize(self):
        cur = self.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id             TEXT PRIMARY KEY,
                target              TEXT NOT NULL,
                scan_type           TEXT NOT NULL DEFAULT 'full',
                scanner_engine      TEXT NOT NULL DEFAULT 'nuclei',
                auth_config         TEXT,
                config              TEXT,
                status              TEXT NOT NULL DEFAULT 'queued',
                phase               TEXT DEFAULT 'initializing',
                raw_finding_count   INTEGER DEFAULT 0,
                unique_finding_count INTEGER DEFAULT 0,
                ai_analysis         TEXT,
                error               TEXT,
                created_at          TEXT NOT NULL,
                completed_at        TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id              TEXT PRIMARY KEY,
                scan_id         TEXT NOT NULL,
                template_id     TEXT,
                name            TEXT NOT NULL,
                severity        TEXT NOT NULL,
                description     TEXT,
                host            TEXT,
                matched_at      TEXT,
                url             TEXT,
                curl_command    TEXT,
                extracted_results TEXT,
                tags            TEXT,
                reference       TEXT,
                matcher_name    TEXT,
                vuln_type       TEXT,
                cve_id          TEXT,
                cvss_score      REAL,
                status          TEXT DEFAULT 'open',
                notes           TEXT,
                assigned_to     TEXT,
                ai_analysis     TEXT,
                poc_script      TEXT,
                poc_screenshot  TEXT,
                poc_evidence    TEXT,
                dedup_hash      TEXT,
                scanner_source  TEXT DEFAULT 'nuclei',
                http_request    TEXT,
                http_response   TEXT,
                replay_verified TEXT,
                replay_result   TEXT,
                ai_fp_reason    TEXT,
                created_at      TEXT NOT NULL,

                FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_findings_scan   ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_sev    ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
            CREATE INDEX IF NOT EXISTS idx_findings_dedup  ON findings(dedup_hash);
            CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(scanner_source);
            CREATE INDEX IF NOT EXISTS idx_scans_status    ON scans(status);
            CREATE INDEX IF NOT EXISTS idx_scans_engine    ON scans(scanner_engine);
            CREATE INDEX IF NOT EXISTS idx_scans_target    ON scans(target);

            CREATE TABLE IF NOT EXISTS scan_schedules (
                id           TEXT PRIMARY KEY,
                target       TEXT NOT NULL,
                config       TEXT NOT NULL,
                interval     TEXT NOT NULL DEFAULT 'weekly',
                next_run     TEXT NOT NULL,
                last_run     TEXT,
                last_scan_id TEXT,
                enabled      INTEGER DEFAULT 1,
                created_at   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_schedules_target   ON scan_schedules(target);
            CREATE INDEX IF NOT EXISTS idx_schedules_next_run ON scan_schedules(next_run);
        """)
        # Migration: add columns if upgrading from older schema
        for col, default in [
            ("scanner_engine",  "'nuclei'"),
            ("auth_config",     "NULL"),
            ("auth_status",     "NULL"),   # JSON: {verified, status_code, message, …}
            ("crawled_urls",    "NULL"),   # JSON list of URLs discovered during spider/nuclei phase
            ("parent_scan_id",  "NULL"),   # scan_id this was rescanned from
            ("is_incremental",  "0"),      # 1 if incremental mode was used
        ]:
            try:
                self.conn.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT DEFAULT {default}")
            except sqlite3.OperationalError:
                pass
        for col, default in [
            ("scanner_source",  "'nuclei'"),
            ("http_request",    "NULL"),
            ("http_response",   "NULL"),
            ("replay_verified", "NULL"),   # True/False/None from HTTP replay verifier
            ("replay_result",   "NULL"),   # JSON: {status_code, reason, …}
            ("ai_fp_reason",    "NULL"),   # reason string when AI scorer flags as FP
        ]:
            try:
                self.conn.execute(f"ALTER TABLE findings ADD COLUMN {col} TEXT DEFAULT {default}")
            except sqlite3.OperationalError:
                pass
        self.conn.commit()

    # ── Scans ────────────────────────────────────────────────────────────────

    def create_scan(self, scan_id: str, target: str, scan_type: str, config: str,
                    scanner_engine: str = "nuclei", auth_config: str = None):
        self.conn.execute(
            "INSERT INTO scans (scan_id, target, scan_type, scanner_engine, auth_config, config, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'queued', ?)",
            (scan_id, target, scan_type, scanner_engine, auth_config, config,
             datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()

    def update_scan(self, scan_id: str, **kwargs):
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        vals = list(kwargs.values()) + [scan_id]
        self.conn.execute(f"UPDATE scans SET {sets} WHERE scan_id = ?", vals)
        self.conn.commit()

    def get_scan(self, scan_id: str) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if row:
            d = dict(row)
            for field in ("ai_analysis", "auth_status"):
                if d.get(field):
                    try:
                        d[field] = json.loads(d[field])
                    except (json.JSONDecodeError, TypeError):
                        pass
            return d
        return None

    def get_scans(self, limit=50, offset=0, status=None) -> list[dict]:
        q = "SELECT * FROM scans"
        params = []
        if status:
            q += " WHERE status = ?"
            params.append(status)
        q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = []
        for r in self.conn.execute(q, params).fetchall():
            d = dict(r)
            for field in ("ai_analysis", "auth_status"):
                if d.get(field):
                    try:
                        d[field] = json.loads(d[field])
                    except (json.JSONDecodeError, TypeError):
                        pass
            rows.append(d)
        return rows

    def delete_scan(self, scan_id: str):
        self.conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        self.conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        self.conn.commit()

    # ── Findings ─────────────────────────────────────────────────────────────

    # Known findings table columns — any extra keys on the dict are silently dropped
    _FINDING_COLUMNS = frozenset({
        "id", "scan_id", "template_id", "name", "severity", "description",
        "host", "matched_at", "url", "curl_command", "extracted_results",
        "tags", "reference", "matcher_name", "vuln_type", "cve_id", "cvss_score",
        "status", "notes", "assigned_to", "ai_analysis", "poc_script",
        "poc_screenshot", "poc_evidence", "dedup_hash", "scanner_source",
        "http_request", "http_response", "replay_verified", "replay_result",
        "ai_fp_reason", "created_at",
    })

    def insert_finding(self, finding: dict):
        # Strip keys that don't exist as columns (e.g. fp_reason, replay_result dicts)
        clean = {k: (v if not isinstance(v, (dict, list)) else __import__("json").dumps(v))
                 for k, v in finding.items() if k in self._FINDING_COLUMNS}
        cols = ", ".join(clean.keys())
        placeholders = ", ".join(["?"] * len(clean))
        self.conn.execute(
            f"INSERT OR IGNORE INTO findings ({cols}) VALUES ({placeholders})",
            list(clean.values()),
        )
        self.conn.commit()

    def update_finding(self, finding_id: str, **kwargs):
        kwargs = {k: v for k, v in kwargs.items() if v is not None}
        if not kwargs:
            return
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        vals = list(kwargs.values()) + [finding_id]
        self.conn.execute(f"UPDATE findings SET {sets} WHERE id = ?", vals)
        self.conn.commit()

    def get_finding(self, finding_id: str) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if row:
            d = dict(row)
            for field in ("ai_analysis", "poc_evidence", "extracted_results"):
                if d.get(field):
                    try:
                        d[field] = json.loads(d[field])
                    except (json.JSONDecodeError, TypeError):
                        pass
            return d
        return None

    def get_findings(self, scan_id=None, severity=None, status=None, scanner_source=None, limit=100, offset=0) -> list[dict]:
        q = "SELECT * FROM findings WHERE 1=1"
        params = []
        if scan_id:
            q += " AND scan_id = ?"
            params.append(scan_id)
        if severity:
            q += " AND severity = ?"
            params.append(severity)
        if status:
            q += " AND status = ?"
            params.append(status)
        if scanner_source:
            q += " AND scanner_source = ?"
            params.append(scanner_source)
        q += (" ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
              "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created_at DESC "
              "LIMIT ? OFFSET ?")
        params.extend([limit, offset])
        return [dict(r) for r in self.conn.execute(q, params).fetchall()]

    # ── Dashboard ────────────────────────────────────────────────────────────

    def get_dashboard_stats(self) -> dict:
        c = self.conn
        total_scans = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        active_scans = c.execute("SELECT COUNT(*) FROM scans WHERE status IN ('queued','scanning')").fetchone()[0]
        total_findings = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        open_findings = c.execute("SELECT COUNT(*) FROM findings WHERE status = 'open'").fetchone()[0]
        severity_dist = {}
        for row in c.execute("SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity").fetchall():
            severity_dist[row["severity"]] = row["cnt"]
        recent_critical = c.execute(
            "SELECT COUNT(*) FROM findings WHERE severity = 'critical' AND created_at >= ?",
            ((datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),),
        ).fetchone()[0]
        targets_scanned = c.execute("SELECT COUNT(DISTINCT target) FROM scans").fetchone()[0]
        # Scanner breakdown
        engine_dist = {}
        for row in c.execute("SELECT scanner_source, COUNT(*) as cnt FROM findings GROUP BY scanner_source").fetchall():
            engine_dist[row["scanner_source"] or "nuclei"] = row["cnt"]
        return {
            "total_scans": total_scans, "active_scans": active_scans,
            "total_findings": total_findings, "open_findings": open_findings,
            "severity_distribution": severity_dist, "critical_last_7d": recent_critical,
            "targets_scanned": targets_scanned, "engine_distribution": engine_dist,
        }

    def get_severity_trend(self, days=30) -> list[dict]:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        rows = self.conn.execute(
            "SELECT DATE(created_at) as day, severity, COUNT(*) as count "
            "FROM findings WHERE created_at >= ? GROUP BY day, severity ORDER BY day",
            (since,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_top_vulnerabilities(self, limit=10) -> list[dict]:
        rows = self.conn.execute(
            "SELECT name, template_id, severity, COUNT(*) as occurrences, "
            "GROUP_CONCAT(DISTINCT host) as affected_hosts "
            "FROM findings GROUP BY template_id ORDER BY occurrences DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_attack_surface(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT host, severity, COUNT(*) as count FROM findings GROUP BY host, severity ORDER BY count DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_previous_crawled_urls(self, target: str) -> set:
        """Return the crawled URL set from the most recent completed scan of the same target."""
        row = self.conn.execute(
            "SELECT crawled_urls FROM scans "
            "WHERE target = ? AND status = 'completed' AND crawled_urls IS NOT NULL "
            "ORDER BY completed_at DESC LIMIT 1",
            (target,),
        ).fetchone()
        if row and row["crawled_urls"]:
            try:
                return set(json.loads(row["crawled_urls"]))
            except (json.JSONDecodeError, TypeError):
                return set()
        return set()

    def finding_hash_exists(self, dedup_hash: str) -> bool:
        row = self.conn.execute("SELECT 1 FROM findings WHERE dedup_hash = ? LIMIT 1", (dedup_hash,)).fetchone()
        return row is not None

    def get_scans_by_target(self, target: str, limit: int = 20) -> list[dict]:
        """Return all scans for a target ordered newest first."""
        rows = self.conn.execute(
            "SELECT scan_id, target, scan_type, scanner_engine, status, phase, "
            "raw_finding_count, unique_finding_count, created_at, completed_at, error, "
            "parent_scan_id, is_incremental "
            "FROM scans WHERE target = ? ORDER BY created_at DESC LIMIT ?",
            (target, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_distinct_targets(self) -> list[dict]:
        """Return each unique target with its scan count and latest scan metadata."""
        rows = self.conn.execute(
            "SELECT target, COUNT(*) as scan_count, MAX(created_at) as last_scan_at, "
            "SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_count "
            "FROM scans GROUP BY target ORDER BY last_scan_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Schedules ─────────────────────────────────────────────────────────────

    def create_schedule(self, schedule_id: str, target: str, config: str,
                        interval: str, next_run: str) -> None:
        self.conn.execute(
            "INSERT INTO scan_schedules (id, target, config, interval, next_run, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (schedule_id, target, config, interval, next_run,
             datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()

    def get_schedules(self, enabled_only: bool = False) -> list[dict]:
        q = "SELECT * FROM scan_schedules"
        if enabled_only:
            q += " WHERE enabled = 1"
        q += " ORDER BY next_run ASC"
        return [dict(r) for r in self.conn.execute(q).fetchall()]

    def get_schedule(self, schedule_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM scan_schedules WHERE id = ?", (schedule_id,)
        ).fetchone()
        return dict(row) if row else None

    def update_schedule(self, schedule_id: str, **kwargs) -> None:
        if not kwargs:
            return
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        vals = list(kwargs.values()) + [schedule_id]
        self.conn.execute(f"UPDATE scan_schedules SET {sets} WHERE id = ?", vals)
        self.conn.commit()

    def delete_schedule(self, schedule_id: str) -> None:
        self.conn.execute("DELETE FROM scan_schedules WHERE id = ?", (schedule_id,))
        self.conn.commit()

    def get_due_schedules(self) -> list[dict]:
        """Return enabled schedules whose next_run is at or before now."""
        now = datetime.now(timezone.utc).isoformat()
        rows = self.conn.execute(
            "SELECT * FROM scan_schedules WHERE enabled = 1 AND next_run <= ?", (now,)
        ).fetchall()
        return [dict(r) for r in rows]
