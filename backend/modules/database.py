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
        """)
        # Migration: add columns if upgrading from older schema
        for col, default in [
            ("scanner_engine", "'nuclei'"),
            ("auth_config", "NULL"),
        ]:
            try:
                self.conn.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT DEFAULT {default}")
            except sqlite3.OperationalError:
                pass
        for col, default in [("scanner_source", "'nuclei'")]:
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
            if d.get("ai_analysis"):
                try:
                    d["ai_analysis"] = json.loads(d["ai_analysis"])
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
        return [dict(r) for r in self.conn.execute(q, params).fetchall()]

    def delete_scan(self, scan_id: str):
        self.conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        self.conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        self.conn.commit()

    # ── Findings ─────────────────────────────────────────────────────────────

    def insert_finding(self, finding: dict):
        cols = ", ".join(finding.keys())
        placeholders = ", ".join(["?"] * len(finding))
        self.conn.execute(
            f"INSERT OR IGNORE INTO findings ({cols}) VALUES ({placeholders})",
            list(finding.values()),
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

    def get_findings(self, scan_id=None, severity=None, status=None, limit=100, offset=0) -> list[dict]:
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

    def finding_hash_exists(self, dedup_hash: str) -> bool:
        row = self.conn.execute("SELECT 1 FROM findings WHERE dedup_hash = ? LIMIT 1", (dedup_hash,)).fetchone()
        return row is not None
