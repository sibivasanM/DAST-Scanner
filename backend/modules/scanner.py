"""
Nuclei Scanner — Async subprocess wrapper for the Nuclei v3 scanning engine.
Parses JSON-line output into structured findings.
"""

import asyncio
import json
import logging
import os
import shutil
import tempfile
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnforge.scanner")

SEVERITY_CVSS_MAP = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0,
}

SCAN_PROFILES = {
    "quick": {
        "rate_limit": 300, "bulk_size": 50, "concurrency": 30,
        "timeout": 10, "retries": 1,
        "extra_flags": [],  # all templates — no -as restriction
    },
    "full": {
        "rate_limit": 150, "bulk_size": 25, "concurrency": 25,
        "timeout": 15, "retries": 2, "extra_flags": [],
    },
    "custom": {
        "rate_limit": 100, "bulk_size": 15, "concurrency": 15,
        "timeout": 20, "retries": 3, "extra_flags": [],
    },
}


class NucleiScanner:
    """Wraps Nuclei CLI execution and output parsing."""

    def __init__(self, nuclei_path: Optional[str] = None):
        self.nuclei_path = nuclei_path or shutil.which("nuclei") or "nuclei"

    async def update_templates(self) -> bool:
        """
        Run `nuclei -update-templates` to pull the latest template set.
        Returns True on success, False if the update failed (scan can still proceed
        with the existing local templates).
        """
        logger.info("[SCAN] Updating Nuclei templates…")
        try:
            proc = await asyncio.create_subprocess_exec(
                self.nuclei_path, "-update-templates",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            out = ((stdout or b"") + (stderr or b"")).decode(errors="replace").strip()
            if out:
                logger.info(f"[SCAN] Template update output:\n{out[:2000]}")
            if proc.returncode == 0:
                logger.info("[SCAN] Nuclei templates updated successfully.")
                return True
            else:
                logger.warning(f"[SCAN] Template update exited with code {proc.returncode} — proceeding with existing templates.")
                return False
        except asyncio.TimeoutError:
            logger.warning("[SCAN] Template update timed out after 5 min — proceeding with existing templates.")
            return False
        except Exception as e:
            logger.warning(f"[SCAN] Template update failed: {e} — proceeding with existing templates.")
            return False

    async def check_health(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.nuclei_path, "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            version_info = (stdout or stderr or b"").decode(errors="replace")
            logger.info(f"Nuclei health check: rc={proc.returncode}, output={version_info.strip()}")
            return proc.returncode == 0
        except Exception as e:
            logger.error(f"Nuclei health check failed: {e}")
            return False

    async def execute(
        self,
        target: str,
        severity: list[str] = None,
        tags: list[str] = None,
        custom_templates: Optional[str] = None,
        scan_type: str = "full",
        exclude_urls_file: Optional[str] = None,
    ) -> list[dict]:
        """Run Nuclei against a target and return parsed findings."""
        profile = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["full"])

        # Use -je (JSON export) for reliable JSONL file output
        output_file = tempfile.mktemp(suffix=".jsonl")

        cmd = [
            self.nuclei_path,
            "-u", target,               # -u for single target (v3 preferred over -target)
            "-je", output_file,          # -je = JSON export to file (guaranteed JSONL)
            "-rl", str(profile["rate_limit"]),
            "-bs", str(profile["bulk_size"]),
            "-c", str(profile["concurrency"]),
            "-timeout", str(profile["timeout"]),
            "-retries", str(profile["retries"]),
            "-nc",                       # no color
            "-silent",
            "-stats",                    # show scan progress stats
        ]

        if severity:
            cmd.extend(["-s", ",".join(severity)])

        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        if custom_templates and os.path.exists(custom_templates):
            cmd.extend(["-t", custom_templates])

        if exclude_urls_file and os.path.exists(exclude_urls_file):
            cmd.extend(["-eu", exclude_urls_file])  # -eu = exclude URLs file (Nuclei v3)

        cmd.extend(profile.get("extra_flags", []))

        logger.info(f"[SCAN] Executing: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=3600
            )

            stdout_text = (stdout or b"").decode(errors="replace").strip()
            stderr_text = (stderr or b"").decode(errors="replace").strip()

            if stdout_text:
                logger.info(f"[SCAN] Nuclei stdout:\n{stdout_text[:3000]}")
            if stderr_text:
                logger.info(f"[SCAN] Nuclei stderr:\n{stderr_text[:3000]}")

            logger.info(f"[SCAN] Nuclei exit code: {proc.returncode}")

            findings = self._parse_output(output_file)
            logger.info(f"[SCAN] Parsed {len(findings)} findings from output")
            return findings

        except asyncio.TimeoutError:
            logger.error("[SCAN] Nuclei timed out after 1 hour")
            proc.kill()
            return self._parse_output(output_file)
        except FileNotFoundError:
            logger.error(f"[SCAN] Nuclei binary not found at {self.nuclei_path}")
            raise RuntimeError(
                f"Nuclei not installed at {self.nuclei_path}. "
                "Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            )
        finally:
            if os.path.exists(output_file):
                try:
                    with open(output_file) as f:
                        content = f.read()
                    logger.info(f"[SCAN] Raw output file ({len(content)} bytes): {content[:1000]}")
                except Exception:
                    pass
                os.unlink(output_file)

    def _parse_output(self, filepath: str) -> list[dict]:
        """Parse Nuclei JSONL output into normalized findings."""
        findings = []
        if not os.path.exists(filepath):
            logger.warning(f"[PARSE] Output file not found: {filepath}")
            return findings

        file_size = os.path.getsize(filepath)
        logger.info(f"[PARSE] Reading output file: {filepath} ({file_size} bytes)")

        with open(filepath, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    # Handle case where a line contains an array of findings
                    if isinstance(raw, list):
                        for item in raw:
                            finding = self._normalize_finding(item)
                            if finding:
                                findings.append(finding)
                    else:
                        finding = self._normalize_finding(raw)
                        if finding:
                            findings.append(finding)
                except json.JSONDecodeError as e:
                    logger.warning(f"[PARSE] Invalid JSON at line {line_num}: {e}")

        return findings

    def _normalize_finding(self, raw: dict) -> Optional[dict]:
        """Normalize a Nuclei JSON finding to our schema."""
        # Handle info which can be dict or list
        info = raw.get("info", {})
        if isinstance(info, list):
            info = info[0] if info else {}
        elif not isinstance(info, dict):
            info = {}
        
        severity = info.get("severity", "info").lower()

        # Handle classification which can be dict or list
        classification = info.get("classification", {})
        if isinstance(classification, list):
            classification = classification[0] if classification else {}
        elif not isinstance(classification, dict):
            classification = {}
        
        cve_id = None
        if classification.get("cve-id"):
            cve_ids = classification["cve-id"]
            cve_id = cve_ids[0] if isinstance(cve_ids, list) else cve_ids

        cvss = classification.get("cvss-score")
        if not cvss:
            cvss_metrics = classification.get("cvss-metrics", "")
            if cvss_metrics:
                try:
                    cvss = float(cvss_metrics.split("/")[-1]) if "/" in cvss_metrics else None
                except (ValueError, IndexError):
                    cvss = None
        if not cvss:
            cvss = SEVERITY_CVSS_MAP.get(severity, 0.0)

        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        refs = info.get("reference", [])
        if isinstance(refs, list):
            refs = "\n".join(str(r) for r in refs)

        return {
            "template_id": raw.get("template-id", raw.get("templateID", "")),
            "name": info.get("name", "Unknown Vulnerability"),
            "severity": severity,
            "description": info.get("description", ""),
            "host": raw.get("host", ""),
            "matched_at": raw.get("matched-at", raw.get("matched", "")),
            "url": raw.get("matched-at", raw.get("host", "")),
            "curl_command": raw.get("curl-command", ""),
            "extracted_results": json.dumps(raw.get("extracted-results", [])),
            "tags": json.dumps(tags),
            "reference": refs if isinstance(refs, str) else "",
            "matcher_name": raw.get("matcher-name", ""),
            "vuln_type": raw.get("type", info.get("type", "")),
            "cve_id": cve_id,
            "cvss_score": cvss,
        }
