"""
SSL/TLS Scanner — Uses sslyze to probe certificate health, protocol
versions, cipher strength, and known TLS vulnerabilities.
Produces normalized findings compatible with the existing findings schema.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("vulnforge.ssl_scanner")

SEVERITY_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}

# Cipher name fragments considered weak
_WEAK_PATTERNS = ["RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "_MD5"]


class SSLScanner:
    """Async wrapper around sslyze for SSL/TLS vulnerability scanning."""

    async def scan(self, target: str, scan_id: str) -> list[dict]:
        """
        Probe the SSL/TLS endpoint for the given target URL.
        Returns a (possibly empty) list of normalized finding dicts.
        """
        parsed = urlparse(target if "://" in target else f"https://{target}")
        hostname = parsed.hostname
        if not hostname:
            logger.warning(f"[SSL] Cannot parse hostname from target: {target}")
            return []

        # Always try 443; honour explicit port for https, fall back to 443 for http
        port = parsed.port or 443

        logger.info(f"[SSL] Starting SSL scan for {hostname}:{port}")
        loop = asyncio.get_event_loop()
        try:
            findings = await loop.run_in_executor(
                None, self._run_sslyze, hostname, port, target
            )
            logger.info(f"[SSL] Completed — {len(findings)} SSL finding(s)")
            return findings
        except Exception as e:
            logger.error(f"[SSL] Unexpected error: {e}")
            return []

    # ── Internal sync runner ─────────────────────────────────────────────────

    def _run_sslyze(self, hostname: str, port: int, target: str) -> list[dict]:
        try:
            from sslyze import Scanner, ServerNetworkLocation, ServerScanRequest
            from sslyze.plugins.scan_commands import ScanCommand
        except ImportError:
            logger.warning(
                "[SSL] sslyze not installed — skipping SSL scan. "
                "Install with: pip install sslyze"
            )
            return []

        findings: list[dict] = []

        try:
            location = ServerNetworkLocation(hostname=hostname, port=port)
            scan_request = ServerScanRequest(
                server_location=location,
                scan_commands={
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                    ScanCommand.HEARTBLEED,
                    ScanCommand.OPENSSL_CCS_INJECTION,
                    ScanCommand.ROBOT,
                    ScanCommand.SESSION_RENEGOTIATION,
                    ScanCommand.HTTP_HEADERS,
                },
            )

            scanner = Scanner()
            scanner.queue_scans([scan_request])

            for result in scanner.get_results():
                if result.scan_result is None:
                    logger.warning(f"[SSL] No scan result for {hostname}")
                    continue

                sr = result.scan_result

                # ── Certificate ──────────────────────────────────────────────
                if sr.certificate_info and not sr.certificate_info.scan_command_error:
                    findings.extend(
                        self._check_cert(sr.certificate_info.result, hostname, target)
                    )

                # ── Deprecated protocols ─────────────────────────────────────
                for proto, attr_name in [
                    ("SSLv2",  "ssl_2_0_cipher_suites"),
                    ("SSLv3",  "ssl_3_0_cipher_suites"),
                    ("TLS 1.0", "tls_1_0_cipher_suites"),
                    ("TLS 1.1", "tls_1_1_cipher_suites"),
                ]:
                    attr = getattr(sr, attr_name, None)
                    if attr and not attr.scan_command_error:
                        r = attr.result
                        if r and r.accepted_cipher_suites:
                            findings.append(
                                self._proto_finding(proto, hostname, target)
                            )

                # ── Weak ciphers in TLS 1.2 ─────────────────────────────────
                if (
                    sr.tls_1_2_cipher_suites
                    and not sr.tls_1_2_cipher_suites.scan_command_error
                ):
                    findings.extend(
                        self._check_weak_ciphers(
                            sr.tls_1_2_cipher_suites.result, hostname, target
                        )
                    )

                # ── Heartbleed ───────────────────────────────────────────────
                if sr.heartbleed and not sr.heartbleed.scan_command_error:
                    hb = sr.heartbleed.result
                    if hb and hb.is_vulnerable_to_heartbleed:
                        findings.append(
                            self._make_finding(
                                name="OpenSSL Heartbleed",
                                severity="critical",
                                description=(
                                    "The server is vulnerable to the Heartbleed bug "
                                    "(CVE-2014-0160). An attacker can read up to 64 KB "
                                    "of server memory per request, potentially leaking "
                                    "private keys, session tokens, and passwords."
                                ),
                                cve_id="CVE-2014-0160",
                                cvss=9.8,
                                check="heartbleed",
                                hostname=hostname,
                                target=target,
                                extra={},
                            )
                        )

                # ── OpenSSL CCS Injection ────────────────────────────────────
                if (
                    sr.openssl_ccs_injection
                    and not sr.openssl_ccs_injection.scan_command_error
                ):
                    ccs = sr.openssl_ccs_injection.result
                    if ccs and ccs.is_vulnerable_to_ccs_injection:
                        findings.append(
                            self._make_finding(
                                name="OpenSSL CCS Injection",
                                severity="high",
                                description=(
                                    "The server is vulnerable to the OpenSSL "
                                    "ChangeCipherSpec injection attack "
                                    "(CVE-2014-0224). A man-in-the-middle attacker "
                                    "can intercept and decrypt TLS traffic."
                                ),
                                cve_id="CVE-2014-0224",
                                cvss=7.4,
                                check="ccs_injection",
                                hostname=hostname,
                                target=target,
                                extra={},
                            )
                        )

                # ── ROBOT ────────────────────────────────────────────────────
                if sr.robot and not sr.robot.scan_command_error:
                    robot = sr.robot.result
                    if robot and "VULNERABLE" in str(robot.robot_result).upper():
                        findings.append(
                            self._make_finding(
                                name="ROBOT Attack — RSA Bleichenbacher Oracle",
                                severity="high",
                                description=(
                                    "The server is vulnerable to the ROBOT attack. "
                                    "An attacker can perform RSA decryption and forge "
                                    "RSA signatures with the server's private key."
                                ),
                                cve_id=None,
                                cvss=7.5,
                                check="robot",
                                hostname=hostname,
                                target=target,
                                extra={"robot_result": str(robot.robot_result)},
                            )
                        )

                # ── Insecure renegotiation ───────────────────────────────────
                if (
                    sr.session_renegotiation
                    and not sr.session_renegotiation.scan_command_error
                ):
                    rn = sr.session_renegotiation.result
                    if rn and rn.is_vulnerable_to_client_renegotiation_dos:
                        findings.append(
                            self._make_finding(
                                name="Insecure TLS Renegotiation (DoS)",
                                severity="medium",
                                description=(
                                    "The server supports client-initiated insecure "
                                    "TLS renegotiation, which can be abused to exhaust "
                                    "CPU resources and cause a denial of service."
                                ),
                                cve_id="CVE-2011-1473",
                                cvss=5.0,
                                check="renegotiation",
                                hostname=hostname,
                                target=target,
                                extra={},
                            )
                        )

                # ── Missing HSTS ─────────────────────────────────────────────
                if sr.http_headers and not sr.http_headers.scan_command_error:
                    hdr = sr.http_headers.result
                    if hdr and hdr.strict_transport_security_header is None:
                        findings.append(
                            self._make_finding(
                                name="Missing HTTP Strict Transport Security (HSTS)",
                                severity="low",
                                description=(
                                    "The server does not send the "
                                    "Strict-Transport-Security header. Without HSTS, "
                                    "browsers may connect over plain HTTP, allowing "
                                    "downgrade and MITM attacks."
                                ),
                                cve_id=None,
                                cvss=2.5,
                                check="hsts",
                                hostname=hostname,
                                target=target,
                                extra={},
                            )
                        )

        except Exception as e:
            logger.error(f"[SSL] sslyze execution error for {hostname}: {e}")

        return findings

    # ── Certificate checks ───────────────────────────────────────────────────

    def _check_cert(self, cert_result, hostname: str, target: str) -> list[dict]:
        findings = []
        if not cert_result:
            return findings

        try:
            for deployment in cert_result.certificate_deployments:
                chain = deployment.received_certificate_chain
                if not chain:
                    continue
                leaf = chain[0]

                # Expiry
                not_after = getattr(leaf, "not_valid_after_utc", None) or getattr(
                    leaf, "not_valid_after", None
                )
                if not_after:
                    if not_after.tzinfo is None:
                        not_after = not_after.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    delta = (not_after - now).days
                    if delta < 0:
                        findings.append(
                            self._make_finding(
                                name="SSL Certificate Expired",
                                severity="critical",
                                description=(
                                    f"The SSL certificate expired {abs(delta)} day(s) ago "
                                    f"on {not_after.strftime('%Y-%m-%d')}. All clients will "
                                    "see a hard security warning and may refuse to connect."
                                ),
                                cve_id=None,
                                cvss=9.0,
                                check="cert_expired",
                                hostname=hostname,
                                target=target,
                                extra={
                                    "expired_at": not_after.isoformat(),
                                    "days_overdue": abs(delta),
                                },
                            )
                        )
                    elif delta < 30:
                        findings.append(
                            self._make_finding(
                                name="SSL Certificate Expiring Soon",
                                severity="medium",
                                description=(
                                    f"The SSL certificate expires in {delta} day(s) on "
                                    f"{not_after.strftime('%Y-%m-%d')}. Renew it before "
                                    "expiry to prevent service disruption."
                                ),
                                cve_id=None,
                                cvss=5.0,
                                check="cert_expiring",
                                hostname=hostname,
                                target=target,
                                extra={
                                    "expires_at": not_after.isoformat(),
                                    "days_remaining": delta,
                                },
                            )
                        )

                # Untrusted / self-signed
                if not deployment.verified_certificate_chain:
                    findings.append(
                        self._make_finding(
                            name="Self-Signed or Untrusted SSL Certificate",
                            severity="high",
                            description=(
                                "The certificate chain could not be verified against "
                                "trusted Certificate Authorities. The certificate may be "
                                "self-signed, which exposes users to man-in-the-middle "
                                "attacks and causes browser security warnings."
                            ),
                            cve_id=None,
                            cvss=7.5,
                            check="cert_untrusted",
                            hostname=hostname,
                            target=target,
                            extra={},
                        )
                    )

                # Hostname mismatch
                if not deployment.leaf_certificate_subject_matches_hostname:
                    findings.append(
                        self._make_finding(
                            name="SSL Certificate Hostname Mismatch",
                            severity="high",
                            description=(
                                f"The certificate subject does not match the hostname "
                                f"'{hostname}'. This causes browser errors and may indicate "
                                "a misconfiguration or an active man-in-the-middle attack."
                            ),
                            cve_id=None,
                            cvss=7.0,
                            check="cert_hostname_mismatch",
                            hostname=hostname,
                            target=target,
                            extra={"hostname": hostname},
                        )
                    )

        except Exception as e:
            logger.warning(f"[SSL] Certificate check error: {e}")

        return findings

    # ── Cipher suite checks ──────────────────────────────────────────────────

    def _check_weak_ciphers(self, cs_result, hostname: str, target: str) -> list[dict]:
        if not cs_result or not cs_result.accepted_cipher_suites:
            return []

        weak = [
            cs.cipher_suite.name
            for cs in cs_result.accepted_cipher_suites
            if any(p in cs.cipher_suite.name.upper() for p in _WEAK_PATTERNS)
        ]
        if not weak:
            return []

        return [
            self._make_finding(
                name="Weak TLS Cipher Suites Enabled",
                severity="medium",
                description=(
                    f"The server accepts {len(weak)} weak cipher suite(s) in TLS 1.2: "
                    f"{', '.join(weak[:6])}{'…' if len(weak) > 6 else ''}. "
                    "Weak ciphers can allow decryption of intercepted traffic."
                ),
                cve_id=None,
                cvss=5.3,
                check="weak_ciphers",
                hostname=hostname,
                target=target,
                extra={"weak_ciphers": weak},
            )
        ]

    # ── Protocol finding builder ─────────────────────────────────────────────

    def _proto_finding(self, proto: str, hostname: str, target: str) -> dict:
        is_ssl = "SSL" in proto
        sev = "critical" if is_ssl else "medium"
        cvss = 9.8 if is_ssl else 5.3
        cve = "CVE-2014-3566" if proto == "SSLv3" else None  # POODLE
        extra_note = (
            " POODLE attack (CVE-2014-3566) applies to SSLv3." if proto == "SSLv3"
            else " SSLv2 is critically broken and must be disabled." if proto == "SSLv2"
            else ""
        )
        return self._make_finding(
            name=f"Deprecated Protocol Enabled: {proto}",
            severity=sev,
            description=(
                f"The server accepts connections using {proto}, which is deprecated "
                f"and known to be insecure.{extra_note} Disable this protocol immediately."
            ),
            cve_id=cve,
            cvss=cvss,
            check="deprecated_protocol",
            hostname=hostname,
            target=target,
            extra={"protocol": proto},
        )

    # ── Generic finding factory ──────────────────────────────────────────────

    def _make_finding(
        self,
        *,
        name: str,
        severity: str,
        description: str,
        cve_id: Optional[str],
        cvss: float,
        check: str,
        hostname: str,
        target: str,
        extra: dict,
    ) -> dict:
        ref = (
            f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            if cve_id
            else "https://ssl-config.mozilla.org/"
        )
        ssl_extra = {"check": check, **extra}
        return {
            "template_id": f"ssl-{check}",
            "name": name,
            "severity": severity,
            "description": description,
            "host": hostname,
            "matched_at": target,
            "url": target,
            "vuln_type": "SSL/TLS Misconfiguration",
            "scanner_source": "ssl-scan",
            "cve_id": cve_id,
            "cvss_score": cvss,
            "tags": json.dumps(["ssl", "tls", "certificate", "crypto"]),
            "reference": ref,
            "extracted_results": json.dumps(ssl_extra),
            "matcher_name": check,
        }
