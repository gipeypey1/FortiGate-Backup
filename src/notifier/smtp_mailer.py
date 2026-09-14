"""
SMTP Email Alerting Module.
Sends structured HTML notifications for config drifts and backup failures.
"""

import html
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional


class MailerError(Exception):
    """Raised when SMTP sending fails."""
    pass


class SMTPMailer:
    """Manages SMTP email alerts."""

    def __init__(self, config: Dict[str, Any]):
        self.host = config["host"]
        self.port = config.get("port", 587)
        self.use_tls = config.get("use_tls", True)
        self.use_ssl = config.get("use_ssl", False)
        self.user = config.get("user", "")
        self.password = config.get("password", "")
        self.sender = config.get("sender", self.user)
        self.recipients = config.get("recipients", [])

    def test_connection(self) -> bool:
        """Verifies SMTP connectivity and credentials."""
        try:
            with self._get_server() as server:
                return True
        except Exception as e:
            raise MailerError(f"SMTP Connection Test failed: {e}")

    def _get_server(self):
        """Creates and authenticates the SMTP connection."""
        if self.use_ssl:
            server = smtplib.SMTP_SSL(self.host, self.port, timeout=20)
        else:
            server = smtplib.SMTP(self.host, self.port, timeout=20)
            server.ehlo()
            if self.use_tls:
                server.starttls()
                server.ehlo()

        if self.user and self.password:
            server.login(self.user, self.password)

        return server

    def _send(self, subject: str, html_body: str, text_body: str) -> None:
        """Internal method to assemble and dispatch email."""
        if not self.recipients:
            raise MailerError("No SMTP recipients defined.")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)

        part_text = MIMEText(text_body, "plain", "utf-8")
        part_html = MIMEText(html_body, "html", "utf-8")
        msg.attach(part_text)
        msg.attach(part_html)

        try:
            with self._get_server() as server:
                server.sendmail(self.sender, self.recipients, msg.as_string())
        except Exception as e:
            raise MailerError(f"Failed to send email alert via {self.host}:{self.port} - {e}")

    def send_drift_alert(
        self,
        device_name: str,
        device_type: str,
        timestamp: str,
        sha256_hash: str,
        real_changes: List[str],
        diff_text: str,
        s3_key: Optional[str] = None
    ) -> None:
        """Sends an HTML alert when real configuration drift is detected."""
        subject = f"[DRIFT DETECTED] Configuration Change on {device_name} ({device_type.upper()})"

        # Format diff lines with max cap
        diff_lines = diff_text.splitlines()
        truncated = False
        if len(diff_lines) > 500:
            diff_lines = diff_lines[:500]
            truncated = True

        formatted_diff_rows = []
        for line in diff_lines:
            escaped = html.escape(line)
            if line.startswith("+"):
                formatted_diff_rows.append(f'<span style="color:#22863a;background:#f0fff4;display:block;">{escaped}</span>')
            elif line.startswith("-"):
                formatted_diff_rows.append(f'<span style="color:#b31d28;background:#ffeef0;display:block;">{escaped}</span>')
            elif line.startswith("@"):
                formatted_diff_rows.append(f'<span style="color:#0366d6;font-weight:bold;display:block;">{escaped}</span>')
            else:
                formatted_diff_rows.append(f'<span style="color:#444;display:block;">{escaped}</span>')

        if truncated:
            formatted_diff_rows.append('<span style="color:#e36209;font-weight:bold;display:block;">... [Diff truncated at 500 lines. See full backup on S3 / local storage]</span>')

        diff_html = "".join(formatted_diff_rows)

        # HTML Body
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .badge-drift {{ background-color: #d9534f; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
                .meta-table {{ width: 100%; border-collapse: collapse; margin-top: 15px; margin-bottom: 20px; }}
                .meta-table th, .meta-table td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; font-size: 13px; }}
                .meta-table th {{ background-color: #f7f7f7; width: 25%; }}
                .diff-container {{ background: #f6f8fa; border: 1px solid #d1d5da; border-radius: 6px; padding: 15px; font-family: Consolas, monospace; font-size: 12px; overflow-x: auto; }}
                .header {{ background-color: #24292e; color: white; padding: 16px; border-radius: 6px 6px 0 0; }}
            </style>
        </head>
        <body>
            <div style="max-width: 850px; margin: auto; border: 1px solid #e1e4e8; border-radius: 6px;">
                <div class="header">
                    <h2 style="margin:0;">🚨 Network Configuration Drift Detected</h2>
                </div>
                <div style="padding: 20px;">
                    <p>Perubahan konfigurasi riil terdeteksi pada perangkat <strong>{device_name}</strong> saat jadwal backup dieksekusi.</p>
                    
                    <table class="meta-table">
                        <tr><th>Device Name</th><td><strong>{device_name}</strong> ({device_type.upper()})</td></tr>
                        <tr><th>Timestamp (UTC)</th><td>{timestamp}</td></tr>
                        <tr><th>New SHA-256</th><td><code>{sha256_hash}</code></td></tr>
                        <tr><th>S3 Object Key</th><td><code>{s3_key or 'Local only'}</code></td></tr>
                        <tr><th>Real Changes Count</th><td><strong>{len(real_changes)} baris</strong> (Noise enkripsi ENC diabaikan)</td></tr>
                    </table>

                    <h3>Ringkasan Unified Diff:</h3>
                    <div class="diff-container">
                        {diff_html}
                    </div>

                    <p style="font-size: 11px; color: #777; margin-top: 25px;">
                        Email ini dihasilkan otomatis oleh Fortinet Automated Backup & Drift Detection Engine.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """

        text_body = f"""Network Configuration Drift Detected
Device: {device_name} ({device_type})
Timestamp: {timestamp}
SHA-256: {sha256_hash}
S3 Key: {s3_key or 'Local only'}
Changes Count: {len(real_changes)}

Unified Diff:
{diff_text[:4000]}
"""

        self._send(subject, html_body, text_body)

    def send_failure_alert(
        self,
        device_name: str,
        error_message: str,
        details: Optional[str] = None
    ) -> None:
        """Sends an HTML alert when a backup fails or baseline validation fails."""
        subject = f"[BACKUP ALERT] Backup Gagal untuk {device_name}"

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .header-err {{ background-color: #cb2431; color: white; padding: 16px; border-radius: 6px 6px 0 0; }}
                .box {{ border: 1px solid #d73a49; background: #ffeef0; padding: 15px; border-radius: 4px; margin-top: 15px; }}
            </style>
        </head>
        <body>
            <div style="max-width: 800px; margin: auto; border: 1px solid #e1e4e8; border-radius: 6px;">
                <div class="header-err">
                    <h2 style="margin:0;">⚠️ Fortinet Backup Execution Failed</h2>
                </div>
                <div style="padding: 20px;">
                    <p>Proses backup otomatis mengalami kegagalan pada perangkat <strong>{device_name}</strong>.</p>
                    
                    <div class="box">
                        <strong style="color: #86181d;">Pesan Error:</strong>
                        <p style="margin: 5px 0 0 0; font-family: monospace;">{html.escape(error_message)}</p>
                    </div>

                    {f'<pre style="background:#f6f8fa; padding:10px; border-radius:4px; font-size:12px; margin-top:15px;">{html.escape(details)}</pre>' if details else ''}

                    <p style="margin-top: 20px;"><strong>Rekomendasi Tindakan:</strong></p>
                    <ul>
                        <li>Periksa konektivitas jaringan ke IP Dedicated Management perangkat.</li>
                        <li>Verifikasi apakah token API kedaluwarsa atau diubah.</li>
                        <li>Jika error terkait <em>Silent Truncation</em>, pastikan hak akses Administrator REST API di FortiOS mencakup <code>System: Read/Write</code> dan kategori lain minimal <code>Read</code>.</li>
                    </ul>
                </div>
            </div>
        </body>
        </html>
        """

        text_body = f"""Fortinet Backup Execution Failed!
Device: {device_name}
Error: {error_message}
{details or ''}
"""

        self._send(subject, html_body, text_body)

