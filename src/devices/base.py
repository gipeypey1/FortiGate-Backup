"""
Base Fortinet Device Client.
Provides session handling, timeouts, and baseline validation against silent truncation (Gotcha #1).
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
import requests
import urllib3


class DeviceError(Exception):
    """Base exception for device communication errors."""
    pass


class TruncatedBackupError(DeviceError):
    """Raised when backup fails baseline validation (silent truncation)."""
    pass


class BaseFortinetDevice(ABC):
    """Abstract Base Class for Fortinet appliances."""

    def __init__(self, config: Dict[str, Any]):
        self.name = config["name"]
        self.description = config.get("description", "")
        self.host = config["host"]
        self.port = config.get("port", 443)
        self.token = config.get("token", "")
        self.token_env = config.get("token_env", "")
        self.min_size_bytes = config.get("min_size_bytes", 10000)
        self.min_lines = config.get("min_lines", 100)
        self.verify_ssl = config.get("verify_ssl", False)
        self.timeout_seconds = config.get("timeout_seconds", 30)

        # Disable SSL warnings if verify_ssl is explicitly turned off for on-premise appliances
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.session = requests.Session()
        self.session.verify = self.verify_ssl

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    def validate_baseline(self, data: bytes) -> None:
        """
        Validates the backup file against expected baseline metrics.
        Solves Gotcha #1: FortiOS silently truncating backups when permissions are missing.
        """
        size_bytes = len(data)
        if size_bytes < self.min_size_bytes:
            raise TruncatedBackupError(
                f"[{self.name}] Potential Silent Truncation! Backup size ({size_bytes} bytes) "
                f"is below the minimum baseline threshold ({self.min_size_bytes} bytes). "
                f"Check API Admin permissions (System must be Read/Write, other categories at least Read)."
            )

        # Validate line count
        try:
            line_count = len(data.decode("utf-8", errors="replace").splitlines())
            if line_count < self.min_lines:
                raise TruncatedBackupError(
                    f"[{self.name}] Potential Silent Truncation! Backup line count ({line_count} lines) "
                    f"is below the minimum baseline threshold ({self.min_lines} lines)."
                )
        except Exception:
            pass

    @abstractmethod
    def pull_config(self) -> bytes:
        """Pulls running configuration bytes from the device REST API."""
        pass

