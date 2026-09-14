import base64
import json
from typing import Dict, Any
import requests
from .base import BaseFortinetDevice, DeviceError


class FortiWebDevice(BaseFortinetDevice):
    """FortiWeb appliance client using Base64 administrator token authentication."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.user_env = config.get("user_env", "")
        self.pass_env = config.get("pass_env", "")
        self.vdom = config.get("vdom", "root")

    def _get_auth_header_value(self) -> str:
        """
        Generates or formats the Base64 Authorization header value.
        FortiWeb requires: Authorization: <base64_encoded_json> (without 'Bearer').
        JSON format: {"username":"user","password":"pwd","vdom":"root"}
        """
        # 1. If username and password are provided, generate Base64 automatically
        if self.username and self.password:
            payload = json.dumps({
                "username": self.username,
                "password": self.password,
                "vdom": self.vdom or "root"
            }, separators=(',', ':'))
            return base64.b64encode(payload.encode("utf-8")).decode("utf-8")

        # 2. If pre-encoded token is provided, clean and use it directly
        if self.token:
            token_val = self.token.strip()
            # Strip 'Bearer ' if accidentally provided by user
            if token_val.lower().startswith("bearer "):
                token_val = token_val[7:].strip()
            return token_val

        raise DeviceError(
            f"[{self.name}] Authentication missing! Either provide '{self.token_env}' (Base64 token) "
            f"or both '{self.user_env}' and '{self.pass_env}' in .env."
        )

    def pull_config(self) -> bytes:
        """
        Pulls running config from FortiWeb REST API.
        Endpoint: /api/v2.0/system/maintenance.backupconfiguration?type=entire
        """
        auth_token = self._get_auth_header_value()

        url = f"{self.base_url}/api/v2.0/system/maintenance.backupconfiguration"
        params = {"type": "entire"}

        # FortiWeb REST API uses raw Base64 token directly in Authorization header
        headers = {
            "Authorization": auth_token,
            "Accept": "application/octet-stream, text/plain, */*",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout_seconds
            )
        except requests.exceptions.SSLError as e:
            raise DeviceError(f"[{self.name}] SSL Error: {e}. Set 'verify_ssl: false' in devices.yaml if using self-signed cert.")
        except requests.exceptions.ConnectTimeout:
            raise DeviceError(f"[{self.name}] Connection timeout connecting to {self.host}:{self.port}.")
        except requests.exceptions.ConnectionError as e:
            raise DeviceError(f"[{self.name}] Connection refused or host unreachable: {e}")
        except requests.exceptions.RequestException as e:
            raise DeviceError(f"[{self.name}] Request error: {e}")

        if response.status_code == 401:
            raise DeviceError(f"[{self.name}] Authentication Failed (401 Unauthorized). Verify API Token.")
        elif response.status_code == 403:
            raise DeviceError(
                f"[{self.name}] Access Forbidden (403). Ensure API user has sufficient Maintenance/Backup privileges."
            )
        elif response.status_code != 200:
            raise DeviceError(
                f"[{self.name}] Failed to fetch config. HTTP Status: {response.status_code}, Body: {response.text[:200]}"
            )

        content = response.content
        if not content:
            raise DeviceError(f"[{self.name}] Received empty configuration payload from FortiWeb.")

        # Baseline validation (Gotcha #1 protection)
        self.validate_baseline(content)

        return content

