import time
from typing import Dict, Any
import requests
from .base import BaseFortinetDevice, DeviceError


class FortiGateDevice(BaseFortinetDevice):
    """FortiGate appliance client."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

    def pull_config(self) -> bytes:
        """
        Pulls running config from FortiGate REST API.
        Endpoint: /api/v2/monitor/system/config/backup?scope=global
        """
        if not self.token:
            raise DeviceError(
                f"[{self.name}] Missing API Token! Ensure environment variable '{self.token_env}' is set in .env."
            )

        url = f"{self.base_url}/api/v2/monitor/system/config/backup"
        params = {"scope": "global"}
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/octet-stream, text/plain, */*"
        }

        try:
            # Modern FortiOS (>= 7.4/7.6) requires POST. Older FortiOS (7.0/7.2) uses GET.
            response = self.session.post(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout_seconds
            )
            if response.status_code == 405:
                # Fallback to GET for older FortiOS versions
                response = self.session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=self.timeout_seconds
                )
            elif response.status_code == 429:
                # Rate limit hit: wait 5 seconds and retry once
                time.sleep(5)
                response = self.session.post(
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
                f"[{self.name}] Access Forbidden (403). Ensure API user has Read/Write permissions on System."
            )
        elif response.status_code != 200:
            raise DeviceError(
                f"[{self.name}] Failed to fetch config. HTTP Status: {response.status_code}, Body: {response.text[:200]}"
            )

        content = response.content
        if not content:
            raise DeviceError(f"[{self.name}] Received empty configuration payload from device.")

        # Baseline validation (Gotcha #1 protection)
        self.validate_baseline(content)

        return content

