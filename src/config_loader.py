"""
Configuration Loader and Validator.
Handles devices.yaml and .env settings safely.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from dotenv import load_dotenv


class ConfigError(Exception):
    """Raised when configuration validation fails."""
    pass


def load_environment(env_path: Optional[str] = None) -> None:
    """Loads environment variables from .env file."""
    if env_path and Path(env_path).exists():
        load_dotenv(dotenv_path=env_path, override=True)
    else:
        # Default search paths
        candidate_paths = [
            Path("config/.env"),
            Path(".env"),
            Path(__file__).parent.parent / "config" / ".env"
        ]
        loaded = False
        for p in candidate_paths:
            if p.exists():
                load_dotenv(dotenv_path=p, override=True)
                loaded = True
                break
        if not loaded:
            # Fall back to default system environment
            load_dotenv()


def get_s3_config() -> Dict[str, Any]:
    """Retrieves and validates S3 configuration (AWS S3 or NetApp S3 compatible)."""
    endpoint_url = os.getenv("S3_ENDPOINT_URL", "").strip() or None
    bucket_name = os.getenv("S3_BUCKET_NAME", "").strip()
    access_key = os.getenv("S3_ACCESS_KEY", "").strip()
    secret_key = os.getenv("S3_SECRET_KEY", "").strip()
    region_name = os.getenv("S3_REGION", "us-east-1").strip()
    verify_ssl_raw = os.getenv("S3_VERIFY_SSL", "true").strip().lower()
    verify_ssl = verify_ssl_raw in ("true", "1", "yes")

    if not bucket_name:
        raise ConfigError("S3_BUCKET_NAME is required in .env")

    return {
        "endpoint_url": endpoint_url,
        "bucket_name": bucket_name,
        "access_key": access_key,
        "secret_key": secret_key,
        "region_name": region_name,
        "verify_ssl": verify_ssl,
        "is_custom_endpoint": endpoint_url is not None
    }


def get_smtp_config() -> Optional[Dict[str, Any]]:
    """Retrieves SMTP configuration if configured."""
    host = os.getenv("SMTP_HOST", "").strip()
    if not host:
        return None

    port = int(os.getenv("SMTP_PORT", "587").strip())
    use_tls = os.getenv("SMTP_USE_TLS", "true").strip().lower() in ("true", "1", "yes")
    use_ssl = os.getenv("SMTP_USE_SSL", "false").strip().lower() in ("true", "1", "yes")
    user = os.getenv("SMTP_USER", "").strip()
    password = os.getenv("SMTP_PASS", "").strip()
    sender = os.getenv("SMTP_FROM", user).strip()
    recipients_raw = os.getenv("SMTP_TO", "").strip()
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]

    return {
        "host": host,
        "port": port,
        "use_tls": use_tls,
        "use_ssl": use_ssl,
        "user": user,
        "password": password,
        "sender": sender,
        "recipients": recipients
    }


def load_devices_config(yaml_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Loads and validates the inventory of Fortinet devices from YAML."""
    if yaml_path and Path(yaml_path).exists():
        path = Path(yaml_path)
    else:
        candidate_paths = [
            Path("config/devices.yaml"),
            Path("devices.yaml"),
            Path(__file__).parent.parent / "config" / "devices.yaml"
        ]
        path = None
        for p in candidate_paths:
            if p.exists():
                path = p
                break

    if not path or not path.exists():
        raise ConfigError("devices.yaml configuration file not found in config/ or root directory.")

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data or "devices" not in data or not isinstance(data["devices"], list):
        raise ConfigError("devices.yaml must contain a top-level 'devices' list.")

    devices = []
    for idx, dev in enumerate(data["devices"]):
        name = dev.get("name")
        if not name:
            raise ConfigError(f"Device at index {idx} is missing 'name'")

        host = dev.get("host")
        if not host:
            raise ConfigError(f"Device '{name}' is missing 'host'")

        dev_type = dev.get("type", "fortigate").lower()
        if dev_type not in ("fortigate", "fortiweb"):
            raise ConfigError(f"Device '{name}' invalid type '{dev_type}'. Must be 'fortigate' or 'fortiweb'")

        token_env = dev.get("token_env")
        token = os.getenv(token_env, "").strip() if token_env else ""

        user_env = dev.get("user_env")
        username = os.getenv(user_env, "").strip() if user_env else ""

        pass_env = dev.get("pass_env")
        password = os.getenv(pass_env, "").strip() if pass_env else ""

        vdom = dev.get("vdom", "root")

        devices.append({
            "name": name,
            "description": dev.get("description", ""),
            "type": dev_type,
            "host": host,
            "port": int(dev.get("port", 443)),
            "token": token,
            "token_env": token_env,
            "username": username,
            "password": password,
            "user_env": user_env,
            "pass_env": pass_env,
            "vdom": vdom,
            "min_size_bytes": int(dev.get("min_size_bytes", 10000)),
            "min_lines": int(dev.get("min_lines", 100)),
            "verify_ssl": bool(dev.get("verify_ssl", False)),
            "timeout_seconds": int(dev.get("timeout_seconds", 30))
        })

    return devices

