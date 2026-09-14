"""
Storage Manager for Local Cache and S3-Compatible Object Storage.
Supports both AWS S3 and NetApp ONTAP / StorageGRID S3.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError


class StorageError(Exception):
    """Base storage error."""
    pass


class LocalStorageManager:
    """Manages local backup storage and version history."""

    def __init__(self, base_dir: str = "backups"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def get_device_dir(self, device_name: str) -> Path:
        device_dir = self.base_dir / device_name
        device_dir.mkdir(parents=True, exist_ok=True)
        return device_dir

    def get_latest_backup(self, device_name: str) -> Optional[Tuple[Path, str]]:
        """
        Retrieves the path and content of the most recent local backup for a device.
        Returns (filepath, content_str) or None if no prior backup exists.
        """
        device_dir = self.get_device_dir(device_name)
        backup_files = sorted(device_dir.glob("*.conf"), key=lambda f: f.stat().st_mtime, reverse=True)

        if not backup_files:
            return None

        latest_file = backup_files[0]
        try:
            content = latest_file.read_text(encoding="utf-8", errors="replace")
            return latest_file, content
        except Exception as e:
            raise StorageError(f"Failed to read local backup {latest_file}: {e}")

    def save_backup(
        self,
        device_name: str,
        config_bytes: bytes,
        timestamp_str: str,
        sha256_hash: str
    ) -> Path:
        """Saves config bytes locally."""
        device_dir = self.get_device_dir(device_name)
        filename = f"{timestamp_str}_{sha256_hash[:12]}.conf"
        target_path = device_dir / filename

        target_path.write_bytes(config_bytes)
        return target_path


class S3StorageManager:
    """
    Manages S3 object storage uploads.
    Compatible with AWS S3 and NetApp S3 (StorageGRID / ONTAP).
    """

    def __init__(self, config: Dict[str, Any]):
        self.bucket = config["bucket_name"]
        self.endpoint_url = config.get("endpoint_url")
        self.is_custom = config.get("is_custom_endpoint", False)
        self.region = config.get("region_name", "us-east-1")
        self.verify_ssl = config.get("verify_ssl", True)

        # NetApp S3 & Third-party S3 compatibility:
        # Boto3 1.36+ defaults to streaming checksum trailers which NetApp ONTAP S3 rejects
        # with 'InvalidArgument: x-amz-content-sha256 must be UNSIGNED-PAYLOAD...'.
        # Setting request_checksum_calculation="when_required" and payload_signing_enabled
        # ensures compatibility with both NetApp S3 and AWS S3.
        boto_cfg = Config(
            signature_version="s3v4",
            retries={"max_attempts": 3, "mode": "standard"},
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
            s3={
                "addressing_style": "path",
                "payload_signing_enabled": True
            }
        )

        client_kwargs = {
            "service_name": "s3",
            "region_name": self.region,
            "aws_access_key_id": config.get("access_key"),
            "aws_secret_access_key": config.get("secret_key"),
            "verify": self.verify_ssl,
            "config": boto_cfg
        }

        if self.endpoint_url:
            client_kwargs["endpoint_url"] = self.endpoint_url

        self.client = boto3.client(**client_kwargs)

    def test_connection(self) -> bool:
        """Verifies access to the target S3 bucket."""
        try:
            self.client.head_bucket(Bucket=self.bucket)
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            raise StorageError(f"S3 Connection Error for bucket '{self.bucket}': [{error_code}] {e}")
        except Exception as e:
            raise StorageError(f"S3 Connection failed: {e}")

    def upload_backup(
        self,
        device_name: str,
        device_type: str,
        config_bytes: bytes,
        timestamp_str: str,
        sha256_hash: str
    ) -> str:
        """
        Uploads backup bytes to S3 with metadata.
        Key structure: {device_name}/{timestamp}_{sha256[:12]}.conf
        """
        key = f"{device_name}/{timestamp_str}_{sha256_hash[:12]}.conf"
        metadata = {
            "sha256": sha256_hash,
            "device": device_name,
            "device_type": device_type,
            "timestamp": timestamp_str
        }

        put_kwargs = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": config_bytes,
            "ContentType": "text/plain",
            "Metadata": metadata
        }

        # Apply ServerSideEncryption if targeting AWS S3 (NetApp S3 may not use aws:kms)
        if not self.is_custom:
            put_kwargs["ServerSideEncryption"] = "AES256"

        try:
            self.client.put_object(**put_kwargs)
            return key
        except (ClientError, BotoCoreError) as e:
            raise StorageError(f"Failed to upload {key} to S3 bucket '{self.bucket}': {e}")

