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

    def get_latest_backup(self, device_name: str) -> Optional[Tuple[Path, bytes]]:
        """
        Retrieves the path and raw bytes of the most recent local backup for a device.
        Supports both .conf and .zip backup archives.
        Returns (filepath, content_bytes) or None if no prior backup exists.
        """
        device_dir = self.get_device_dir(device_name)
        backup_files = sorted(
            [f for f in device_dir.iterdir() if f.is_file() and (f.suffix in (".conf", ".zip") or f.name.endswith(".conf.zip"))],
            key=lambda f: f.stat().st_mtime,
            reverse=True
        )

        if not backup_files:
            return None

        latest_file = backup_files[0]
        try:
            content_bytes = latest_file.read_bytes()
            return latest_file, content_bytes
        except Exception as e:
            raise StorageError(f"Failed to read local backup {latest_file}: {e}")

    def save_backup(
        self,
        device_name: str,
        config_bytes: bytes,
        filename: str
    ) -> Path:
        """Saves config bytes locally using specified filename."""
        device_dir = self.get_device_dir(device_name)
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
            "verify": self.verify_ssl,
            "config": boto_cfg
        }

        # If access_key and secret_key are provided, use static credentials.
        # Otherwise, Boto3 automatically assumes IAM Role (AWS Lambda / EC2 Instance Profile).
        if config.get("access_key") and config.get("secret_key"):
            client_kwargs["aws_access_key_id"] = config["access_key"]
            client_kwargs["aws_secret_access_key"] = config["secret_key"]

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

    def get_latest_backup(self, device_name: str) -> Optional[Tuple[str, bytes]]:
        """
        Retrieves the most recent backup directly from S3 for stateless / Lambda environments.
        Lists objects under prefix {device_name}/, sorts by LastModified, and downloads raw bytes.
        Returns (object_key, content_bytes) or None if no prior backup exists.
        """
        try:
            prefix = f"{device_name}/"
            paginator = self.client.get_paginator("list_objects_v2")
            objects = []
            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                if "Contents" in page:
                    objects.extend(page["Contents"])

            if not objects:
                return None

            # Filter valid backup extensions (.conf or .zip)
            valid_objects = [
                obj for obj in objects
                if obj["Key"].endswith(".conf") or obj["Key"].endswith(".zip")
            ]
            if not valid_objects:
                return None

            # Sort by LastModified descending
            latest_obj = max(valid_objects, key=lambda x: x["LastModified"])
            key = latest_obj["Key"]
            resp = self.client.get_object(Bucket=self.bucket, Key=key)
            content_bytes = resp["Body"].read()
            return key, content_bytes
        except ClientError as ce:
            error_code = ce.response.get("Error", {}).get("Code", "")
            if error_code in ("NoSuchKey", "404"):
                return None
            raise StorageError(f"Failed to fetch previous backup from S3 for '{device_name}': {ce}")
        except Exception as e:
            raise StorageError(f"Failed to fetch previous backup from S3 for '{device_name}': {e}")

    def upload_backup(
        self,
        device_name: str,
        device_type: str,
        config_bytes: bytes,
        filename: str,
        timestamp_str: str,
        sha256_hash: str
    ) -> str:
        """
        Uploads backup bytes to S3 with metadata.
        Key structure: {device_name}/{filename}
        """
        key = f"{device_name}/{filename}"
        content_type = "application/zip" if filename.endswith(".zip") else "text/plain"

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
            "ContentType": content_type,
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

