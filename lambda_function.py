"""
AWS Lambda Function Handler for Fortinet Automated Backup & Drift Detection.
Serverless entry point triggered by Amazon EventBridge (Cron).
Designed for AWS VPC execution, AWS Secrets Manager, and IAM Role access to S3.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# Ensure botocore checksum compatibility
os.environ.setdefault("AWS_REQUEST_CHECKSUM_CALCULATION", "when_required")
os.environ.setdefault("AWS_RESPONSE_CHECKSUM_VALIDATION", "when_required")

from src.config_loader import (
    load_environment,
    load_devices_config,
    get_s3_config,
    get_smtp_config,
    ConfigError
)
from src.secrets_manager import load_aws_secrets
from src.drift import calculate_sha256, analyze_drift
from src.devices import FortiGateDevice, FortiWebDevice, DeviceError, TruncatedBackupError
from src.storage import S3StorageManager, LocalStorageManager, StorageError
from src.notifier import SMTPMailer, MailerError

# Configure Lambda Logger
logger = logging.getLogger("forti_backup")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


def lambda_handler(event: Dict[str, Any] = None, context: Any = None) -> Dict[str, Any]:
    """
    AWS Lambda entry point.
    Triggered by Amazon EventBridge scheduled rule (e.g. cron(0 */6 * * ? *)).
    """
    logger.info("Starting Fortinet Backup Lambda execution...")

    # 1. Load credentials from AWS Secrets Manager if configured, fallback to Lambda Env
    try:
        load_aws_secrets()
    except Exception as e:
        logger.warning(f"Could not load secrets from AWS Secrets Manager: {e}")

    # Fallback to local .env if present (e.g. for local sam / docker testing)
    load_environment()

    # 2. Load Inventory (config/devices.yaml)
    try:
        devices = load_devices_config()
    except ConfigError as ce:
        logger.error(f"Configuration Error: {ce}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(ce)})
        }

    # Filter specific device if passed in event payload
    if event and isinstance(event, dict) and "device" in event:
        target_dev = event["device"].lower()
        devices = [d for d in devices if d["name"].lower() == target_dev]
        if not devices:
            return {
                "statusCode": 404,
                "body": json.dumps({"error": f"Device '{target_dev}' not found in inventory."})
            }

    # 3. Initialize S3 (Using Lambda IAM Execution Role - Zero hardcoded keys!)
    try:
        s3_cfg = get_s3_config()
        s3_manager = S3StorageManager(s3_cfg)
        logger.info(f"Connected to S3 bucket '{s3_cfg['bucket_name']}' via IAM Role.")
    except Exception as e:
        logger.error(f"Failed to initialize S3 Manager: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": f"S3 initialization failed: {e}"})
        }

    # 4. Initialize Local Cache in Lambda ephemeral /tmp directory
    local_storage = LocalStorageManager(base_dir="/tmp/backups")

    # 5. Initialize Mailer
    smtp_cfg = get_smtp_config()
    mailer = SMTPMailer(smtp_cfg) if smtp_cfg else None
    if not mailer:
        logger.info("SMTP configuration not detected or incomplete. Email alerts disabled.")

    # 6. Process Devices
    summary: List[Dict[str, Any]] = []
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    for dev in devices:
        dev_name = dev["name"]
        dev_type = dev["type"]
        logger.info(f"[{dev_name}] Processing backup ({dev_type.upper()} @ {dev['host']})")

        # Instantiate Client
        if dev_type == "fortigate":
            client = FortiGateDevice(dev)
        elif dev_type == "fortiweb":
            client = FortiWebDevice(dev)
        else:
            summary.append({"device": dev_name, "type": dev_type, "status": "ERROR", "message": "Unknown type"})
            continue

        # Pull Configuration from Appliance REST API
        try:
            config_bytes = client.pull_config()
        except (TruncatedBackupError, DeviceError) as e:
            err_msg = str(e)
            logger.error(f"[{dev_name}] Backup failed: {err_msg}")
            if mailer:
                try:
                    mailer.send_failure_alert(dev_name, err_msg)
                except Exception as me:
                    logger.warning(f"[{dev_name}] Failed to dispatch failure email: {me}")
            summary.append({"device": dev_name, "type": dev_type, "status": "FAILED", "message": err_msg})
            continue
        except Exception as e:
            err_msg = f"Unexpected error: {e}"
            logger.exception(f"[{dev_name}] Unexpected error: {err_msg}")
            if mailer:
                try:
                    mailer.send_failure_alert(dev_name, err_msg)
                except Exception:
                    pass
            summary.append({"device": dev_name, "type": dev_type, "status": "FAILED", "message": err_msg})
            continue

        # Fingerprint and Filename
        sha256_hash = calculate_sha256(config_bytes)
        filename = client.get_filename(timestamp, sha256_hash)
        config_text = client.extract_text_for_drift(config_bytes)
        logger.info(f"[{dev_name}] Downloaded: {filename} ({len(config_bytes):,} bytes, SHA-256: {sha256_hash[:16]}...)")

        # Stateless Drift Detection: Fetch previous backup from /tmp or directly from S3!
        prev_backup = local_storage.get_latest_backup(dev_name)
        if not prev_backup:
            try:
                s3_prev = s3_manager.get_latest_backup(dev_name)
                if s3_prev:
                    s3_key, s3_bytes = s3_prev
                    prev_backup = (Path(s3_key), s3_bytes)
                    logger.info(f"[{dev_name}] Retrieved previous baseline backup from S3: {s3_key}")
            except Exception as se:
                logger.warning(f"[{dev_name}] Could not retrieve previous backup from S3: {se}")

        drift_status = "INITIAL_BACKUP"
        drift_result = None

        if prev_backup:
            prev_path, prev_bytes = prev_backup
            prev_text = client.extract_text_for_drift(prev_bytes)
            drift_result = analyze_drift(
                old_content=prev_text,
                new_content=config_text,
                old_label=f"{dev_name} ({prev_path.name})",
                new_label=f"{dev_name} (Current {timestamp})"
            )

            if drift_result.has_real_drift:
                drift_status = "DRIFT_DETECTED"
                logger.warning(
                    f"[{dev_name}] Real configuration drift detected! "
                    f"Changed lines: {len(drift_result.real_changes)}. ENC noise filtered: {drift_result.enc_noise_count}."
                )
            elif drift_result.has_raw_diff and not drift_result.has_real_drift:
                drift_status = "NO_DRIFT (ENC_FILTERED)"
                logger.info(f"[{dev_name}] Benign ENC noise detected ({drift_result.enc_noise_count} tokens). Alert suppressed.")
            else:
                drift_status = "NO_DRIFT"
                logger.info(f"[{dev_name}] Configuration unchanged. Matches S3 baseline.")
        else:
            logger.info(f"[{dev_name}] No prior backup found in S3 or /tmp. Establishing initial baseline.")

        # Save copy in ephemeral /tmp
        local_storage.save_backup(dev_name, config_bytes, filename)

        # Upload to S3 using IAM Role
        s3_key = None
        try:
            s3_key = s3_manager.upload_backup(
                device_name=dev_name,
                device_type=dev_type,
                config_bytes=config_bytes,
                filename=filename,
                timestamp_str=timestamp,
                sha256_hash=sha256_hash
            )
            logger.info(f"[{dev_name}] Successfully uploaded to S3: {s3_key}")
        except StorageError as se:
            logger.error(f"[{dev_name}] S3 Upload failed: {se}")

        # Send SMTP Alert if Drift Detected
        if mailer and drift_status == "DRIFT_DETECTED" and drift_result:
            try:
                mailer.send_drift_alert(
                    device_name=dev_name,
                    device_type=dev_type,
                    timestamp=timestamp,
                    sha256_hash=sha256_hash,
                    real_changes=drift_result.real_changes,
                    diff_text=drift_result.filtered_diff or drift_result.raw_diff,
                    s3_key=s3_key
                )
                logger.info(f"[{dev_name}] Drift alert email dispatched successfully.")
            except MailerError as me:
                logger.error(f"[{dev_name}] Failed to dispatch drift email: {me}")

        summary.append({
            "device": dev_name,
            "type": dev_type,
            "status": "SUCCESS",
            "drift": drift_status,
            "sha256": sha256_hash,
            "size_bytes": len(config_bytes),
            "s3_key": s3_key
        })

    logger.info("Lambda execution completed.")
    return {
        "statusCode": 200,
        "body": json.dumps(summary, default=str)
    }

