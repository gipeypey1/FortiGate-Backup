#!/usr/bin/env python3
"""
Fortinet Automated Backup & Drift Detection Engine.
Author: Network & Security Automation
Supports: FortiGate (HA Dedicated Mgmt), FortiWeb (HA Dedicated Mgmt),
          S3 (AWS S3 & NetApp S3), Smart Drift Detection, SMTP Alerting.
"""

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

# NetApp ONTAP S3 & StorageGRID compatibility
os.environ.setdefault("AWS_REQUEST_CHECKSUM_CALCULATION", "when_required")
os.environ.setdefault("AWS_RESPONSE_CHECKSUM_VALIDATION", "when_required")

from src.config_loader import (
    load_environment,
    load_devices_config,
    get_s3_config,
    get_smtp_config,
    ConfigError
)
from src.logger import setup_logger
from src.drift import calculate_sha256, analyze_drift
from src.devices import FortiGateDevice, FortiWebDevice, DeviceError, TruncatedBackupError
from src.storage import S3StorageManager, LocalStorageManager, StorageError
from src.notifier import SMTPMailer, MailerError


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fortinet Automated Backup & Drift Detection Tool"
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to devices.yaml configuration file"
    )
    parser.add_argument(
        "--env",
        type=str,
        default=None,
        help="Path to .env configuration file"
    )
    parser.add_argument(
        "--device",
        type=str,
        default=None,
        help="Run backup for a specific device name only"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Execute backup & drift analysis without uploading to S3 or sending emails"
    )
    parser.add_argument(
        "--test-smtp",
        action="store_true",
        help="Test connection to the configured SMTP server and exit"
    )
    parser.add_argument(
        "--test-s3",
        action="store_true",
        help="Test connection to the target S3 bucket (AWS/NetApp) and exit"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging output"
    )
    return parser.parse_args()


def process_device(
    dev_cfg: Dict[str, Any],
    local_storage: LocalStorageManager,
    s3_manager: S3StorageManager,
    mailer: SMTPMailer,
    dry_run: bool,
    logger
) -> Dict[str, Any]:
    """Processes backup, validation, drift detection, storage, and alerting for a single device."""
    dev_name = dev_cfg["name"]
    dev_type = dev_cfg["type"]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    logger.info(f"[{dev_name}] Starting backup process ({dev_type.upper()} @ {dev_cfg['host']})")

    # 1. Instantiate Device Client
    if dev_type == "fortigate":
        client = FortiGateDevice(dev_cfg)
    elif dev_type == "fortiweb":
        client = FortiWebDevice(dev_cfg)
    else:
        logger.error(f"[{dev_name}] Unsupported device type: {dev_type}")
        return {"device": dev_name, "status": "ERROR", "message": f"Unsupported type {dev_type}"}

    # 2. Pull configuration from REST API
    try:
        config_bytes = client.pull_config()
    except (TruncatedBackupError, DeviceError) as e:
        err_msg = str(e)
        logger.error(f"[{dev_name}] Backup failed: {err_msg}", extra={"device": dev_name, "event": "BACKUP_FAILED"})
        if not dry_run and mailer:
            try:
                mailer.send_failure_alert(dev_name, err_msg)
            except Exception as mail_err:
                logger.warning(f"[{dev_name}] Failed to send error email: {mail_err}")
        return {"device": dev_name, "type": dev_type, "status": "FAILED", "message": err_msg}
    except Exception as e:
        err_msg = f"Unexpected error: {e}"
        logger.exception(f"[{dev_name}] Unexpected error during pull")
        if not dry_run and mailer:
            try:
                mailer.send_failure_alert(dev_name, err_msg)
            except Exception:
                pass
        return {"device": dev_name, "type": dev_type, "status": "FAILED", "message": err_msg}

    # 3. Calculate SHA-256 fingerprint
    sha256_hash = calculate_sha256(config_bytes)
    config_text = config_bytes.decode("utf-8", errors="replace")
    logger.info(f"[{dev_name}] Backup downloaded successfully. SHA-256: {sha256_hash[:16]}... ({len(config_bytes):,} bytes)")

    # 4. Drift Detection against previous local backup
    prev_backup = local_storage.get_latest_backup(dev_name)
    s3_key = None
    drift_status = "INITIAL_BACKUP"

    if prev_backup:
        prev_path, prev_text = prev_backup
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
                f"Changed lines: {len(drift_result.real_changes)}. ENC noise filtered: {drift_result.enc_noise_count}.",
                extra={"device": dev_name, "event": "DRIFT_DETECTED", "changes_count": len(drift_result.real_changes)}
            )
        elif drift_result.has_raw_diff and not drift_result.has_real_drift:
            drift_status = "NO_DRIFT (ENC_FILTERED)"
            logger.info(
                f"[{dev_name}] Raw difference detected, but changes are solely dynamic ENC re-encryption noise. "
                f"Filtered {drift_result.enc_noise_count} ENC tokens. Alert suppressed.",
                extra={"device": dev_name, "event": "ENC_NOISE_IGNORED"}
            )
        else:
            drift_status = "NO_DRIFT"
            logger.info(f"[{dev_name}] Configuration unchanged. Fingerprint matches baseline.")
    else:
        logger.info(f"[{dev_name}] No previous backup found. Establishing initial baseline.")
        drift_result = None

    # 5. Save local backup copy
    saved_path = local_storage.save_backup(dev_name, config_bytes, timestamp, sha256_hash)
    logger.debug(f"[{dev_name}] Saved local cache to {saved_path}")

    # 6. Upload to S3 (if not dry-run)
    if not dry_run and s3_manager:
        try:
            s3_key = s3_manager.upload_backup(
                device_name=dev_name,
                device_type=dev_type,
                config_bytes=config_bytes,
                timestamp_str=timestamp,
                sha256_hash=sha256_hash
            )
            logger.info(f"[{dev_name}] Successfully uploaded to S3: {s3_key}", extra={"device": dev_name, "s3_key": s3_key})
        except StorageError as se:
            logger.error(f"[{dev_name}] S3 Upload failed: {se}")

    # 7. Send SMTP Alert if Real Drift Detected
    if not dry_run and mailer and drift_status == "DRIFT_DETECTED" and drift_result:
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
            logger.info(f"[{dev_name}] Drift alert email dispatched successfully to recipients.")
        except MailerError as me:
            logger.error(f"[{dev_name}] Failed to dispatch drift email alert: {me}")

    return {
        "device": dev_name,
        "type": dev_type,
        "status": "SUCCESS",
        "drift": drift_status,
        "sha256": sha256_hash,
        "size_bytes": len(config_bytes),
        "s3_key": s3_key
    }


def main():
    args = parse_arguments()
    logger = setup_logger(debug=args.debug)

    print("=" * 70)
    print(" Fortinet Automated Backup & Drift Detection Engine")
    print("=" * 70)

    # 1. Load Environment (.env)
    try:
        load_environment(args.env)
    except Exception as e:
        logger.error(f"Failed to load environment: {e}")
        sys.exit(1)

    # 2. Test S3 mode if requested
    if args.test_s3:
        try:
            s3_cfg = get_s3_config()
            s3_mgr = S3StorageManager(s3_cfg)
            target_desc = f"NetApp S3 ({s3_cfg['endpoint_url']})" if s3_cfg["is_custom_endpoint"] else "AWS S3"
            logger.info(f"Testing connectivity to {target_desc} bucket '{s3_cfg['bucket_name']}'...")
            s3_mgr.test_connection()
            logger.info(">>> S3 Connection Test PASSED successfully! <<<")
            sys.exit(0)
        except Exception as e:
            logger.error(f">>> S3 Connection Test FAILED: {e} <<<")
            sys.exit(1)

    # 3. Test SMTP mode if requested
    if args.test_smtp:
        smtp_cfg = get_smtp_config()
        if not smtp_cfg:
            logger.error("SMTP is not configured in .env")
            sys.exit(1)
        try:
            logger.info(f"Testing SMTP connection to {smtp_cfg['host']}:{smtp_cfg['port']}...")
            mailer = SMTPMailer(smtp_cfg)
            mailer.test_connection()
            logger.info(">>> SMTP Connection Test PASSED successfully! <<<")
            sys.exit(0)
        except Exception as e:
            logger.error(f">>> SMTP Connection Test FAILED: {e} <<<")
            sys.exit(1)

    # 4. Load Devices Inventory
    try:
        devices = load_devices_config(args.config)
    except ConfigError as ce:
        logger.error(f"Configuration Error: {ce}")
        sys.exit(1)

    # Filter device if --device is passed
    if args.device:
        devices = [d for d in devices if d["name"].lower() == args.device.lower()]
        if not devices:
            logger.error(f"Device '{args.device}' not found in configuration.")
            sys.exit(1)

    # 5. Initialize S3 & Local Storage
    local_storage = LocalStorageManager()
    s3_manager = None
    if not args.dry_run:
        try:
            s3_cfg = get_s3_config()
            s3_manager = S3StorageManager(s3_cfg)
        except ConfigError as ce:
            logger.warning(f"S3 is not configured: {ce}. Running in local-only mode.")

    # 6. Initialize Mailer
    smtp_cfg = get_smtp_config()
    mailer = SMTPMailer(smtp_cfg) if smtp_cfg else None
    if not mailer:
        logger.info("SMTP configuration not detected or incomplete. Email alerts disabled.")

    if args.dry_run:
        logger.info("[DRY-RUN MODE ACTIVE] No files will be uploaded to S3 and no emails will be sent.")

    # 7. Execute backup loop
    summary: List[Dict[str, Any]] = []
    for dev in devices:
        res = process_device(
            dev_cfg=dev,
            local_storage=local_storage,
            s3_manager=s3_manager,
            mailer=mailer,
            dry_run=args.dry_run,
            logger=logger
        )
        summary.append(res)

    # 8. Print Run Summary
    print("\n" + "=" * 70)
    print(" EXECUTION SUMMARY")
    print("=" * 70)
    print(f"{'DEVICE':<15} {'TYPE':<10} {'STATUS':<10} {'DRIFT':<22} {'SIZE'}")
    print("-" * 70)
    for s in summary:
        dev = s.get("device", "-")
        dtype = s.get("type", "-")
        status = s.get("status", "-")
        drift = s.get("drift", "-")
        size = f"{s.get('size_bytes', 0):,} B" if "size_bytes" in s else s.get("message", "-")
        print(f"{dev:<15} {dtype:<10} {status:<10} {drift:<22} {size}")
    print("=" * 70)


if __name__ == "__main__":
    main()

