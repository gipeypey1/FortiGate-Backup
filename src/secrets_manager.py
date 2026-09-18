"""
AWS Secrets Manager Loader.
Retrieves credentials securely from AWS Secrets Manager and injects them
into the environment, avoiding hardcoded secrets in .env or Lambda definitions.
"""

import json
import logging
import os
from typing import Dict, Optional
import boto3
from botocore.exceptions import ClientError, BotoCoreError

logger = logging.getLogger("forti_backup")


def load_aws_secrets(
    secret_name: Optional[str] = None,
    region_name: Optional[str] = None
) -> Dict[str, str]:
    """
    Fetches JSON credentials from AWS Secrets Manager and injects them into os.environ.
    If secret_name is not passed, checks environment variable 'AWS_SECRET_NAME' or 'FORTINET_SECRET_NAME'.
    Returns dictionary of loaded secrets.
    """
    name = (
        secret_name
        or os.getenv("AWS_SECRET_NAME", "").strip()
        or os.getenv("FORTINET_SECRET_NAME", "").strip()
    )

    if not name:
        # No AWS Secrets Manager secret specified; rely on environment variables
        return {}

    region = (
        region_name
        or os.getenv("AWS_REGION", "").strip()
        or os.getenv("S3_REGION", "us-east-1").strip()
    )

    logger.info(f"Retrieving credentials from AWS Secrets Manager: '{name}' (region: {region})...")

    try:
        client = boto3.client("secretsmanager", region_name=region)
        response = client.get_secret_value(SecretId=name)

        secret_str = response.get("SecretString")
        if not secret_str:
            logger.warning(f"AWS Secret '{name}' does not contain SecretString payload.")
            return {}

        secrets_dict = json.loads(secret_str)
        if not isinstance(secrets_dict, dict):
            logger.warning(f"AWS Secret '{name}' payload is not a valid JSON object.")
            return {}

        # Inject retrieved secrets into os.environ
        injected_count = 0
        for key, val in secrets_dict.items():
            if val is not None:
                os.environ[key] = str(val)
                injected_count += 1

        logger.info(f"Successfully loaded and injected {injected_count} secrets from AWS Secrets Manager.")
        return secrets_dict

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        logger.error(f"Failed to fetch secret from AWS Secrets Manager [{error_code}]: {e}")
        return {}
    except (BotoCoreError, json.JSONDecodeError) as e:
        logger.error(f"Error processing AWS Secret '{name}': {e}")
        return {}

