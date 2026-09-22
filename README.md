import boto3
import json
import logging
import os

from datetime import datetime, timezone
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


# ============================================================
# CONFIGURATION
# ============================================================

CENTRAL_BUCKET = os.environ.get(
    "CENTRAL_BUCKET",
    "clsa-aws-cloudtrail-381492218357"
)

MEMBER_ROLE_NAME = os.environ.get(
    "MEMBER_ROLE_NAME",
    "KMSInventoryReadRole"
)

CURRENT_OBJECT_KEY = os.environ.get(
    "CURRENT_OBJECT_KEY",
    "current/kms-inventory.json"
)

EXTERNAL_ID = os.environ.get(
    "EXTERNAL_ID",
    ""
).strip()


# Start with ONE account first.
# After the test succeeds, add the remaining accounts.
TARGET_ACCOUNTS = [
    {
        "account_id": "590183669178",
        "account_name": "Test-Account"
    }
]


# ============================================================
# LOGGING AND AWS CLIENT CONFIGURATION
# ============================================================

logger = logging.getLogger()
logger.setLevel(logging.INFO)

BOTO_CONFIG = Config(
    retries={
        "max_attempts": 8,
        "mode": "adaptive"
    },
    connect_timeout=10,
    read_timeout=60
)

sts_client = boto3.client(
    "sts",
    config=BOTO_CONFIG
)

s3_client = boto3.client(
    "s3",
    config=BOTO_CONFIG
)


# ============================================================
# GENERAL HELPERS
# ============================================================

def to_utc_iso(value):
    if value is None:
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc).isoformat()


def create_empty_record(
    snapshot_time,
    account_id,
    account_name,
    region,
    collection_error=None
):
    return {
        "snapshot_time": snapshot_time,
        "account_id": account_id,
        "account_name": account_name,
        "region": region,
        "key_id": None,
        "key_arn": None,
        "aliases": [],
        "primary_alias": None,
        "description": None,
        "key_state": None,
        "key_manager": None,
        "key_spec": None,
        "key_usage": None,
        "origin": None,
        "creation_date": None,
        "deletion_date": None,
        "enabled": None,
        "multi_region": None,
        "pending_deletion": None,
        "tags": {},
        "rotation_supported": None,
        "rotation_enabled": None,
        "rotation_period_days": None,
        "next_rotation_date": None,
        "collection_error": collection_error
    }


def append_error(record, message):
    if record.get("collection_error"):
        record["collection_error"] = (
            record["collection_error"] + "; " + message
        )
    else:
        record["collection_error"] = message


# ============================================================
# CROSS-ACCOUNT ACCESS
# ============================================================

def assume_member_role(account_id):
    role_arn = (
        "arn:aws:iam::"
        + account_id
        + ":role/"
        + MEMBER_ROLE_NAME
    )

    request = {
        "RoleArn": role_arn,
        "RoleSessionName": "KMSInventoryCollector",
        "DurationSeconds": 3600
    }

    if EXTERNAL_ID:
        request["ExternalId"] = EXTERNAL_ID

    response = sts_client.assume_role(**request)
    credentials = response["Credentials"]

    logger.info("AssumeRole successful: %s", role_arn)

    return {
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"],
        "aws_session_token": credentials["SessionToken"]
    }


def create_assumed_client(
    service_name,
    region_name,
    credentials
):
    return boto3.client(
        service_name,
        region_name=region_name,
        aws_access_key_id=credentials[
            "aws_access_key_id"
        ],
        aws_secret_access_key=credentials[
            "aws_secret_access_key"
        ],
        aws_session_token=credentials[
            "aws_session_token"
        ],
        config=BOTO_CONFIG
    )


# ============================================================
# REGION DISCOVERY
# ============================================================

def list_enabled_regions(credentials):
    ec2_client = create_assumed_client(
        service_name="ec2",
        region_name="us-east-1",
        credentials=credentials
    )

    response = ec2_client.describe_regions(
        AllRegions=False
    )

    regions = []

    for region in response.get("Regions", []):
        region_name = region.get("RegionName")

        if region_name:
            regions.append(region_name)

    return sorted(regions)


# ============================================================
# KMS HELPERS
# ============================================================

def list_all_keys(kms_client):
    keys = []

    paginator = kms_client.get_paginator(
        "list_keys"
    )

    for page in paginator.paginate():
        keys.extend(
            page.get("Keys", [])
        )

    return keys


def build_alias_map(kms_client):
    alias_map = {}

    paginator = kms_client.get_paginator(
        "list_aliases"
    )

    for page in paginator.paginate():
        for alias_entry in page.get(
            "Aliases",
            []
        ):
            target_key_id = alias_entry.get(
                "TargetKeyId"
            )

            alias_name = alias_entry.get(
                "AliasName"
            )

            if target_key_id and alias_name:
                alias_map.setdefault(
                    target_key_id,
                    []
                ).append(alias_name)

    for key_id in alias_map:
        alias_map[key_id] = sorted(
            set(alias_map[key_id])
        )

    return alias_map


def get_key_tags(kms_client, key_id):
    tags = {}
    marker = None

    while True:
        request = {
            "KeyId": key_id,
            "Limit": 50
        }

        if marker:
            request["Marker"] = marker

        response = kms_client.list_resource_tags(
            **request
        )

        for tag in response.get("Tags", []):
            tag_key = tag.get("TagKey")
            tag_value = tag.get(
                "TagValue",
                ""
            )

            if tag_key
