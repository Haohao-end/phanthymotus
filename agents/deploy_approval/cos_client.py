"""COS (Tencent Cloud Object Storage) client for evidence uploads (final alignment).

Uses cos-python-sdk-v5 for authenticated uploads. Credentials are fully
separate from GitHub / Agent Core tokens.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from .config import Config

logger = logging.getLogger(__name__)


class CosError(Exception):
    pass


class CosClient:
    """Minimal COS client for uploading deploy artifacts.

    In production, this uses cos-python-sdk-v5. For testing, a fake
    implementation is provided.
    """

    def __init__(self, config: Config, _fake: bool = False):
        self.config = config
        self._fake = _fake
        self._uploads: list[dict] = []

    def build_object_key(
        self, repo: str, pr_number: int, head_sha: str,
        deployment_id: str,
    ) -> str:
        """Build a deterministic COS object key.

        Uses the full 40-character HEAD SHA. Never puts tokens or
        user-controlled path traversal in object keys.
        """
        safe_repo = repo.replace("/", "_").replace("..", "_")
        safe_head = head_sha[:40] if len(head_sha) > 40 else head_sha
        safe_dpl = deployment_id.replace("..", "_").replace("/", "_")
        timestamp = str(int(time.time()))
        return (
            f"{self.config.cos_prefix}/{safe_repo}/"
            f"pr{pr_number}/{safe_head}/{safe_dpl}/"
            f"{timestamp}/evidence.tar.gz"
        )

    async def upload_evidence_archive(
        self, object_key: str, archive_bytes: bytes
    ) -> bool:
        """Upload the evidence archive as bytes.

        Returns True on success, False on failure.
        """
        if self._fake:
            self._uploads.append({
                "key": object_key,
                "size": len(archive_bytes),
                "timestamp": time.time(),
            })
            return True

        if not self._has_credentials():
            return False

        try:
            from qcloud_cos import CosConfig, CosS3Client  # type: ignore
        except Exception as e:
            logger.error("COS SDK import failed: %s", e)
            return False

        try:
            config = CosConfig(
                Region=self.config.cos_region,
                SecretId=self.config.cos_secret_id,
                SecretKey=self.config.cos_secret_key,
                Token=self.config.cos_session_token or None,
            )
            client = CosS3Client(config)
            await asyncio.to_thread(
                client.put_object,
                Bucket=self.config.cos_bucket,
                Body=archive_bytes,
                Key=object_key,
            )
            return True
        except Exception as e:
            logger.error("COS upload failed: %s", e)
            return False

    async def generate_signed_url(self, object_key: str) -> str:
        """Generate a signed GET URL with bounded TTL.

        Returns empty string on failure.
        """
        if self._fake:
            return f"https://cos.example.com/{object_key}?signed={int(time.time())}"

        if not self._has_credentials():
            return ""

        try:
            from qcloud_cos import CosConfig, CosS3Client  # type: ignore
        except Exception as e:
            logger.error("COS SDK import failed: %s", e)
            return ""

        try:
            config = CosConfig(
                Region=self.config.cos_region,
                SecretId=self.config.cos_secret_id,
                SecretKey=self.config.cos_secret_key,
                Token=self.config.cos_session_token or None,
            )
            client = CosS3Client(config)
            return await asyncio.to_thread(
                client.get_presigned_url,
                Bucket=self.config.cos_bucket,
                Key=object_key,
                Method="GET",
                Expired=self.config.cos_signed_url_ttl_seconds,
            )
        except Exception as e:
            logger.error("COS signed URL generation failed: %s", e)
            return ""


    def _has_credentials(self) -> bool:
        return bool(
            self.config.cos_region
            and self.config.cos_bucket
            and self.config.cos_secret_id
            and self.config.cos_secret_key
        )
