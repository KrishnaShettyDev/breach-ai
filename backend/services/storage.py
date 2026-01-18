"""
BREACH.AI - Cloud Storage Service
==================================

Cloudflare R2 / S3-compatible storage for:
- Scan reports (PDF, HTML, JSON)
- Evidence files (screenshots, data samples)
- Attack payloads and responses
- Exported data

Uses aioboto3 for async S3 operations.
"""

import hashlib
import mimetypes
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Optional, Dict, Any, BinaryIO, Union
from uuid import UUID, uuid4

import structlog
from pydantic import BaseModel

from backend.config import settings

logger = structlog.get_logger(__name__)


# Storage configuration
class StorageConfig(BaseModel):
    """Storage configuration."""
    endpoint_url: str = ""
    access_key_id: str = ""
    secret_access_key: str = ""
    bucket_name: str = "breach-ai"
    region: str = "auto"
    public_url: Optional[str] = None  # For public access URLs


# File metadata
class StoredFile(BaseModel):
    """Metadata for a stored file."""
    key: str
    bucket: str
    size: int
    content_type: str
    etag: str
    url: str
    created_at: datetime


class StorageService:
    """
    S3-compatible storage service for Cloudflare R2.

    Provides async file upload, download, and management.
    Falls back to local file storage if R2 is not configured.
    """

    def __init__(
        self,
        endpoint_url: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        bucket_name: Optional[str] = None,
        region: str = "auto",
        public_url: Optional[str] = None,
    ):
        self.endpoint_url = endpoint_url or getattr(settings, 'r2_endpoint_url', '')
        self.access_key_id = access_key_id or getattr(settings, 'r2_access_key_id', '')
        self.secret_access_key = secret_access_key or getattr(settings, 'r2_secret_access_key', '')
        self.bucket_name = bucket_name or getattr(settings, 'r2_bucket_name', 'breach-ai')
        self.region = region
        self.public_url = public_url or getattr(settings, 'r2_public_url', None)

        self._client = None
        self._session = None
        self._initialized = False

        # Check if R2 is configured
        self.enabled = bool(self.endpoint_url and self.access_key_id and self.secret_access_key)

        if not self.enabled:
            logger.warning(
                "storage_not_configured",
                message="R2 storage not configured. Using local file storage."
            )

    async def _get_client(self):
        """Get or create the S3 client."""
        if not self.enabled:
            return None

        if self._client is None:
            try:
                import aioboto3

                self._session = aioboto3.Session()
                self._client = await self._session.client(
                    's3',
                    endpoint_url=self.endpoint_url,
                    aws_access_key_id=self.access_key_id,
                    aws_secret_access_key=self.secret_access_key,
                    region_name=self.region,
                ).__aenter__()

                logger.info("storage_client_initialized", endpoint=self.endpoint_url)

            except ImportError:
                logger.error("aioboto3_not_installed", message="Install aioboto3 for R2 storage")
                self.enabled = False
                return None
            except Exception as e:
                logger.error("storage_client_failed", error=str(e))
                self.enabled = False
                return None

        return self._client

    async def initialize(self):
        """Initialize storage and ensure bucket exists."""
        if self._initialized or not self.enabled:
            return

        client = await self._get_client()
        if not client:
            return

        try:
            # Check if bucket exists, create if not
            try:
                await client.head_bucket(Bucket=self.bucket_name)
                logger.info("bucket_exists", bucket=self.bucket_name)
            except Exception:
                await client.create_bucket(Bucket=self.bucket_name)
                logger.info("bucket_created", bucket=self.bucket_name)

            self._initialized = True

        except Exception as e:
            logger.error("storage_init_failed", error=str(e))

    async def close(self):
        """Close the storage client."""
        if self._client:
            await self._client.__aexit__(None, None, None)
            self._client = None

    def _generate_key(
        self,
        folder: str,
        filename: str,
        organization_id: Optional[UUID] = None,
    ) -> str:
        """Generate a storage key for a file."""
        timestamp = datetime.utcnow().strftime("%Y/%m/%d")

        if organization_id:
            return f"{folder}/{organization_id}/{timestamp}/{filename}"
        return f"{folder}/{timestamp}/{filename}"

    def _get_content_type(self, filename: str) -> str:
        """Get content type from filename."""
        content_type, _ = mimetypes.guess_type(filename)
        return content_type or "application/octet-stream"

    # ============== Upload Operations ==============

    async def upload_file(
        self,
        file_data: Union[bytes, BinaryIO, BytesIO],
        filename: str,
        folder: str = "uploads",
        organization_id: Optional[UUID] = None,
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Optional[StoredFile]:
        """
        Upload a file to storage.

        Args:
            file_data: File content (bytes or file-like object)
            filename: Original filename
            folder: Folder/prefix for organization
            organization_id: Optional org association
            content_type: MIME type (auto-detected if not provided)
            metadata: Additional metadata to store

        Returns:
            StoredFile with metadata, or None if failed
        """
        await self.initialize()

        # Generate unique key
        unique_filename = f"{uuid4().hex[:8]}_{filename}"
        key = self._generate_key(folder, unique_filename, organization_id)

        # Get content type
        if not content_type:
            content_type = self._get_content_type(filename)

        # Convert to bytes if needed
        if isinstance(file_data, (BytesIO, BinaryIO)):
            file_data.seek(0)
            data = file_data.read()
        else:
            data = file_data

        # Calculate hash
        file_hash = hashlib.sha256(data).hexdigest()

        if self.enabled:
            return await self._upload_to_r2(
                key=key,
                data=data,
                content_type=content_type,
                metadata=metadata or {},
                file_hash=file_hash,
            )
        else:
            return await self._upload_to_local(
                key=key,
                data=data,
                content_type=content_type,
                file_hash=file_hash,
            )

    async def _upload_to_r2(
        self,
        key: str,
        data: bytes,
        content_type: str,
        metadata: Dict[str, str],
        file_hash: str,
    ) -> Optional[StoredFile]:
        """Upload to Cloudflare R2."""
        client = await self._get_client()
        if not client:
            return None

        try:
            response = await client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=data,
                ContentType=content_type,
                Metadata=metadata,
            )

            # Generate URL
            if self.public_url:
                url = f"{self.public_url.rstrip('/')}/{key}"
            else:
                url = f"{self.endpoint_url}/{self.bucket_name}/{key}"

            logger.info(
                "file_uploaded_r2",
                key=key,
                size=len(data),
                content_type=content_type,
            )

            return StoredFile(
                key=key,
                bucket=self.bucket_name,
                size=len(data),
                content_type=content_type,
                etag=file_hash,
                url=url,
                created_at=datetime.utcnow(),
            )

        except Exception as e:
            logger.error("r2_upload_failed", key=key, error=str(e))
            return None

    async def _upload_to_local(
        self,
        key: str,
        data: bytes,
        content_type: str,
        file_hash: str,
    ) -> Optional[StoredFile]:
        """Fallback to local file storage."""
        try:
            # Create local storage directory
            storage_dir = Path("./storage")
            file_path = storage_dir / key
            file_path.parent.mkdir(parents=True, exist_ok=True)

            # Write file
            with open(file_path, "wb") as f:
                f.write(data)

            logger.info(
                "file_uploaded_local",
                path=str(file_path),
                size=len(data),
            )

            return StoredFile(
                key=key,
                bucket="local",
                size=len(data),
                content_type=content_type,
                etag=file_hash,
                url=f"/storage/{key}",
                created_at=datetime.utcnow(),
            )

        except Exception as e:
            logger.error("local_upload_failed", key=key, error=str(e))
            return None

    # ============== Download Operations ==============

    async def download_file(self, key: str) -> Optional[bytes]:
        """
        Download a file from storage.

        Args:
            key: The storage key

        Returns:
            File contents as bytes, or None if not found
        """
        if self.enabled:
            return await self._download_from_r2(key)
        else:
            return await self._download_from_local(key)

    async def _download_from_r2(self, key: str) -> Optional[bytes]:
        """Download from Cloudflare R2."""
        client = await self._get_client()
        if not client:
            return None

        try:
            response = await client.get_object(
                Bucket=self.bucket_name,
                Key=key,
            )

            data = await response['Body'].read()
            logger.debug("file_downloaded_r2", key=key, size=len(data))
            return data

        except Exception as e:
            logger.error("r2_download_failed", key=key, error=str(e))
            return None

    async def _download_from_local(self, key: str) -> Optional[bytes]:
        """Download from local storage."""
        try:
            file_path = Path("./storage") / key

            if not file_path.exists():
                logger.warning("local_file_not_found", key=key)
                return None

            with open(file_path, "rb") as f:
                data = f.read()

            logger.debug("file_downloaded_local", path=str(file_path), size=len(data))
            return data

        except Exception as e:
            logger.error("local_download_failed", key=key, error=str(e))
            return None

    # ============== Presigned URLs ==============

    async def get_presigned_url(
        self,
        key: str,
        expires_in: int = 3600,
        method: str = "get_object",
    ) -> Optional[str]:
        """
        Generate a presigned URL for temporary access.

        Args:
            key: The storage key
            expires_in: URL expiration in seconds (default 1 hour)
            method: 'get_object' for download, 'put_object' for upload

        Returns:
            Presigned URL string, or None if failed
        """
        if not self.enabled:
            # For local storage, return direct path
            return f"/storage/{key}"

        client = await self._get_client()
        if not client:
            return None

        try:
            url = await client.generate_presigned_url(
                method,
                Params={
                    'Bucket': self.bucket_name,
                    'Key': key,
                },
                ExpiresIn=expires_in,
            )

            return url

        except Exception as e:
            logger.error("presigned_url_failed", key=key, error=str(e))
            return None

    # ============== Delete Operations ==============

    async def delete_file(self, key: str) -> bool:
        """
        Delete a file from storage.

        Args:
            key: The storage key

        Returns:
            True if deleted successfully
        """
        if self.enabled:
            return await self._delete_from_r2(key)
        else:
            return await self._delete_from_local(key)

    async def _delete_from_r2(self, key: str) -> bool:
        """Delete from Cloudflare R2."""
        client = await self._get_client()
        if not client:
            return False

        try:
            await client.delete_object(
                Bucket=self.bucket_name,
                Key=key,
            )
            logger.info("file_deleted_r2", key=key)
            return True

        except Exception as e:
            logger.error("r2_delete_failed", key=key, error=str(e))
            return False

    async def _delete_from_local(self, key: str) -> bool:
        """Delete from local storage."""
        try:
            file_path = Path("./storage") / key

            if file_path.exists():
                file_path.unlink()
                logger.info("file_deleted_local", path=str(file_path))
                return True

            return False

        except Exception as e:
            logger.error("local_delete_failed", key=key, error=str(e))
            return False

    # ============== List Operations ==============

    async def list_files(
        self,
        prefix: str = "",
        limit: int = 100,
    ) -> list[Dict[str, Any]]:
        """
        List files with a given prefix.

        Args:
            prefix: Key prefix to filter by
            limit: Maximum number of results

        Returns:
            List of file metadata dictionaries
        """
        if self.enabled:
            return await self._list_from_r2(prefix, limit)
        else:
            return await self._list_from_local(prefix, limit)

    async def _list_from_r2(self, prefix: str, limit: int) -> list[Dict[str, Any]]:
        """List files from Cloudflare R2."""
        client = await self._get_client()
        if not client:
            return []

        try:
            response = await client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=prefix,
                MaxKeys=limit,
            )

            files = []
            for obj in response.get('Contents', []):
                files.append({
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'last_modified': obj['LastModified'],
                    'etag': obj['ETag'].strip('"'),
                })

            return files

        except Exception as e:
            logger.error("r2_list_failed", prefix=prefix, error=str(e))
            return []

    async def _list_from_local(self, prefix: str, limit: int) -> list[Dict[str, Any]]:
        """List files from local storage."""
        try:
            storage_dir = Path("./storage")
            if not storage_dir.exists():
                return []

            files = []
            for file_path in storage_dir.rglob("*"):
                if file_path.is_file():
                    rel_path = str(file_path.relative_to(storage_dir))
                    if rel_path.startswith(prefix):
                        stat = file_path.stat()
                        files.append({
                            'key': rel_path,
                            'size': stat.st_size,
                            'last_modified': datetime.fromtimestamp(stat.st_mtime),
                            'etag': hashlib.sha256(file_path.read_bytes()).hexdigest()[:32],
                        })

                        if len(files) >= limit:
                            break

            return files

        except Exception as e:
            logger.error("local_list_failed", prefix=prefix, error=str(e))
            return []

    # ============== Convenience Methods ==============

    async def upload_report(
        self,
        report_data: bytes,
        report_type: str,  # 'pdf', 'html', 'json'
        scan_id: UUID,
        organization_id: UUID,
    ) -> Optional[StoredFile]:
        """Upload a scan report."""
        filename = f"report_{scan_id}.{report_type}"
        content_type = {
            'pdf': 'application/pdf',
            'html': 'text/html',
            'json': 'application/json',
        }.get(report_type, 'application/octet-stream')

        return await self.upload_file(
            file_data=report_data,
            filename=filename,
            folder="reports",
            organization_id=organization_id,
            content_type=content_type,
            metadata={
                'scan_id': str(scan_id),
                'report_type': report_type,
            },
        )

    async def upload_evidence(
        self,
        evidence_data: bytes,
        filename: str,
        breach_session_id: UUID,
        organization_id: UUID,
        evidence_type: str = "screenshot",
    ) -> Optional[StoredFile]:
        """Upload breach evidence."""
        return await self.upload_file(
            file_data=evidence_data,
            filename=filename,
            folder="evidence",
            organization_id=organization_id,
            metadata={
                'breach_session_id': str(breach_session_id),
                'evidence_type': evidence_type,
            },
        )

    async def get_health(self) -> Dict[str, Any]:
        """Get storage health status."""
        if not self.enabled:
            return {
                'status': 'local',
                'message': 'Using local file storage (R2 not configured)',
                'bucket': 'local',
            }

        try:
            client = await self._get_client()
            if client:
                await client.head_bucket(Bucket=self.bucket_name)
                return {
                    'status': 'healthy',
                    'provider': 'cloudflare_r2',
                    'bucket': self.bucket_name,
                    'endpoint': self.endpoint_url,
                }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
            }

        return {'status': 'unknown'}


# ============== Global Instance ==============

_storage_service: Optional[StorageService] = None


def get_storage_service() -> StorageService:
    """Get the global storage service instance."""
    global _storage_service
    if _storage_service is None:
        _storage_service = StorageService()
    return _storage_service


async def upload_file(
    file_data: Union[bytes, BinaryIO],
    filename: str,
    folder: str = "uploads",
    organization_id: Optional[UUID] = None,
) -> Optional[StoredFile]:
    """Convenience function to upload a file."""
    storage = get_storage_service()
    return await storage.upload_file(
        file_data=file_data,
        filename=filename,
        folder=folder,
        organization_id=organization_id,
    )


async def download_file(key: str) -> Optional[bytes]:
    """Convenience function to download a file."""
    storage = get_storage_service()
    return await storage.download_file(key)


async def get_presigned_url(key: str, expires_in: int = 3600) -> Optional[str]:
    """Convenience function to get a presigned URL."""
    storage = get_storage_service()
    return await storage.get_presigned_url(key, expires_in)
