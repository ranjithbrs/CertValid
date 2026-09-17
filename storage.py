"""
storage.py - Cloud Storage Adapter for CertValid.
Supports AWS S3 object storage with transparent fallback to local disk.
"""

import os
import logging

logger = logging.getLogger(__name__)

S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', '')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

_s3_client = None


def get_s3_client():
    """Get or initialize boto3 S3 client if S3_BUCKET_NAME is set."""
    global _s3_client
    if _s3_client:
        return _s3_client

    if not S3_BUCKET_NAME:
        return None

    try:
        import boto3
        _s3_client = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            region_name=AWS_REGION
        )
        return _s3_client
    except Exception as e:
        logger.error(f"Failed to initialize S3 client: {e}")
        return None


def upload_to_s3(local_file_path: str, object_name: str = None) -> str:
    """
    Upload a local file to AWS S3 if S3_BUCKET_NAME is defined.
    Returns S3 public URL if uploaded, or local file path fallback.
    """
    s3 = get_s3_client()
    if not s3 or not S3_BUCKET_NAME:
        return local_file_path

    if object_name is None:
        object_name = f"certs/{os.path.basename(local_file_path)}"

    try:
        s3.upload_file(
            local_file_path,
            S3_BUCKET_NAME,
            object_name,
            ExtraArgs={'ContentType': 'image/png'}
        )
        s3_url = f"https://{S3_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{object_name}"
        logger.info(f"Uploaded {local_file_path} to S3: {s3_url}")
        return s3_url
    except Exception as e:
        logger.error(f"S3 upload failed: {e}")
        return local_file_path
