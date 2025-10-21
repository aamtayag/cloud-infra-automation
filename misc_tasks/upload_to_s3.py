#!/usr/bin/env python3

# ###########################################################
# Script name: upload_to_s3.py
# Description
#   Upload a local file to an AWS S3 bucket.
# Usage:
#   python upload_to_s3.py /path/to/file.zip my-bucket
#   python upload_to_s3.py ./report.csv my-bucket --key data/2025/report.csv
#   python upload_to_s3.py ./video.mp4 my-bucket --profile myaws --acl private --storage-class STANDARD_IA
# Requires:
#   - boto3
#   - (optional) tqdm for a nicer progress bar
# IAM needed:
#   - s3:PutObject
#   - s3:PutObjectAcl (only if you use --acl)
#   - kms:Encrypt (if you use SSE-KMS with --sse aws:kms)
# ###########################################################

import argparse
import os
import sys
import mimetypes
from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from boto3.s3.transfer import TransferConfig

# -------- Progress helper --------
class ProgressBar:
    def __init__(self, filename: str, size: int):
        self.size = size
        self.seen = 0
        # Try nice progress bar if tqdm is available
        try:
            from tqdm import tqdm  # type: ignore
            self._bar = tqdm(total=size, unit='B', unit_scale=True, desc=os.path.basename(filename))
            self._use_tqdm = True
        except Exception:
            self._bar = None
            self._use_tqdm = False

    def __call__(self, bytes_amount: int):
        self.seen += bytes_amount
        if self._use_tqdm:
            self._bar.update(bytes_amount)
        else:
            # Simple fallback: print percentage occasionally
            pct = (self.seen / self.size * 100) if self.size else 100
            if self.seen == self.size or self.seen % (1024 * 1024) < 8192:  # every ~1MB
                print(f"\rUploaded {self.seen}/{self.size} bytes ({pct:.1f}%)", end="", flush=True)

    def close(self):
        if self._use_tqdm and self._bar:
            self._bar.close()
        else:
            print()  # newline for fallback mode


def guess_content_type(path: str) -> str:
    ctype, _ = mimetypes.guess_type(path)
    return ctype or "application/octet-stream"


def parse_args():
    p = argparse.ArgumentParser(description="Upload a local file to an AWS S3 bucket.")
    p.add_argument("file_path", help="Path to the local file to upload")
    p.add_argument("bucket", help="Target S3 bucket name")
    p.add_argument("--key", help="S3 object key (defaults to basename of file_path)")
    p.add_argument("--profile", help="AWS credential profile name")
    p.add_argument("--region", help="AWS region (optional; usually not required for S3)")
    p.add_argument("--acl", choices=["private", "public-read", "public-read-write", "authenticated-read",
                                     "aws-exec-read", "bucket-owner-read", "bucket-owner-full-control"],
                   help="Canned ACL to apply to the object")
    p.add_argument("--storage-class", default="STANDARD",
                   choices=["STANDARD", "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA",
                            "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE"],
                   help="S3 storage class (default: STANDARD)")
    p.add_argument("--sse", choices=["AES256", "aws:kms"],
                   help="Server-side encryption (SSE-S3=AES256 or SSE-KMS=aws:kms)")
    p.add_argument("--kms-key-id", help="KMS key ID/ARN (required if --sse aws:kms without a default bucket key)")
    p.add_argument("--metadata", action="append",
                   help="Add user metadata as key=value (repeatable), e.g., --metadata project=foo --metadata env=dev")
    p.add_argument("--multipart-threshold-mb", type=int, default=64,
                   help="Multipart upload threshold in MB (default: 64MB)")
    p.add_argument("--max-concurrency", type=int, default=8,
                   help="Max threads for multipart upload (default: 8)")
    return p.parse_args()


def parse_metadata(meta_args) -> Optional[dict]:
    if not meta_args:
        return None
    md = {}
    for item in meta_args:
        if "=" not in item:
            raise ValueError(f"Invalid --metadata '{item}', expected key=value")
        k, v = item.split("=", 1)
        md[k.strip()] = v.strip()
    return md


# #####################################
# Main
# #####################################

def main():
    args = parse_args()

    # Validate file
    if not os.path.isfile(args.file_path):
        print(f"ERROR: File not found: {args.file_path}", file=sys.stderr)
        sys.exit(1)

    file_size = os.path.getsize(args.file_path)
    key = args.key or os.path.basename(args.file_path)

    # AWS session
    session_kwargs = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    if args.region:
        session_kwargs["region_name"] = args.region
    session = boto3.Session(**session_kwargs)

    s3 = session.client("s3")

    # Transfer config for big files
    config = TransferConfig(
        multipart_threshold=args.multipart_threshold_mb * 1024 * 1024,
        max_concurrency=args.max_concurrency,
        multipart_chunksize=8 * 1024 * 1024,   # 8MB parts
        use_threads=True,
    )

    extra_args = {
        "ContentType": guess_content_type(args.file_path),
        "StorageClass": args.storage_class,
    }
    if args.acl:
        extra_args["ACL"] = args.acl
    if args.sse:
        # SSE-S3 or SSE-KMS
        if args.sse == "AES256":
            extra_args["ServerSideEncryption"] = "AES256"
        else:
            extra_args["ServerSideEncryption"] = "aws:kms"
            if args.kms_key_id:
                extra_args["SSEKMSKeyId"] = args.kms_key_id
    metadata = parse_metadata(args.metadata)
    if metadata:
        extra_args["Metadata"] = metadata

    progress = ProgressBar(args.file_path, file_size)
    try:
        s3.upload_file(
            Filename=args.file_path,
            Bucket=args.bucket,
            Key=key,
            ExtraArgs=extra_args,
            Callback=progress,
            Config=config,
        )
    except (ClientError, BotoCoreError) as e:
        progress.close()
        print(f"\nUpload failed: {e}", file=sys.stderr)
        sys.exit(2)
    else:
        progress.close()
        url = f"s3://{args.bucket}/{key}"
        print(f"Upload succeeded: {url}")
        # You can also print a presigned URL if desired:
        # presigned = s3.generate_presigned_url('get_object', Params={'Bucket': args.bucket, 'Key': key}, ExpiresIn=3600)
        # print(f"Temporary download URL (1h): {presigned}")


if __name__ == "__main__":
    main()
