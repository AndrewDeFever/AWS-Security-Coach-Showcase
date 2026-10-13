#!/usr/bin/env bash
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
BUCKET_NAME="${CLOUDTRAIL_BUCKET_NAME:-aws-cloudtrail-logs-123456789012-example}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIFECYCLE_FILE="${SCRIPT_DIR}/cloudtrail-lifecycle.json"

aws s3api put-bucket-lifecycle-configuration \
  --bucket "${BUCKET_NAME}" \
  --lifecycle-configuration "file://${LIFECYCLE_FILE}" \
  --region "${REGION}"

aws s3api get-bucket-lifecycle-configuration \
  --bucket "${BUCKET_NAME}" \
  --region "${REGION}" \
  --output json
