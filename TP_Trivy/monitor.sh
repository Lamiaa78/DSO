#!/bin/bash

IMAGES=("nginx:latest" "alpine:latest")
LOG_FILE="daily-scan.log"
DATE=$(date '+%Y-%m-%d')
SEVERITY="CRITICAL,HIGH"

echo "===== Container Vulnerability Scan: ${DATE} =====" > "${LOG_FILE}"

for IMAGE in "${IMAGES[@]}"; do
  echo -e "\nScanning image: ${IMAGE}" >> "${LOG_FILE}"
  if ! trivy image \
        --severity "${SEVERITY}" \
        --format table \
        --exit-code 1 \
        --cache-dir ~/.cache/trivy \
        "${IMAGE}" >> "${LOG_FILE}" 2>&1; then
    echo "WARNING: ${IMAGE} has ${SEVERITY} vulnerabilities!" >> "${LOG_FILE}"
  fi
done

echo -e "\nScan completed at $(date)" >> "${LOG_FILE}"
