#!/bin/bash

# Ensure an image name was provided
if [ -z "$1" ]; then
  echo "Error: No image specified"
  echo "Usage: $0 <image-name>"
  exit 1
fi

IMAGE=$1
echo "Scanning $IMAGE for CRITICAL vulnerabilities..."
trivy image --exit-code 1 --severity CRITICAL $IMAGE

exit_code=$?
if [ $exit_code -eq 0 ]; then
  echo "No CRITICAL vulnerabilities found"
else
  echo "CRITICAL vulnerabilities found"
fi

exit $exit_code