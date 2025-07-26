#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Set up base command arguments - local path is the mounted repository
CMD_ARGS="--local-path /workspace"

# Set default output directory  
OUTPUT_DIR="/app/security-reports"
CMD_ARGS="$CMD_ARGS --output-dir $OUTPUT_DIR"

# Add verbose flag by default
CMD_ARGS="$CMD_ARGS"

# Add any additional arguments passed from local.sh
if [ "$#" -gt 0 ]; then
  echo "Adding additional arguments: $@"
  CMD_ARGS="$CMD_ARGS $@"
fi

# Print the command being executed
echo "Running security analysis with command: python -m src.main $CMD_ARGS"

# Execute the security analysis from the /app directory (where the source code is located)
cd /app
python -m src.main $CMD_ARGS

# Check if the output directory exists
if [ -d "$OUTPUT_DIR" ]; then
    echo "Security analysis complete. Reports available in $OUTPUT_DIR directory."
else
    echo "::warning::Output directory $OUTPUT_DIR not found. Reports may not have been generated."
fi 
