#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Set up command arguments - local path is always the current directory
CMD_ARGS="--local-path $(pwd)"

# Set default output directory
OUTPUT_DIR="./security-reports"
CMD_ARGS="$CMD_ARGS --output-dir $OUTPUT_DIR"

# Add extra ignore dirs if INPUT_EXTRA_IGNORE_DIRS is set
if [ -n "$INPUT_EXTRA_IGNORE_DIRS" ]; then
  echo "Adding extra ignore directories: $INPUT_EXTRA_IGNORE_DIRS"
  CMD_ARGS="$CMD_ARGS --extra-ignore-dirs $INPUT_EXTRA_IGNORE_DIRS"
fi

# Set other default parameters
CMD_ARGS="$CMD_ARGS"

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
