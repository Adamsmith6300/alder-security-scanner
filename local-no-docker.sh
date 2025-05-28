#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# --- Configuration ---
ENV_FILE=".env"
REPORTS_DIR="./local-reports-no-docker" # Separate reports directory
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=9
PYTHON_CMD="python3" # Command to run python. Change this if your desired python 3.9+ is named differently (e.g., python3.11)
# -------------------

# --- Helper Function for Python Version Check ---
check_python_version() {
    if ! command -v $PYTHON_CMD &> /dev/null; then
        echo "Error: $PYTHON_CMD is not installed or not in PATH."
        echo "Please install Python $MIN_PYTHON_MAJOR.$MIN_PYTHON_MINOR or newer."
        exit 1
    fi

    PY_VERSION_OUTPUT=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PY_MAJOR=$(echo "$PY_VERSION_OUTPUT" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION_OUTPUT" | cut -d. -f2)

    if ! [[ "$PY_MAJOR" -gt "$MIN_PYTHON_MAJOR" || ( "$PY_MAJOR" -eq "$MIN_PYTHON_MAJOR" && "$PY_MINOR" -ge "$MIN_PYTHON_MINOR" ) ]]; then
        echo "Error: Your $PYTHON_CMD version is $PY_MAJOR.$PY_MINOR."
        echo "This script requires Python $MIN_PYTHON_MAJOR.$MIN_PYTHON_MINOR or newer (Python 3.11 is used in Docker).
Please use a virtual environment with an appropriate Python version or set the PYTHON_CMD variable in this script
to point to a compatible Python executable (e.g., python3.9, python3.10, python3.11)."
        exit 1
    fi
    echo "$PYTHON_CMD version $PY_MAJOR.$PY_MINOR found, which meets the requirement (>= $MIN_PYTHON_MAJOR.$MIN_PYTHON_MINOR)."
}
# -----------------------------------------------

# --- Argument Parsing ---
if [ -z "$1" ]; then
  echo "Usage: ./local-no-docker.sh <path_to_repo_to_scan> [optional: --verbose] [optional: --extra-ignore-dirs <dirs>]"
  echo "Example: ./local-no-docker.sh ../my-test-repo"
  echo "Example: ./local-no-docker.sh ../my-test-repo --verbose"
  echo "Example: ./local-no-docker.sh ../my-test-repo --extra-ignore-dirs 'node_modules,dist'"
  exit 1
fi

REPO_PATH="$1"
shift # Remove the repo_path from arguments, remaining are for main.py

if [ ! -d "$REPO_PATH" ]; then
  echo "Error: Repository path '$REPO_PATH' not found."
  exit 1
fi

# Convert repo path to absolute path
REPO_ABS_PATH=$(cd "$REPO_PATH" && pwd)

# --- Pre-run Checks ---
# Check Python version first
check_python_version

# Check if .env file exists
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE file not found."
    echo "Please create an $ENV_FILE file with your GEMINI_API_KEY and OPENAI_API_KEY."
    exit 1
fi

# Source environment variables
echo "Loading environment variables from $ENV_FILE..."
set -o allexport # Export all variables defined from now on
source "$ENV_FILE"
set +o allexport # Stop exporting all variables

# Check required environment variables are loaded
if [ -z "$GEMINI_API_KEY" ] || [ -z "$OPENAI_API_KEY" ]; then
  echo "Error: One or more required environment variables (GEMINI_API_KEY, OPENAI_API_KEY) are missing or not set in $ENV_FILE."
  exit 1
fi
echo "Required environment variables loaded."

# Check for requirements.txt and prompt for installation
if [ -f "requirements.txt" ]; then
    echo "Checking Python dependencies from requirements.txt..."
    # Attempt to import a core package to see if venv might be active or packages installed
    # Use the validated $PYTHON_CMD
    if ! $PYTHON_CMD -c "import tiktoken" &> /dev/null; then # tiktoken is a key dependency
        echo "It seems some Python dependencies are missing or were installed with an incompatible Python version."
        echo "Make sure you are in a virtual environment with Python $MIN_PYTHON_MAJOR.$MIN_PYTHON_MINOR+ if you choose to install."
        read -p "Do you want to try installing/reinstalling them using '$PYTHON_CMD -m pip install -r requirements.txt'? (y/N): " choice
        if [[ "$choice" == "Y" || "$choice" == "y" ]]; then
            $PYTHON_CMD -m pip install -r requirements.txt
            echo "Dependencies installation attempted with $PYTHON_CMD."
        else
            echo "Please install dependencies manually using '$PYTHON_CMD -m pip install -r requirements.txt' in an appropriate environment (Python $MIN_PYTHON_MAJOR.$MIN_PYTHON_MINOR +) before running the script."
            exit 1
        fi
    else
        echo "Core dependencies seem to be present for $PYTHON_CMD."
    fi
else
    echo "Warning: requirements.txt not found. Assuming dependencies are already installed in the environment for $PYTHON_CMD."
fi
# ---------------------

# --- Setup ---
# Create reports directory
mkdir -p "$REPORTS_DIR"
REPORTS_ABS_PATH=$(cd "$REPORTS_DIR" && pwd)

echo "Scanning repository: $REPO_ABS_PATH"
echo "Reports will be saved to: $REPORTS_ABS_PATH"
# -------------

# --- Run Python Application ---
echo "Starting Python application src/main.py using $PYTHON_CMD..."

# Construct arguments for main.py
# The script's own arguments ($@) are passed along after $REPO_PATH was shifted out.
# These can include --verbose, --extra-ignore-dirs, etc.
PYTHON_ARGS="--verbose --local-path $REPO_ABS_PATH --output-dir $REPORTS_ABS_PATH $@"

echo "Executing command: $PYTHON_CMD -m src.main $PYTHON_ARGS"

# Run the python script
# Ensure PYTHONPATH includes the project root for `from .orchestrator import ...` to work
export PYTHONPATH=$(pwd):$PYTHONPATH
$PYTHON_CMD -m src.main $PYTHON_ARGS

# --- Completion ---
echo "---------------------------------------------------"
echo "Local scan (no-docker) finished."
echo "Reports should be available in: $REPORTS_DIR"
echo "---------------------------------------------------"
# ---------------- 
