#!/bin/bash

VENV_NAME="netscan_venv"

python3 -m venv "$VENV_NAME"
source "$VENV_NAME/bin/activate"

pip install -e .

echo "Virtual environment '$VENV_NAME' is set up and activated."
echo "Run 'sudo netscan --help' to get started."
