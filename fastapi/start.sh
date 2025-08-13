#!/bin/bash
cd "$(dirname "$0")"  # Change to the directory containing the script
source ../venv/bin/activate
export PYTHONPATH=$PYTHONPATH:$(dirname $(pwd))
uvicorn endpoints:app --host 0.0.0.0 --port 8000 --reload
