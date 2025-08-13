#!/bin/bash
source venv/bin/activate
uvicorn endpoints:app --host 0.0.0.0 --port 8000 --reload
