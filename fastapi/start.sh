source venv/bin/activate
python3 -m uvicorn endpoints:app --reload
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
