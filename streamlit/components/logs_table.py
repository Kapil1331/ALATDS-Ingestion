import requests
import pandas as pd
import streamlit as st
import json

def render_logs_table():
    API_URL = "http://localhost:8000/wsl_predictions"

    st.header("WSL Predictions Logs")

    rows_to_show = 100

    try:
        # Fetch data
        response = requests.get(API_URL, timeout=10)
        response.raise_for_status()
        data = response.json()

        # Parse each record
        parsed_rows = []
        for row in data:
            # Copy base fields
            parsed_row = {k: v for k, v in row.items() if k != "log"}

            # Parse "log" JSON string (if it is a string)
            if isinstance(row.get("log"), str):
                try:
                    log_data = json.loads(row["log"])
                except json.JSONDecodeError:
                    log_data = {}
            elif isinstance(row.get("log"), dict):
                log_data = row["log"]
            else:
                log_data = {}

            # Merge top-level log fields
            for key, value in log_data.items():
                if key != "log":
                    parsed_row[f"log_{key}"] = value

            # Handle nested "log" inside "log"
            if isinstance(log_data.get("log"), dict):
                for key, value in log_data["log"].items():
                    parsed_row[f"inner_log_{key}"] = value

            parsed_rows.append(parsed_row)

        # Convert to DataFrame
        df = pd.DataFrame(parsed_rows)

        # Show limited rows
        st.dataframe(df.head(rows_to_show))

    except requests.RequestException as e:
        st.error(f"Failed to fetch data: {e}")
    except ValueError:
        st.error("Invalid JSON received from API.")