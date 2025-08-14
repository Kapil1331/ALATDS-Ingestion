import streamlit as st
import requests
import pandas as pd

API_URL = "http://localhost:8000/employee_analysis"

def render_employee_analysis_table():
    st.subheader("👥 Employee Analysis Results")
    try:
        response = requests.get(API_URL, timeout=5)
        if response.status_code == 200:
            data = response.json()

            # Parse the `log` field which is a JSON string
            parsed_data = []
            for row in data:
                log_info = {}
                try:
                    log_info = eval(row.get("log", "{}"))  # Can replace eval with json.loads if safer
                except Exception:
                    pass
                parsed_data.append({
                    "ID": row.get("id"),
                    "Log Type": row.get("log_type"),
                    "Log ID": row.get("log_id"),
                    "Is Threat": row.get("is_threat"),
                    **log_info
                })

            df = pd.DataFrame(parsed_data)

            # Display table
            st.dataframe(df, use_container_width=True)
        else:
            st.error(f"Failed to fetch data: {response.status_code}")
    except requests.RequestException as e:
        st.error(f"Error connecting to API: {e}")
