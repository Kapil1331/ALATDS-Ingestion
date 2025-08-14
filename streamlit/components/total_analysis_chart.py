import streamlit as st
import requests
import pandas as pd

def total_analysis_chart():
    """Fetch total_analysis data and display a bar chart."""
    backend_url = "http://localhost:8000/total_analysis"

    try:
        response = requests.get(backend_url)
        response.raise_for_status()
        data = response.json()

        if data:
            df = pd.DataFrame(data)

            # Make sure the types are correct
            df["seq"] = pd.to_numeric(df["seq"], errors="coerce")

            # Show table (optional)
            st.dataframe(df, use_container_width=True)

            # Show bar chart
            st.bar_chart(df.set_index("name")["seq"])
        else:
            st.warning("No data available for Total Analysis.")
    except Exception as e:
        st.error(f"Failed to fetch Total Analysis: {e}")
