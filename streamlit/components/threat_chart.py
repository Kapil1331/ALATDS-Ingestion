import streamlit as st
import pandas as pd
import requests
import plotly.express as px
import time

def threat_chart_component():
    st.subheader("🛡 Threat Distribution")

    backend_url = "http://localhost:8000/threat_dist"
    logtype = "wsl_predictions"  # fixed

    try:
        response = requests.get(backend_url, params={"logtype": logtype})
        if response.status_code == 200:
            data = response.json()
            df = pd.DataFrame(data)

            if not df.empty:
                st.write(df)

                fig = px.pie(
                    df,
                    names="threat_level",
                    values="count",
                    title=f"Threat Distribution for {logtype}",
                    hole=0.3
                )
                # Unique key to avoid duplicate ID error
                st.plotly_chart(fig, use_container_width=True, key=f"threat_chart_{time.time()}")

            else:
                st.warning("No data available for this log type.")
        else:
            st.error(f"Error {response.status_code}: {response.text}")

    except Exception as e:
        st.error(f"Failed to fetch data: {e}")
