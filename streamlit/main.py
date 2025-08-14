import streamlit as st
import time
from components.terminal import terminal_component
from components.threat_chart import threat_chart_component
from components.logs_table import render_logs_table
from components.total_analysis_chart import total_analysis_chart
from components.employee_analysis_table import render_employee_analysis_table

st.set_page_config(page_title="Log Dashboard", layout="wide")

st.title("🚀 Log Monitoring & Threat Detection Dashboard")

# Create placeholder containers for components
terminal_placeholder = st.empty()
threat_chart_placeholder = st.empty()
total_analysis_placeholder = st.empty()
employee_analysis_placeholder = st.empty()
table_placeholder = st.empty()

# Refresh only components in a loop
refresh_interval = 5 # seconds

while True:
    with terminal_placeholder.container():
        terminal_component()

    with threat_chart_placeholder.container():
        threat_chart_component()

    with total_analysis_placeholder.container():
        total_analysis_chart()

    with employee_analysis_placeholder.container():
        render_employee_analysis_table()

    with table_placeholder.container():
        render_logs_table()

    time.sleep(refresh_interval)
