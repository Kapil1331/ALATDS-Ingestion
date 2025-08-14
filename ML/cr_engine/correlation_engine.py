#!/usr/bin/env python3
"""
correlation_engine.py

Class for correlating anomalies across different event sources
within a defined time window.
"""

import pandas as pd
import numpy as np


class CorrelationEngine:
    def __init__(self, time_window_minutes=30):
        """
        Initialize the correlation engine.
        Args:
            time_window_minutes (int): Time window in minutes for correlation.
        """
        self.time_window = time_window_minutes

    def calculate_time_window(self, df_list):
        """
        Calculate optimal correlation window using median inter-event times.
        Args:
            df_list (list): List of DataFrames, each containing 'user' and 'datetime' columns.
        Returns:
            float: Optimal correlation window in minutes.
        """
        all_events = pd.concat([df[['user', 'datetime']] for df in df_list])
        all_events = all_events.sort_values(['user', 'datetime'])
        diffs = all_events.groupby('user')['datetime'].diff().dt.total_seconds().dropna()

        if diffs.empty:
            return self.time_window

        median_diff = (diffs.quantile(0.75) - diffs.quantile(0.25))  # seconds
        optimal_window_min = max(10, min(60, median_diff / 60))
        self.time_window = optimal_window_min
        return self.time_window

    def correlate(self, anomalies_df):
        """
        Correlate anomalies within the configured time window.
        Args:
            anomalies_df (pd.DataFrame): DataFrame containing at least:
                ['datetime', 'user', 'source_type', 'anomaly_types']
        Returns:
            pd.DataFrame: Correlated events with related events for each primary event.
        """
        if anomalies_df.empty:
            return pd.DataFrame()

        window_ns = pd.Timedelta(minutes=self.time_window).value
        results = []

        print("inside correlation engine----------------------------------------------------")

        for user, group in anomalies_df.groupby('user'):
            group = group.sort_values('datetime')
            timestamps = group['datetime'].values.astype('datetime64[ns]').astype('int64')

            for i in range(len(group)):
                time_diff = np.abs(timestamps - timestamps[i])
                mask = (time_diff <= window_ns) & \
                       (group['source_type'].values != group['source_type'].iloc[i])

                if mask.any():
                    results.append({
                        'primary_event': group.iloc[i]['anomaly_types'],
                        'primary_timestamp': group.iloc[i]['datetime'],
                        'user': user,
                        'related_events': group[mask].to_dict('records'),
                        'time_window_mins': self.time_window
                    })

        return pd.DataFrame(results)
    