#!/usr/bin/env python3
"""
analysis_full_with_ldap.py - Class version

Optimized analyzer implementing statistical baselines and anomaly detection rules.
Outputs a result DataFrame with detected anomalies.
"""

from pathlib import Path
import re
from datetime import datetime
import pandas as pd
import numpy as np
import glob
from ..cr_engine.correlation_engine import CorrelationEngine
from ..cr_engine.threat_engine import ThreatEngine

class emp_data_classifier:
    def __init__(self, logon_df=None, device_df=None, http_df=None, ldap_dir="Dataset 1/LDAP"):
        """Initialize with input DataFrames
        Args:
            logon_df: DataFrame containing logon events
            device_df: DataFrame containing device events
            http_df: DataFrame containing HTTP events
            ldap_dir: Path to LDAP directory (optional)
        """
        # Store input DataFrames
        self.logon = logon_df
        self.device = device_df
        self.http = http_df
        self.LDAP_DIR = Path(ldap_dir)
        
        # Analysis thresholds
        self.BASELINE_MIN_DAYS = 5
        self.BASELINE_MAD_K = 3.5
        self.SHARED_PC_Z_K = 1.5
        self.FIRST_TIME_DOMAIN_FLAG = True
        self.AFTER_HOURS_START = 7 * 60  # 07:00 in minutes
        self.AFTER_HOURS_END = 19 * 60   # 19:00 in minutes
        self.SUSPICIOUS_PATTERNS = [
            r"malicious", r"phish", r"evil", r"bad-", r"-bad", r"untrusted"
        ]
        self.SUSPICIOUS_REGEX = re.compile(
            "|".join(self.SUSPICIOUS_PATTERNS), flags=re.IGNORECASE
        )
        
        # Data storage
        self.logon = None
        self.device = None
        self.http = None
        self.user_last_ldap = None
        self.ldap_admins = None
        print("In init !!!!!!!!!!!")
        
    def load_csv(self, path: Path, **kwargs) -> pd.DataFrame:
        """Helper to load CSV files with error handling."""
        if not path.exists():
            raise FileNotFoundError(f"{path} not found")
        return pd.read_csv(path, low_memory=False, **kwargs)
    
    def parse_http_domains(self, url_series: pd.Series) -> pd.Series:
        """Extract domains from URLs."""
        domain = url_series.str.extract(r'://([^/]+)', expand=False)
        domain = domain.fillna(url_series.str.split('/').str[0])
        domain = domain.str.lower().replace(r'^\s*$', np.nan, regex=True)
        return domain
    
    def month_to_cutoff(self, first_month_str):
        """Convert YYYY-MM month string to cutoff datetime (first of next month)."""
        y, m = map(int, first_month_str.split('-'))
        if m < 12:
            return datetime(y, m+1, 1)
        return datetime(y+1, 1, 1)
    
    def mad(self, series):
        """Median Absolute Deviation calculation."""
        med = series.median()
        return (np.abs(series - med)).median()
    
    def load_ldap_snapshots(self):
        """Load LDAP data to get termination dates and admin users."""
        self.user_last_ldap = {}
        self.ldap_admins = set()
        
        if not self.LDAP_DIR.exists():
            return
            
        files = sorted(glob.glob(str(self.LDAP_DIR / "*.csv")))
        frames = []
        
        for f in files:
            try:
                df = pd.read_csv(f, dtype=str)
                if 'user_id' not in df.columns:
                    continue
                    
                # Infer month from filename if present
                m = re.search(r'(\d{4}-\d{2})', Path(f).name)
                month = m.group(1) if m else datetime.fromtimestamp(
                    Path(f).stat().st_mtime
                ).strftime("%Y-%m")
                df['month'] = month
                frames.append(df[['user_id', 'role', 'month']])
            except Exception:
                continue
                
        if not frames:
            return
            
        allf = pd.concat(frames, ignore_index=True)
        allf = allf.dropna(subset=['user_id'])
        
        # Last seen month (max lexicographically works for YYYY-MM)
        self.user_last_ldap = allf.groupby('user_id')['month'].max().to_dict()
        
        # Admin detection
        role_lower = allf['role'].fillna('').str.lower()
        admin_rows = allf[role_lower.str.contains('admin', na=False)]
        self.ldap_admins = set(admin_rows['user_id'].unique())
    
    def load_and_preprocess_data(self):
        """Preprocess all data sources."""
        if self.logon is None or self.device is None or self.http is None:
            raise ValueError("All input DataFrames (logon, device, http) are required")

        # Process logon data
        self.logon = self.logon.copy()
        self.logon['datetime'] = pd.to_datetime(self.logon['datetime'] if 'datetime' in self.logon.columns else self.logon['date'])
        self.logon['log_id'] = self.logon['log_id'] if 'log_id' in self.logon.columns else self.logon['id']
        
        # Process device data
        self.device = self.device.copy()
        self.device['datetime'] = pd.to_datetime(self.device['datetime'] if 'datetime' in self.device.columns else self.device['date'])
        self.device['log_id'] = self.device['log_id'] if 'log_id' in self.device.columns else self.device['id']
        
        # Process HTTP data
        self.http = self.http.copy()
        self.http['datetime'] = pd.to_datetime(self.http['datetime'] if 'datetime' in self.http.columns else self.http['date'])
        self.http['log_id'] = self.http['log_id'] if 'log_id' in self.http.columns else self.http['id']
        
        # Add common derived columns
        for df in (self.logon, self.device, self.http):
            df['user'] = df['user'].astype(str)
            df['pc'] = df['pc'].astype(str)
            df['day'] = df['datetime'].dt.date
            df['minute_of_day'] = df['datetime'].dt.hour * 60 + df['datetime'].dt.minute
        
        # Parse HTTP domains
        self.http['domain'] = self.parse_http_domains(self.http['url'].astype(str))
        
        # Load LDAP data
        self.load_ldap_snapshots()
    
    def detect_logon_anomalies(self):
        """Detect anomalies in logon data."""
        anomalies = []
        L = self.logon.sort_values(['user', 'datetime']).reset_index(drop=True)
        L['activity_lc'] = L['activity'].astype(str).str.lower()
        
        # Add previous/next activity columns
        L['prev_act'] = L.groupby('user')['activity_lc'].shift(1)
        L['next_act'] = L.groupby('user')['activity_lc'].shift(-1)
        
        # Rule: Logoff without preceding logon
        cond = (L['activity_lc'] == 'logoff') & (L['prev_act'] != 'logon')
        if cond.any():
            df = L.loc[cond, ['datetime', 'user', 'pc', 'id']].copy()  # Include log_id
            df['log_type'] = 'logon'
            df['anomaly_type'] = 'logoff_without_preceding_logon'
            df['detail'] = 'Logoff occurred without prior Logon'
            anomalies.append(df)
        
        # Rule: Consecutive logon without logoff
        cond = (L['activity_lc'] == 'logon') & (L['prev_act'] == 'logon')
        if cond.any():
            df = L.loc[cond, ['datetime', 'user', 'pc']].copy()
            df['log_type'] = 'logon'
            df['anomaly_type'] = 'consecutive_logon_without_logoff'
            df['detail'] = 'Multiple Logon events without intervening Logoff'
            anomalies.append(df)
        
        # Rule: Orphaned sessions (Logon not followed by Logoff)
        cond = (L['activity_lc'] == 'logon') & (L['next_act'] != 'logoff')
        if cond.any():
            df = L.loc[cond, ['datetime', 'user', 'pc']].copy()
            df['log_type'] = 'logon'
            df['anomaly_type'] = 'orphaned_session'
            df['detail'] = 'Logon with no following Logoff (session may be orphaned)'
            anomalies.append(df)
        
        # Rule: After-hours logons
        after_mask = (
            (L['activity_lc'] == 'logon') & 
            ((L['minute_of_day'] < self.AFTER_HOURS_START) | 
             (L['minute_of_day'] >= self.AFTER_HOURS_END)))
        if after_mask.any():
            df = L.loc[after_mask, ['datetime', 'user', 'pc']].copy()
            df['log_type'] = 'logon'
            df['anomaly_type'] = 'after_hours_logon'
            df['detail'] = 'Logon during after-hours window'
            anomalies.append(df)
        
        return anomalies
    
    def build_session_baselines(self):
        """Build session baselines and detect deviations."""
        anomalies = []
        L = self.logon.copy()
        L['activity_lc'] = L['activity'].astype(str).str.lower()
        
        # Get first logon and last logoff per user-day
        first_logon = (L[L['activity_lc'] == 'logon']
                      .assign(day=L['datetime'].dt.date)
                      .groupby(['user', 'day'], as_index=False)
                      .agg(first_logon=('datetime', 'min')))
        
        last_logoff = (L[L['activity_lc'] == 'logoff']
                      .assign(day=L['datetime'].dt.date)
                      .groupby(['user', 'day'], as_index=False)
                      .agg(last_logoff=('datetime', 'max')))
        
        session_bounds = pd.merge(first_logon, last_logoff, on=['user', 'day'], how='outer')
        
        # Start time baseline analysis
        if not first_logon.empty:
            first_logon['start_min'] = (
                first_logon['first_logon'].dt.hour * 60 + 
                first_logon['first_logon'].dt.minute
            )
            
            user_start_stats = (first_logon.groupby('user')
                               .agg(days_count=('day', 'nunique'), 
                                    median_start=('start_min', 'median'))
                               .reset_index())
            
            # Compute MAD for start times
            start_mads = (first_logon.groupby('user')['start_min']
                          .agg(lambda s: self.mad(s)).rename('start_mad')
                          .reset_index())
            
            user_start_stats = user_start_stats.merge(start_mads, on='user', how='left')
            
            # Detect start time deviations
            eligible_users = user_start_stats[
                user_start_stats['days_count'] >= self.BASELINE_MIN_DAYS
            ]
            
            if not eligible_users.empty:
                merged = first_logon.merge(
                    eligible_users[['user', 'median_start', 'start_mad']], 
                    on='user', 
                    how='inner'
                )
                merged['start_min'] = (
                    merged['first_logon'].dt.hour * 60 + 
                    merged['first_logon'].dt.minute
                )
                
                merged['start_mad_fallback'] = merged['start_mad'].replace({0: 10}).fillna(10)
                merged['dev_units'] = (
                    (merged['start_min'] - merged['median_start']).abs() / 
                    merged['start_mad_fallback']
                )
                
                dev_mask = merged['dev_units'] > self.BASELINE_MAD_K
                if dev_mask.any():
                    df = merged.loc[dev_mask, ['first_logon', 'user']].copy()
                    df = df.rename(columns={'first_logon': 'datetime'})
                    df['pc'] = None
                    df['log_type'] = 'logon'
                    df['anomaly_type'] = 'baseline_start_deviation'
                    df['detail'] = 'First-logon deviates from user median start (MAD-based)'
                    anomalies.append(df)
        
        # Session duration baseline analysis
        if not session_bounds.empty:
            session_bounds['duration_min'] = (
                (session_bounds['last_logoff'] - session_bounds['first_logon'])
                .dt.total_seconds() / 60.0
            )
            
            sb_valid = session_bounds[
                session_bounds['duration_min'].notna() & 
                (session_bounds['duration_min'] > 0)
            ].copy()
            
            user_dur_stats = (sb_valid.groupby('user')
                             .agg(days_with_duration=('day', 'nunique'), 
                                  median_dur=('duration_min', 'median'))
                             .reset_index())
            
            # Compute MAD for durations
            dur_mads = (sb_valid.groupby('user')['duration_min']
                        .agg(lambda s: self.mad(s)).rename('dur_mad')
                        .reset_index())
            
            user_dur_stats = user_dur_stats.merge(dur_mads, on='user', how='left')
            
            # Detect duration deviations
            eligible_users = user_dur_stats[
                user_dur_stats['days_with_duration'] >= self.BASELINE_MIN_DAYS
            ]
            
            if not eligible_users.empty:
                merged = sb_valid.merge(
                    eligible_users[['user', 'median_dur', 'dur_mad']], 
                    on='user', 
                    how='inner'
                )
                
                merged['dur_mad_fallback'] = merged['dur_mad'].replace({0: 10}).fillna(10)
                merged['dev_units'] = (
                    (merged['duration_min'] - merged['median_dur']).abs() / 
                    merged['dur_mad_fallback']
                )
                
                dev_mask = merged['dev_units'] > self.BASELINE_MAD_K
                if dev_mask.any():
                    df = merged.loc[dev_mask, ['first_logon', 'user', 'duration_min']].copy()
                    df = df.rename(columns={'first_logon': 'datetime'})
                    df['pc'] = None
                    df['log_type'] = 'logon'
                    df['anomaly_type'] = 'baseline_duration_deviation'
                    df['detail'] = df['duration_min'].apply(
                        lambda d: f'session_duration={d:.1f}min deviates from median'
                    )
                    anomalies.append(df)
        
        return anomalies, session_bounds
    
    def detect_ldap_anomalies(self, session_bounds):
        """Detect anomalies based on LDAP data."""
        anomalies = []
        
        if not self.user_last_ldap:
            return anomalies
            
        # Build dataframe of last-seen cutoff datetimes
        us = pd.DataFrame(list(self.user_last_ldap.items()), 
                          columns=['user', 'last_month'])
        us['cutoff'] = us['last_month'].apply(self.month_to_cutoff)
        
        # Merge with logon events
        ll = self.logon[['datetime', 'user', 'pc']].copy()
        merged = ll.merge(us[['user', 'cutoff']], on='user', how='left')
        
        # Detect post-termination activity
        post_mask = merged['cutoff'].notna() & (merged['datetime'] >= merged['cutoff'])
        if post_mask.any():
            df = merged.loc[post_mask, ['datetime', 'user', 'pc']].copy()
            df['log_type'] = 'logon'
            df['anomaly_type'] = 'post_termination_activity'
            df['detail'] = 'Activity after last LDAP-seen month (possible post-termination)'
            anomalies.append(df)
        
        return anomalies
    
    def detect_device_anomalies(self):
        """Detect anomalies in device data."""
        anomalies = []
        D = self.device.sort_values(['user', 'pc', 'datetime']).reset_index(drop=True)
        D['activity_lc'] = D['activity'].astype(str).str.lower()
        
        # Add previous activity column
        D['prev_act'] = D.groupby(['user', 'pc'])['activity_lc'].shift(1)
        
        # Rule: Disconnect without prior connect
        cond = (D['activity_lc'] == 'disconnect') & (D['prev_act'] != 'connect')
        if cond.any():
            df = D.loc[cond, ['datetime', 'user', 'pc', 'id']].copy()  # Include log_id
            df['log_type'] = 'device'
            df['anomaly_type'] = 'disconnect_without_prior_connect'
            df['detail'] = 'Disconnect with no prior connect'
            anomalies.append(df)
        
        # Rule: Connect while already connected
        cond = (D['activity_lc'] == 'connect') & (D['prev_act'] == 'connect')
        if cond.any():
            df = D.loc[cond, ['datetime', 'user', 'pc']].copy()
            df['log_type'] = 'device'
            df['anomaly_type'] = 'consecutive_connect_without_disconnect'
            df['detail'] = 'Connect while already connected'
            anomalies.append(df)
        
        # Rule: First-time device connect per (user,pc)
        connects = D[D['activity_lc'] == 'connect']
        if not connects.empty:
            first_connect = connects.drop_duplicates(
                subset=['user', 'pc'], 
                keep='first'
            )[['datetime', 'user', 'pc']].copy()
            first_connect['log_type'] = 'device'
            first_connect['anomaly_type'] = 'first_time_device_connect'
            first_connect['detail'] = 'First observed connect for user-pc pair'
            anomalies.append(first_connect)
        
        # Rule: Missing disconnects (last activity is connect)
        last_act = D.groupby(['user', 'pc'], as_index=False).agg(
            last_activity=('activity_lc', 'last'), 
            last_dt=('datetime', 'last')
        )
        miss_mask = last_act['last_activity'] == 'connect'
        if miss_mask.any():
            rows = last_act.loc[miss_mask, ['last_dt', 'user', 'pc']].copy()
            rows = rows.rename(columns={'last_dt': 'datetime'})
            rows['log_type'] = 'device'
            rows['anomaly_type'] = 'missing_disconnect'
            rows['detail'] = 'No disconnect after last connect'
            anomalies.append(rows)
        
        # Rule: Non-USB users performing connects
        usb_users = set(connects['user'].unique())
        all_users = set(self.logon['user'].unique()).union(
            set(self.device['user'].unique())).union(
            set(self.http['user'].unique()))
        non_usb_users = all_users - usb_users
        
        cond = D['user'].isin(non_usb_users) & (D['activity_lc'] == 'connect')
        if cond.any():
            df = D.loc[cond, ['datetime', 'user', 'pc']].copy()
            df['log_type'] = 'device'
            df['anomaly_type'] = 'nonusb_user_connect'
            df['detail'] = 'User historically non-USB performed connect'
            anomalies.append(df)
        
        return anomalies
    
    def detect_http_anomalies(self, session_bounds):
        """Detect anomalies in HTTP data."""
        anomalies = []
        H = self.http.sort_values(['user', 'datetime']).reset_index(drop=True)
        
        # Rule: After-hours browsing
        after_mask = (
            (H['minute_of_day'] < self.AFTER_HOURS_START) | 
            (H['minute_of_day'] >= self.AFTER_HOURS_END)
        )
        if after_mask.any():
            df = H.loc[after_mask, ['datetime', 'user', 'pc', 'log_id']].copy()  # Include log_id
            df['log_type'] = 'http'
            df['anomaly_type'] = 'after_hours_browsing'
            df['detail'] = 'HTTP during after-hours'
            anomalies.append(df)
        
        # Rule: Suspicious domains
        sus_mask = H['domain'].fillna('').str.contains(self.SUSPICIOUS_REGEX)
        if sus_mask.any():
            rows = H.loc[sus_mask, ['datetime', 'user', 'pc', 'domain']].copy()
            rows['log_type'] = 'http'
            rows['anomaly_type'] = 'suspicious_domain'
            rows['detail'] = rows['domain'].apply(
                lambda d: f'Visited suspicious-like domain {d}'
            )
            anomalies.append(rows)
        
        # Rule: First-time domain visits
        H_nonnull = H[H['domain'].notna()].copy()
        first_user_domain = H_nonnull.drop_duplicates(
            subset=['user', 'domain'], 
            keep='first'
        )[['datetime', 'user', 'pc', 'domain']].copy()
        
        if not first_user_domain.empty and self.FIRST_TIME_DOMAIN_FLAG:
            first_user_domain['log_type'] = 'http'
            first_user_domain['anomaly_type'] = 'first_time_domain_visit'
            first_user_domain['detail'] = first_user_domain['domain'].apply(
                lambda d: f'First-time visit to {d}'
            )
            anomalies.append(first_user_domain)
        
        # Rule: HTTP outside session windows
        if not session_bounds.empty:
            H['day'] = H['datetime'].dt.date
            merged = H.merge(session_bounds, on=['user', 'day'], how='left')
            cond_outside = (
                merged['first_logon'].notna() & 
                merged['last_logoff'].notna() & 
                ((merged['datetime'] < merged['first_logon']) | 
                 (merged['datetime'] > merged['last_logoff']))
            )
            
            if cond_outside.any():
                df = merged.loc[cond_outside, ['datetime', 'user', 'pc']].copy()
                df['log_type'] = 'http'
                df['anomaly_type'] = 'http_outside_session_window'
                df['detail'] = 'HTTP outside logon-logoff window for that user-day'
                anomalies.append(df)
        
        return anomalies
    
    def detect_shared_pc_anomalies(self):
        """Detect anomalies related to shared PCs."""
        anomalies = []
        
        # Calculate unique users per PC
        pc_user_counts = self.logon.groupby('pc')['user'].nunique().reset_index(
            name='unique_users'
        )
        
        if pc_user_counts.empty:
            return anomalies
            
        # Determine shared PCs (statistical outlier detection)
        mu = pc_user_counts['unique_users'].mean()
        sigma = pc_user_counts['unique_users'].std(ddof=0)
        
        if sigma == 0:
            # Fallback: treat top percentile as shared
            threshold = pc_user_counts['unique_users'].quantile(0.95)
        else:
            threshold = mu + self.SHARED_PC_Z_K * sigma
        
        shared_pcs = set(
            pc_user_counts.loc[
                pc_user_counts['unique_users'] > threshold, 'pc'
            ].tolist()
        )
        
        # Rule: First-time access to shared PC
        if shared_pcs:
            L_shared = self.logon[self.logon['pc'].isin(shared_pcs)].copy()
            first_shared = L_shared.drop_duplicates(
                subset=['user', 'pc'], 
                keep='first'
            )[['datetime', 'user', 'pc']]
            
            if not first_shared.empty:
                first_shared['log_type'] = 'logon'
                first_shared['anomaly_type'] = 'first_time_shared_pc_access'
                first_shared['detail'] = 'First observed access to a shared PC by user'
                anomalies.append(first_shared)
        
        return anomalies
    
    def detect_admin_anomalies(self):
        """Detect anomalies related to admin users."""
        anomalies = []
        
        if not self.ldap_admins:
            return anomalies
            
        # Rule: Admin first-time PC access
        L_admins = self.logon[self.logon['user'].isin(self.ldap_admins)].copy()
        
        if not L_admins.empty:
            admin_first = L_admins.drop_duplicates(
                subset=['user', 'pc'], 
                keep='first'
            )[['datetime', 'user', 'pc']]
            
            admin_first['log_type'] = 'logon'
            admin_first['anomaly_type'] = 'admin_first_time_pc_access'
            admin_first['detail'] = 'Admin first-time PC access'
            anomalies.append(admin_first)
        
        return anomalies
    
    def analyze(self):
        """Run complete analysis and return results DataFrame."""
        # Load and preprocess all data
        self.load_and_preprocess_data()
        
        # Detect all types of anomalies
        logon_anoms = self.detect_logon_anomalies()
        baseline_anoms, session_bounds = self.build_session_baselines()
        ldap_anoms = self.detect_ldap_anomalies(session_bounds)
        device_anoms = self.detect_device_anomalies()
        http_anoms = self.detect_http_anomalies(session_bounds)
        shared_pc_anoms = self.detect_shared_pc_anomalies()
        admin_anoms = self.detect_admin_anomalies()
        
        # Combine all anomalies
        all_anoms = (
            logon_anoms + baseline_anoms + ldap_anoms + 
            device_anoms + http_anoms + shared_pc_anoms + admin_anoms
        )
        
        # Create final DataFrame
        if all_anoms:
            result_df = pd.concat(all_anoms, ignore_index=True, sort=False)
            
            # Ensure consistent columns
            keep_cols = ['datetime', 'user', 'pc', 'log_type', 'anomaly_type', 'detail', 'log_id']
            for c in keep_cols:
                if c not in result_df.columns:
                    result_df[c] = None
            
            result_df = result_df[keep_cols]
            result_df = result_df.sort_values('datetime').reset_index(drop=True)
            
            # Match back to original data to get log_ids
            result_df['log_id'] = None
            
            # For logon events
            logon_mask = result_df['log_type'] == 'logon'
            if logon_mask.any():
                logon_matches = result_df[logon_mask].merge(
                    self.logon[['datetime', 'user', 'pc', 'log_id']],
                    on=['datetime', 'user', 'pc'],
                    how='left'
                )
                result_df.loc[logon_mask, 'log_id'] = logon_matches['log_id']
            
            # For device events
            device_mask = result_df['log_type'] == 'device'
            if device_mask.any():
                device_matches = result_df[device_mask].merge(
                    self.device[['datetime', 'user', 'pc', 'log_id']],
                    on=['datetime', 'user', 'pc'],
                    how='left'
                )
                result_df.loc[device_mask, 'log_id'] = device_matches['log_id']
            
            # For HTTP events
            http_mask = result_df['log_type'] == 'http'
            if http_mask.any():
                http_matches = result_df[http_mask].merge(
                    self.http[['datetime', 'user', 'pc', 'log_id']],
                    on=['datetime', 'user', 'pc'],
                    how='left'
                )
                result_df.loc[http_mask, 'log_id'] = http_matches['log_id']

            # Create the output format with log_type and log details
            output_df = pd.DataFrame({
                'log_type': result_df['log_type'],
                'log_id': result_df['log_id'],
                'is_threat': True,
                'log': result_df.to_dict(orient='records')
            })
        else:
            output_df = pd.DataFrame(columns=[
                'log_type', 'log_id', 'is_threat', 'log'
            ])

        print("Reached output!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        corr_engine = CorrelationEngine()
        threat_engine = ThreatEngine()
        correlated_df = corr_engine.correlate(output_df)
        output_df = threat_engine.assign_threat_level(output_df)
        
        return output_df,correlated_df

# ----------------------
# Main execution
# ----------------------
if __name__ == "__main__":
    analyzer = emp_data_classifier()
    result_df = analyzer.analyze()