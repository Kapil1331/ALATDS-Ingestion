#!/usr/bin/env python3
"""
threat_engine.py

Class for determining threat levels based on classifier outputs.
Each classifier's results follow the schema:
- log_type (str)
- log_id (int)
- is_threat (bool)
- log (dict): Original features used for classification
"""

import pandas as pd
from typing import Dict, Union

class ThreatEngine:
    def __init__(self):
        """Initialize threat engine with rules for different classifiers."""
        # For emp_data_classifier
        self.EMP_DATA_RULES = {
            # High severity - direct security implications
            'HIGH': [
                'post_termination_activity',
                'nonusb_user_connect',
                'suspicious_domain',
                'http_outside_session_window',
                'admin_first_time_pc_access'
            ],
            # Medium severity - suspicious but not definitive
            'MEDIUM': [
                'logoff_without_preceding_logon',
                'consecutive_logon_without_logoff',
                'after_hours_logon',
                'disconnect_without_prior_connect',
                'consecutive_connect_without_disconnect',
                'after_hours_browsing',
                'first_time_shared_pc_access'
            ],
            # Low severity - anomalous but might be benign
            'LOW': [
                'orphaned_session',
                'baseline_start_deviation',
                'baseline_duration_deviation',
                'first_time_device_connect',
                'missing_disconnect',
                'first_time_domain_visit'
            ]
        }

        # For wsl_classifier
        self.WSL_CONFIDENCE_THRESHOLDS = {
            'CRITICAL': 0.90,  # 90%+ confidence
            'HIGH': 0.75,      # 75-90% confidence
            'MEDIUM': 0.50,    # 50-75% confidence
            'LOW': 0.25        # 25-50% confidence
        }

        # For syslog_classifier
        self.SYSLOG_RULES = {
            'CRITICAL': [
                'THREAT_PARENTCHILD',      # Parent-child process threats
                'privilege_escalation',
                'remote_code_execution'
            ],
            'HIGH': [
                'THREAT_PROCNAME',         # Malicious process names
                'THREAT_PATH',             # Suspicious paths
                'account_manipulation',
                'excessive_failed_logins'
            ],
            'MEDIUM': [
                'unusual_service_install',
                'network_connection',
                'scheduled_task',
                'registry_modification'
            ],
            'LOW': [
                'unusual_time',
                'new_process',
                'file_access'
            ]
        }

        # For network_classifier
        self.NETWORK_RULES = {
            'CRITICAL': [
                'data_exfiltration',
                'c2_communication',
                'ransomware_pattern'
            ],
            'HIGH': [
                'port_scan',
                'ddos_attempt',
                'bruteforce_attempt',
                'blacklisted_ip'
            ],
            'MEDIUM': [
                'suspicious_dns',
                'unusual_protocol',
                'high_volume',
                'unusual_port'
            ],
            'LOW': [
                'first_time_connection',
                'uncommon_useragent',
                'geo_anomaly'
            ]
        }

    def assign_emp_data_threat_level(self, log_data: Dict) -> str:
        """Determine threat level for employee data anomalies."""
        if not log_data:
            return 'NONE'

        # Try to get anomaly_type from different possible locations in the data structure
        anomaly_type = log_data.get('anomaly_type', '')
        if not anomaly_type and isinstance(log_data.get('log'), dict):
            anomaly_type = log_data['log'].get('anomaly_type', '')
        if not anomaly_type and isinstance(log_data.get('detail'), str):
            # Try to extract from detail field if it exists
            detail = log_data['detail'].lower()
            for level, patterns in self.EMP_DATA_RULES.items():
                if any(pattern.lower() in detail for pattern in patterns):
                    return level
        
        # Check against rule sets
        for level, patterns in self.EMP_DATA_RULES.items():
            if anomaly_type in patterns:
                return level
        
        return 'LOW'  # Default if no match

    def assign_wsl_threat_level(self, log_data: Dict) -> str:
        """Determine threat level for web server log threats."""
        if not log_data:
            return 'NONE'

        # Access confidence directly if it exists, otherwise try to get from log field
        confidence = log_data.get('confidence', 0)
        if confidence == 0 and isinstance(log_data.get('log'), dict):
            confidence = log_data['log'].get('confidence', 0)
        
        # Check confidence thresholds
        if confidence >= self.WSL_CONFIDENCE_THRESHOLDS['CRITICAL']:
            return 'CRITICAL'
        elif confidence >= self.WSL_CONFIDENCE_THRESHOLDS['HIGH']:
            return 'HIGH'
        elif confidence >= self.WSL_CONFIDENCE_THRESHOLDS['MEDIUM']:
            return 'MEDIUM'
        elif confidence >= self.WSL_CONFIDENCE_THRESHOLDS['LOW']:
            return 'LOW'
        
        return 'LOW'

    def assign_syslog_threat_level(self, log_data: Dict) -> str:
        """Determine threat level for system log threats."""
        if not log_data:
            return 'NONE'

        # Check for known threat patterns in log data
        for level, patterns in self.SYSLOG_RULES.items():
            for pattern in patterns:
                # Check if any key in log_data starts with the pattern
                if any(key.startswith(pattern) for key in log_data.keys()):
                    return level
        
        return 'LOW'

    def assign_network_threat_level(self, log_data: Dict) -> str:
        """Determine threat level for network threats."""
        if not log_data:
            return 'NONE'

        # Check log data against network rules
        for level, patterns in self.NETWORK_RULES.items():
            for pattern in patterns:
                # Look for pattern matches in log values
                if any(pattern in str(v).lower() for v in log_data.values()):
                    return level
        
        return 'LOW'

    def assign_threat_level(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add threat levels to the input DataFrame based on classifier type.
        
        Args:
            df: DataFrame with standard schema (log_type, log_id, is_threat, log)
            
        Returns:
            DataFrame with added threat_level column
        """
        df = df.copy()
        
        def determine_level(row):
            # If not a threat, return NONE
            if not row['is_threat']:
                return 'NONE'
                
            log_type = row['log_type'].lower()
            try:
                # Handle different log data structures
                log_data = row['log']
                if isinstance(log_data, str):
                    import json
                    log_data = json.loads(log_data)
                elif isinstance(log_data, list):
                    log_data = log_data[0]
                
                # print(f"\nProcessing log_type: {log_type}")
                # print(f"Log data structure: {type(log_data)}")
                # print(f"Log data content: {log_data}")
                
                # Route to appropriate threat level function
                if any(x in log_type for x in ['logon', 'device', 'http']):
                    level = self.assign_emp_data_threat_level(log_data)
                elif 'all_datas_f' in log_type or 'wsl' in log_type or 'web' in log_type:
                    level = self.assign_wsl_threat_level(log_data)
                elif 'syslog' in log_type or 'event' in log_type:
                    level = self.assign_syslog_threat_level(log_data)
                elif 'network' in log_type or 'flow' in log_type:
                    level = self.assign_network_threat_level(log_data)
                else:
                    level = 'LOW'
                    
                print(f"Assigned threat level: {level}")
                return level
                
            except Exception as e:
                print(f"Error processing row: {e}")
                print(f"Row content: {row}")
                return 'LOW'  # Default if processing fails
        
        df['threat_level'] = df.apply(determine_level, axis=1)
        return df

# Example usage
if __name__ == "__main__":
    # Example DataFrame with the standard schema
    example_df = pd.DataFrame({
        'log_type': ['logon', 'http', 'wsl'],
        'log_id': [1, 2, 3],
        'is_threat': [True, True, True],
        'log': [
            {'anomaly_type': 'after_hours_logon', 'user': 'user1'},
            {'anomaly_type': 'suspicious_domain', 'domain': 'evil.com'},
            {'confidence': 0.95, 'attack_type': 'sql_injection'}
        ]
    })
    
    # Process with threat engine
    engine = ThreatEngine()
    result_df = engine.assign_threat_level(example_df)
    print("\nResults with threat levels:")
    print(result_df[['log_type', 'is_threat', 'threat_level']])
