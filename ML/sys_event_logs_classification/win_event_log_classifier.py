import pandas as pd
import numpy as np
import json
from pandas import json_normalize
import bz2
import pickle


class syslog_classifier:
    def __init__(self, df):
        """Initialize with the raw event DataFrame"""
        self.original_columns = df.columns.tolist()
        self.df = self._clean_data(df.copy())
        self.threat_flags = pd.DataFrame()
    
    def __init__(self, df):
        """Initialize with the raw event DataFrame"""
        # Load reference data from pkl files
        try:
            with open('event_id_db.pkl', 'rb') as file:
                self.EVENT_ID_DB = pickle.load(file)
            with open('malicious_indicators.pkl', 'rb') as file:
                self.MALICIOUS_INDICATORS = pickle.load(file)
        except FileNotFoundError as e:
            raise ValueError(f"Required pkl files not found: {str(e)}")
            
        self.original_columns = df.columns.tolist()
        self.df = self._clean_data(df.copy())
        self.threat_flags = pd.DataFrame()

    def _clean_data(self, df):
        """Clean and standardize the raw data with proper error handling"""
        try:
            # Ensure required columns exist
            if 'EventID' not in df.columns:
                raise ValueError("DataFrame must contain 'EventID' column")
            
            # Convert EventID to numeric safely
            df['EventID'] = pd.to_numeric(df['EventID'], errors='coerce')
            
            # Convert hex strings to integers safely
            hex_cols = [col for col in ['ProcessID', 'ParentProcessID', 'LogonID'] if col in df.columns]
            for col in hex_cols:
                df[col] = df[col].astype(str).str.replace('0x', '', regex=False)
                try:
                    df[col] = pd.to_numeric(df[col])
                except (ValueError, TypeError):
                    df[col] = pd.NA
            
            # Standardize process names safely
            if 'ProcessName' in df.columns:
                df['ProcessName'] = df['ProcessName'].str.lower().fillna('')
                df['ProcessName'] = df['ProcessName'].apply(
                    lambda x: x if pd.isna(x) or '.' in str(x) else f"{x}.exe" if x else x)
            
            # Add computer account flag
            if 'UserName' in df.columns:
                df['IsComputerAccount'] = df['UserName'].str.endswith('$', na=False)
            
            # Add event metadata from reference DB and preserve original event type
            if 'EventType' in df.columns:
                # Use original EventType if present
                df['log_type'] = df['EventType']
            else:
                # Fall back to category from EVENT_ID_DB
                df['log_type'] = df['EventID'].map(
                    lambda x: self.EVENT_ID_DB.get(int(x), {}).get('category', 'unknown') 
                    if pd.notna(x) else 'unknown')
            
            df['EventDescription'] = df['EventID'].map(
                lambda x: self.EVENT_ID_DB.get(int(x), {}).get('description', 'unknown') 
                if pd.notna(x) else 'unknown')
            
            return df
        
        except Exception as e:
            raise ValueError(f"Data cleaning failed: {str(e)}")

    def _detect_threats(self):
        """Detect all threat patterns with robust error handling"""
        try:
            flags = pd.DataFrame(index=self.df.index)
            
            # Process creation threats (EventID 4688)
            if 'EventID' in self.df.columns and 'ProcessName' in self.df.columns:
                is_process_event = (self.df['EventID'] == 4688)
                
                # Malicious process name patterns
                for pattern, description, severity in self.MALICIOUS_INDICATORS['process_names']:
                    col_name = f"THREAT_PROCNAME_{description[:20].upper()}"
                    try:
                        flags[col_name] = (
                            is_process_event & 
                            self.df['ProcessName'].str.contains(pattern, regex=True, na=False)
                        )
                        flags[col_name + "_SEVERITY"] = severity
                    except Exception:
                        continue
                
                # Suspicious paths
                for pattern, description, severity in self.MALICIOUS_INDICATORS['paths']:
                    col_name = f"THREAT_PATH_{description[:20].upper()}"
                    try:
                        flags[col_name] = (
                            is_process_event & 
                            self.df['ProcessName'].str.contains(pattern, regex=True, na=False)
                        )
                        flags[col_name + "_SEVERITY"] = severity
                    except Exception:
                        continue
                
                # Suspicious parent-child pairs
                if 'ParentProcessName' in self.df.columns:
                    for parent, child, description, severity in self.MALICIOUS_INDICATORS['parent_child']:
                        col_name = f"THREAT_PARENTCHILD_{description[:20].upper()}"
                        try:
                            flags[col_name] = (
                                is_process_event &
                                self.df['ParentProcessName'].str.lower().str.contains(parent, regex=False, na=False) &
                                self.df['ProcessName'].str.contains(child, regex=True, na=False)
                            )
                            flags[col_name + "_SEVERITY"] = severity
                        except Exception:
                            continue
            
            # Authentication threats
            if 'EventID' in self.df.columns and 'LogonType' in self.df.columns:
                is_auth_event = self.df['EventID'].isin([4624, 4625, 4648])
                
                # Removed after-hours check since time data is unreliable
                
                # Failed logon sequences
                if 'EventID' in self.df.columns and 'LogHost' in self.df.columns and 'UserName' in self.df.columns:
                    try:
                        fail_counts = self.df[self.df['EventID'] == 4625].groupby(
                            ['LogHost', 'UserName']).size().reset_index(name='FailedCount')
                        flags = flags.merge(
                            fail_counts, 
                            how='left', 
                            on=['LogHost', 'UserName'])
                        flags['THREAT_FAILED_LOGON_SEQUENCE'] = (
                            is_auth_event & 
                            (flags['FailedCount'] > 3))
                        flags['THREAT_FAILED_LOGON_SEQUENCE_SEVERITY'] = 4
                        flags.drop('FailedCount', axis=1, inplace=True)
                    except Exception:
                        pass
                
                # Network logons from unusual sources
                if 'Source' in self.df.columns and 'LogHost' in self.df.columns:
                    try:
                        flags['THREAT_EXTERNAL_NETWORK_LOGON'] = (
                            is_auth_event & 
                            (self.df['LogonType'] == 3) & 
                            (self.df['Source'] != self.df['LogHost']))
                        flags['THREAT_EXTERNAL_NETWORK_LOGON_SEVERITY'] = 4
                    except Exception:
                        pass
            
            # Privilege and account threats
            if 'EventID' in self.df.columns:
                is_priv_event = self.df['EventID'].isin([4672, 4720, 4728, 7045, 4698])
                
                # Privileges assigned to non-system accounts
                if 'IsComputerAccount' in self.df.columns:
                    try:
                        flags['THREAT_USER_PRIVILEGE_ASSIGNMENT'] = (
                            is_priv_event & 
                            ~self.df['IsComputerAccount'])
                        flags['THREAT_USER_PRIVILEGE_ASSIGNMENT_SEVERITY'] = 5
                    except Exception:
                        pass
            
            return flags
        
        except Exception as e:
            print(f"Threat detection failed: {str(e)}")
            return pd.DataFrame(index=self.df.index)

    def _run_rule_based_detection(self):
        threat_flags = self._detect_threats()
        threat_cols = [c for c in threat_flags.columns if not c.endswith('_SEVERITY')]
        if not threat_flags.empty:
            self.df = pd.concat([self.df, threat_flags[threat_cols]], axis=1)
            self.df['ThreatDetected'] = self.df[threat_cols].any(axis=1)
        else:
            self.df['ThreatDetected'] = False

    def analyze(self):
        """Run all rule-based detection methods and format output"""
        try:
            self._run_rule_based_detection()
            
            # Create output DataFrame with specified format
            output_df = pd.DataFrame({
                'log_type': self.df['log_type'],
                'log_id': self.df['log_id'],  # Using EventID as log_id
                'is_threat': self.df['ThreatDetected'],
                'log': self.df.to_dict(orient='records')  # Each row as a dictionary
            })
            
            return output_df
        except Exception as e:
            print(f"Analysis failed: {str(e)}")
            return pd.DataFrame(columns=['log_type', 'log_id', 'is_threat', 'log'])


# Example Usage
if __name__ == "__main__":
    def load_event_logs(filepath, nrows=None):
        with bz2.open(filepath, 'rt') as f:
            lines = [line.strip() for line in f.readlines(nrows)]
        records = []
        for line in lines:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return json_normalize(records)

    df = load_event_logs("Host Events/wls_day-02.bz2", nrows=400000)
    analyzer = syslog_classifier(df)
    results_df = analyzer.analyze()
    print(results_df[results_df['ThreatDetected']].head())