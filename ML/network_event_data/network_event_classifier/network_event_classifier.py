import os
import sys

# This ensures the ML package can be imported from any directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import os
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

class network_threat_classifier:
    MODEL_PATH = "network_threat_rf_model.joblib"
    SUSPICIOUS_PORTS = {
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
        465, 993, 995, 1433, 1521, 3306, 3389, 5060, 5900, 8080
    }

    def __init__(self):
        self.model = None
        if os.path.exists(self.MODEL_PATH):
            print(f"✅ Loading model from {self.MODEL_PATH}")
            self.model = joblib.load(self.MODEL_PATH)

    def feature_engineering(self, df):
        df['SrcPort'] = pd.to_numeric(df['SrcPort'], errors='coerce').fillna(0).astype(int)
        df['DstPort'] = pd.to_numeric(df['DstPort'], errors='coerce').fillna(0).astype(int)

        df['PacketRatio'] = df['SrcPackets'] / (df['DstPackets'] + 1)
        df['ByteRatio'] = df['SrcBytes'] / (df['DstBytes'] + 1)
        df['BytesPerPacketSrc'] = df['SrcBytes'] / (df['SrcPackets'] + 1)
        df['BytesPerPacketDst'] = df['DstBytes'] / (df['DstPackets'] + 1)
        df['TotalPackets'] = df['SrcPackets'] + df['DstPackets']
        df['TotalBytes'] = df['SrcBytes'] + df['DstBytes']
        df['PortDiff'] = abs(df['SrcPort'] - df['DstPort'])
        df['DurationLog'] = np.log1p(df['Duration'])

        df['ProtocolCat'] = df['Protocol'].apply(lambda x: x if x in [1, 6, 17] else 0)
        df['SrcPortSuspicious'] = df['SrcPort'].isin(self.SUSPICIOUS_PORTS).astype(int)
        df['DstPortSuspicious'] = df['DstPort'].isin(self.SUSPICIOUS_PORTS).astype(int)

        df['PacketRate'] = df['TotalPackets'] / (df['Duration'] + 1e-6)
        threshold_pkt_rate = df['PacketRate'].quantile(0.99)
        df['HighPacketRate'] = (df['PacketRate'] > threshold_pkt_rate).astype(int)

        df['ByteRate'] = df['TotalBytes'] / (df['Duration'] + 1e-6)
        threshold_byte_rate = df['ByteRate'].quantile(0.99)
        df['HighByteRate'] = (df['ByteRate'] > threshold_byte_rate).astype(int)

        df['ShortBurst'] = ((df['Duration'] < 1) & (df['TotalPackets'] > 100)).astype(int)

        threshold_large_transfer = df['TotalBytes'].quantile(0.99)
        df['LargeTransfer'] = (df['TotalBytes'] > threshold_large_transfer).astype(int)

        portscan_counts = df.groupby('SrcDevice')['DstPort'].transform('nunique')
        threshold_portscan = portscan_counts.quantile(0.99)
        df['PortScan'] = (portscan_counts > threshold_portscan).astype(int)

        for col in ['SrcDevice', 'DstDevice']:
            freq = df[col].value_counts(normalize=True)
            df[col + '_FreqEnc'] = df[col].map(freq).fillna(0)

        return df

    def create_heuristic_labels(self, df):
        flags = ['SrcPortSuspicious', 'DstPortSuspicious', 'HighPacketRate', 'HighByteRate',
                 'ShortBurst', 'LargeTransfer', 'PortScan']
        df['ThreatScore'] = df[flags].sum(axis=1)
        df['Label'] = (df['ThreatScore'] >= 2).astype(int)
        return df

    def prepare_features(self, df):
        features = [
            'DurationLog', 'SrcPort', 'DstPort', 'ProtocolCat',
            'PacketRatio', 'ByteRatio', 'BytesPerPacketSrc', 'BytesPerPacketDst',
            'TotalPackets', 'TotalBytes', 'PortDiff',
            'PacketRate', 'ByteRate',
            'SrcPortSuspicious', 'DstPortSuspicious',
            'HighPacketRate', 'HighByteRate',
            'ShortBurst', 'LargeTransfer', 'PortScan',
            'SrcDevice_FreqEnc', 'DstDevice_FreqEnc'
        ]
        return df[features].fillna(0)

    def train(self, df):
        df = self.feature_engineering(df)
        df = self.create_heuristic_labels(df)
        X = self.prepare_features(df)
        y = df['Label']

        rf = RandomForestClassifier(
            n_estimators=100,
            class_weight='balanced',
            max_features='sqrt',
            random_state=42,
            n_jobs=-1
        )
        rf.fit(X, y)
        self.model = rf
        joblib.dump(rf, self.MODEL_PATH)
        print(f"💾 Model saved to {self.MODEL_PATH}")

    def assign_threat_level(self, prob):
        if prob > 0.9:
            return "critical"
        elif prob > 0.75:
            return "high"
        elif prob > 0.5:
            return "medium"
        elif prob > 0.3:
            return "low"
        else:
            return "none"

    def predict(self, df):
        if self.model is None:
            raise ValueError("Model not loaded. Call train() first.")

        df = self.feature_engineering(df)
        X = self.prepare_features(df)
        probs = self.model.predict_proba(X)[:, 1]
        is_threat = probs > 0.3

        result_df = pd.DataFrame({
            'log_type': df['log_type'],
            'log_id': df['id'],
            'is_threat': is_threat.astype(bool),
            'threat_level': [self.assign_threat_level(p) for p in probs],
            'log': df.to_dict(orient='records')
        })

        return result_df
