import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
import joblib

MODEL_PATH = "network_threat_rf_model.joblib"

SUSPICIOUS_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    465, 993, 995, 1433, 1521, 3306, 3389, 5060, 5900, 8080
}

def feature_engineering(df):
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

    df['ProtocolCat'] = df['Protocol'].apply(lambda x: x if x in [1,6,17] else 0)
    df['SrcPortSuspicious'] = df['SrcPort'].isin(SUSPICIOUS_PORTS).astype(int)
    df['DstPortSuspicious'] = df['DstPort'].isin(SUSPICIOUS_PORTS).astype(int)

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

def create_heuristic_labels(df):
    flags = ['SrcPortSuspicious', 'DstPortSuspicious', 'HighPacketRate', 'HighByteRate',
             'ShortBurst', 'LargeTransfer', 'PortScan']
    df['ThreatScore'] = df[flags].sum(axis=1)
    df['Label'] = (df['ThreatScore'] >= 2).astype(int)
    return df

def prepare_features(df):
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

def train_rf(X, y):
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight='balanced',
        max_features='sqrt',
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X, y)
    return rf

def assign_threat_level(prob):
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

def predict(df, model):
    df = feature_engineering(df)
    X = prepare_features(df)
    probs = model.predict_proba(X)[:, 1]
    df['threat_probability'] = probs
    df['is_threat'] = (probs > 0.3).astype(int)
    df['level'] = df['threat_probability'].apply(assign_threat_level)
    return df

if __name__ == "__main__":
    import sys

    input_path = sys.argv[1] if len(sys.argv) > 1 else "network_event_data/netflow_day-02.bz2"
    print(f"Loading data from {input_path} ...")
    df = pd.read_csv(input_path, compression='bz2', nrows=200000)
    df.columns = [
        'Time', 'Duration', 'SrcDevice', 'DstDevice', 'Protocol', 
        'SrcPort', 'DstPort', 'SrcPackets', 'DstPackets', 'SrcBytes', 'DstBytes'
    ]

    df = feature_engineering(df)
    df = create_heuristic_labels(df)

    print(f"Label distribution:\n{df['Label'].value_counts()}")

    X = prepare_features(df)
    y = df['Label']

    if os.path.exists(MODEL_PATH):
        print("Loading existing RF model...")
        model = joblib.load(MODEL_PATH)
    else:
        print("Training new RF model...")
        model = train_rf(X, y)
        joblib.dump(model, MODEL_PATH)
        print(f"RF model saved to {MODEL_PATH}")

    df_pred = predict(df, model)
    print(f"Predicted")
