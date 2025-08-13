import os
import re
import json
import math
import joblib
import urllib.parse
import pandas as pd
from collections import Counter
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from ..cr_engine.threat_engine import ThreatEngine

class wsl_classifier:
    MODEL_FILE = "wsl_rf_model.pkl"
    PATTERNS_FILE = os.path.join(os.path.dirname(__file__), "attack_patterns.json")
    TRAIN_DATA_FILE = os.path.join(os.path.dirname(__file__), "all_datas_f.csv")
    DEFAULT_PREDICT_FILE = "2bad_reqff.csv"

    def __init__(self):
        # print("in init !!!!!!!!!!!!")
        if not os.path.exists(self.PATTERNS_FILE):
            raise FileNotFoundError(f"Attack patterns file {self.PATTERNS_FILE} not found!")
        with open(self.PATTERNS_FILE, "r") as f:
            self.attack_patterns = json.load(f)

        self.model = None
        if os.path.exists(self.MODEL_FILE):
            print(f"✅ Loading model from {self.MODEL_FILE}")
            self.model = joblib.load(self.MODEL_FILE)
            print("Model loaded successfully.")

    def count_occurrences(self, text, chars):
        return sum(text.count(c) for c in chars)

    def get_entropy(self, text):
        counts = Counter(text)
        prob = [c / len(text) for c in counts.values()] if len(text) > 0 else [1]
        return -sum(p * math.log2(p) for p in prob)

    def preprocess_text(self, text):
        # Decode URL encoded and lower
        if not isinstance(text, str):
            text = ''
        decoded = urllib.parse.unquote_plus(text.lower())
        return decoded

    def engineer_http_features(self, df):
        features = []
        for _, row in df.iterrows():
            path = self.preprocess_text(row.get('path', ''))
            body = self.preprocess_text(row.get('body', ''))
            combined = f"{path} {body}"

            row_features = {
                "single_q": combined.count("'"),
                "double_q": combined.count('"'),
                "dashes": combined.count('-'),
                "braces": self.count_occurrences(combined, "{}()[]"),
                "percentages": combined.count('%'),
                "semicolons": combined.count(';'),
                "path_length": len(path),
                "body_length": len(body),
                "entropy": self.get_entropy(combined),
            }

            for name, pattern in self.attack_patterns.items():
                row_features[f"attack_{name}"] = bool(re.search(pattern, combined, re.IGNORECASE))

            features.append(row_features)
        return pd.DataFrame(features)

    def train(self):
        print(f"⚡ Loading training data from {self.TRAIN_DATA_FILE}...")
        df = pd.read_csv(self.TRAIN_DATA_FILE)
        X = self.engineer_http_features(df)
        y = df['class']

        print("⚡ Splitting data...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, stratify=y, random_state=42
        )

        print("⚡ Training Random Forest Classifier...")
        clf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        print("Model evaluation on test set:")
        print(classification_report(y_test, y_pred))

        self.model = clf
        joblib.dump(clf, self.MODEL_FILE)
        print(f"💾 Model saved to {self.MODEL_FILE}")

    def predict(self, df=None):
        if self.model is None:
            raise ValueError("Model not loaded or trained. Call train() first.")

        if df is None:
            print(f"⚡ Loading prediction data from {self.DEFAULT_PREDICT_FILE}...")
            df = pd.read_csv(self.DEFAULT_PREDICT_FILE)

        features = self.engineer_http_features(df)
        preds = self.model.predict(features)
        probs = self.model.predict_proba(features)[:, 1]

        is_threat = preds == 1
        df['confidence'] = probs

        threat_engine = ThreatEngine()
        df_result = pd.DataFrame({'log_type': df['log_type'],
                                  'log_id' : df['log_id'],
                                  'is_threat' : is_threat,
                                   'log':df.to_dict(orient='records')})
        
        df_result = threat_engine.assign_threat_level(df_result)
        return df_result

if __name__ == "__main__":
    wsl_model = wsl_classifier()

    # Train model if not loaded
    if wsl_model.model is None:
        wsl_model.train()

    # Predict on default file (2bad_reqff.csv)
    result_df = wsl_model.predict(pd.read_csv("Web Server Logs/2bad_reqff.csv"))
    # print(result_df.head())
