"""
Threat Engine for assigning threat levels based on confidence scores and other factors.
"""

class ThreatEngine:
    def __init__(self):
        # Define threat level thresholds
        self.THRESHOLD_HIGH = 0.8
        self.THRESHOLD_MEDIUM = 0.5
        self.THRESHOLD_LOW = 0.3

    def get_threat_level(self, confidence):
        """Determine threat level based on confidence score."""
        if confidence >= self.THRESHOLD_HIGH:
            return "high"
        elif confidence >= self.THRESHOLD_MEDIUM:
            return "medium"
        elif confidence >= self.THRESHOLD_LOW:
            return "low"
        return "info"

    def assign_threat_level(self, df):
        """Assign threat levels to a DataFrame based on confidence scores."""
        if 'confidence' in df['log'].iloc[0]:  # Check if confidence exists in the log column
            df['threat_level'] = df['log'].apply(lambda x: self.get_threat_level(x['confidence']))
        else:
            # If no confidence score, use is_threat to determine level
            df['threat_level'] = df['is_threat'].apply(lambda x: "medium" if x else "info")
        return df

# Create a singleton instance
threat_engine = ThreatEngine()
