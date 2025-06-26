from sklearn.ensemble import IsolationForest
from .features import extract_features
import numpy as np

class MLAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.05, n_estimators=100)
        self.trained = False

    def fit(self, packets):
        if len(packets) < 100:
            print("[!] Warning: Insufficient packets for effective training")
            
        features = [list(extract_features(p).values()) for p in packets]
        self.model.fit(features)
        self.trained = True

    def is_anomalous(self, packet):
        if not self.trained:
            return False
        try:
            feature = np.array(list(extract_features(packet).values())).reshape(1, -1)
            return self.model.predict(feature)[0] == -1
        except Exception:
            return False
