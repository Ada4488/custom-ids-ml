import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import threading
import queue
import os
import time

class MLDetectionEngine:
    def __init__(self, feature_queue, alert_queue, model_path=None, learning_mode=False):
        self.feature_queue = feature_queue
        self.alert_queue = alert_queue
        self.model_path = model_path
        self.learning_mode = learning_mode
        self.model = self._load_model() if model_path and os.path.exists(model_path) else None
        self.scaler = None
        self.stop_detection_flag = threading.Event()
        self.detection_thread = None
        self.training_data = []
        self.max_training_samples = 10000
        
    def start_detection(self):
        self.stop_detection_flag.clear()
        self.detection_thread = threading.Thread(target=self._detection_loop)
        self.detection_thread.daemon = True
        self.detection_thread.start()
        
    def stop_detection(self):
        self.stop_detection_flag.set()
        if self.detection_thread:
            self.detection_thread.join(timeout=1.0)
            
    def _load_model(self):
        """Load a pre-trained model from disk"""
        try:
            model = joblib.load(self.model_path)
            scaler_path = self.model_path.replace('.pkl', '_scaler.pkl')
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
            return model
        except Exception as e:
            print(f"Error loading model: {e}")
            return None
            
    def _detection_loop(self):
        """Main detection loop that processes feature batches"""
        while not self.stop_detection_flag.is_set():
            try:
                features_batch = self.feature_queue.get(timeout=1.0)
                if not features_batch:
                    continue
                    
                # Convert batch to DataFrame for processing
                df = pd.DataFrame(features_batch)
                
                # Store for incremental training if needed
                if len(self.training_data) < self.max_training_samples:
                    self.training_data.extend(features_batch)
                    
                    # Train initial model if we have enough data and no model yet
                    if len(self.training_data) >= 1000 and (self.model is None or self.learning_mode):
                        self._train_model()
                
                # Detect anomalies if model is available and not in pure learning mode
                if self.model and not self.learning_mode:
                    self._detect_anomalies(df)
                    
                self.feature_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"ML detection error: {e}")
                
    def _train_model(self):
        """Train anomaly detection model on collected data"""
        print("Training anomaly detection model...")
        try:
            # Convert collected data to DataFrame
            df = pd.DataFrame(self.training_data)
            
            # Extract features for training (exclude non-numeric columns)
            feature_cols = [col for col in df.columns if col not in ['flow_key', 'timestamp']]
            X = df[feature_cols].copy()
            
            # Scale features
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest model
            self.model = IsolationForest(
                n_estimators=100,
                max_samples='auto',
                contamination=0.05,  # Expected ratio of anomalies
                random_state=42
            )
            self.model.fit(X_scaled)
            
            # Save the model if path is specified
            if self.model_path:
                os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
                joblib.dump(self.model, self.model_path)
                scaler_path = self.model_path.replace('.pkl', '_scaler.pkl')
                joblib.dump(self.scaler, scaler_path)
                
            print("Model training complete")
        except Exception as e:
            print(f"Error training model: {e}")
            
    def _detect_anomalies(self, df):
        """Detect anomalies in the provided feature batch"""
        try:
            # Extract features for prediction
            feature_cols = [col for col in df.columns if col not in ['flow_key', 'timestamp']]
            X = df[feature_cols].copy()
            
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Predict anomalies (-1 for anomalies, 1 for normal)
            predictions = self.model.predict(X_scaled)
            anomaly_scores = self.model.decision_function(X_scaled)
            
            # Process results
            for i, pred in enumerate(predictions):
                if pred == -1:  # Anomaly detected
                    flow_key = df.iloc[i]['flow_key']
                    score = anomaly_scores[i]
                    
                    # Create alert
                    alert = {
                        'timestamp': df.iloc[i]['timestamp'],
                        'flow_key': flow_key,
                        'alert_type': 'ANOMALY',
                        'confidence': abs(score),
                        'description': f"Anomalous network flow detected",
                        'features': df.iloc[i].to_dict()
                    }
                    
                    # Send to alert queue
                    self.alert_queue.put(alert)
                    
        except Exception as e:
            print(f"Error in anomaly detection: {e}")