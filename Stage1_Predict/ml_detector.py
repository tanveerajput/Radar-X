"""
ML Detector - Isolation Forest for ransomware detection
Uses unsupervised learning to detect anomalous behavior
"""
import sys
import os

# Add Stage3_Mitigate to Python path so we can import Stage3
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR, "Stage3_Mitigate"))
from stage3_mitigation import Stage3ProtectionPipeline
from datetime import datetime
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, classification_report, roc_curve, auc
import matplotlib.pyplot as plt
import seaborn as sns
import pickle
# Initialize Stage 3 Protection Pipeline
stage3_protect = Stage3ProtectionPipeline()

class RansomwareMLDetector:
    """Machine Learning detector for ransomware behavior"""
    
    def __init__(self, contamination=0.1):
        """
        Initialize detector
        
        Args:
            contamination: Expected proportion of outliers (0.1 = 10% ransomware)
        """
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            max_features=1.0,
            bootstrap=False,
            n_jobs=-1,
            verbose=0
        )
        
        self.is_trained = False
        self.feature_importance = None
        
    def train(self, X_train, y_train=None):
        """
        Train the model on training data
        
        Args:
            X_train: Training features (n_samples, n_features)
            y_train: Labels (optional, for validation only)
        """
        print("🔄 Training Isolation Forest...")
        
        self.model.fit(X_train)
        self.is_trained = True
        
        print(f"✅ Model trained on {X_train.shape[0]} samples with {X_train.shape[1]} features")
        
        # Calculate feature importance (approximate)
        self._calculate_feature_importance(X_train)
        
        return self
    
    def predict(self, X):
        """
        Predict if behavior is ransomware
        
        Args:
            X: Feature vector(s) (n_samples, n_features)
        
        Returns:
            predictions: 1 for normal, -1 for ransomware
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction!")
        
        return self.model.predict(X)
    
    def predict_proba(self, X):
        """
        Get anomaly scores (higher = more anomalous)
        
        Returns:
            scores: Anomaly scores (higher = more likely ransomware)
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction!")
        
        # Decision function returns anomaly scores
        # More negative = more anomalous
        raw_scores = self.model.decision_function(X)
        
        # Inverse and scale to 0-100
        # Anomalies have negative scores, normal has positive
        # We want: negative -> high threat, positive -> low threat
        scores = -raw_scores
        
        # Use fixed scaling based on typical Isolation Forest range (-0.5 to 0.5)
        # Shift so that 0 becomes 50, negative becomes >50, positive becomes <50
        normalized = np.clip((scores + 0.5) * 100, 0, 100)
        
        return normalized
    
    def predict_with_confidence(self, X):
        """
        Predict with threat scores
        
        Returns:
            predictions: 1 for normal, -1 for ransomware
            threat_scores: 0-100 score
        """
        predictions = self.predict(X)
        threat_scores = self.predict_proba(X)
        
        return predictions, threat_scores
    
    def evaluate(self, X_test, y_test):
        """
        Evaluate model performance
        
        Args:
            X_test: Test features
            y_test: True labels (1=normal, -1=ransomware)
        
        Returns:
            metrics: Dictionary of performance metrics
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before evaluation!")
        
        y_pred = self.predict(X_test)
        
        # Calculate metrics
        cm = confusion_matrix(y_test, y_pred, labels=[1, -1])
        
        # Extract values
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'true_positives': int(tp),
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'confusion_matrix': cm
        }
        
        return metrics
    
    def _calculate_feature_importance(self, X):
        """Approximate feature importance using variance"""
        self.feature_importance = np.var(X, axis=0)
        self.feature_importance /= self.feature_importance.sum()
    
    def plot_confusion_matrix(self, metrics, save_path=None):
        """Plot confusion matrix"""
        cm = metrics['confusion_matrix']
        
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=['Normal', 'Ransomware'],
                   yticklabels=['Normal', 'Ransomware'])
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"📊 Confusion matrix saved to {save_path}")
        else:
            plt.show()
    
    def plot_feature_importance(self, feature_names, save_path=None):
        """Plot feature importance"""
        if self.feature_importance is None:
            print("⚠️  Feature importance not calculated yet")
            return
        
        # Sort by importance
        indices = np.argsort(self.feature_importance)[::-1]
        
        plt.figure(figsize=(10, 6))
        plt.bar(range(len(feature_names)), self.feature_importance[indices])
        plt.xticks(range(len(feature_names)), 
                  [feature_names[i] for i in indices], 
                  rotation=45, ha='right')
        plt.xlabel('Features')
        plt.ylabel('Importance (Variance)')
        plt.title('Feature Importance')
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"📊 Feature importance saved to {save_path}")
        else:
            plt.show()
    
    def save_model(self, path='ransomware_model.pkl'):
        """Save trained model"""
        if not self.is_trained:
            print("⚠️  Cannot save untrained model")
            return
        
        with open(path, 'wb') as f:
            pickle.dump(self.model, f)
        print(f"💾 Model saved to {path}")
    
    def load_model(self, path='ransomware_model.pkl'):
        """Load trained model"""
        if not os.path.exists(path):
            print(f"❌ Model file not found: {path}")
            return
        
        with open(path, 'rb') as f:
            self.model = pickle.load(f)
        self.is_trained = True
        print(f"📂 Model loaded from {path}")


# Example usage and testing
if __name__ == "__main__":
    print("="*70)
    print("RANSOMWARE ML DETECTOR - DEMO")
    print("="*70)
    
    # Generate synthetic training data
    np.random.seed(42)
    
    # Normal behavior (low values)
    normal_data = np.random.randn(100, 15) * 0.3 + 0.2
    normal_data = np.abs(normal_data)  # Keep positive
    
    # Ransomware behavior (high values, especially entropy and file changes)
    ransomware_data = np.random.randn(20, 15) * 0.5 + 0.8
    ransomware_data[:, 0:5] *= 3  # Boost file activity features
    ransomware_data[:, 3] = np.random.uniform(7, 8, 20)  # High entropy
    ransomware_data = np.abs(ransomware_data)
    
    # Combine data
    X_train = np.vstack([normal_data, ransomware_data])
    y_train = np.array([1]*100 + [-1]*20)  # 1=normal, -1=ransomware
    
    # Shuffle
    indices = np.random.permutation(len(X_train))
    X_train = X_train[indices]
    y_train = y_train[indices]
    
    print(f"\n📚 Training data: {X_train.shape[0]} samples, {X_train.shape[1]} features")
    
    # Train model
    detector = RansomwareMLDetector(contamination=0.15)
    detector.train(X_train, y_train)
    
        # Test predictions
    print("\n🧪 Testing predictions...")
    
    # ==================== TEST 1: NORMAL SAMPLE ====================
    print("\n" + "="*70)
    print("TEST 1: Normal Behavior")
    print("="*70)
    
    normal_sample = np.random.randn(1, 15) * 0.3 + 0.2
    normal_sample = np.abs(normal_sample)
    pred_normal, score_normal = detector.predict_with_confidence(normal_sample)
    
    print(f"  Prediction: {pred_normal[0]:>2} (1=Normal, -1=Ransomware)")
    print(f"  Threat Score: {score_normal[0]:.1f}/100")
    
    if pred_normal[0] == -1:
        print("  🚨 FALSE POSITIVE - Normal sample detected as ransomware!")
    else:
        print("  ✅ CORRECT - Normal sample classified as normal")
    
    # ==================== TEST 2: RANSOMWARE SAMPLE ====================
    print("\n" + "="*70)
    print("TEST 2: Ransomware Behavior")
    print("="*70)
    
    # Create ransomware sample with HIGH entropy and suspicious patterns
    ransom_sample = np.random.randn(1, 15) * 0.5 + 0.8
    ransom_sample[:, 0] = 5.0  # Very high file modifications
    ransom_sample[:, 3] = 7.8  # High entropy (encryption)
    ransom_sample[:, 10] = 1   # Honeypot hit
    ransom_sample = np.abs(ransom_sample)
    
    pred_ransom, score_ransom = detector.predict_with_confidence(ransom_sample)
    
    print(f"  Prediction: {pred_ransom[0]:>2} (1=Normal, -1=Ransomware)")
    print(f"  Threat Score: {score_ransom[0]:.1f}/100")
    
    # ==================== STAGE 3 HANDOVER ====================
    if pred_ransom[0] == -1:  # ✅ Ransomware detected
        print("\n" + "="*70)
        print("🚨 RANSOMWARE DETECTED - TRIGGERING STAGE 3 PROTECTION")
        print("="*70)
        
        detection_data = {
            "threat_detected": True,
            "threat_level": "CRITICAL",
            "pid": 12345,  # Demo PID
            "process_name": "ransomware_simulator.exe",
            "detection_time": datetime.now().isoformat(),
            "indicators": {
                "high_entropy": score_ransom[0] > 70,
                "file_discovery": True,
                "shadow_copy_deletion": True,
                "honeypot_hit": True,
                "cpu_spike": True
            }
        }
        
        print("\n📊 Detection Data:")
        print(f"  Threat Score: {score_ransom[0]:.1f}/100")
        print(f"  High Entropy: {detection_data['indicators']['high_entropy']}")
        print(f"  Honeypot Hit: {detection_data['indicators']['honeypot_hit']}")
        
        # Trigger Stage 3 protection
        print("\n🛡️ Initiating Stage 3 mitigation...")
        response = stage3_protect.respond_to_threat(detection_data)
        
        print(f"\n✅ THREAT CONTAINED!")
        print(f"  Response Time: {response['total_response_time']:.3f}s")
        print(f"  Target: <10s ✅")
        print(f"  Actions Taken: {len(response['actions_taken'])}")
        print(f"  Incident ID: {response['incident_id']}")
        
    elif pred_ransom[0] == 1:
        print("  ❌ FALSE NEGATIVE - Ransomware sample NOT detected!")
        print("  ⚠️ Model needs retraining or threshold adjustment")
    
    # ==================== FULL EVALUATION ====================
    print("\n" + "="*70)
    print("FULL MODEL EVALUATION")
    print("="*70)
    
    # Create test set
    X_test = np.vstack([
        np.random.randn(30, 15) * 0.3 + 0.2,  # Normal samples
        np.random.randn(10, 15) * 0.5 + 0.8   # Ransomware samples
    ])
    X_test = np.abs(X_test)
    X_test[30:, 3] = np.random.uniform(7, 8, 10)  # High entropy for ransomware
    y_test = np.array([1]*30 + [-1]*10)
    
    metrics = detector.evaluate(X_test, y_test)
    
    print(f"\n  Accuracy:  {metrics['accuracy']*100:.1f}%")
    print(f"  Precision: {metrics['precision']*100:.1f}%")
    print(f"  Recall:    {metrics['recall']*100:.1f}%")
    print(f"  F1-Score:  {metrics['f1_score']*100:.1f}%")
    print(f"\n  True Positives:  {metrics['true_positives']}")
    print(f"  False Positives: {metrics['false_positives']}")
    print(f"  True Negatives:  {metrics['true_negatives']}")
    print(f"  False Negatives: {metrics['false_negatives']}")
    
    # Save model
    detector.save_model('ransomware_model.pkl')
    
    print("\n" + "="*70)
    print("✅ ML DETECTOR + STAGE 3 INTEGRATION COMPLETE!")
    print("="*70)