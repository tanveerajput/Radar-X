"""
Federated Learning Client - Integrated with Stage 1
ULTRA GRADUAL learning configuration
"""

import argparse
import numpy as np
import pandas as pd
import flwr as fl
from sklearn.linear_model import SGDClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, log_loss
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple
import warnings
warnings.filterwarnings('ignore')


class IntegratedFederatedClient(fl.client.NumPyClient):
    """
    Federated client with SLOW learning for gradual improvement.
    """
    
    def __init__(self, data_path: str, organization: str):
        self.data_path = data_path
        self.organization = organization
        
        # Ultra-conservative learning for gradual improvement
        self.model = SGDClassifier(
            loss='log_loss',
            penalty='l2',
            alpha=0.05,           # Higher regularization (learns slower)
            learning_rate='constant',
            eta0=0.01,            # Lower learning rate
            max_iter=20,          # Fewer iterations per round
            random_state=42,
            warm_start=True,
            tol=None              # Don't stop early
        )
        
        self.scaler = StandardScaler()
        
        print(f"\n{'='*70}")
        print(f"FEDERATED CLIENT: {organization}")
        print(f"{'='*70}")
        self._load_data()
        
    def _load_data(self):
        """Load CSV data with Stage 1's 15 features."""
        try:
            df = pd.read_csv(self.data_path)
            print(f"Data file: {self.data_path}")
            print(f"Data shape: {df.shape}")
            
            if df.shape[1] != 16:
                print(f"Warning: Expected 16 columns, got {df.shape[1]}")
            
            X = df.iloc[:, :-1].values
            y = df.iloc[:, -1].values
            
            # Split data
            self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Normalize features
            self.X_train = self.scaler.fit_transform(self.X_train).astype(np.float32)
            self.X_test = self.scaler.transform(self.X_test).astype(np.float32)
            self.y_train = self.y_train.astype(np.int32)
            self.y_test = self.y_test.astype(np.int32)

            print(f"Features: {df.shape[1] - 1}")
            print(f"Training samples: {len(self.X_train)}")
            print(f"  • Normal: {sum(self.y_train == 0)}")
            print(f"  • Ransomware: {sum(self.y_train == 1)}")
            print(f"Testing samples: {len(self.X_test)}")
            print(f"Learning rate: SLOW (for gradual improvement)")
            print(f"{'='*70}\n")
            
        except Exception as e:
            print(f"❌ Error loading data: {e}")
            raise
    
    def get_parameters(self, config: Dict) -> List[np.ndarray]:
        """Return model parameters."""
        if not hasattr(self.model, 'coef_'):
            return []
        return [self.model.coef_, self.model.intercept_]
    
    def set_parameters(self, parameters: List[np.ndarray]):
        """Update model with server parameters."""
        if len(parameters) == 2:
            self.model.coef_ = parameters[0]
            self.model.intercept_ = parameters[1]
    
    def fit(self, parameters: List[np.ndarray], config: Dict) -> Tuple[List[np.ndarray], int, Dict]:
        """Train model on local data."""
        print(f"\n{'='*70}")
        print(f"TRAINING - {self.organization}")
        print(f"{'='*70}")
        
        # Set parameters from server
        self.set_parameters(parameters)
        
        # Train model with partial_fit (incremental)
        if not hasattr(self.model, 'classes_'):
            self.model.partial_fit(self.X_train, self.y_train, classes=[0, 1])
        else:
            self.model.partial_fit(self.X_train, self.y_train)
        
        # Training metrics
        y_pred = self.model.predict(self.X_train)
        y_pred_proba = self.model.predict_proba(self.X_train)
        
        train_accuracy = accuracy_score(self.y_train, y_pred)
        train_loss = log_loss(self.y_train, y_pred_proba)
        
        print(f"Training accuracy: {train_accuracy:.4f}")
        print(f"Training loss: {train_loss:.4f}")
        
        # Show feature importance
        feature_names = [
            'files_modified', 'files_created', 'files_deleted', 'entropy',
            'extensions', 'cpu', 'memory', 'suspicious_proc', 'disk_io',
            'new_proc', 'honeypot_hit', 'honeypot_rate', 'acceleration',
            'burst', 'consistency'
        ]
        
        if hasattr(self.model, 'coef_'):
            coef = np.abs(self.model.coef_[0])
            top_3_idx = np.argsort(coef)[-3:][::-1]
            print(f"\nTop 3 important features:")
            for idx in top_3_idx:
                print(f"  • {feature_names[idx]}: {coef[idx]:.4f}")
        
        print(f"{'='*70}\n")
        
        metrics = {
            "accuracy": float(train_accuracy),
            "loss": float(train_loss)
        }
        
        return self.get_parameters({}), len(self.X_train), metrics
    
    def evaluate(self, parameters: List[np.ndarray], config: Dict) -> Tuple[float, int, Dict]:
        """Evaluate model on test data."""
        print(f"\n{'='*70}")
        print(f"EVALUATION - {self.organization}")
        print(f"{'='*70}")
        
        self.set_parameters(parameters)
        
        y_pred = self.model.predict(self.X_test)
        y_pred_proba = self.model.predict_proba(self.X_test)
        
        test_accuracy = accuracy_score(self.y_test, y_pred)
        test_loss = log_loss(self.y_test, y_pred_proba)
        
        from sklearn.metrics import confusion_matrix
        cm = confusion_matrix(self.y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        
        print(f"Test accuracy: {test_accuracy:.4f}")
        print(f"Test loss: {test_loss:.4f}")
        print(f"\nConfusion Matrix:")
        print(f"  True Negatives:  {tn}")
        print(f"  False Positives: {fp}")
        print(f"  False Negatives: {fn}")
        print(f"  True Positives:  {tp}")
        print(f"{'='*70}\n")
        
        metrics = {
            "accuracy": float(test_accuracy),
            "true_positives": int(tp),
            "false_positives": int(fp)
        }
        
        return float(test_loss), len(self.X_test), metrics


def main():
    """Start federated learning client."""
    parser = argparse.ArgumentParser(description="Integrated Federated Learning Client")
    parser.add_argument("--data", type=str, required=True, help="Path to CSV data file")
    parser.add_argument("--org", type=str, default="Organization", help="Organization name")
    parser.add_argument("--server", type=str, default="127.0.0.1:8080", help="Server address")
    
    args = parser.parse_args()
    
    # Auto-detect organization
    org_name = args.org
    if 'hospital' in args.data.lower():
        org_name = "Hospital"
    elif 'bank' in args.data.lower():
        org_name = "Bank"
    elif 'university' in args.data.lower():
        org_name = "University"
    
    print("="*70)
    print("INTEGRATED FEDERATED LEARNING CLIENT")
    print("="*70)
    print(f"Organization: {org_name}")
    print(f"Data file: {args.data}")
    print(f"Server: {args.server}")
    print(f"Model: SGDClassifier (ULTRA GRADUAL learning)")
    print("="*70)
    
    client = IntegratedFederatedClient(
        data_path=args.data,
        organization=org_name
    )
    
    print(f"Connecting to server at {args.server}...\n")
    fl.client.start_client(
        server_address=args.server,
        client=client.to_client()
    )
    
    print("\n" + "="*70)
    print(f"{org_name} - TRAINING COMPLETE")
    print("="*70)


if __name__ == "__main__":
    main()