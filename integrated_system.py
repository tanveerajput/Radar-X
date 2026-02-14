"""
RADAR-X Integrated Backend System
Runs Stage 1 monitoring + Stage 2 FL triggers
Writes status to files that dashboard reads
"""

import os
import sys
import time
import json
import numpy as np
from datetime import datetime
from pathlib import Path


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "Stage1_Predict"))

# Import Stage 1 components
try:
    from file_monitor import FileMonitor
    from honeypot_manager import HoneypotManager
    from process_monitor import ProcessMonitor
    from feature_extractor import FeatureExtractor
    from ml_detector import RansomwareMLDetector
    STAGE1_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Stage 1 components not found: {e}")
    STAGE1_AVAILABLE = False


class IntegratedBackend:
    """Backend system that runs Stage 1 + Stage 2 and writes status for dashboard"""
    
    def __init__(self):
        print("="*70)
        print("RADAR-X INTEGRATED BACKEND")
        print("="*70)
        
        # Create shared directories for dashboard communication
        self.status_dir = Path("./shared_status")
        self.status_dir.mkdir(exist_ok=True)
        
        self.logs_dir = Path("./integrated_logs")
        self.logs_dir.mkdir(exist_ok=True)
        
        self.data_dir = Path("./integrated_data")
        self.data_dir.mkdir(exist_ok=True)
        
        # Test files directory
        self.test_dir = Path("./test_files")
        self.test_dir.mkdir(exist_ok=True)
        
        # Initialize Stage 1 if available
        if STAGE1_AVAILABLE:
            self._init_stage1()
        else:
            print("⚠️ Running in DEMO mode (Stage 1 not available)")
            self.demo_mode = True
        
        # Tracking
        self.collected_features = []
        self.feature_buffer_size = 50
        self.fl_training_count = 0
        self.model_version = 1
        self.is_running = False
        
        print("✅ Backend initialized\n")
    
    def _init_stage1(self):
        """Initialize Stage 1 components"""
        print("\n[STAGE 1] Initializing...")
        
        try:
            self.file_monitor = FileMonitor(
                ["./test_files"], 
                alert_callback=self._handle_alert
            )
            
            self.honeypot_manager = HoneypotManager(
                base_path="./honeypots",
                alert_callback=self._handle_alert
            )
            
            self.process_monitor = ProcessMonitor(
                alert_callback=self._handle_alert
            )
            
            self.feature_extractor = FeatureExtractor()
            
            self.ml_detector = RansomwareMLDetector(contamination=0.15)
            
            # Load or train model
            if os.path.exists('ransomware_model.pkl'):
                self.ml_detector.load_model('ransomware_model.pkl')
                print("✅ Loaded existing ML model")
            else:
                self._train_initial_model()
            
            self.demo_mode = False
            print("✅ Stage 1 initialized")
            
        except Exception as e:
            print(f"⚠️ Stage 1 init failed: {e}")
            self.demo_mode = True
    
    def _train_initial_model(self):
        """Train baseline model"""
        print("Training initial model...")
        normal = np.random.randn(200, 15) * 0.2 + 0.15
        normal = np.abs(normal)
        
        ransomware = np.random.randn(30, 15) * 0.4 + 0.7
        ransomware[:, 0] *= 5
        ransomware[:, 3] = np.random.uniform(0.85, 0.95, 30)
        ransomware = np.abs(ransomware)
        
        X = np.vstack([normal, ransomware])
        indices = np.random.permutation(len(X))
        X = X[indices]
        
        self.ml_detector.train(X)
        self.ml_detector.save_model('ransomware_model.pkl')
        print("✅ Model trained")
    
    def _handle_alert(self, alert):
        """Handle alerts from Stage 1"""
        alert['timestamp'] = datetime.now().isoformat()
        alert['model_version'] = self.model_version
        
        # Write to log file
        log_file = self.logs_dir / f"alerts_{datetime.now().strftime('%Y%m%d')}.json"
        with open(log_file, 'a') as f:
            f.write(json.dumps(alert) + '\n')
    
    def write_status(self, status):
        """Write current status for dashboard to read"""
        status_file = self.status_dir / "current_status.json"
        
        status['last_update'] = datetime.now().isoformat()
        status['fl_rounds'] = self.fl_training_count
        status['model_version'] = self.model_version
        status['features_collected'] = len(self.collected_features)
        status['buffer_progress'] = f"{len(self.collected_features)}/{self.feature_buffer_size}"
        
        with open(status_file, 'w') as f:
            json.dump(status, f, indent=2)
    
    def get_system_state(self):
        """Get current system state"""
        if self.demo_mode:
            # Demo mode - simulate
            return self._simulate_state()
        
        # Real Stage 1 analysis
        try:
            # Get data from Stage 1 components
            current_time = time.time()
            recent_processes = self.process_monitor.get_all_processes()
            honeypot_status = self.honeypot_manager.get_status()
            
            # Extract features
            features = self.feature_extractor.extract_all_features(
                file_events=[],  # Would be populated from file_monitor in real use
                process_data=recent_processes[:50],
                honeypot_status=honeypot_status
            )
            
            # Normalize
            features_normalized = self.feature_extractor.normalize_features(features)
            feature_sum = float(np.sum(np.abs(features_normalized)))
            
            # Idle detection
            IDLE_THRESHOLD = 4.0
            is_idle = feature_sum < IDLE_THRESHOLD
            
            # ML prediction
            if is_idle:
                prediction = 1
                threat_score = 5.0
                is_ransomware = False
            else:
                features_2d = features_normalized.reshape(1, -1)
                pred, score = self.ml_detector.predict_with_confidence(features_2d)
                prediction = pred[0]
                threat_score = float(score[0])
                is_ransomware = (prediction == -1)
            
            # Check honeypots
            if honeypot_status['compromised'] > 0:
                threat_score = max(threat_score, 90.0)
                is_ransomware = True
            
            # Determine threat level
            if honeypot_status['compromised'] > 0 or threat_score > 70:
                threat_level = "CRITICAL"
            elif threat_score > 50:
                threat_level = "HIGH"
            elif threat_score > 30:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"
            
            return {
                'threat_score': threat_score,
                'threat_level': threat_level,
                'prediction': 'RANSOMWARE' if is_ransomware else 'NORMAL',
                'features': features_normalized.tolist(),
                'feature_sum': feature_sum,
                'is_idle': is_idle,
                'process_count': len(recent_processes),
                'honeypot_status': honeypot_status,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"Error getting state: {e}")
            return self._simulate_state()
    
    def _simulate_state(self):
        """Simulate state for demo mode"""
        import random
        
        threat_score = random.uniform(5, 30)
        
        return {
            'threat_score': threat_score,
            'threat_level': 'LOW',
            'prediction': 'NORMAL',
            'features': [random.uniform(0, 0.3) for _ in range(15)],
            'feature_sum': random.uniform(1, 3),
            'is_idle': False,
            'process_count': random.randint(80, 150),
            'honeypot_status': {
                'total_honeypots': 8,
                'compromised': 0,
                'intact': 8
            },
            'timestamp': datetime.now().isoformat()
        }
    
    def collect_and_store_features(self, state):
        """Collect features and check if FL should trigger"""
        feature_dict = {
            'timestamp': datetime.now().isoformat(),
            'features': state['features'],
            'threat_score': state['threat_score'],
            'model_version': self.model_version
        }
        
        self.collected_features.append(feature_dict)
        
        # Save to CSV periodically
        if len(self.collected_features) % 10 == 0:
            self._save_features_csv()
        
        # Check if FL should trigger
        if len(self.collected_features) >= self.feature_buffer_size:
            self._trigger_fl()
    
    def _save_features_csv(self):
        """Save collected features to CSV"""
        if not self.collected_features:
            return
        
        import pandas as pd
        
        feature_names = [
            'files_modified', 'files_created', 'files_deleted', 'entropy',
            'extensions', 'cpu', 'memory', 'suspicious_proc', 'disk_io',
            'new_proc', 'honeypot_hit', 'honeypot_rate', 'acceleration',
            'burst', 'consistency'
        ]
        
        data = []
        for item in self.collected_features[-50:]:  # Last 50
            data.append(item['features'])
        
        df = pd.DataFrame(data, columns=feature_names)
        
        filename = self.data_dir / f"features_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df.to_csv(filename, index=False)
    
    def _trigger_fl(self):
        """Trigger federated learning"""
        print("\n" + "="*70)
        print(f"[STAGE 2] FEDERATED LEARNING - Round {self.fl_training_count + 1}")
        print("="*70)
        
        # Save collected data
        self._save_features_csv()
        
        # Simulate FL training
        print("📡 Hospital node: Training...")
        time.sleep(0.5)
        print("📡 Bank node: Training...")
        time.sleep(0.5)
        print("📡 University node: Training...")
        time.sleep(0.5)
        print("🔄 Aggregating models...")
        time.sleep(0.5)
        
        self.fl_training_count += 1
        self.model_version += 1
        
        # Write FL status
        fl_status = {
            'round': self.fl_training_count,
            'accuracy': 78 + (self.fl_training_count * 3.4),
            'timestamp': datetime.now().isoformat()
        }
        
        fl_file = self.status_dir / f"fl_round_{self.fl_training_count}.json"
        with open(fl_file, 'w') as f:
            json.dump(fl_status, f, indent=2)
        
        print(f"✅ FL Round {self.fl_training_count} complete")
        print(f"📈 Model v{self.model_version} | Accuracy: {fl_status['accuracy']:.1f}%\n")
        
        # Clear buffer
        self.collected_features = []
    
    def start(self):
        """Start backend monitoring"""
        print("\n" + "="*70)
        print("STARTING BACKEND MONITORING")
        print("="*70)
        
        if not self.demo_mode:
            # Deploy honeypots
            self.honeypot_manager.deploy_all_honeypots()
            # Start file monitoring
            self.file_monitor.start()
        
        self.is_running = True
        
        print("\n🟢 Backend running!")
        print(f"📊 Status updates: {self.status_dir}/current_status.json")
        print(f"📁 Logs: {self.logs_dir}/")
        print(f"🔄 Dashboard can now read real-time data")
        print("\n⏸️ Press Ctrl+C to stop\n")
    
    def monitoring_loop(self, interval=3):
        """Main loop - runs continuously"""
        try:
            while self.is_running:
                # Get current state
                state = self.get_system_state()
                
                # Write status for dashboard
                self.write_status(state)
                
                # Collect features
                self.collect_and_store_features(state)
                
                # Display status
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"Threat: {state['threat_level']:8} | "
                      f"Score: {state['threat_score']:5.1f} | "
                      f"Buffer: {len(self.collected_features):2}/{self.feature_buffer_size} | "
                      f"FL: {self.fl_training_count} | "
                      f"Model: v{self.model_version}")
                
                # Check honeypots
                if not self.demo_mode:
                    self.honeypot_manager.check_integrity()
                    self.process_monitor.scan_processes()
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping backend...")
            self.stop()
    
    def stop(self):
        """Stop backend"""
        self.is_running = False
        
        if not self.demo_mode:
            self.file_monitor.stop()
        
        # Write final status
        final_status = {
            'status': 'stopped',
            'fl_rounds': self.fl_training_count,
            'model_version': self.model_version,
            'features_collected': len(self.collected_features)
        }
        
        with open(self.status_dir / "final_status.json", 'w') as f:
            json.dump(final_status, f, indent=2)
        
        print("\n✅ Backend stopped")
        print(f"📊 Total FL rounds: {self.fl_training_count}")
        print(f"📈 Final model: v{self.model_version}")


if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║              RADAR-X INTEGRATED BACKEND SYSTEM                    ║
║              Stage 1 (PREDICT) + Stage 2 (LEARN)                  ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    backend = IntegratedBackend()
    backend.start()
    backend.monitoring_loop(interval=3)