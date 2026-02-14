"""
Stage 1 Integrated System
Combines all detection components with ML prediction
"""

import time
import os
import json
import numpy as np
from datetime import datetime
from pathlib import Path

# Import all Stage 1 components
# NOTE: Make sure all previous files are in the same directory
try:
    from file_monitor import FileMonitor
    from honeypot_manager import HoneypotManager
    from process_monitor import ProcessMonitor
    from feature_extractor import FeatureExtractor
    from ml_detector import RansomwareMLDetector
except ImportError:
    print("⚠️  Make sure all Stage 1 files are in the same directory!")
    print("Required files:")
    print("  - file_monitor.py")
    print("  - honeypot_manager.py")
    print("  - process_monitor.py")
    print("  - feature_extractor.py")
    print("  - ml_detector.py")
    exit(1)


class Stage1IntegratedSystem:
    """Complete Stage 1: PREDICT system"""
    
    def __init__(self, watch_paths=None, log_dir="./data/logs"):
        print("="*70)
        print("INITIALIZING STAGE 1: PREDICT SYSTEM")
        print("="*70)
        
        # Create directories
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Watch paths
        self.watch_paths = watch_paths or ["./test_files"]
        for path in self.watch_paths:
            os.makedirs(path, exist_ok=True)
        
        # Initialize components
        print("\n1️⃣ Initializing File Monitor...")
        self.file_monitor = FileMonitor(
            self.watch_paths, 
            alert_callback=self._handle_file_alert
        )
        
        print("2️⃣ Initializing Honeypot System...")
        self.honeypot_manager = HoneypotManager(
            base_path="./honeypots",
            alert_callback=self._handle_honeypot_alert
        )
        
        print("3️⃣ Initializing Process Monitor...")
        self.process_monitor = ProcessMonitor(
            alert_callback=self._handle_process_alert
        )
        
        print("4️⃣ Initializing Feature Extractor...")
        self.feature_extractor = FeatureExtractor()
        
        print("5️⃣ Loading ML Detector...")
        self.ml_detector = RansomwareMLDetector(contamination=0.15)
        
        # Try to load pre-trained model
        if os.path.exists('ransomware_model.pkl'):
            self.ml_detector.load_model('ransomware_model.pkl')
        else:
            print("   ⚠️  No pre-trained model found. Training new model...")
            self._train_initial_model()
        
        # Data collection
        self.file_events = []
        self.process_events = []
        self.all_alerts = []
        
        # Status
        self.is_running = False
        self.threat_level = "LOW"
        
        print("\n✅ Stage 1 system initialized successfully!")
    
    def _train_initial_model(self):
        """Train initial ML model with synthetic data"""
        import numpy as np
        
        print("   Training initial model with synthetic data...")
        
        # Generate more realistic baseline data
        # Normal behavior - low values across all features
        normal = np.random.randn(200, 15) * 0.2 + 0.15
        normal = np.abs(normal)
        
        # Ransomware behavior - high values, especially for file activity and entropy
        ransomware = np.random.randn(30, 15) * 0.4 + 0.7
        ransomware[:, 0] *= 5  # High file modification rate
        ransomware[:, 3] = np.random.uniform(0.85, 0.95, 30)  # High entropy (normalized)
        ransomware[:, 11] = np.random.uniform(0.3, 1.0, 30)  # Honeypot compromised
        ransomware = np.abs(ransomware)
        
        X = np.vstack([normal, ransomware])
        
        # Shuffle
        indices = np.random.permutation(len(X))
        X = X[indices]
        
        self.ml_detector.train(X)
        self.ml_detector.save_model('ransomware_model.pkl')
        print("   ✅ Initial model trained on 230 samples")
    
    def _handle_file_alert(self, alert):
        """Handle file monitoring alerts"""
        self.file_events.append(alert)
        self.all_alerts.append({**alert, 'source': 'file_monitor'})
        self._log_alert(alert, 'file_monitor')
    
    def _handle_honeypot_alert(self, alert):
        """Handle honeypot alerts"""
        self.all_alerts.append({**alert, 'source': 'honeypot'})
        self._log_alert(alert, 'honeypot')
        print(f"\n🚨 CRITICAL: {alert['message']}")
    
    def _handle_process_alert(self, alert):
        """Handle process monitoring alerts"""
        self.process_events.append(alert)
        self.all_alerts.append({**alert, 'source': 'process_monitor'})
        self._log_alert(alert, 'process_monitor')
    
    def _log_alert(self, alert, source):
        """Log alert to file"""
        log_file = self.log_dir / f"alerts_{datetime.now().strftime('%Y%m%d')}.json"
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'source': source,
            'alert': alert
        }
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def start(self):
        """Start all monitoring systems"""
        print("\n" + "="*70)
        print("STARTING STAGE 1 MONITORING")
        print("="*70)
        
        # Deploy honeypots
        self.honeypot_manager.deploy_all_honeypots()
        
        # Start file monitoring
        self.file_monitor.start()
        
        self.is_running = True
        print("\n🟢 All systems operational!")
        print("\nMonitoring:")
        print(f"  📁 Files: {', '.join(self.watch_paths)}")
        print(f"  🍯 Honeypots: ./honeypots")
        print(f"  💻 Processes: All system processes")
        print("\nPress Ctrl+C to stop...\n")
    
    def analyze_current_state(self):
        """Analyze current system state with ML"""
        # Get recent events (last 60 seconds)
        current_time = time.time()
        
        # Filter recent file events - handle both float and string timestamps
        recent_files = []
        for e in self.file_events:
            timestamp = e.get('timestamp', 0)
            # Convert string timestamp to float if needed
            if isinstance(timestamp, str):
                try:
                    from dateutil import parser
                    timestamp = parser.parse(timestamp).timestamp()
                except:
                    continue
            
            if current_time - timestamp < 60:
                recent_files.append(e)
        
        recent_processes = self.process_monitor.get_all_processes()
        honeypot_status = self.honeypot_manager.get_status()
        
        # Extract features
        features = self.feature_extractor.extract_all_features(
            file_events=recent_files,
            process_data=recent_processes,
            honeypot_status=honeypot_status
        )
        
        # CRITICAL: Normalize features to 0-1 range
        features = self.feature_extractor.normalize_features(features)
        
        # Check if system is idle (all features near zero)
        feature_sum = float(np.sum(np.abs(features)))
        is_idle = feature_sum < 0.5
        
        # Determine prediction and threat score
        if is_idle:
            # System is completely idle - override ML prediction
            prediction_value = 1  # Normal
            threat_score_value = 5.0  # Very low threat
            is_ransomware = False
        else:
            # System has activity - use ML prediction
            features_2d = features.reshape(1, -1)
            prediction_array, threat_score_array = self.ml_detector.predict_with_confidence(features_2d)
            prediction_value = prediction_array[0]
            threat_score_value = threat_score_array[0]
            is_ransomware = (prediction_value == -1)
        
        # Determine threat level based on score, prediction, and honeypot status
        if honeypot_status['compromised'] > 0:
            # Honeypot triggered - always CRITICAL
            self.threat_level = "CRITICAL"
            threat_score_value = max(threat_score_value, 90.0)
            is_ransomware = True
        elif is_ransomware or threat_score_value > 70:
            self.threat_level = "CRITICAL"
        elif threat_score_value > 50:
            self.threat_level = "HIGH"
        elif threat_score_value > 30:
            self.threat_level = "MEDIUM"
        else:
            self.threat_level = "LOW"
        
        return {
            'prediction': 'RANSOMWARE' if is_ransomware else 'NORMAL',
            'threat_score': float(threat_score_value),
            'threat_level': self.threat_level,
            'features': features.tolist(),
            'feature_sum': feature_sum,
            'honeypot_status': honeypot_status,
            'recent_file_events': len(recent_files),
            'suspicious_processes': sum(1 for p in recent_processes 
                                      if p.get('threat_score', 0) > 30),
            'is_idle': is_idle
        }
    
    def monitoring_loop(self, interval=5):
        """Main monitoring loop"""
        try:
            while self.is_running:
                # Check honeypots
                self.honeypot_manager.check_integrity()
                
                # Scan processes
                self.process_monitor.scan_processes()
                
                # Analyze state with ML
                analysis = self.analyze_current_state()
                
                # Display status
                idle_marker = " [IDLE]" if analysis.get('is_idle', False) else ""
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"Threat: {analysis['threat_level']} | "
                      f"Score: {analysis['threat_score']:.1f}/100 | "
                      f"Prediction: {analysis['prediction']}{idle_marker}")
                
                if analysis['threat_level'] in ['HIGH', 'CRITICAL']:
                    print(f"  ⚠️  {analysis['suspicious_processes']} suspicious processes")
                    print(f"  ⚠️  {analysis['recent_file_events']} recent file events")
                
                time.sleep(interval)
        
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping monitoring...")
            self.stop()
    
    def stop(self):
        """Stop all monitoring"""
        self.is_running = False
        self.file_monitor.stop()
        print("✅ Stage 1 system stopped")
    
    def get_summary(self):
        """Get system summary"""
        return {
            'total_alerts': len(self.all_alerts),
            'file_events': len(self.file_events),
            'process_alerts': len(self.process_events),
            'threat_level': self.threat_level,
            'honeypot_status': self.honeypot_manager.get_status(),
            'file_monitor_stats': self.file_monitor.get_stats()
        }


# Main execution
if __name__ == "__main__":
    # Initialize system
    system = Stage1IntegratedSystem(
        watch_paths=["./test_files"],
        log_dir="./data/logs"
    )
    
    # Start monitoring
    system.start()
    
    # Run monitoring loop
    system.monitoring_loop(interval=5)
    
    # Print summary on exit
    print("\n" + "="*70)
    print("SESSION SUMMARY")
    print("="*70)
    summary = system.get_summary()
    for key, value in summary.items():
        print(f"  {key}: {value}")