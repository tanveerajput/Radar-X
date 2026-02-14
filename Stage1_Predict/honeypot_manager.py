"""
Honeypot Manager - Creates decoy files to detect ransomware
Strategy: Place fake "valuable" files that ransomware will target first
"""

import os
import hashlib
import json
from pathlib import Path
from datetime import datetime
import time

class HoneypotManager:
    """Creates and monitors honeypot decoy files"""
    
    def __init__(self, base_path="./honeypots", alert_callback=None):
        self.base_path = Path(base_path)
        self.base_path.mkdir(exist_ok=True)
        self.alert_callback = alert_callback
        
        # Track all honeypot files
        self.honeypots = {}
        
        # Attractive file names for ransomware
        self.decoy_templates = [
            ("passwords.txt", "text", "username: admin\npassword: ********"),
            ("financial_data.xlsx", "binary", b"PK\x03\x04" + b"\x00" * 100),
            ("backup_keys.txt", "text", "SSH Private Key:\n-----BEGIN RSA PRIVATE KEY-----"),
            ("client_database.db", "binary", b"SQLite format" + b"\x00" * 200),
            ("tax_returns_2024.pdf", "binary", b"%PDF-1.4" + b"\x00" * 300),
            ("credit_cards.csv", "text", "card_number,cvv,expiry\n4532-****-****-1234,***,12/25"),
            ("bitcoin_wallet.dat", "binary", b"\x00\x00\x00\x01" + os.urandom(150)),
            ("medical_records.docx", "binary", b"PK\x03\x04" + b"\x00" * 250),
        ]
    
    def create_honeypot(self, filename, content_type, content):
        """Create a single honeypot file"""
        file_path = self.base_path / filename
        
        # Write content
        if content_type == "text":
            with open(file_path, 'w') as f:
                f.write(content)
        else:
            with open(file_path, 'wb') as f:
                f.write(content)
        
        # Calculate original hash
        file_hash = self._calculate_hash(file_path)
        
        # Store honeypot metadata
        self.honeypots[str(file_path)] = {
            'filename': filename,
            'created': datetime.now().isoformat(),
            'original_hash': file_hash,
            'size': os.path.getsize(file_path),
            'accessed': False,
            'modified': False
        }
        
        return file_path
    
    def deploy_all_honeypots(self):
        """Deploy all honeypot files"""
        print(f"🍯 Deploying honeypots in: {self.base_path}")
        
        for filename, content_type, content in self.decoy_templates:
            path = self.create_honeypot(filename, content_type, content)
            print(f"  ✅ Created: {filename}")
        
        print(f"🎯 {len(self.honeypots)} honeypots deployed!")
        self._save_honeypot_registry()
    
    def check_integrity(self):
        """Check if any honeypot has been tampered with"""
        alerts = []
        
        for file_path, metadata in self.honeypots.items():
            if not os.path.exists(file_path):
                # File deleted
                alert = self._trigger_alert(file_path, "DELETED", metadata)
                alerts.append(alert)
                continue
            
            # Check if file was modified
            current_hash = self._calculate_hash(file_path)
            current_size = os.path.getsize(file_path)
            
            if current_hash != metadata['original_hash']:
                # File modified - RANSOMWARE DETECTED!
                alert = self._trigger_alert(file_path, "MODIFIED", metadata, current_hash)
                alerts.append(alert)
                metadata['modified'] = True
            
            if current_size != metadata['size']:
                # Size changed
                alert = self._trigger_alert(file_path, "SIZE_CHANGED", metadata)
                alerts.append(alert)
        
        return alerts
    
    def _calculate_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            return None
    
    def _trigger_alert(self, file_path, alert_type, metadata, new_hash=None):
        """Trigger ransomware alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'alert_type': alert_type,
            'honeypot_file': file_path,
            'filename': metadata['filename'],
            'original_hash': metadata['original_hash'],
            'new_hash': new_hash,
            'threat_score': 95,  # Honeypot triggers are HIGH confidence
            'message': f"🚨 RANSOMWARE DETECTED! Honeypot '{metadata['filename']}' was {alert_type.lower()}!"
        }
        
        if self.alert_callback:
            self.alert_callback(alert)
        
        return alert
    
    def _save_honeypot_registry(self):
        """Save honeypot registry to disk"""
        registry_path = self.base_path / "honeypot_registry.json"
        with open(registry_path, 'w') as f:
            json.dump(self.honeypots, f, indent=2)
    
    def _load_honeypot_registry(self):
        """Load existing honeypot registry"""
        registry_path = self.base_path / "honeypot_registry.json"
        if registry_path.exists():
            with open(registry_path, 'r') as f:
                self.honeypots = json.load(f)
            print(f"📂 Loaded {len(self.honeypots)} existing honeypots")
    
    def start_monitoring(self, interval=5):
        """Continuously monitor honeypots"""
        print(f"👁️  Monitoring honeypots every {interval} seconds...")
        
        try:
            while True:
                alerts = self.check_integrity()
                if alerts:
                    for alert in alerts:
                        print(f"\n{'='*60}")
                        print(alert['message'])
                        print(f"File: {alert['filename']}")
                        print(f"Type: {alert['alert_type']}")
                        print(f"Threat Score: {alert['threat_score']}/100")
                        print(f"{'='*60}\n")
                
                time.sleep(interval)
        
        except KeyboardInterrupt:
            print("\n🛑 Honeypot monitoring stopped")
    
    def get_status(self):
        """Get honeypot system status"""
        total = len(self.honeypots)
        modified = sum(1 for h in self.honeypots.values() if h['modified'])
        intact = total - modified
        
        return {
            'total_honeypots': total,
            'intact': intact,
            'compromised': modified,
            'status': 'ALERT' if modified > 0 else 'SECURE'
        }


# Example usage and testing
if __name__ == "__main__":
    def alert_handler(alert):
        """Handle honeypot alerts"""
        print("\n" + "="*70)
        print("🚨 CRITICAL ALERT - RANSOMWARE DETECTED!")
        print("="*70)
        print(f"Time: {alert['timestamp']}")
        print(f"Honeypot: {alert['filename']}")
        print(f"Action: {alert['alert_type']}")
        print(f"Threat Score: {alert['threat_score']}/100")
        print("="*70 + "\n")
    
    # Initialize honeypot system
    manager = HoneypotManager(alert_callback=alert_handler)
    
    # Deploy honeypots
    manager.deploy_all_honeypots()
    
    print("\n" + "="*70)
    print("HONEYPOT SYSTEM READY")
    print("="*70)
    print("Try modifying files in './honeypots' folder to trigger detection")
    print("Press Ctrl+C to stop monitoring\n")
    
    # Start monitoring
    manager.start_monitoring(interval=3)