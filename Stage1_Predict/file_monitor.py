"""
File Monitor - Detects suspicious file system activity
Watches for: rapid file changes, encryption patterns, mass deletions
"""

import os
import time
import math
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from collections import defaultdict
from datetime import datetime
import json

class RansomwareDetector(FileSystemEventHandler):
    def __init__(self, alert_callback=None):
        super().__init__()
        self.alert_callback = alert_callback
        
        # Tracking metrics
        self.file_changes = defaultdict(list)  # Track changes per minute
        self.extensions_changed = set()
        self.suspicious_extensions = {'.encrypted', '.locked', '.crypto', '.crypt'}
        
        # Thresholds
        self.RAPID_CHANGE_THRESHOLD = 10  # files per minute
        self.HIGH_ENTROPY_THRESHOLD = 7.5  # entropy > 7.5 suggests encryption
        
        # Statistics
        self.total_events = 0
        self.suspicious_events = 0
        
    def calculate_entropy(self, file_path):
        """Calculate Shannon entropy of a file (encrypted files have high entropy)"""
        try:
            with open(file_path, 'rb') as f:
                # Read first 1KB for speed
                data = f.read(1024)
                
            if len(data) == 0:
                return 0
            
            # Calculate byte frequency
            frequency = defaultdict(int)
            for byte in data:
                frequency[byte] += 1
            
            # Shannon entropy formula
            entropy = 0
            for count in frequency.values():
                probability = count / len(data)
                entropy -= probability * math.log2(probability)
            
            return entropy
        except Exception as e:
            return 0
    
    def on_modified(self, event):
        """Called when a file is modified"""
        if event.is_directory:
            return
        
        self.total_events += 1
        self._process_file_event(event.src_path, "modified")
    
    def on_created(self, event):
        """Called when a file is created"""
        if event.is_directory:
            return
        
        self.total_events += 1
        self._process_file_event(event.src_path, "created")
    
    def on_deleted(self, event):
        """Called when a file is deleted"""
        if event.is_directory:
            return
        
        self.total_events += 1
        self._process_file_event(event.src_path, "deleted")
    
    def _process_file_event(self, file_path, event_type):
        """Process and analyze file events"""
        current_minute = int(time.time() / 60)
        current_timestamp = time.time()  # Store as float
        
        # Track changes per minute
        self.file_changes[current_minute].append({
            'path': file_path,
            'type': event_type,
            'timestamp': current_timestamp  # Already a float
        })
        
        # Check file extension
        extension = Path(file_path).suffix.lower()
        if extension:
            self.extensions_changed.add(extension)
        
        # Calculate entropy for modified/created files
        entropy = 0
        if event_type in ['modified', 'created'] and os.path.exists(file_path):
            entropy = self.calculate_entropy(file_path)
        
        # Detect suspicious patterns
        is_suspicious = False
        reasons = []
        
        # Pattern 1: Rapid file changes
        recent_changes = len(self.file_changes[current_minute])
        if recent_changes >= self.RAPID_CHANGE_THRESHOLD:
            is_suspicious = True
            reasons.append(f"Rapid changes: {recent_changes} files/min")
        
        # Pattern 2: High entropy (encryption)
        if entropy > self.HIGH_ENTROPY_THRESHOLD:
            is_suspicious = True
            reasons.append(f"High entropy: {entropy:.2f} (likely encrypted)")
        
        # Pattern 3: Suspicious extension
        if extension in self.suspicious_extensions:
            is_suspicious = True
            reasons.append(f"Suspicious extension: {extension}")
        
        # Pattern 4: Many different extensions being modified
        if len(self.extensions_changed) > 5:
            is_suspicious = True
            reasons.append(f"Multiple file types: {len(self.extensions_changed)}")
        
        if is_suspicious:
            self.suspicious_events += 1
            alert_data = {
                'timestamp': current_timestamp,  # Use float timestamp
                'file': file_path,
                'event_type': event_type,
                'entropy': entropy,
                'reasons': reasons,
                'threat_score': min(100, len(reasons) * 25 + (entropy * 5))
            }
            
            if self.alert_callback:
                self.alert_callback(alert_data)
            
            return alert_data
        
        return None
    
    def get_statistics(self):
        """Get current monitoring statistics"""
        current_minute = int(time.time() / 60)
        recent_changes = len(self.file_changes[current_minute])
        
        return {
            'total_events': self.total_events,
            'suspicious_events': self.suspicious_events,
            'recent_changes_per_min': recent_changes,
            'unique_extensions': len(self.extensions_changed),
            'threat_level': 'HIGH' if recent_changes > 20 else 'MEDIUM' if recent_changes > 10 else 'LOW'
        }


class FileMonitor:
    """Main file monitoring system"""
    
    def __init__(self, watch_paths, alert_callback=None):
        self.watch_paths = watch_paths if isinstance(watch_paths, list) else [watch_paths]
        self.event_handler = RansomwareDetector(alert_callback)
        self.observer = Observer()
        
    def start(self):
        """Start monitoring"""
        for path in self.watch_paths:
            if os.path.exists(path):
                self.observer.schedule(self.event_handler, path, recursive=True)
                print(f"✅ Monitoring: {path}")
            else:
                print(f"⚠️  Path not found: {path}")
        
        self.observer.start()
        print("🔍 File monitoring started...")
    
    def stop(self):
        """Stop monitoring"""
        self.observer.stop()
        self.observer.join()
        print("🛑 File monitoring stopped")
    
    def get_stats(self):
        """Get monitoring statistics"""
        return self.event_handler.get_statistics()


# Example usage and testing
if __name__ == "__main__":
    def alert_handler(alert):
        """Called when suspicious activity detected"""
        print("\n🚨 SUSPICIOUS ACTIVITY DETECTED!")
        print(f"File: {alert['file']}")
        print(f"Threat Score: {alert['threat_score']}/100")
        print(f"Reasons: {', '.join(alert['reasons'])}")
        print("-" * 60)
    
    # Create test directory
    test_dir = "./test_monitor"
    os.makedirs(test_dir, exist_ok=True)
    
    # Start monitoring
    monitor = FileMonitor(test_dir, alert_callback=alert_handler)
    monitor.start()
    
    try:
        print("\n📊 Monitoring active. Create/modify files in './test_monitor' to see detection.")
        print("Press Ctrl+C to stop...\n")
        
        while True:
            time.sleep(5)
            stats = monitor.get_stats()
            print(f"Stats: {stats['total_events']} events | "
                  f"{stats['suspicious_events']} suspicious | "
                  f"Threat: {stats['threat_level']}")
    
    except KeyboardInterrupt:
        monitor.stop()