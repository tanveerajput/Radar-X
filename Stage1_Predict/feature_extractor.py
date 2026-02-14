"""
Feature Extractor - Converts monitoring data into ML features
Extracts 15 features from file, process, and honeypot data
"""

import numpy as np
from collections import defaultdict
import time

class FeatureExtractor:
    """Extract machine learning features from monitoring data"""
    
    def __init__(self):
        # Feature history for time-based features
        self.file_history = defaultdict(list)
        self.process_history = defaultdict(list)
        self.window_size = 60  # 60 second window
        
    def extract_file_features(self, file_events):
        """
        Extract features from file monitoring events
        
        Features:
        1. files_modified_per_minute
        2. files_created_per_minute
        3. files_deleted_per_minute
        4. average_entropy
        5. unique_extensions_count
        """
        if not file_events:
            return [0, 0, 0, 0, 0]
        
        current_time = time.time()
        
        # Count events by type
        modified = sum(1 for e in file_events if e.get('type') == 'modified')
        created = sum(1 for e in file_events if e.get('type') == 'created')
        deleted = sum(1 for e in file_events if e.get('type') == 'deleted')
        
        # Calculate rates (per minute)
        time_span = max((current_time - file_events[0].get('timestamp', current_time)) / 60, 1)
        modified_rate = modified / time_span
        created_rate = created / time_span
        deleted_rate = deleted / time_span
        
        # Average entropy
        entropies = [e.get('entropy', 0) for e in file_events if 'entropy' in e]
        avg_entropy = np.mean(entropies) if entropies else 0
        
        # Unique extensions
        extensions = set()
        for event in file_events:
            path = event.get('path', '')
            if '.' in path:
                extensions.add(path.split('.')[-1])
        
        return [
            modified_rate,
            created_rate,
            deleted_rate,
            avg_entropy,
            len(extensions)
        ]
    
    def extract_process_features(self, process_data):
        """
        Extract features from process monitoring data
        
        Features:
        6. max_cpu_usage
        7. total_memory_usage_mb
        8. suspicious_process_count
        9. disk_write_rate_mb_per_sec
        10. process_creation_rate
        """
        if not process_data:
            return [0, 0, 0, 0, 0]
        
        # Max CPU usage
        cpu_values = [p.get('cpu_percent', 0) for p in process_data]
        max_cpu = max(cpu_values) if cpu_values else 0
        
        # Total memory
        memory_values = [p.get('memory_mb', 0) for p in process_data]
        total_memory = sum(memory_values)
        
        # Suspicious process count (based on threat score)
        suspicious_count = sum(1 for p in process_data if p.get('threat_score', 0) > 30)
        
        # Disk write rate (if available)
        write_rates = []
        for p in process_data:
            io = p.get('io_counters')
            if io and hasattr(io, 'write_bytes'):
                write_rates.append(io.write_bytes / (1024 * 1024))
        disk_write_rate = sum(write_rates) if write_rates else 0
        
        # Process creation rate (new processes in last minute)
        current_time = time.time()
        new_processes = sum(1 for p in process_data 
                          if current_time - p.get('start_time', 0) < 60)
        
        return [
            max_cpu,
            total_memory,
            suspicious_count,
            disk_write_rate,
            new_processes
        ]
    
    def extract_honeypot_features(self, honeypot_status):
        """
        Extract features from honeypot system
        
        Features:
        11. honeypots_compromised
        12. honeypot_access_rate
        """
        if not honeypot_status:
            return [0, 0]
        
        compromised = honeypot_status.get('compromised', 0)
        
        # Access rate (compromised / total)
        total = honeypot_status.get('total_honeypots', 1)
        access_rate = compromised / total if total > 0 else 0
        
        return [compromised, access_rate]
    
    def extract_temporal_features(self, file_events):
        """
        Extract time-based features
        
        Features:
        13. file_change_acceleration (rate of change increase)
        14. burst_activity_score (sudden spikes)
        15. consistency_score (how consistent the activity is)
        """
        if not file_events or len(file_events) < 2:
            return [0, 0, 1]
        
        # Sort by timestamp
        sorted_events = sorted(file_events, key=lambda x: x.get('timestamp', 0))
        
        # Calculate time deltas
        deltas = []
        for i in range(1, len(sorted_events)):
            delta = sorted_events[i]['timestamp'] - sorted_events[i-1]['timestamp']
            deltas.append(delta)
        
        # Acceleration (are events getting faster?)
        if len(deltas) >= 2:
            acceleration = (deltas[-1] - deltas[0]) / len(deltas)
        else:
            acceleration = 0
        
        # Burst detection (standard deviation of deltas)
        burst_score = np.std(deltas) if len(deltas) > 1 else 0
        
        # Consistency (coefficient of variation)
        mean_delta = np.mean(deltas) if deltas else 1
        consistency = burst_score / mean_delta if mean_delta > 0 else 0
        
        return [
            acceleration,
            burst_score,
            consistency
        ]
    
    def extract_all_features(self, file_events=None, process_data=None, honeypot_status=None):
        """
        Extract all 15 features
        
        Returns: numpy array of shape (15,)
        """
        features = []
        
        # File features (5)
        features.extend(self.extract_file_features(file_events or []))
        
        # Process features (5)
        features.extend(self.extract_process_features(process_data or []))
        
        # Honeypot features (2)
        features.extend(self.extract_honeypot_features(honeypot_status or {}))
        
        # Temporal features (3)
        features.extend(self.extract_temporal_features(file_events or []))
        
        return np.array(features)
    
    def get_feature_names(self):
        """Get names of all features"""
        return [
            # File features
            'files_modified_per_min',
            'files_created_per_min',
            'files_deleted_per_min',
            'average_entropy',
            'unique_extensions',
            # Process features
            'max_cpu_usage',
            'total_memory_mb',
            'suspicious_processes',
            'disk_write_rate',
            'new_processes_rate',
            # Honeypot features
            'honeypots_compromised',
            'honeypot_access_rate',
            # Temporal features
            'file_change_acceleration',
            'burst_activity',
            'activity_consistency'
        ]
    
    def normalize_features(self, features):
        """Normalize features to 0-1 range"""
        # Define max values for each feature
        max_values = np.array([
            100,  # files_modified_per_min
            50,   # files_created_per_min
            50,   # files_deleted_per_min
            8,    # average_entropy
            20,   # unique_extensions
            100,  # max_cpu_usage
            2000, # total_memory_mb
            10,   # suspicious_processes
            100,  # disk_write_rate
            20,   # new_processes_rate
            10,   # honeypots_compromised
            1,    # honeypot_access_rate
            1,    # file_change_acceleration
            10,   # burst_activity
            2     # activity_consistency
        ])
        
        # Avoid division by zero
        max_values = np.where(max_values == 0, 1, max_values)
        
        # Normalize
        normalized = features / max_values
        normalized = np.clip(normalized, 0, 1)
        
        return normalized


# Example usage and testing
if __name__ == "__main__":
    extractor = FeatureExtractor()
    
    # Example: Simulate file events
    file_events = [
        {'type': 'modified', 'timestamp': time.time(), 'entropy': 7.8, 'path': 'file1.txt'},
        {'type': 'modified', 'timestamp': time.time() + 1, 'entropy': 7.9, 'path': 'file2.doc'},
        {'type': 'created', 'timestamp': time.time() + 2, 'entropy': 7.7, 'path': 'file3.pdf'},
        {'type': 'deleted', 'timestamp': time.time() + 3, 'path': 'file4.xlsx'},
    ]
    
    # Example: Simulate process data
    process_data = [
        {'cpu_percent': 85, 'memory_mb': 450, 'threat_score': 45, 'start_time': time.time()},
        {'cpu_percent': 40, 'memory_mb': 200, 'threat_score': 15, 'start_time': time.time() - 120},
    ]
    
    # Example: Honeypot status
    honeypot_status = {
        'total_honeypots': 8,
        'compromised': 2
    }
    
    # Extract features
    features = extractor.extract_all_features(file_events, process_data, honeypot_status)
    feature_names = extractor.get_feature_names()
    
    print("="*70)
    print("FEATURE EXTRACTION DEMO")
    print("="*70)
    
    print("\n📊 Extracted Features:")
    for name, value in zip(feature_names, features):
        print(f"  {name:.<40} {value:.3f}")
    
    # Normalize
    normalized = extractor.normalize_features(features)
    print("\n📏 Normalized Features (0-1):")
    for name, value in zip(feature_names, normalized):
        print(f"  {name:.<40} {value:.3f}")
    
    print("\n✅ Feature extraction complete!")
    print(f"Total features: {len(features)}")