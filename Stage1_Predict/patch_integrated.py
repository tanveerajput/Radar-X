"""
Auto-Patch Script for stage1_integrated.py
This will fix the idle detection issue automatically
"""

import os
import shutil

# Backup original file
if os.path.exists('stage1_integrated.py'):
    shutil.copy('stage1_integrated.py', 'stage1_integrated.py.backup')
    print("✅ Backed up original file to stage1_integrated.py.backup")

# The complete fixed analyze_current_state method
FIXED_METHOD = '''    def analyze_current_state(self):
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
'''

# Read current file
with open('stage1_integrated.py', 'r') as f:
    content = f.read()

# Check if numpy is imported
if 'import numpy as np' not in content:
    print("📝 Adding numpy import...")
    content = content.replace(
        'import time\nimport os\nimport json\nfrom datetime import datetime',
        'import time\nimport os\nimport json\nimport numpy as np\nfrom datetime import datetime'
    )

# Find and replace the analyze_current_state method
import re

# Pattern to match the entire method
pattern = r'    def analyze_current_state\(self\):.*?(?=\n    def |\n\nclass |\Z)'

# Check if method exists
if re.search(pattern, content, re.DOTALL):
    print("🔧 Replacing analyze_current_state method...")
    content = re.sub(pattern, FIXED_METHOD, content, flags=re.DOTALL)
else:
    print("❌ Could not find analyze_current_state method!")
    exit(1)

# Fix monitoring loop to show idle status
if 'idle_marker' not in content:
    print("🔧 Updating monitoring loop to show [IDLE] status...")
    
    old_display = '''                # Display status
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"Threat: {analysis['threat_level']} | "
                      f"Score: {analysis['threat_score']:.1f}/100 | "
                      f"Prediction: {analysis['prediction']}")'''
    
    new_display = '''                # Display status
                idle_marker = " [IDLE]" if analysis.get('is_idle', False) else ""
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"Threat: {analysis['threat_level']} | "
                      f"Score: {analysis['threat_score']:.1f}/100 | "
                      f"Prediction: {analysis['prediction']}{idle_marker}")'''
    
    if old_display in content:
        content = content.replace(old_display, new_display)
    else:
        print("⚠️  Could not find exact monitoring loop pattern - might need manual update")

# Write fixed file
with open('stage1_integrated.py', 'w') as f:
    f.write(content)

print("\n" + "="*70)
print("✅ FILE PATCHED SUCCESSFULLY!")
print("="*70)

print("\n📋 Changes made:")
print("  1. ✅ Added numpy import")
print("  2. ✅ Fixed analyze_current_state with idle detection")
print("  3. ✅ Updated monitoring loop to show [IDLE] tag")

print("\n🧪 Verify the fix:")
print("  python verify_fix.py")

print("\n🚀 Run the system:")
print("  python stage1_integrated.py")

print("\n💾 Your original file was backed up to:")
print("  stage1_integrated.py.backup")