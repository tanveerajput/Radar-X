"""
Diagnostic Script - Check if everything is working
"""

import os
import sys
import numpy as np

print("="*70)
print("STAGE 1 SYSTEM DIAGNOSTICS")
print("="*70)

# Check 1: Required files exist
print("\n1️⃣ Checking files...")
required_files = [
    'file_monitor.py',
    'honeypot_manager.py', 
    'process_monitor.py',
    'feature_extractor.py',
    'ml_detector.py',
    'stage1_integrated.py'
]

all_present = True
for file in required_files:
    if os.path.exists(file):
        print(f"  ✅ {file}")
    else:
        print(f"  ❌ {file} - MISSING!")
        all_present = False

# Check 2: Dependencies installed
print("\n2️⃣ Checking dependencies...")
try:
    import watchdog
    print("  ✅ watchdog")
except ImportError:
    print("  ❌ watchdog - Run: pip install watchdog")

try:
    import sklearn
    print("  ✅ scikit-learn")
except ImportError:
    print("  ❌ scikit-learn - Run: pip install scikit-learn")

try:
    import psutil
    print("  ✅ psutil")
except ImportError:
    print("  ❌ psutil - Run: pip install psutil")

try:
    import numpy
    print("  ✅ numpy")
except ImportError:
    print("  ❌ numpy - Run: pip install numpy")

# Check 3: Model file
print("\n3️⃣ Checking ML model...")
if os.path.exists('ransomware_model.pkl'):
    print("  ✅ ransomware_model.pkl exists")
    
    # Try loading and testing it
    try:
        from ml_detector import RansomwareMLDetector
        detector = RansomwareMLDetector()
        detector.load_model('ransomware_model.pkl')
        
        # Test with zeros
        test = np.zeros((1, 15))
        pred, score = detector.predict_with_confidence(test)
        print(f"  ✅ Model loaded successfully")
        print(f"     Test prediction: {pred[0]} (1=normal, -1=ransomware)")
        print(f"     Test score: {score[0]:.1f}/100")
        
        if score[0] == 0.0:
            print(f"  ⚠️  WARNING: Score is 0.0 - model may not be working correctly")
            print(f"     Solution: Run 'python fix_model.py'")
        elif pred[0] == -1 and score[0] > 50:
            print(f"  ⚠️  WARNING: Empty input detected as ransomware")
            print(f"     This is expected - system handles idle state separately")
        else:
            print(f"  ✅ Model predictions look good")
            
    except Exception as e:
        print(f"  ❌ Error loading model: {e}")
        print(f"     Solution: Run 'python fix_model.py'")
else:
    print("  ❌ ransomware_model.pkl not found")
    print("     Solution: Run 'python fix_model.py'")

# Check 4: Test directories
print("\n4️⃣ Checking directories...")
dirs = ['./test_files', './honeypots', './data/logs']
for dir_path in dirs:
    if os.path.exists(dir_path):
        print(f"  ✅ {dir_path}")
    else:
        print(f"  ⚠️  {dir_path} - Will be created automatically")

# Check 5: Feature extraction test
print("\n5️⃣ Testing feature extraction...")
try:
    from feature_extractor import FeatureExtractor
    import time
    
    extractor = FeatureExtractor()
    test_events = [{
        'timestamp': time.time(),
        'entropy': 0.5,
        'type': 'modified',
        'path': 'test.txt'
    }]
    
    features = extractor.extract_all_features(file_events=test_events)
    print(f"  ✅ Feature extraction working")
    print(f"     Features shape: {features.shape}")
    print(f"     Sample values: {features[:5]}")
    
    if np.all(features == 0):
        print(f"  ⚠️  All features are zero - this may cause issues")
    
except Exception as e:
    print(f"  ❌ Feature extraction failed: {e}")

# Summary
print("\n" + "="*70)
print("DIAGNOSTIC SUMMARY")
print("="*70)

if all_present:
    print("\n✅ All core files present")
else:
    print("\n❌ Some files are missing - check artifacts and re-download")

print("\n📋 Next steps:")
print("  1. If model issues detected: python fix_model.py")
print("  2. Start monitoring: python stage1_integrated.py")
print("  3. Run tests: python test_stage1.py (in another terminal)")

print("\n💡 Common issues:")
print("  • 'Score: 0.0' everywhere → Run fix_model.py")
print("  • 'Always RANSOMWARE' → Idle state issue (fixed in new code)")
print("  • 'TypeError timestamp' → Update file_monitor.py")