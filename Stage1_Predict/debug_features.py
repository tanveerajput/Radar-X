"""
Debug script to see what features are being extracted
This will show you why idle detection isn't working
"""

import numpy as np
from feature_extractor import FeatureExtractor
from process_monitor import ProcessMonitor

print("="*70)
print("DEBUGGING FEATURE EXTRACTION WITH NORMALIZATION")
print("="*70)

# Initialize components
extractor = FeatureExtractor()
process_monitor = ProcessMonitor()

# Get current system processes
print("\n[1] Getting current system processes...")
processes = process_monitor.get_all_processes()
print(f"   Found {len(processes)} processes running")

# Extract features with NO file events (idle file system)
print("\n[2] Extracting features (no file events)...")
features = extractor.extract_all_features(
    file_events=[],
    process_data=processes,
    honeypot_status={'total_honeypots': 8, 'compromised': 0}
)

print("\n[3] BEFORE normalization:")
print(f"   Feature sum: {np.sum(np.abs(features)):.2f}")

# NORMALIZE (this is what's missing!)
features_normalized = extractor.normalize_features(features)

print("\n[4] AFTER normalization:")
print(f"   Feature sum: {np.sum(np.abs(features_normalized)):.4f}")

feature_names = extractor.get_feature_names()

print("\n" + "="*70)
print("NORMALIZED FEATURE BREAKDOWN")
print("="*70)
for i, (name, value) in enumerate(zip(feature_names, features_normalized)):
    marker = "HIGH" if value > 0.1 else "low"
    print(f"[{marker:4}] {i+1:2}. {name:30} = {value:.4f}")

# Calculate feature sum
feature_sum = float(np.sum(np.abs(features_normalized)))
print("\n" + "="*70)
print(f"NORMALIZED FEATURE SUM: {feature_sum:.4f}")
print(f"Current threshold: 0.5")
print(f"Is idle (sum < 0.5)? {feature_sum < 0.5}")
print("="*70)

if feature_sum >= 0.5:
    print("\n[ISSUE]")
    print(f"Feature sum ({feature_sum:.4f}) is still >= 0.5")
    print("Even after normalization!")
    
    # Find which features are contributing
    top_features = []
    for name, value in zip(feature_names, features_normalized):
        if value > 0.01:
            top_features.append((name, value))
    
    top_features.sort(key=lambda x: x[1], reverse=True)
    
    print("\nTop normalized features:")
    for name, value in top_features[:5]:
        print(f"  - {name}: {value:.4f}")
    
    # Calculate recommended threshold
    recommended = round(feature_sum * 1.5, 2)
    
    print("\n" + "="*70)
    print("SOLUTION")
    print("="*70)
    print(f"\nEven normalized, your baseline is: {feature_sum:.2f}")
    print(f"Recommended threshold: {recommended}")
    
    print(f"\nChange in stage1_integrated.py:")
    print(f"  self.IDLE_THRESHOLD = {recommended}")
    
else:
    print("\n[OK] Should work with threshold 0.5!")

print("\n" + "="*70)