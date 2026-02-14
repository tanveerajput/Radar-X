"""
Final Model Fix - Retrain with proper idle handling
Run this to fix the model once and for all
"""

import os
import numpy as np
from ml_detector import RansomwareMLDetector

print("="*70)
print("FINAL MODEL FIX - RETRAINING")
print("="*70)

# Delete old model
if os.path.exists('ransomware_model.pkl'):
    os.remove('ransomware_model.pkl')
    print("✅ Deleted old model")

print("\n📊 Generating NEW training data with idle samples...")

# 1. IDLE samples (feature_sum < 0.5) - Should be NORMAL
idle_samples = []
for i in range(50):
    sample = np.random.uniform(0, 0.03, 15)  # Very low values
    idle_samples.append(sample)
idle_samples = np.array(idle_samples)
print(f"  • Idle samples: {len(idle_samples)} (feature_sum < 0.5)")

# 2. NORMAL activity samples (feature_sum 0.5-5) - Should be NORMAL
normal_samples = []
for i in range(150):
    sample = np.random.randn(15) * 0.15 + 0.3
    sample = np.abs(sample)
    sample[0] = np.random.uniform(0.1, 0.5)  # Low-medium file changes
    sample[3] = np.random.uniform(0.3, 0.6)  # Normal entropy
    sample[11] = 0  # No honeypot hits
    normal_samples.append(sample)
normal_samples = np.array(normal_samples)
print(f"  • Normal samples: {len(normal_samples)} (feature_sum 0.5-5)")

# 3. RANSOMWARE samples (feature_sum > 5) - Should be RANSOMWARE
ransomware_samples = []
for i in range(30):
    sample = np.random.randn(15) * 0.3 + 0.8
    sample = np.abs(sample)
    # Clear ransomware indicators
    sample[0] = np.random.uniform(3, 12)  # VERY high file mod rate
    sample[1] = np.random.uniform(1, 5)   # High creation rate
    sample[3] = np.random.uniform(0.85, 0.98)  # VERY high entropy
    sample[6] = np.random.uniform(0.8, 2.0)  # High memory
    sample[8] = np.random.uniform(2, 8)   # High disk I/O
    sample[11] = np.random.uniform(0.3, 1.0)  # Honeypot compromised
    ransomware_samples.append(sample)
ransomware_samples = np.array(ransomware_samples)
print(f"  • Ransomware samples: {len(ransomware_samples)} (feature_sum > 10)")

# Combine all
X_train = np.vstack([idle_samples, normal_samples, ransomware_samples])
indices = np.random.permutation(len(X_train))
X_train = X_train[indices]

print(f"\n📚 Total training samples: {len(X_train)}")

# Train with adjusted contamination
print("\n🔄 Training Isolation Forest...")
detector = RansomwareMLDetector(contamination=0.12)  # 12% are ransomware (30/250)
detector.train(X_train)

# Comprehensive testing
print("\n🧪 Testing predictions...\n")

tests = [
    ("Idle (all zeros)", np.zeros(15), "NORMAL", 5, 50),
    ("Idle (very low)", np.full(15, 0.02), "NORMAL", 5, 50),
    ("Light activity", np.array([0.1, 0.05, 0.02, 0.4, 2, 0.3, 0.4, 1, 0.2, 1, 0, 0, 0.01, 0.05, 0.3]), "NORMAL", 5, 45),
    ("Normal work", np.array([0.3, 0.1, 0.05, 0.5, 3, 0.4, 0.6, 1, 0.3, 2, 0, 0, 0.05, 0.1, 0.5]), "NORMAL", 20, 55),
    ("Heavy work", np.array([1.0, 0.5, 0.2, 0.65, 5, 0.6, 0.9, 2, 0.8, 3, 0, 0, 0.2, 0.3, 1.0]), "NORMAL or SUSPICIOUS", 30, 70),
    ("Suspicious", np.array([2.0, 1.0, 0.5, 0.8, 7, 0.75, 1.2, 3, 1.5, 4, 1, 0.25, 0.5, 1.0, 1.5]), "SUSPICIOUS", 50, 75),
    ("Clear Ransomware", np.array([8.0, 3.0, 1.5, 0.95, 10, 0.9, 1.8, 5, 5.0, 8, 2, 0.8, 2.0, 3.0, 2.5]), "RANSOMWARE", 75, 100),
]

all_correct = True
for name, test_sample, expected, min_score, max_score in tests:
    test_2d = test_sample.reshape(1, -1)
    pred, score = detector.predict_with_confidence(test_2d)
    feature_sum = float(np.sum(np.abs(test_sample)))
    
    pred_label = "NORMAL" if pred[0] == 1 else "RANSOMWARE"
    status = "✅" if (min_score <= score[0] <= max_score) else "⚠️"
    
    print(f"{status} {name:20} | Sum: {feature_sum:6.2f} | Pred: {pred_label:12} | Score: {score[0]:5.1f}/100")
    print(f"   Expected: {expected:20} | Score range: {min_score}-{max_score}")
    
    if not (min_score <= score[0] <= max_score):
        all_correct = False

# Save model
detector.save_model('ransomware_model.pkl')

print("\n" + "="*70)
if all_correct:
    print("✅ MODEL TRAINED PERFECTLY!")
else:
    print("⚠️  MODEL TRAINED (some scores outside expected range)")
print("="*70)

print("\n🎯 Key insight:")
print("  • Idle detection will override ML for feature_sum < 0.5")
print("  • ML handles everything with feature_sum >= 0.5")
print("  • This creates a robust two-layer defense")

print("\n🚀 Ready to run:")
print("  python stage1_integrated.py")
print("\nExpected behavior:")
print("  No activity    → [IDLE] LOW | 5.0/100 | NORMAL")
print("  Normal work    → LOW-MEDIUM | 20-50/100 | NORMAL")  
print("  Ransomware     → HIGH-CRITICAL | 70-100/100 | RANSOMWARE")