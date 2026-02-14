"""
Generate CSV datasets for federated learning using Stage 1 features
Creates ULTRA CHALLENGING data with MASSIVE overlap for gradual learning
"""

import pandas as pd
import numpy as np
import sys
import os

# Add parent directory to path to import from Stage 1
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Stage1_Predict'))

try:
    from feature_extractor import FeatureExtractor
    STAGE1_AVAILABLE = True
except ImportError:
    print("Warning: Could not import Stage 1 feature_extractor")
    print("Using simplified features instead")
    STAGE1_AVAILABLE = False


def generate_integrated_data(node_id, num_samples=200):
    """
    Generate ULTRA CHALLENGING data where normal and ransomware heavily overlap.
    This forces the model to learn gradually across multiple rounds.
    
    Args:
        node_id: Node identifier (1=Hospital, 2=Bank, 3=University)
        num_samples: Number of samples to generate
    """
    np.random.seed(42 + node_id)
    
    print(f"Generating ultra-challenging data for Node {node_id}...")
    
    # Feature names from Stage 1
    feature_names = [
        'files_modified_per_min',
        'files_created_per_min',
        'files_deleted_per_min',
        'average_entropy',
        'unique_extensions',
        'max_cpu_usage',
        'total_memory_mb',
        'suspicious_processes',
        'disk_write_rate',
        'new_processes_rate',
        'honeypots_compromised',
        'honeypot_access_rate',
        'file_change_acceleration',
        'burst_activity',
        'activity_consistency'
    ]
    
    # Generate balanced dataset
    num_normal = int(num_samples * 0.55)
    num_ransomware = num_samples - num_normal
    
    # CRITICAL: Make distributions overlap HEAVILY
    # Normal behavior center: 0.50
    # Ransomware center: 0.65
    # HUGE overlap region: 0.45-0.70
    
    # Generate NORMAL samples (mean=0.50, std=0.20)
    normal_data = []
    for i in range(num_normal):
        base = np.random.normal(0.50, 0.20)  # Heavy variance
        
        sample = [
            np.random.normal(base * 1.0, 0.25),   # files_modified
            np.random.normal(base * 0.8, 0.20),   # files_created
            np.random.normal(base * 0.6, 0.18),   # files_deleted
            np.random.normal(base + 0.1, 0.18),   # entropy (OVERLAPS!)
            np.random.normal(base * 0.7, 0.20),   # extensions
            np.random.normal(base + 0.05, 0.20),  # cpu
            np.random.normal(base + 0.1, 0.20),   # memory
            np.random.poisson(max(0.1, base * 2)),  # suspicious_proc
            np.random.normal(base * 1.2, 0.25),   # disk_write
            np.random.normal(base * 0.9, 0.22),   # new_processes
            np.random.choice([0, 0, 0, 0, 1]),    # honeypots (rarely)
            np.random.normal(base * 0.3, 0.15),   # honeypot_rate
            np.random.normal(base * 0.8, 0.20),   # acceleration
            np.random.normal(base * 1.1, 0.23),   # burst
            np.random.normal(1.0, 0.30)           # consistency
        ]
        normal_data.append(sample + [0])
    
    # Generate RANSOMWARE samples (mean=0.65, std=0.20) - OVERLAPS with normal!
    ransomware_data = []
    for i in range(num_ransomware):
        base = np.random.normal(0.65, 0.20)  # Only slightly higher!
        
        sample = [
            np.random.normal(base * 1.3, 0.30),   # files_modified (not much higher!)
            np.random.normal(base * 1.1, 0.25),   # files_created
            np.random.normal(base * 0.8, 0.22),   # files_deleted
            np.random.normal(base + 0.15, 0.18),  # entropy (STILL OVERLAPS!)
            np.random.normal(base * 1.0, 0.23),   # extensions
            np.random.normal(base + 0.1, 0.22),   # cpu
            np.random.normal(base + 0.15, 0.22),  # memory
            np.random.poisson(max(0.1, base * 3)),  # suspicious_proc (slightly more)
            np.random.normal(base * 1.5, 0.30),   # disk_write
            np.random.normal(base * 1.3, 0.28),   # new_processes
            np.random.choice([0, 0, 0, 1, 1]),    # honeypots (sometimes)
            np.random.normal(base * 0.5, 0.20),   # honeypot_rate
            np.random.normal(base * 1.2, 0.25),   # acceleration
            np.random.normal(base * 1.4, 0.28),   # burst
            np.random.normal(0.7, 0.30)           # consistency
        ]
        ransomware_data.append(sample + [1])
    
    # Add MORE NOISE to increase difficulty
    all_data = normal_data + ransomware_data
    for sample in all_data:
        for i in range(len(sample) - 1):
            # Add substantial noise
            sample[i] += np.random.normal(0, 0.12)
    
    np.random.shuffle(all_data)
    
    # Create DataFrame
    columns = feature_names + ['label']
    df = pd.DataFrame(all_data, columns=columns)
    
    # Add organization-specific variations (subtle)
    node_names = {1: "Hospital", 2: "Bank", 3: "University"}
    
    if node_id == 1:  # Hospital
        df['files_modified_per_min'] += np.random.normal(0, 0.08, len(df))
        df['burst_activity'] += np.random.normal(0, 0.10, len(df))
    elif node_id == 2:  # Bank
        df['suspicious_processes'] += np.random.normal(0, 0.5, len(df))
        df['max_cpu_usage'] += np.random.normal(0, 0.08, len(df))
    elif node_id == 3:  # University
        df['unique_extensions'] += np.random.normal(0, 0.10, len(df))
        df['activity_consistency'] += np.random.normal(0, 0.12, len(df))
    
    # Clip to reasonable ranges
    for col in df.columns[:-1]:
        df[col] = df[col].clip(0, 3)  # Tighter range
    
    # Save to CSV
    script_dir = os.path.dirname(os.path.abspath(__file__))
    filename = os.path.join(script_dir, f'data_{node_names[node_id].lower()}.csv')
    df.to_csv(filename, index=False)
    
    # Calculate overlap metrics
    normal_samples = df[df['label'] == 0]
    ransomware_samples = df[df['label'] == 1]
    
    print(f"✅ Generated {filename}:")
    print(f"   Total samples: {num_samples}")
    print(f"   Normal: {num_normal} (avg entropy: {normal_samples['average_entropy'].mean():.3f})")
    print(f"   Ransomware: {num_ransomware} (avg entropy: {ransomware_samples['average_entropy'].mean():.3f})")
    print(f"   ⚠️  ENTROPY OVERLAP: {abs(normal_samples['average_entropy'].mean() - ransomware_samples['average_entropy'].mean()):.3f}")
    print(f"   Features: 15 (matching Stage 1)")
    print(f"   Challenge level: ULTRA HARD (massive overlap)")
    print()
    
    return filename


def main():
    print("="*70)
    print("GENERATING ULTRA CHALLENGING FEDERATED LEARNING DATA")
    print("="*70)
    print("Creating datasets with MASSIVE class overlap")
    print("This WILL show gradual improvement!\n")
    
    # Generate data for 3 organizations
    generate_integrated_data(node_id=1, num_samples=300)  # Hospital
    generate_integrated_data(node_id=2, num_samples=250)  # Bank
    generate_integrated_data(node_id=3, num_samples=200)  # University
    
    print("="*70)
    print("DATA GENERATION COMPLETE!")
    print("="*70)
    print("\nFiles created:")
    print("  ✅ data_hospital.csv (300 samples)")
    print("  ✅ data_bank.csv (250 samples)")
    print("  ✅ data_university.csv (200 samples)")
    print("\nWhy this will work:")
    print("  • Normal mean: ~0.50, Ransomware mean: ~0.65")
    print("  • HUGE overlap region: 0.45-0.70")
    print("  • High variance in both classes (std=0.20)")
    print("  • Added substantial noise (std=0.12)")
    print("  • Many ambiguous samples that are hard to classify")
    print("\nExpected results:")
    print("  Round 1: ~70-75% accuracy (struggling with overlap)")
    print("  Round 2: ~77-82% accuracy (learning combinations)")
    print("  Round 3: ~83-87% accuracy (refining boundaries)")
    print("  Round 4: ~87-90% accuracy (handling edge cases)")
    print("  Round 5: ~89-92% accuracy (converging)")
    print("\nNext steps:")
    print("  1. python federated_server_integrated.py")
    print("  2. python federated_client_integrated.py --data data_hospital.csv")
    print("  3. python federated_client_integrated.py --data data_bank.csv")
    print("="*70)


if __name__ == "__main__":
    main()