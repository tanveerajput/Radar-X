"""
Quick fix to add feature normalization
This is the missing piece!
"""

import shutil

print("="*70)
print("APPLYING NORMALIZATION FIX")
print("="*70)

# Backup
shutil.copy('stage1_integrated.py', 'stage1_integrated_backup.py')
print("\nBackup created: stage1_integrated_backup.py")

# Read file
with open('stage1_integrated.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find and replace
old_code = """        # Extract features
        features = self.feature_extractor.extract_all_features(
            file_events=recent_files,
            process_data=recent_processes,
            honeypot_status=honeypot_status
        )
        
        # Check if system is idle (all features near zero)
        feature_sum = float(np.sum(np.abs(features)))
        is_idle = feature_sum < 0.5"""

new_code = """        # Extract features
        features = self.feature_extractor.extract_all_features(
            file_events=recent_files,
            process_data=recent_processes,
            honeypot_status=honeypot_status
        )
        
        # CRITICAL: Normalize features to 0-1 range
        features = self.feature_extractor.normalize_features(features)
        
        # Check if system is idle (all features near zero)
        feature_sum = float(np.sum(np.abs(features)))
        is_idle = feature_sum < 0.5"""

if old_code in content:
    content = content.replace(old_code, new_code)
    print("Found and fixed the normalization issue!")
    
    # Write back
    with open('stage1_integrated.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("\n" + "="*70)
    print("SUCCESS - FILE PATCHED")
    print("="*70)
    print("\nThe issue: Features were not normalized!")
    print("  total_memory_mb was 13774 (should be 0-1)")
    print("  disk_write_rate was 10805 (should be 0-1)")
    print("\nNow they will be normalized before ML prediction.")
    
    print("\nRun this to verify:")
    print("  python debug_features.py")
    print("\nThen run:")
    print("  python stage1_integrated.py")
    
else:
    print("\nCould not find exact code block.")
    print("Please manually add this line after feature extraction:")
    print("  features = self.feature_extractor.normalize_features(features)")