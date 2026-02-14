"""
Universal fix - Works with any formatting
"""

import re

print("="*70)
print("UNIVERSAL NORMALIZATION FIX")
print("="*70)

# Read file
with open('stage1_integrated.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find the line with "extract_all_features"
fixed = False
new_lines = []

for i, line in enumerate(lines):
    new_lines.append(line)
    
    # Look for the closing parenthesis after extract_all_features
    if 'extract_all_features(' in line:
        # Find the closing line
        paren_count = line.count('(') - line.count(')')
        j = i
        while paren_count > 0 and j < len(lines) - 1:
            j += 1
            paren_count += lines[j].count('(') - lines[j].count(')')
            new_lines.append(lines[j])
        
        # Check if normalization is already there
        next_few_lines = ''.join(lines[j:j+5])
        if 'normalize_features' not in next_few_lines:
            # Add normalization
            indent = ' ' * (len(line) - len(line.lstrip()))
            new_lines.append(f'\n{indent}# CRITICAL: Normalize features to 0-1 range\n')
            new_lines.append(f'{indent}features = self.feature_extractor.normalize_features(features)\n')
            fixed = True
            print(f"\nFound extract_all_features at line {i+1}")
            print("Added normalization code!")
        else:
            print("\nNormalization already present!")
        
        # Skip to after the closing paren
        while i < j:
            i += 1
        break

if fixed:
    # Write back
    with open('stage1_integrated.py', 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    
    print("\n" + "="*70)
    print("SUCCESS")
    print("="*70)
    print("\nVerify the fix:")
    print("  python debug_features.py")
    print("\nThen run:")
    print("  python stage1_integrated.py")
else:
    print("\n" + "="*70)
    print("MANUAL FIX REQUIRED")
    print("="*70)
    print("\nOpen stage1_integrated.py")
    print("Find this line:")
    print("  features = self.feature_extractor.extract_all_features(...)")
    print("\nAdd AFTER it:")
    print("  features = self.feature_extractor.normalize_features(features)")