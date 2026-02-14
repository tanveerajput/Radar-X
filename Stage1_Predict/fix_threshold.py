"""
Fix the IDLE_THRESHOLD to the correct value
"""

print("="*70)
print("FIXING IDLE THRESHOLD TO CORRECT VALUE")
print("="*70)

# Read file
with open('stage1_integrated.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find and replace the IDLE_THRESHOLD line
fixed = False
for i, line in enumerate(lines):
    if 'self.IDLE_THRESHOLD' in line:
        old_line = line.strip()
        lines[i] = '        self.IDLE_THRESHOLD = 4.0  # Calibrated for your system baseline\n'
        new_line = lines[i].strip()
        fixed = True
        print(f"\n✅ Found threshold setting at line {i+1}")
        print(f"\nOLD: {old_line}")
        print(f"NEW: {new_line}")
        break

if fixed:
    # Write back
    with open('stage1_integrated.py', 'w', encoding='utf-8') as f:
        f.writelines(lines)
    
    print("\n" + "="*70)
    print("SUCCESS")
    print("="*70)
    print("\n📊 Explanation:")
    print("  Your system's normalized baseline: 2.50")
    print("  New threshold: 4.0 (allows some headroom)")
    print("  This means: feature_sum < 4.0 = IDLE")
    print("\n🚀 Now run: python stage1_integrated.py")
    print("\nYou should see: [IDLE] status now!")
else:
    print("\n⚠️ Could not find IDLE_THRESHOLD line")
    print("\nManual fix:")
    print("  Open stage1_integrated.py")
    print("  Find: self.IDLE_THRESHOLD = ...")
    print("  Change to: self.IDLE_THRESHOLD = 4.0")