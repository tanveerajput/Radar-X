"""
Ransomware Attack Simulator
Use this to demonstrate RADAR-X detection for judges
"""

import os
import time
from pathlib import Path
import random

def simulate_ransomware_attack():
    """
    Simulates ransomware behavior to trigger RADAR-X alert
    """
    
    print("="*70)
    print("RADAR-X ATTACK SIMULATOR")
    print("="*70)
    print()
    print("This will simulate ransomware behavior to demonstrate")
    print("RADAR-X's detection and response capabilities.")
    print()
    print("⚠️  Make sure RADAR-X is running before starting!")
    print()
    input("Press Enter to start simulation...")
    
    print("\n[SIMULATION STARTED]\n")
    
    # Ensure honeypots directory exists
    honeypot_dir = Path("honeypots")
    honeypot_dir.mkdir(exist_ok=True)
    
    # Create honeypot files if they don't exist
    print("Step 1: Setting up honeypot traps...")
    honeypot_files = []
    for i in range(8):
        hf = honeypot_dir / f"decoy_{i}.txt"
        if not hf.exists():
            hf.write_text(f"Honeypot decoy file {i}\nDO NOT MODIFY")
        honeypot_files.append(hf)
    print(f"  ✓ Created {len(honeypot_files)} honeypot files")
    time.sleep(1)
    
    # Simulate rapid file access (typical ransomware behavior)
    print("\nStep 2: Simulating rapid file access...")
    for _ in range(5):
        hf = random.choice(honeypot_files)
        try:
            content = hf.read_text()
            print(f"  • Accessing {hf.name}")
            time.sleep(0.2)
        except:
            pass
    time.sleep(1)
    
    # Trigger honeypot by modifying files
    print("\nStep 3: Triggering honeypot detection...")
    print("  ⚠️  MODIFYING HONEYPOT FILES (RANSOMWARE BEHAVIOR)")
    
    for i, hf in enumerate(honeypot_files[:4]):  # Compromise half
        try:
            # Write random data to simulate encryption
            encrypted_data = "ENCRYPTED_" + "X" * 1000 + str(i)
            hf.write_text(encrypted_data)
            print(f"  • Modified {hf.name} → {len(encrypted_data)} bytes")
            time.sleep(0.3)
        except Exception as e:
            print(f"  • Error with {hf.name}: {e}")
    
    print("\n" + "="*70)
    print("SIMULATION COMPLETE!")
    print("="*70)
    print()
    print("✓ Honeypot files compromised: 4/8")
    print("✓ Ransomware behavior simulated")
    print()
    print("📊 RADAR-X should now:")
    print("  1. Detect the threat (score > 90)")
    print("  2. Show CRITICAL ALERT popup")
    print("  3. Trigger Stage 3 mitigation")
    print("  4. Generate forensic report")
    print()
    print("⏰ Expected alert time: 5-10 seconds")
    print()
    print("If you don't see an alert:")
    print("  • Check RADAR-X is running (green tray icon)")
    print("  • Ensure protection is started")
    print("  • Wait up to 15 seconds")
    print()
    

def cleanup_honeypots():
    """Clean up modified honeypots"""
    print("\nCleaning up honeypots...")
    
    honeypot_dir = Path("honeypots")
    if honeypot_dir.exists():
        for hf in honeypot_dir.glob("*.txt"):
            try:
                # Reset to original state
                hf.write_text(f"Honeypot decoy file\nDO NOT MODIFY")
                print(f"  ✓ Reset {hf.name}")
            except:
                pass
    
    print("✓ Cleanup complete")


def main():
    """Main menu"""
    while True:
        print("\n" + "="*70)
        print("RADAR-X ATTACK SIMULATOR - DEMO TOOL")
        print("="*70)
        print()
        print("1. Simulate Ransomware Attack (triggers alert)")
        print("2. Cleanup Honeypots (reset after demo)")
        print("3. Exit")
        print()
        
        choice = input("Enter choice (1-3): ").strip()
        
        if choice == "1":
            simulate_ransomware_attack()
        elif choice == "2":
            cleanup_honeypots()
        elif choice == "3":
            print("\nExiting...")
            break
        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()