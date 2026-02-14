"""
Test Script for Stage 1
Simulates ransomware behavior to test detection
"""

import os
import time
import random
import string
from pathlib import Path

class RansomwareSimulator:
    """Simulate ransomware behavior for testing"""
    
    def __init__(self, target_dir="./test_files"):
        self.target_dir = Path(target_dir)
        self.target_dir.mkdir(exist_ok=True)
        
    def simulate_normal_activity(self, duration=30):
        """Simulate normal file operations"""
        print("\n✅ Simulating NORMAL user activity...")
        
        start_time = time.time()
        file_count = 0
        
        while time.time() - start_time < duration:
            # Create a normal file
            filename = f"document_{file_count}.txt"
            filepath = self.target_dir / filename
            
            with open(filepath, 'w') as f:
                f.write(f"This is a normal document #{file_count}\n")
                f.write("Normal content with regular text.\n")
                f.write("User is working normally.\n")
            
            file_count += 1
            time.sleep(random.uniform(2, 5))  # Normal pace
        
        print(f"  Created {file_count} normal files")
    
    def simulate_ransomware_attack(self, duration=20):
        """Simulate ransomware encryption behavior"""
        print("\n🚨 Simulating RANSOMWARE ATTACK...")
        
        start_time = time.time()
        file_count = 0
        
        # Phase 1: Rapid file creation
        print("  Phase 1: Rapid file modifications...")
        while time.time() - start_time < duration / 2:
            filename = f"file_{file_count}.doc"
            filepath = self.target_dir / filename
            
            # Write random data (simulating encryption)
            with open(filepath, 'wb') as f:
                random_data = os.urandom(100)  # Random bytes = high entropy
                f.write(random_data)
            
            file_count += 1
            time.sleep(0.1)  # VERY FAST - ransomware behavior
        
        # Phase 2: Modify honeypots
        print("  Phase 2: Attacking honeypots...")
        honeypot_dir = Path("./honeypots")
        if honeypot_dir.exists():
            for honeypot in honeypot_dir.glob("*.txt"):
                with open(honeypot, 'wb') as f:
                    f.write(os.urandom(50))
                print(f"    ⚠️  Modified: {honeypot.name}")
                time.sleep(0.5)
        
        # Phase 3: Add ransomware extensions
        print("  Phase 3: Adding ransom extensions...")
        for i in range(5):
            filename = f"encrypted_{i}.locked"
            filepath = self.target_dir / filename
            with open(filepath, 'wb') as f:
                f.write(os.urandom(100))
            time.sleep(0.2)
        
        # Phase 4: Create ransom note
        ransom_note = self.target_dir / "RANSOM_NOTE.txt"
        with open(ransom_note, 'w') as f:
            f.write("YOUR FILES HAVE BEEN ENCRYPTED!\n")
            f.write("Pay 1 BTC to recover your data.\n")
        
        print(f"  Attack simulation complete: {file_count} files encrypted")
    
    def simulate_mixed_behavior(self):
        """Simulate both normal and malicious behavior"""
        print("\n🔄 Simulating MIXED behavior...")
        
        for i in range(10):
            if random.random() < 0.3:  # 30% chance of suspicious activity
                filename = f"suspicious_{i}.dat"
                filepath = self.target_dir / filename
                with open(filepath, 'wb') as f:
                    f.write(os.urandom(50))
            else:
                filename = f"normal_{i}.txt"
                filepath = self.target_dir / filename
                with open(filepath, 'w') as f:
                    f.write(f"Normal document {i}\n")
            
            time.sleep(random.uniform(0.5, 2))
        
        print("  Mixed simulation complete")
    
    def cleanup(self):
        """Clean up test files"""
        print("\n🧹 Cleaning up test files...")
        
        if self.target_dir.exists():
            for file in self.target_dir.glob("*"):
                try:
                    file.unlink()
                except Exception as e:
                    print(f"  ⚠️  Could not delete {file}: {e}")
        
        print("  Cleanup complete")


def run_full_test():
    """Run complete test suite"""
    print("="*70)
    print("STAGE 1 DETECTION SYSTEM - FULL TEST")
    print("="*70)
    
    simulator = RansomwareSimulator()
    
    # Test 1: Normal Activity
    print("\n" + "="*70)
    print("TEST 1: NORMAL USER ACTIVITY")
    print("="*70)
    print("Expected: LOW threat score, no alerts")
    
    simulator.simulate_normal_activity(duration=15)
    time.sleep(5)
    
    # Test 2: Ransomware Attack
    print("\n" + "="*70)
    print("TEST 2: RANSOMWARE ATTACK")
    print("="*70)
    print("Expected: HIGH/CRITICAL threat score, multiple alerts")
    
    simulator.simulate_ransomware_attack(duration=20)
    time.sleep(5)
    
    # Test 3: Mixed Behavior
    print("\n" + "="*70)
    print("TEST 3: MIXED BEHAVIOR")
    print("="*70)
    print("Expected: MEDIUM threat score, some alerts")
    
    simulator.simulate_mixed_behavior()
    time.sleep(5)
    
    print("\n" + "="*70)
    print("TEST SUITE COMPLETE")
    print("="*70)
    print("\nReview the Stage 1 system output for detection results.")
    print("Check ./data/logs/ for detailed alert logs.")
    
    # Cleanup
    input("\nPress Enter to cleanup test files...")
    simulator.cleanup()


if __name__ == "__main__":
    print("\n⚠️  WARNING: This script simulates ransomware behavior!")
    print("Make sure Stage 1 system is running in another terminal.")
    print("\nTo run Stage 1 system:")
    print("  python stage1_integrated.py")
    print("\nThen run this test script:")
    print("  python test_stage1.py")
    
    choice = input("\nStart tests? (yes/no): ").lower()
    
    if choice == 'yes':
        run_full_test()
    else:
        print("Tests cancelled.")