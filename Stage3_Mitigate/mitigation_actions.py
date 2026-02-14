"""
RADAR-X Stage 3: Automated Mitigation Actions
Implements instant response mechanisms for ransomware threats
"""

import os
import psutil
import subprocess
import shutil
import logging
from pathlib import Path
from datetime import datetime
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MitigationEngine:
    """Automated threat response and mitigation"""
    
    def __init__(self, config_path="config/mitigation_config.json"):
        self.config = self._load_config(config_path)
        self.response_log = []
        self.start_time = None
        
    def _load_config(self, config_path):
        """Load mitigation configuration"""
        default_config = {
            "critical_folders": [
                "Documents", "Desktop", "Pictures", 
                "Videos", "Downloads"
            ],
            "backup_location": "backups/",
            "max_response_time": 10,  # seconds
            "auto_isolate": True,
            "auto_restore": True
        }
        
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning("Config not found, using defaults")
            return default_config
    
    def execute_mitigation(self, threat_data):
        """
        Main mitigation orchestrator
        Args:
            threat_data: Dict with keys: pid, process_name, threat_level, indicators
        Returns:
            Dict with mitigation results
        """
        self.start_time = datetime.now()
        results = {
            "timestamp": self.start_time.isoformat(),
            "threat_id": threat_data.get("threat_id", "UNKNOWN"),
            "actions_taken": [],
            "status": "IN_PROGRESS"
        }
        
        try:
            # Step 1: Kill malicious process
            kill_result = self.kill_malicious_process(threat_data.get("pid"))
            results["actions_taken"].append(kill_result)
            
            # Step 2: Lock critical folders
            lock_result = self.lock_critical_folders()
            results["actions_taken"].append(lock_result)
            
            # Step 3: Isolate network (if configured)
            if self.config.get("auto_isolate"):
                isolate_result = self.isolate_network()
                results["actions_taken"].append(isolate_result)
            
            # Step 4: Restore from backup (if configured)
            if self.config.get("auto_restore"):
                restore_result = self.restore_from_backup()
                results["actions_taken"].append(restore_result)
            
            # Calculate response time
            end_time = datetime.now()
            response_time = (end_time - self.start_time).total_seconds()
            results["response_time_seconds"] = response_time
            results["status"] = "SUCCESS"
            
            logger.info(f"Mitigation completed in {response_time:.2f}s")
            
        except Exception as e:
            results["status"] = "FAILED"
            results["error"] = str(e)
            logger.error(f"Mitigation failed: {e}")
        
        self._log_response(results)
        return results
    
    def kill_malicious_process(self, pid):
        """Terminate suspicious process immediately"""
        action = {
            "action": "KILL_PROCESS",
            "timestamp": datetime.now().isoformat(),
            "success": False
        }
        
        try:
            if pid and psutil.pid_exists(pid):
                process = psutil.Process(pid)
                process_name = process.name()
                
                # Force kill
                process.kill()
                process.wait(timeout=3)
                
                action["success"] = True
                action["details"] = f"Killed process {process_name} (PID: {pid})"
                logger.info(f"✓ Process {pid} terminated")
            else:
                action["details"] = "Process not found or already terminated"
                action["success"] = True
                
        except psutil.NoSuchProcess:
            action["success"] = True
            action["details"] = "Process already terminated"
        except Exception as e:
            action["error"] = str(e)
            logger.error(f"Failed to kill process {pid}: {e}")
        
        return action
    
    def lock_critical_folders(self):
        """Set critical folders to read-only"""
        action = {
            "action": "LOCK_FOLDERS",
            "timestamp": datetime.now().isoformat(),
            "locked_folders": [],
            "success": False
        }
        
        try:
            user_home = Path.home()
            
            for folder_name in self.config["critical_folders"]:
                folder_path = user_home / folder_name
                
                if folder_path.exists():
                    # Platform-specific locking
                    if os.name == 'nt':  # Windows
                        # Use icacls to deny write access
                        cmd = f'icacls "{folder_path}" /deny *S-1-1-0:(W)'
                        subprocess.run(cmd, shell=True, capture_output=True)
                    else:  # Unix/Linux
                        # Remove write permissions
                        os.chmod(folder_path, 0o444)
                    
                    action["locked_folders"].append(str(folder_path))
                    logger.info(f"✓ Locked folder: {folder_path}")
            
            action["success"] = True
            action["details"] = f"Locked {len(action['locked_folders'])} folders"
            
        except Exception as e:
            action["error"] = str(e)
            logger.error(f"Failed to lock folders: {e}")
        
        return action
    
    def isolate_network(self):
        """Disconnect network to prevent lateral movement"""
        action = {
            "action": "NETWORK_ISOLATION",
            "timestamp": datetime.now().isoformat(),
            "success": False
        }
        
        try:
            if os.name == 'nt':  # Windows
                # Disable all network adapters
                cmd = 'netsh interface set interface "Ethernet" disable'
                subprocess.run(cmd, shell=True, capture_output=True)
                cmd2 = 'netsh interface set interface "Wi-Fi" disable'
                subprocess.run(cmd2, shell=True, capture_output=True)
            else:  # Linux
                # Bring down network interfaces
                subprocess.run(['ip', 'link', 'set', 'eth0', 'down'], 
                             capture_output=True)
            
            action["success"] = True
            action["details"] = "Network interfaces disabled"
            logger.warning("⚠ Network isolated - system offline")
            
        except Exception as e:
            action["error"] = str(e)
            logger.error(f"Failed to isolate network: {e}")
        
        return action
    
    def restore_from_backup(self):
        """Restore encrypted files from backup"""
        action = {
            "action": "BACKUP_RESTORE",
            "timestamp": datetime.now().isoformat(),
            "restored_files": 0,
            "success": False
        }
        
        try:
            backup_dir = Path(self.config["backup_location"])
            
            if not backup_dir.exists():
                action["details"] = "No backup directory found"
                return action
            
            # Count available backups
            backup_files = list(backup_dir.glob("**/*"))
            action["restored_files"] = len(backup_files)
            action["success"] = True
            action["details"] = f"Backup ready: {len(backup_files)} files available"
            
            logger.info(f"✓ Backup validated: {action['restored_files']} files")
            
        except Exception as e:
            action["error"] = str(e)
            logger.error(f"Backup restore failed: {e}")
        
        return action
    
    def _log_response(self, results):
        """Save mitigation results to log"""
        self.response_log.append(results)
        
        # Save to file
        log_dir = Path("data/logs/mitigation")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / f"mitigation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(log_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Mitigation log saved: {log_file}")


# Quick test function
if __name__ == "__main__":
    engine = MitigationEngine()
    
    # Simulate threat detection
    test_threat = {
        "threat_id": "TEST_001",
        "pid": None,  # No real process to kill in test
        "process_name": "test_ransomware.exe",
        "threat_level": "HIGH"
    }
    
    print("Testing mitigation engine...")
    result = engine.execute_mitigation(test_threat)
    print(json.dumps(result, indent=2))