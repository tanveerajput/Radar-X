"""
RADAR-X Attack Chain Tracker
Maps ransomware behavior to MITRE ATT&CK framework
Predicts next attack stage for proactive defense
"""

import json
import logging
from datetime import datetime
from typing import List, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AttackChainTracker:
    """Track and predict ransomware attack progression"""
    
    # MITRE ATT&CK Techniques for Ransomware
    ATTACK_CHAIN = {
        "T1566": {
            "name": "Phishing",
            "stage": 1,
            "next_stages": ["T1204", "T1059"],
            "description": "Initial Access - Malicious attachment/link"
        },
        "T1204": {
            "name": "User Execution",
            "stage": 2,
            "next_stages": ["T1059", "T1055"],
            "description": "Execution - User opens malicious file"
        },
        "T1059": {
            "name": "Command and Scripting",
            "stage": 3,
            "next_stages": ["T1055", "T1082"],
            "description": "Execution - PowerShell/cmd execution"
        },
        "T1055": {
            "name": "Process Injection",
            "stage": 4,
            "next_stages": ["T1082", "T1083"],
            "description": "Defense Evasion - Inject into legitimate process"
        },
        "T1082": {
            "name": "System Information Discovery",
            "stage": 5,
            "next_stages": ["T1083", "T1490"],
            "description": "Discovery - Gather system info"
        },
        "T1083": {
            "name": "File and Directory Discovery",
            "stage": 6,
            "next_stages": ["T1490", "T1486"],
            "description": "Discovery - Enumerate files for encryption"
        },
        "T1490": {
            "name": "Inhibit System Recovery",
            "stage": 7,
            "next_stages": ["T1486"],
            "description": "Impact - Delete shadow copies/backups"
        },
        "T1486": {
            "name": "Data Encrypted for Impact",
            "stage": 8,
            "next_stages": ["T1657"],
            "description": "Impact - Encrypt user files"
        },
        "T1657": {
            "name": "Ransom Note",
            "stage": 9,
            "next_stages": [],
            "description": "Impact - Display ransom demand"
        }
    }
    
    def __init__(self):
        self.detected_techniques = []
        self.current_stage = 0
        self.attack_timeline = []
        
    def map_behavior_to_technique(self, behavior_indicators: Dict) -> List[str]:
        """
        Map observed behavior to MITRE ATT&CK techniques
        
        Args:
            behavior_indicators: Dict with keys like:
                - high_entropy: bool
                - file_access_spike: bool
                - shadow_copy_deletion: bool
                - process_injection: bool
        
        Returns:
            List of matched technique IDs
        """
        matched_techniques = []
        
        # Behavioral pattern matching
        if behavior_indicators.get("shadow_copy_deletion"):
            matched_techniques.append("T1490")
        
        if behavior_indicators.get("high_entropy"):
            matched_techniques.append("T1486")
        
        if behavior_indicators.get("file_discovery"):
            matched_techniques.append("T1083")
        
        if behavior_indicators.get("process_injection"):
            matched_techniques.append("T1055")
        
        if behavior_indicators.get("script_execution"):
            matched_techniques.append("T1059")
        
        if behavior_indicators.get("system_info_collection"):
            matched_techniques.append("T1082")
        
        # Update tracking
        for tech_id in matched_techniques:
            self._record_technique(tech_id)
        
        return matched_techniques
    
    def _record_technique(self, technique_id: str):
        """Record detected technique with timestamp"""
        if technique_id not in [t["id"] for t in self.detected_techniques]:
            technique_info = self.ATTACK_CHAIN.get(technique_id, {})
            
            record = {
                "id": technique_id,
                "name": technique_info.get("name", "Unknown"),
                "stage": technique_info.get("stage", 0),
                "timestamp": datetime.now().isoformat(),
                "description": technique_info.get("description", "")
            }
            
            self.detected_techniques.append(record)
            self.attack_timeline.append(record)
            
            # Update current stage
            if record["stage"] > self.current_stage:
                self.current_stage = record["stage"]
            
            logger.info(f"🔍 Detected: {record['name']} (Stage {record['stage']})")
    
    def predict_next_stage(self) -> Dict:
        """
        Predict next attack techniques based on current stage
        
        Returns:
            Dict with predicted next techniques and recommended actions
        """
        if not self.detected_techniques:
            return {
                "predicted_techniques": [],
                "confidence": 0.0,
                "recommended_actions": ["Continue monitoring"]
            }
        
        # Get most recent technique
        latest_technique = self.detected_techniques[-1]
        tech_id = latest_technique["id"]
        
        # Look up next stages
        next_stages = self.ATTACK_CHAIN.get(tech_id, {}).get("next_stages", [])
        
        predicted = []
        for next_id in next_stages:
            tech_info = self.ATTACK_CHAIN.get(next_id, {})
            predicted.append({
                "id": next_id,
                "name": tech_info.get("name", "Unknown"),
                "stage": tech_info.get("stage", 0),
                "description": tech_info.get("description", "")
            })
        
        # Calculate confidence based on attack progression
        confidence = min(0.95, 0.5 + (self.current_stage * 0.08))
        
        # Recommend actions based on predicted stage
        recommended_actions = self._get_recommended_actions(predicted)
        
        prediction = {
            "current_stage": self.current_stage,
            "current_technique": latest_technique,
            "predicted_techniques": predicted,
            "confidence": confidence,
            "recommended_actions": recommended_actions,
            "urgency": self._calculate_urgency()
        }
        
        logger.warning(f"⚠ Prediction: {len(predicted)} next stages likely")
        return prediction
    
    def _get_recommended_actions(self, predicted_techniques: List[Dict]) -> List[str]:
        """Generate recommended mitigation actions"""
        actions = []
        
        for tech in predicted_techniques:
            tech_id = tech["id"]
            
            if tech_id == "T1490":  # Inhibit System Recovery
                actions.append("URGENT: Block access to shadow copies")
                actions.append("Protect backup systems immediately")
            
            elif tech_id == "T1486":  # Data Encryption
                actions.append("CRITICAL: Lock all sensitive folders NOW")
                actions.append("Isolate system from network")
                actions.append("Kill suspicious processes immediately")
            
            elif tech_id == "T1083":  # File Discovery
                actions.append("Monitor file system access patterns")
                actions.append("Enable honeypot file alerts")
            
            elif tech_id == "T1055":  # Process Injection
                actions.append("Monitor process creation/injection")
                actions.append("Enable process integrity checks")
        
        return list(set(actions)) if actions else ["Continue enhanced monitoring"]
    
    def _calculate_urgency(self) -> str:
        """Calculate threat urgency level"""
        if self.current_stage >= 7:
            return "CRITICAL"
        elif self.current_stage >= 5:
            return "HIGH"
        elif self.current_stage >= 3:
            return "MEDIUM"
        else:
            return "LOW"
    
    def generate_attack_report(self) -> Dict:
        """Generate comprehensive attack chain report"""
        report = {
            "report_id": f"ATTACK_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "attack_summary": {
                "total_techniques_detected": len(self.detected_techniques),
                "current_stage": self.current_stage,
                "attack_progression": self.current_stage / 9 * 100,  # % complete
                "urgency": self._calculate_urgency()
            },
            "detected_techniques": self.detected_techniques,
            "attack_timeline": self.attack_timeline,
            "predictions": self.predict_next_stage()
        }
        
        return report


# Test the tracker
if __name__ == "__main__":
    tracker = AttackChainTracker()
    
    # Simulate attack progression
    print("=== Simulating Ransomware Attack Chain ===\n")
    
    # Stage 1: File discovery
    behaviors_1 = {
        "file_discovery": True,
        "high_entropy": False
    }
    techniques = tracker.map_behavior_to_technique(behaviors_1)
    print(f"Detected: {techniques}")
    print(f"Prediction: {tracker.predict_next_stage()['predicted_techniques']}\n")
    
    # Stage 2: Shadow copy deletion
    behaviors_2 = {
        "shadow_copy_deletion": True
    }
    techniques = tracker.map_behavior_to_technique(behaviors_2)
    print(f"Detected: {techniques}")
    
    # Generate report
    report = tracker.generate_attack_report()
    print("\n=== Attack Chain Report ===")
    print(json.dumps(report, indent=2))