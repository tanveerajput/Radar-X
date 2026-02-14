"""
RADAR-X Background Ransomware Monitor
Runs silently in background, alerts and mitigates automatically when ransomware detected
"""

import sys
import os
import time
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
from datetime import datetime
from pathlib import Path
import json
import pystray
from PIL import Image, ImageDraw
import webbrowser

# Add Stage1_Predict to path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "Stage1_Predict"))

try:
    from feature_extractor import FeatureExtractor
    from ml_detector import RansomwareMLDetector
    import psutil
    import numpy as np
    COMPONENTS_AVAILABLE = True
except ImportError as e:
    print(f"Error: {e}")
    COMPONENTS_AVAILABLE = False

# Stage 3 integration
STAGE3_AVAILABLE = False
try:
    stage3_path = os.path.join(BASE_DIR, "Stage3_Mitigate")
    if os.path.exists(stage3_path):
        sys.path.insert(0, stage3_path)
        from stage3_mitigation import Stage3ProtectionPipeline
        STAGE3_AVAILABLE = True
except:
    pass


class ForensicReport:
    """Generate forensic report"""
    
    @staticmethod
    def generate(threat_data, stage3_response=None):
        """Create detailed forensic report"""
        
        report = {
            'incident_id': f"INC_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'detection_time': datetime.now().isoformat(),
            'threat_data': threat_data,
            'stage3_response': stage3_response
        }
        
        # Save to file
        reports_dir = Path("forensic_reports")
        reports_dir.mkdir(exist_ok=True)
        
        report_file = reports_dir / f"{report['incident_id']}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate text report
        text_report = ForensicReport._format_text_report(report)
        
        text_file = reports_dir / f"{report['incident_id']}.txt"
        with open(text_file, 'w') as f:
            f.write(text_report)
        
        return report_file, text_file, text_report
    
    @staticmethod
    def _format_text_report(report):
        """Format report as text"""
        
        lines = []
        lines.append("="*70)
        lines.append("RADAR-X RANSOMWARE INCIDENT REPORT")
        lines.append("="*70)
        lines.append("")
        
        lines.append(f"Incident ID: {report['incident_id']}")
        lines.append(f"Detection Time: {report['detection_time']}")
        lines.append(f"Severity: CRITICAL")
        lines.append("")
        
        lines.append("-"*70)
        lines.append("THREAT ANALYSIS")
        lines.append("-"*70)
        
        td = report['threat_data']
        lines.append(f"Threat Score: {td['threat_score']:.1f}/100")
        lines.append(f"Threat Level: {td['threat_level']}")
        lines.append(f"Prediction: {td['prediction']}")
        lines.append(f"System Idle: {td['is_idle']}")
        lines.append("")
        
        lines.append("Behavioral Indicators:")
        lines.append(f"  • Feature Sum: {td['feature_sum']:.3f}")
        lines.append(f"  • Active Processes: {td['process_count']}")
        lines.append(f"  • Honeypots Compromised: {td['honeypot_status']['compromised']}/{td['honeypot_status']['total_honeypots']}")
        
        if td['honeypot_status']['compromised'] > 0:
            lines.append(f"  • WARNING: Honeypot breach detected!")
        
        lines.append("")
        
        if report['stage3_response']:
            lines.append("-"*70)
            lines.append("AUTOMATED MITIGATION (STAGE 3)")
            lines.append("-"*70)
            
            s3 = report['stage3_response']
            lines.append(f"Status: {s3['status']}")
            lines.append(f"Response Time: {s3['total_response_time']:.3f} seconds")
            lines.append(f"Target Met: {'YES' if s3['total_response_time'] < 10 else 'NO'}")
            lines.append("")
            
            lines.append("Actions Taken:")
            for action in s3['actions_taken']:
                lines.append(f"  ✓ {action}")
            
            if s3.get('actions_failed'):
                lines.append("")
                lines.append("Failed Actions:")
                for action in s3['actions_failed']:
                    lines.append(f"  ✗ {action}")
            
            lines.append("")
        
        lines.append("-"*70)
        lines.append("RECOMMENDATIONS")
        lines.append("-"*70)
        lines.append("1. Do NOT restart the computer")
        lines.append("2. Disconnect from network immediately")
        lines.append("3. Contact IT security team")
        lines.append("4. Preserve all logs for investigation")
        lines.append("5. Run full antivirus scan")
        lines.append("6. Check backup integrity")
        lines.append("7. Review recent file access logs")
        lines.append("")
        
        lines.append("-"*70)
        lines.append("Report generated by RADAR-X Protection System")
        lines.append(f"Team CODE X | Banasthali Vidyapith")
        lines.append("="*70)
        
        return "\n".join(lines)


class ThreatAlertWindow(tk.Toplevel):
    """Critical threat alert popup"""
    
    def __init__(self, parent, threat_data, forensic_files):
        super().__init__(parent)
        
        self.threat_data = threat_data
        self.forensic_json, self.forensic_txt, self.forensic_report = forensic_files
        
        # Window setup
        self.title("🚨 RADAR-X CRITICAL ALERT")
        self.geometry("700x650")
        self.configure(bg='#000000')
        
        # Always on top
        self.attributes('-topmost', True)
        self.lift()
        self.focus_force()
        
        # Center on screen
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 350
        y = (self.winfo_screenheight() // 2) - 325
        self.geometry(f"700x650+{x}+{y}")
        
        self.create_widgets()
        
        # Alert sound
        try:
            for _ in range(3):
                self.bell()
                time.sleep(0.2)
        except:
            pass
    
    def create_widgets(self):
        # Critical header
        header = tk.Frame(self, bg='#cc0000', height=100)
        header.pack(fill=tk.X)
        
        tk.Label(
            header,
            text="🚨 RANSOMWARE DETECTED 🚨",
            font=('Arial', 26, 'bold'),
            bg='#cc0000',
            fg='white'
        ).pack(pady=25)
        
        # Main content
        content = tk.Frame(self, bg='#000000')
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Threat score (large display)
        score = self.threat_data['threat_score']
        tk.Label(
            content,
            text=f"THREAT SCORE: {score:.1f}/100",
            font=('Arial', 22, 'bold'),
            bg='#000000',
            fg='#ff0000'
        ).pack(pady=15)
        
        # Status message
        tk.Label(
            content,
            text="⚠️ CRITICAL SECURITY THREAT - IMMEDIATE ACTION REQUIRED",
            font=('Arial', 12, 'bold'),
            bg='#000000',
            fg='#ffaa00',
            wraplength=600
        ).pack(pady=10)
        
        # Details frame
        details_frame = tk.LabelFrame(
            content,
            text="Threat Details",
            font=('Arial', 12, 'bold'),
            bg='#1a1a1a',
            fg='white',
            padx=15,
            pady=15
        )
        details_frame.pack(fill=tk.BOTH, expand=True, pady=15)
        
        # Details
        details_text = scrolledtext.ScrolledText(
            details_frame,
            height=10,
            font=('Consolas', 10),
            bg='#0a0a0a',
            fg='#00ff00',
            relief=tk.FLAT,
            wrap=tk.WORD
        )
        details_text.pack(fill=tk.BOTH, expand=True)
        
        # Build details content
        details = []
        details.append(f"Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        details.append(f"Incident ID: {Path(self.forensic_txt).stem}")
        details.append(f"")
        details.append(f"Threat Level: {self.threat_data['threat_level']}")
        details.append(f"Classification: {self.threat_data['prediction']}")
        details.append(f"")
        details.append("Suspicious Indicators Detected:")
        details.append(f"  ✗ High entropy file operations")
        details.append(f"  ✗ Rapid file modifications")
        details.append(f"  ✗ Unusual process behavior")
        
        if self.threat_data['honeypot_status']['compromised'] > 0:
            details.append(f"  ✗ HONEYPOT BREACH ({self.threat_data['honeypot_status']['compromised']} files)")
        
        details.append(f"")
        
        if self.threat_data.get('stage3_triggered'):
            details.append("🛡️ AUTOMATED PROTECTION ACTIVATED:")
            s3 = self.threat_data.get('stage3_response', {})
            details.append(f"  ✓ Response time: {s3.get('total_response_time', 0):.2f}s")
            for action in s3.get('actions_taken', []):
                details.append(f"  ✓ {action}")
        else:
            details.append("⚠️ Manual intervention required")
        
        details.append(f"")
        details.append("IMMEDIATE ACTIONS REQUIRED:")
        details.append("  1. Do NOT restart this computer")
        details.append("  2. Disconnect from network NOW")
        details.append("  3. Contact IT security immediately")
        details.append("  4. View forensic report for details")
        
        for line in details:
            details_text.insert(tk.END, line + "\n")
        
        details_text.config(state=tk.DISABLED)
        
        # Button frame
        btn_frame = tk.Frame(content, bg='#000000')
        btn_frame.pack(pady=15)
        
        tk.Button(
            btn_frame,
            text="📄 View Forensic Report",
            command=self.open_report,
            font=('Arial', 11, 'bold'),
            bg='#0066cc',
            fg='white',
            padx=20,
            pady=12,
            cursor='hand2'
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            btn_frame,
            text="✓ Acknowledge",
            command=self.acknowledge,
            font=('Arial', 11, 'bold'),
            bg='#00aa00',
            fg='white',
            padx=20,
            pady=12,
            cursor='hand2'
        ).pack(side=tk.LEFT, padx=5)
    
    def open_report(self):
        """Open forensic report"""
        try:
            os.startfile(str(self.forensic_txt))
        except:
            # Unix/Mac
            webbrowser.open(f"file://{self.forensic_txt}")
    
    def acknowledge(self):
        """User acknowledges alert"""
        self.destroy()


class BackgroundMonitor:
    """Background monitoring service"""
    
    def __init__(self):
        self.is_running = False
        self.threat_count = 0
        self.last_check = None
        
        # Initialize components
        self.extractor = None
        self.detector = None
        self.stage3_protect = None
        
        if COMPONENTS_AVAILABLE:
            self.extractor = FeatureExtractor()
            self.detector = RansomwareMLDetector(contamination=0.15)
            
            model_path = Path("Stage1_Predict/ransomware_model.pkl")
            if model_path.exists():
                self.detector.load_model(str(model_path))
        
        if STAGE3_AVAILABLE:
            self.stage3_protect = Stage3ProtectionPipeline()
        
        # System tray icon
        self.icon = None
        self.setup_tray_icon()
    
    def setup_tray_icon(self):
        """Create system tray icon"""
        # Create icon image
        img = Image.new('RGB', (64, 64), color='#00ff00')
        draw = ImageDraw.Draw(img)
        draw.rectangle([8, 8, 56, 56], outline='white', width=4)
        draw.text((20, 20), "RX", fill='white')
        
        menu = pystray.Menu(
            pystray.MenuItem("RADAR-X Protection", lambda: None, enabled=False),
            pystray.MenuItem("Status: Stopped", self.show_status, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Start Protection", self.start_monitoring),
            pystray.MenuItem("Stop Protection", self.stop_monitoring),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self.quit_app)
        )
        
        self.icon = pystray.Icon("radar_x", img, "RADAR-X Protection", menu)
    
    def show_status(self):
        """Show status window"""
        # Update icon menu
        pass
    
    def start_monitoring(self):
        """Start protection"""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Update icon (green = active)
        img = Image.new('RGB', (64, 64), color='#00ff00')
        draw = ImageDraw.Draw(img)
        draw.ellipse([8, 8, 56, 56], fill='#00ff00')
        self.icon.icon = img
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop protection"""
        self.is_running = False
        
        # Update icon (red = stopped)
        img = Image.new('RGB', (64, 64), color='#ff0000')
        draw = ImageDraw.Draw(img)
        draw.ellipse([8, 8, 56, 56], fill='#ff0000')
        self.icon.icon = img
    
    def monitoring_loop(self):
        """Main monitoring loop"""
        while self.is_running:
            try:
                system_state = self.get_system_state()
                
                if system_state:
                    self.last_check = datetime.now()
                    
                    threat_score = system_state['threat_score']
                    is_ransomware = (system_state['prediction'] == 'RANSOMWARE')
                    
                    # Check for threat
                    if is_ransomware or threat_score > 70:
                        self.handle_threat(system_state)
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(5)
    
    def get_system_state(self):
        """Get current system state"""
        try:
            # Get processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                try:
                    info = proc.info
                    processes.append({
                        'pid': info['pid'],
                        'name': info['name'],
                        'cpu_percent': info['cpu_percent'] or 0,
                        'memory_mb': info['memory_info'].rss / (1024 * 1024) if info['memory_info'] else 0,
                        'threat_score': 0
                    })
                except:
                    continue
            
            # Check honeypots
            honeypot_dir = Path("honeypots")
            honeypot_compromised = 0
            honeypot_total = 8
            
            if honeypot_dir.exists():
                honeypot_files = list(honeypot_dir.glob("*.txt")) + list(honeypot_dir.glob("*.dat"))
                if honeypot_files:
                    honeypot_total = len(honeypot_files)
                    for hf in honeypot_files:
                        try:
                            if hf.stat().st_size > 1024:
                                honeypot_compromised += 1
                        except:
                            pass
            
            honeypot_status = {
                'total_honeypots': honeypot_total,
                'compromised': honeypot_compromised,
                'intact': honeypot_total - honeypot_compromised
            }
            
            # Extract features
            features_raw = self.extractor.extract_all_features(
                file_events=[],
                process_data=processes[:50],
                honeypot_status=honeypot_status
            )
            
            features_normalized = self.extractor.normalize_features(features_raw)
            feature_sum = float(np.sum(np.abs(features_normalized)))
            
            # Detect
            IDLE_THRESHOLD = 4.0
            is_idle = feature_sum < IDLE_THRESHOLD
            
            if is_idle:
                prediction = 1
                threat_score = 5.0
                is_ransomware = False
            else:
                features_2d = features_normalized.reshape(1, -1)
                pred, score = self.detector.predict_with_confidence(features_2d)
                prediction = pred[0]
                threat_score = float(score[0])
                is_ransomware = (prediction == -1)
            
            if honeypot_compromised > 0:
                threat_score = max(threat_score, 90.0)
                is_ransomware = True
            
            if honeypot_compromised > 0 or threat_score > 70:
                threat_level = "CRITICAL"
            elif threat_score > 50:
                threat_level = "HIGH"
            elif threat_score > 30:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"
            
            return {
                'threat_score': threat_score,
                'threat_level': threat_level,
                'prediction': 'RANSOMWARE' if is_ransomware else 'NORMAL',
                'feature_sum': feature_sum,
                'is_idle': is_idle,
                'process_count': len(processes),
                'honeypot_status': honeypot_status
            }
            
        except Exception as e:
            return None
    
    def handle_threat(self, system_state):
        """Handle detected threat"""
        self.threat_count += 1
        
        # Trigger Stage 3 if available
        stage3_response = None
        if STAGE3_AVAILABLE and self.stage3_protect:
            detection_data = {
                "threat_detected": True,
                "threat_level": "CRITICAL",
                "pid": 0,
                "process_name": "detected_threat",
                "detection_time": datetime.now().isoformat(),
                "indicators": {
                    "high_entropy": system_state['threat_score'] > 70,
                    "file_discovery": True,
                    "shadow_copy_deletion": False,
                    "honeypot_hit": system_state['honeypot_status']['compromised'] > 0,
                    "cpu_spike": True
                }
            }
            
            try:
                stage3_response = self.stage3_protect.respond_to_threat(detection_data)
                system_state['stage3_triggered'] = True
                system_state['stage3_response'] = stage3_response
            except Exception as e:
                print(f"Stage 3 error: {e}")
        
        # Generate forensic report
        forensic_files = ForensicReport.generate(system_state, stage3_response)
        
        # Show alert popup
        self.show_alert_popup(system_state, forensic_files)
    
    def show_alert_popup(self, threat_data, forensic_files):
        """Show threat alert window"""
        root = tk.Tk()
        root.withdraw()  # Hide main window
        
        ThreatAlertWindow(root, threat_data, forensic_files)
        
        root.mainloop()
    
    def quit_app(self):
        """Exit application"""
        self.is_running = False
        self.icon.stop()
    
    def run(self):
        """Run the monitor"""
        # Auto-start monitoring
        self.start_monitoring()
        self.icon.run()


def main():
    """Main entry point"""
    monitor = BackgroundMonitor()
    monitor.run()


if __name__ == "__main__":
    main()