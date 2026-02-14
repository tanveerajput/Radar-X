"""
Process Monitor - Tracks suspicious process behavior
Detects: high CPU usage, excessive disk I/O, suspicious process names
"""

import psutil
import time
from datetime import datetime
from collections import defaultdict

class ProcessMonitor:
    """Monitor system processes for ransomware-like behavior"""
    
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        
        # Suspicious process name patterns
        self.suspicious_names = [
            'encrypt', 'crypt', 'ransom', 'locker', 'lock',
            'wcry', 'wannacry', 'petya', 'ryuk', 'maze'
        ]
        
        # Thresholds
        self.CPU_THRESHOLD = 80  # % CPU usage
        self.DISK_IO_THRESHOLD = 50 * 1024 * 1024  # 50 MB/s
        self.MEMORY_THRESHOLD = 500 * 1024 * 1024  # 500 MB
        
        # Tracking
        self.process_history = defaultdict(list)
        self.suspicious_processes = set()
        self.baseline_established = False
        self.baseline_io = {}
    
    def get_all_processes(self):
        """Get information about all running processes"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'io_counters']):
            try:
                info = proc.info
                processes.append({
                    'pid': info['pid'],
                    'name': info['name'],
                    'cpu_percent': info['cpu_percent'],
                    'memory_mb': info['memory_info'].rss / (1024 * 1024) if info['memory_info'] else 0,
                    'io_counters': info['io_counters']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return processes
    
    def analyze_process(self, proc_info):
        """Analyze a single process for suspicious behavior"""
        suspicious_indicators = []
        threat_score = 0
        
        pid = proc_info['pid']
        name = proc_info['name'].lower()
        
        # Check 1: Suspicious process name
        if any(pattern in name for pattern in self.suspicious_names):
            suspicious_indicators.append(f"Suspicious name: {proc_info['name']}")
            threat_score += 40
        
        # Check 2: High CPU usage
        if proc_info['cpu_percent'] > self.CPU_THRESHOLD:
            suspicious_indicators.append(f"High CPU: {proc_info['cpu_percent']:.1f}%")
            threat_score += 20
        
        # Check 3: High memory usage
        if proc_info['memory_mb'] > self.MEMORY_THRESHOLD / (1024 * 1024):
            suspicious_indicators.append(f"High memory: {proc_info['memory_mb']:.1f} MB")
            threat_score += 15
        
        # Check 4: Excessive disk I/O
        if proc_info['io_counters']:
            if pid in self.baseline_io:
                prev_read = self.baseline_io[pid]['read_bytes']
                prev_write = self.baseline_io[pid]['write_bytes']
                prev_time = self.baseline_io[pid]['timestamp']
                
                curr_read = proc_info['io_counters'].read_bytes
                curr_write = proc_info['io_counters'].write_bytes
                curr_time = time.time()
                
                time_delta = curr_time - prev_time
                if time_delta > 0:
                    read_rate = (curr_read - prev_read) / time_delta
                    write_rate = (curr_write - prev_write) / time_delta
                    
                    if write_rate > self.DISK_IO_THRESHOLD:
                        suspicious_indicators.append(f"High disk write: {write_rate / (1024*1024):.1f} MB/s")
                        threat_score += 25
            
            # Update baseline
            self.baseline_io[pid] = {
                'read_bytes': proc_info['io_counters'].read_bytes,
                'write_bytes': proc_info['io_counters'].write_bytes,
                'timestamp': time.time()
            }
        
        return suspicious_indicators, threat_score
    
    def scan_processes(self):
        """Scan all processes and detect suspicious behavior"""
        processes = self.get_all_processes()
        alerts = []
        
        for proc in processes:
            indicators, threat_score = self.analyze_process(proc)
            
            if threat_score > 30:  # Threshold for alert
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'pid': proc['pid'],
                    'process_name': proc['name'],
                    'cpu_percent': proc['cpu_percent'],
                    'memory_mb': proc['memory_mb'],
                    'threat_score': min(threat_score, 100),
                    'indicators': indicators
                }
                
                alerts.append(alert)
                self.suspicious_processes.add(proc['pid'])
                
                if self.alert_callback:
                    self.alert_callback(alert)
        
        return alerts
    
    def get_system_stats(self):
        """Get overall system statistics"""
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk_io = psutil.disk_io_counters()
        
        return {
            'cpu_usage': cpu_percent,
            'memory_used_percent': memory.percent,
            'memory_available_mb': memory.available / (1024 * 1024),
            'disk_read_mb': disk_io.read_bytes / (1024 * 1024) if disk_io else 0,
            'disk_write_mb': disk_io.write_bytes / (1024 * 1024) if disk_io else 0,
            'suspicious_processes': len(self.suspicious_processes)
        }
    
    def start_monitoring(self, interval=5):
        """Continuously monitor processes"""
        print(f"🔍 Starting process monitoring (interval: {interval}s)...")
        
        try:
            while True:
                alerts = self.scan_processes()
                
                if alerts:
                    print(f"\n⚠️  Found {len(alerts)} suspicious processes:")
                    for alert in alerts:
                        print(f"  • {alert['process_name']} (PID: {alert['pid']}) - Threat: {alert['threat_score']}/100")
                        for indicator in alert['indicators']:
                            print(f"    - {indicator}")
                
                # Show system stats
                stats = self.get_system_stats()
                print(f"\n📊 System: CPU {stats['cpu_usage']:.1f}% | "
                      f"RAM {stats['memory_used_percent']:.1f}% | "
                      f"Suspicious: {stats['suspicious_processes']}")
                
                time.sleep(interval)
        
        except KeyboardInterrupt:
            print("\n🛑 Process monitoring stopped")
    
    def kill_process(self, pid):
        """Terminate a suspicious process (use with caution!)"""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc.terminate()
            print(f"✅ Terminated process: {proc_name} (PID: {pid})")
            return True
        except Exception as e:
            print(f"❌ Failed to terminate PID {pid}: {e}")
            return False


# Example usage and testing
if __name__ == "__main__":
    def alert_handler(alert):
        """Handle process alerts"""
        print("\n" + "="*70)
        print("🚨 SUSPICIOUS PROCESS DETECTED!")
        print("="*70)
        print(f"Process: {alert['process_name']} (PID: {alert['pid']})")
        print(f"CPU: {alert['cpu_percent']:.1f}% | Memory: {alert['memory_mb']:.1f} MB")
        print(f"Threat Score: {alert['threat_score']}/100")
        print("Indicators:")
        for indicator in alert['indicators']:
            print(f"  • {indicator}")
        print("="*70 + "\n")
    
    # Initialize monitor
    monitor = ProcessMonitor(alert_callback=alert_handler)
    
    print("="*70)
    print("PROCESS MONITORING SYSTEM ACTIVE")
    print("="*70)
    print("Watching for:")
    print("  • High CPU usage (>80%)")
    print("  • Excessive disk I/O (>50 MB/s)")
    print("  • Suspicious process names")
    print("\nPress Ctrl+C to stop\n")
    
    # Start monitoring
    monitor.start_monitoring(interval=3)