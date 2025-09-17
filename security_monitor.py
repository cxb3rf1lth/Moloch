#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RexPloit Security Monitor
Comprehensive security monitoring and audit logging system
For tracking all security-relevant events in the framework
"""

import os
import sys
import json
import time
import threading
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict, deque

# Rich for console output
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


class SecurityMonitor:
    """Comprehensive security monitoring and audit system"""
    
    def __init__(self, log_dir="logs"):
        self.log_dir = log_dir
        self.audit_log = os.path.join(log_dir, "security_audit.json")
        self.threat_log = os.path.join(log_dir, "threat_events.json")
        self.access_log = os.path.join(log_dir, "access_control.json")
        
        # In-memory tracking for real-time monitoring
        self.failed_attempts = defaultdict(list)
        self.suspicious_patterns = defaultdict(int)
        self.active_sessions = {}
        self.recent_events = deque(maxlen=1000)
        
        # Thresholds for security alerts
        self.max_failed_attempts = 5
        self.suspicious_threshold = 3
        self.session_timeout = 3600  # 1 hour
        
        # Ensure log directory exists
        os.makedirs(log_dir, mode=0o750, exist_ok=True)
        
        # Start background monitoring thread
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._background_monitor)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def log_security_event(self, event_type: str, details: Dict, severity: str = "MEDIUM", 
                          source_ip: str = "127.0.0.1", user_agent: str = "rexploit_framework"):
        """Log comprehensive security events"""
        try:
            event = {
                "timestamp": datetime.now().isoformat(),
                "event_type": event_type,
                "severity": severity,
                "source_ip": source_ip,
                "user_agent": user_agent,
                "details": details,
                "session_id": self._get_session_id(),
                "checksum": self._calculate_event_hash(event_type, details, severity)
            }
            
            # Write to audit log
            with open(self.audit_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event) + "\n")
            
            # Add to recent events for monitoring
            self.recent_events.append(event)
            
            # Check for suspicious patterns
            self._analyze_event_patterns(event)
            
            # Trigger alerts if necessary
            if severity in ["HIGH", "CRITICAL"]:
                self._trigger_security_alert(event)
            
            return True
            
        except Exception as e:
            console.print(f"[red]Security Monitor Error: {e}[/red]")
            return False
    
    def log_access_attempt(self, action: str, resource: str, success: bool, 
                          user_id: str = "anonymous", details: Dict = None):
        """Log access control events"""
        try:
            access_event = {
                "timestamp": datetime.now().isoformat(),
                "action": action,
                "resource": resource,
                "success": success,
                "user_id": user_id,
                "details": details or {},
                "session_id": self._get_session_id()
            }
            
            # Track failed attempts
            if not success:
                self.failed_attempts[user_id].append(datetime.now())
                # Clean old attempts (older than 1 hour)
                cutoff = datetime.now() - timedelta(hours=1)
                self.failed_attempts[user_id] = [
                    attempt for attempt in self.failed_attempts[user_id] 
                    if attempt > cutoff
                ]
                
                # Check for brute force patterns
                if len(self.failed_attempts[user_id]) >= self.max_failed_attempts:
                    self.log_security_event(
                        "brute_force_detected",
                        {"user_id": user_id, "attempts": len(self.failed_attempts[user_id])},
                        "HIGH"
                    )
            
            with open(self.access_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(access_event) + "\n")
            
            return True
            
        except Exception as e:
            console.print(f"[red]Access Log Error: {e}[/red]")
            return False
    
    def log_threat_event(self, threat_type: str, indicators: Dict, confidence: float):
        """Log potential security threats"""
        try:
            threat_event = {
                "timestamp": datetime.now().isoformat(),
                "threat_type": threat_type,
                "indicators": indicators,
                "confidence": confidence,
                "mitigation_status": "detected",
                "investigation_required": confidence > 0.7
            }
            
            with open(self.threat_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(threat_event) + "\n")
            
            # High confidence threats get immediate alerts
            if confidence > 0.8:
                self._trigger_threat_alert(threat_event)
            
            return True
            
        except Exception as e:
            console.print(f"[red]Threat Log Error: {e}[/red]")
            return False
    
    def get_security_summary(self) -> Dict:
        """Get comprehensive security summary"""
        try:
            summary = {
                "monitoring_status": "active" if self.monitoring_active else "inactive",
                "recent_events_count": len(self.recent_events),
                "failed_attempts_summary": {
                    user: len(attempts) for user, attempts in self.failed_attempts.items()
                },
                "suspicious_patterns": dict(self.suspicious_patterns),
                "active_sessions": len(self.active_sessions),
                "last_updated": datetime.now().isoformat()
            }
            
            return summary
            
        except Exception as e:
            console.print(f"[red]Summary Error: {e}[/red]")
            return {"error": str(e)}
    
    def generate_security_report(self) -> str:
        """Generate comprehensive security report"""
        try:
            # Analyze recent events
            recent_events = list(self.recent_events)[-100:]  # Last 100 events
            
            # Count events by severity
            severity_counts = defaultdict(int)
            event_type_counts = defaultdict(int)
            
            for event in recent_events:
                severity_counts[event.get('severity', 'UNKNOWN')] += 1
                event_type_counts[event.get('event_type', 'unknown')] += 1
            
            # Create report
            report = []
            report.append("=" * 60)
            report.append("RexPloit Security Monitor Report")
            report.append("=" * 60)
            report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report.append("")
            
            # Summary section
            report.append("SECURITY SUMMARY:")
            report.append("-" * 20)
            summary = self.get_security_summary()
            for key, value in summary.items():
                if isinstance(value, dict):
                    report.append(f"{key}:")
                    for sub_key, sub_value in value.items():
                        report.append(f"  {sub_key}: {sub_value}")
                else:
                    report.append(f"{key}: {value}")
            
            report.append("")
            
            # Event analysis
            report.append("EVENT ANALYSIS:")
            report.append("-" * 15)
            report.append("Severity Distribution:")
            for severity, count in sorted(severity_counts.items()):
                report.append(f"  {severity}: {count}")
            
            report.append("")
            report.append("Top Event Types:")
            sorted_events = sorted(event_type_counts.items(), key=lambda x: x[1], reverse=True)
            for event_type, count in sorted_events[:10]:
                report.append(f"  {event_type}: {count}")
            
            report.append("")
            report.append("=" * 60)
            
            return "\n".join(report)
            
        except Exception as e:
            return f"Error generating report: {e}"
    
    def _get_session_id(self) -> str:
        """Generate or get current session ID"""
        try:
            # Simple session ID based on process start time
            if not hasattr(self, '_session_id'):
                self._session_id = hashlib.md5(
                    f"{datetime.now().isoformat()}{os.getpid()}".encode()
                ).hexdigest()[:16]
            return self._session_id
        except Exception:
            return "unknown_session"
    
    def _calculate_event_hash(self, event_type: str, details: Dict, severity: str) -> str:
        """Calculate hash for event integrity"""
        try:
            content = f"{event_type}{json.dumps(details, sort_keys=True)}{severity}"
            return hashlib.sha256(content.encode()).hexdigest()[:16]
        except Exception:
            return "hash_error"
    
    def _analyze_event_patterns(self, event):
        """Analyze events for suspicious patterns"""
        try:
            # Track patterns
            pattern_key = f"{event['event_type']}:{event['severity']}"
            self.suspicious_patterns[pattern_key] += 1
            
            # Check for unusual activity
            if self.suspicious_patterns[pattern_key] > self.suspicious_threshold:
                self.log_security_event(
                    "suspicious_pattern_detected",
                    {"pattern": pattern_key, "count": self.suspicious_patterns[pattern_key]},
                    "MEDIUM"
                )
        
        except Exception as e:
            console.print(f"[yellow]Pattern analysis error: {e}[/yellow]")
    
    def _trigger_security_alert(self, event):
        """Trigger immediate security alert"""
        try:
            console.print(Panel(
                f"🚨 SECURITY ALERT 🚨\n\n"
                f"Event: {event['event_type']}\n"
                f"Severity: {event['severity']}\n"
                f"Time: {event['timestamp']}\n"
                f"Details: {json.dumps(event['details'], indent=2)}",
                title="Security Alert",
                border_style="red"
            ))
        except Exception as e:
            console.print(f"[red]Alert Error: {e}[/red]")
    
    def _trigger_threat_alert(self, threat_event):
        """Trigger threat-specific alert"""
        try:
            console.print(Panel(
                f"⚠️  THREAT DETECTED ⚠️\n\n"
                f"Type: {threat_event['threat_type']}\n"
                f"Confidence: {threat_event['confidence']:.2%}\n"
                f"Indicators: {json.dumps(threat_event['indicators'], indent=2)}",
                title="Threat Alert",
                border_style="yellow"
            ))
        except Exception as e:
            console.print(f"[red]Threat Alert Error: {e}[/red]")
    
    def _background_monitor(self):
        """Background monitoring thread"""
        while self.monitoring_active:
            try:
                # Clean up old data
                cutoff = datetime.now() - timedelta(hours=24)
                
                # Clean failed attempts
                for user_id in list(self.failed_attempts.keys()):
                    self.failed_attempts[user_id] = [
                        attempt for attempt in self.failed_attempts[user_id]
                        if attempt > cutoff
                    ]
                    if not self.failed_attempts[user_id]:
                        del self.failed_attempts[user_id]
                
                # Sleep for monitoring interval
                time.sleep(300)  # 5 minutes
                
            except Exception as e:
                console.print(f"[yellow]Monitor thread error: {e}[/yellow]")
                time.sleep(60)  # Wait a minute before retrying
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.monitoring_active = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)


# Global security monitor instance
security_monitor = None

def get_security_monitor(log_dir="logs") -> SecurityMonitor:
    """Get or create global security monitor instance"""
    global security_monitor
    if security_monitor is None:
        security_monitor = SecurityMonitor(log_dir)
    return security_monitor


# CLI interface for security monitoring
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="RexPloit Security Monitor")
    parser.add_argument("--report", action="store_true", help="Generate security report")
    parser.add_argument("--summary", action="store_true", help="Show security summary")
    parser.add_argument("--monitor", action="store_true", help="Start interactive monitoring")
    parser.add_argument("--log-dir", default="logs", help="Log directory path")
    
    args = parser.parse_args()
    
    monitor = get_security_monitor(args.log_dir)
    
    if args.report:
        print(monitor.generate_security_report())
    elif args.summary:
        summary = monitor.get_security_summary()
        console.print(Panel(json.dumps(summary, indent=2), title="Security Summary"))
    elif args.monitor:
        console.print("[green]Security Monitor started. Press Ctrl+C to stop.[/green]")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            monitor.stop_monitoring()
            console.print("[yellow]Security Monitor stopped.[/yellow]")
    else:
        console.print("[cyan]RexPloit Security Monitor ready.[/cyan]")
        console.print("Use --help for available options.")