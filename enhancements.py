#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Additional features and enhancements for RexPloit
"""

import os
import sys
import json
import hashlib
import random
import string
import socket
import requests
import ipaddress
from datetime import datetime

# These will be imported into the main rexploit.py
class TargetValidator:
    """Validates target systems before attacking"""

    def __init__(self, logger=None):
        self.logger = logger

    def validate_ip(self, ip_addr):
        """Validate if a string is a valid IP address"""
        try:
            ipaddress.ip_address(ip_addr)
            return True
        except ValueError:
            return False

    def validate_port(self, port):
        """Validate if a port is within valid range"""
        try:
            port_num = int(port)
            return 0 < port_num < 65536
        except ValueError:
            return False

    def check_target_connectivity(self, target, timeout=5):
        """Check if target is reachable"""
        if self.logger:
            self.logger.log(f"Checking connectivity to {target}", "INFO")

        parsed_url = None

        # Handle URLs
        if target.startswith(('http://', 'https://')):
            try:
                response = requests.get(target, timeout=timeout, verify=False)
                return response.status_code < 500  # Consider 4xx as "reachable but unauthorized"
            except requests.exceptions.RequestException:
                return False

        # Handle IP addresses or hostnames (without protocol)
        elif self.validate_ip(target) or "." in target:
            host = target
            port = 80  # Default to HTTP port

            # If port specified (host:port format)
            if ":" in target:
                parts = target.split(":")
                host = parts[0]
                if len(parts) > 1 and self.validate_port(parts[1]):
                    port = int(parts[1])

            # Try to connect
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((host, port))
                    return True
            except (socket.timeout, socket.error):
                return False

        return False

    def check_common_services(self, ip_addr):
        """Check for common open services on a target IP"""
        if self.logger:
            self.logger.log(f"Scanning common ports on {ip_addr}", "INFO")

        common_ports = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443]
        open_ports = []

        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((ip_addr, port))
                    if result == 0:
                        open_ports.append(port)
                        if self.logger:
                            self.logger.log(f"Port {port} open on {ip_addr}", "INFO")
            except:
                pass

        return open_ports

class SecurityUtils:
    """Security and cryptographic utilities"""

    @staticmethod
    def generate_secure_token(length=32):
        """Generate a secure random token"""
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

    @staticmethod
    def hash_payload(payload_content, algorithm="sha256"):
        """Hash payload content for integrity verification"""
        if algorithm == "sha256":
            return hashlib.sha256(payload_content.encode()).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(payload_content.encode()).hexdigest()
        else:
            return hashlib.md5(payload_content.encode()).hexdigest()

    @staticmethod
    def encrypt_file(input_path, output_path, password):
        """Simple encryption for files (placeholder for real encryption)"""
        try:
            with open(input_path, 'rb') as f:
                content = f.read()

            # In a real implementation, this would use proper encryption
            # Here we'll just simulate it with a hash
            encrypted = hashlib.sha256(password.encode() + content).digest() + content

            with open(output_path, 'wb') as f:
                f.write(encrypted)

            return True
        except Exception as e:
            return False

    @staticmethod
    def check_file_integrity(file_path, expected_hash):
        """Check file integrity using hash"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            file_hash = hashlib.sha256(content).hexdigest()
            return file_hash == expected_hash
        except:
            return False

class ReportGenerator:
    """Generate professional security reports"""

    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def create_report(self, data, report_type="security_assessment"):
        """Generate a professional security report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.output_dir, f"{report_type}_{timestamp}.json")

        # Add metadata
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "report_type": report_type,
            "data": data
        }

        # Write report to file
        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=4)

        return report_path

    def generate_html_report(self, json_report_path):
        """Convert JSON report to HTML"""
        html_path = json_report_path.replace('.json', '.html')

        try:
            # Load JSON report
            with open(json_report_path, 'r') as f:
                report_data = json.load(f)

            # Generate simple HTML report
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Security Report - {report_data['timestamp']}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1, h2, h3 {{ color: #2c3e50; }}
                    .header {{ background-color: #34495e; color: white; padding: 10px; }}
                    .section {{ margin-bottom: 20px; border: 1px solid #ddd; padding: 10px; }}
                    .critical {{ color: #e74c3c; }}
                    .high {{ color: #e67e22; }}
                    .medium {{ color: #f39c12; }}
                    .low {{ color: #3498db; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Professional Security Assessment Report</h1>
                    <p>Generated: {report_data['timestamp']}</p>
                </div>
            """

            # Add report sections based on data
            if report_data['report_type'] == "security_assessment":
                # Add vulnerability findings section
                if 'findings' in report_data['data']:
                    html_content += """
                    <div class="section">
                        <h2>Vulnerability Findings</h2>
                        <table>
                            <tr>
                                <th>Vulnerability</th>
                                <th>Severity</th>
                                <th>CVSS Score</th>
                                <th>Target</th>
                                <th>Description</th>
                            </tr>
                    """

                    for finding in report_data['data']['findings']:
                        severity_class = "medium"
                        if finding['severity'] == "Critical":
                            severity_class = "critical"
                        elif finding['severity'] == "High":
                            severity_class = "high"
                        elif finding['severity'] == "Low":
                            severity_class = "low"

                        html_content += f"""
                        <tr>
                            <td>{finding['vulnerability']}</td>
                            <td class="{severity_class}">{finding['severity']}</td>
                            <td>{finding['cvss_score']}</td>
                            <td>{finding['target']}</td>
                            <td>{finding['description']}</td>
                        </tr>
                        """

                    html_content += """
                        </table>
                    </div>
                    """

                # Add payload section
                if 'payloads' in report_data['data']:
                    html_content += """
                    <div class="section">
                        <h2>Payload Deployments</h2>
                        <table>
                            <tr>
                                <th>Target</th>
                                <th>Vector</th>
                                <th>Status</th>
                                <th>Timestamp</th>
                            </tr>
                    """

                    for payload in report_data['data']['payloads']:
                        status_class = "high" if payload['status'] == "delivered" else "medium"

                        html_content += f"""
                        <tr>
                            <td>{payload['target']}</td>
                            <td>{payload['vector']}</td>
                            <td class="{status_class}">{payload['status']}</td>
                            <td>{payload['timestamp']}</td>
                        </tr>
                        """

                    html_content += """
                        </table>
                    </div>
                    """

            # Close HTML
            html_content += """
            </body>
            </html>
            """

            # Write HTML to file
            with open(html_path, 'w') as f:
                f.write(html_content)

            return html_path

        except Exception as e:
            print(f"Error generating HTML report: {str(e)}")
            return None

class NetworkScanner:
    """Professional network scanning capabilities"""

    def __init__(self, logger=None):
        self.logger = logger

    def scan_network(self, target_network):
        """Scan network for live hosts"""
        if self.logger:
            self.logger.log(f"Scanning network: {target_network}", "INFO")

        try:
            network = ipaddress.ip_network(target_network)
            live_hosts = []

            for ip in network.hosts():
                ip_str = str(ip)

                # Use ping to check if host is up
                response = os.system(f"ping -c 1 -W 1 {ip_str} > /dev/null 2>&1")

                if response == 0:
                    if self.logger:
                        self.logger.log(f"Host found: {ip_str}", "INFO")
                    live_hosts.append(ip_str)

            return live_hosts
        except Exception as e:
            if self.logger:
                self.logger.log(f"Network scan error: {str(e)}", "ERROR")
            return []

    def port_scan(self, target_ip, port_range=(1, 1024), timeout=1):
        """Scan ports on target IP"""
        if self.logger:
            self.logger.log(f"Scanning ports on {target_ip}", "INFO")

        open_ports = []

        for port in range(port_range[0], port_range[1] + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((target_ip, port))
                    if result == 0:
                        service = self._get_service_name(port)
                        open_ports.append((port, service))
                        if self.logger:
                            self.logger.log(f"Port {port} ({service}) open on {target_ip}", "INFO")
            except:
                pass

        return open_ports

    def _get_service_name(self, port):
        """Get service name for common ports"""
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            123: "NTP",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            587: "SMTP",
            3389: "RDP",
            8080: "HTTP-ALT"
        }

        return services.get(port, "Unknown")

    def service_detection(self, target_ip, port):
        """Detect service banner on open port"""
        if self.logger:
            self.logger.log(f"Detecting service on {target_ip}:{port}", "INFO")

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target_ip, port))

                # Try to get banner
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024)

                return banner.decode('utf-8', errors='ignore').strip()
        except:
            return None

# Example usage of these classes:
if __name__ == "__main__":
    # Just demonstrate functionality
    validator = TargetValidator()
    print(f"IP validation: {validator.validate_ip('192.168.1.1')}")

    utils = SecurityUtils()
    token = utils.generate_secure_token()
    print(f"Secure token: {token}")

    scanner = NetworkScanner()
    print("Scanner initialized (demo mode)")

    report_gen = ReportGenerator()
    print(f"Report generator initialized, output dir: {report_gen.output_dir}")