#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RexPloit Integration Tests
For validating all components work together
"""

import os
import sys
import time
import unittest
import threading
import socket
import json
from contextlib import contextmanager

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import RexPloit components
from enhancements import (
    TargetValidator, 
    SecurityUtils,
    ReportGenerator,
    NetworkScanner
)

class IntegrationServer:
    """Test server for integration testing"""
    
    def __init__(self, host="127.0.0.1", port=9000):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.thread = None
        
    def start(self):
        """Start integration test server"""
        if self.running:
            print(f"[*] Integration server already running on {self.host}:{self.port}")
            return
            
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        
        # Start server in background thread
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()
        
        print(f"[+] Integration server started on {self.host}:{self.port}")
        
    def _run_server(self):
        """Handle incoming connections"""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                client, addr = self.server_socket.accept()
                print(f"[+] Integration test connection from {addr[0]}:{addr[1]}")
                
                # Send test response
                response = json.dumps({
                    "status": "success",
                    "message": "Integration test successful"
                })
                
                client.send(f"HTTP/1.1 200 OK\r\nContent-Length: {len(response)}\r\n\r\n{response}".encode())
                client.close()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[-] Integration server error: {str(e)}")
                    
    def stop(self):
        """Stop integration test server"""
        if not self.running:
            return
            
        self.running = False
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
                
        # Join thread
        if self.thread:
            self.thread.join(timeout=2.0)
            
        print("[*] Integration test server stopped")

@contextmanager
def integration_environment():
    """Context manager for integration test environment"""
    # Set up test environment
    test_server = IntegrationServer()
    test_server.start()
    
    try:
        yield test_server
    finally:
        # Clean up test environment
        test_server.stop()

class RexPloitIntegrationTests(unittest.TestCase):
    """Integration tests for RexPloit framework"""
    
    def setUp(self):
        """Set up integration test environment"""
        # Set up test directories
        self.test_report_dir = "tests/reports"
        os.makedirs(self.test_report_dir, exist_ok=True)
        
    def test_target_validator_with_network_scanner(self):
        """Test TargetValidator integration with NetworkScanner"""
        # Create components
        validator = TargetValidator()
        scanner = NetworkScanner()
        
        # Test valid IP
        self.assertTrue(validator.validate_ip("127.0.0.1"))
        self.assertFalse(validator.validate_ip("invalid.ip"))
        
        # Test valid port
        self.assertTrue(validator.validate_port("8080"))
        self.assertFalse(validator.validate_port("invalid"))
        self.assertFalse(validator.validate_port("999999"))
        
        # Test integration with network scanner
        with integration_environment() as server:
            # Check connectivity to test server
            self.assertTrue(validator.check_target_connectivity("127.0.0.1:9000", timeout=2))
            
            # Check services on localhost
            open_ports = validator.check_common_services("127.0.0.1")
            self.assertIn(9000, open_ports)  # Our test server should be found
            
            # Scan should find our test server
            hosts = scanner.scan_network("127.0.0.1/32")
            self.assertIn("127.0.0.1", hosts)
            
            # Port scan should find our test server port
            ports = scanner.port_scan("127.0.0.1", port_range=(9000, 9000))
            self.assertEqual(len(ports), 1)
            self.assertEqual(ports[0][0], 9000)
            
    def test_security_utils(self):
        """Test SecurityUtils functionality"""
        # Test secure token generation
        token1 = SecurityUtils.generate_secure_token()
        token2 = SecurityUtils.generate_secure_token()
        
        self.assertEqual(len(token1), 32)
        self.assertEqual(len(token2), 32)
        self.assertNotEqual(token1, token2)  # Tokens should be unique
        
        # Test payload hashing
        payload = "Test payload content"
        hash1 = SecurityUtils.hash_payload(payload)
        hash2 = SecurityUtils.hash_payload(payload)
        
        self.assertEqual(hash1, hash2)  # Same content should produce same hash
        self.assertNotEqual(hash1, SecurityUtils.hash_payload("Different content"))
        
    def test_report_generator(self):
        """Test ReportGenerator functionality"""
        # Create report generator
        report_gen = ReportGenerator(self.test_report_dir)
        
        # Test data
        test_data = {
            "findings": [
                {
                    "vulnerability": "Test Vulnerability",
                    "severity": "Critical",
                    "cvss_score": 9.8,
                    "target": "test.example.com",
                    "description": "Test vulnerability description"
                }
            ]
        }
        
        # Generate report
        report_path = report_gen.create_report(test_data)
        self.assertTrue(os.path.exists(report_path))
        
        # Verify report content
        with open(report_path, "r") as f:
            report_content = json.load(f)
            self.assertEqual(report_content["report_type"], "security_assessment")
            self.assertEqual(len(report_content["data"]["findings"]), 1)
            
        # Generate HTML report
        html_path = report_gen.generate_html_report(report_path)
        self.assertTrue(os.path.exists(html_path))
        
        # Verify HTML content
        with open(html_path, "r") as f:
            html_content = f.read()
            self.assertIn("Security Report", html_content)
            self.assertIn("Test Vulnerability", html_content)
            self.assertIn("Critical", html_content)

def run_integration_tests():
    """Run integration tests"""
    print("\n" + "=" * 60)
    print(" REXPLOIT INTEGRATION TESTS ".center(60, "="))
    print("=" * 60 + "\n")
    
    # Run tests
    unittest.main(argv=['first-arg-is-ignored'], exit=False)

if __name__ == "__main__":
    run_integration_tests()