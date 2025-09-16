#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Testing Environment for RexPloit Framework
For authorized testing purposes only
"""

import os
import sys
import socket
import threading
import time
import subprocess
from contextlib import contextmanager
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import RexPloit components
from rexploit import Logger, C2Manager, PayloadGenerator, Injector, VulnerabilityScanner, load_config

class TestServer:
    """Mock server for simulating target systems"""
    
    def __init__(self, host="127.0.0.1", port=8000):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.thread = None
        self.connections = []
        self.payloads_received = []
        
    def start(self):
        """Start test server"""
        if self.running:
            print(f"[*] Server already running on {self.host}:{self.port}")
            return
            
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        
        # Start server in background thread
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()
        
        print(f"[+] Test server started on {self.host}:{self.port}")
        
    def _run_server(self):
        """Handle incoming connections"""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                client, addr = self.server_socket.accept()
                self.connections.append((client, addr))
                print(f"[+] Connection from {addr[0]}:{addr[1]}")
                
                # Handle client in background thread
                handler_thread = threading.Thread(
                    target=self._handle_client, 
                    args=(client, addr),
                    daemon=True
                )
                handler_thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[-] Server error: {str(e)}")
                    
    def _handle_client(self, client, addr):
        """Process client connection"""
        try:
            # Read up to 4096 bytes from client
            data = client.recv(4096)
            if data:
                print(f"[+] Received data from {addr[0]}:{addr[1]}")
                self.payloads_received.append({
                    "timestamp": datetime.now().isoformat(),
                    "source": f"{addr[0]}:{addr[1]}",
                    "data": data
                })
                
                # Send response
                client.send(b"HTTP/1.1 200 OK\\r\\nContent-Length: 15\\r\\n\\r\\nTest successful\\n")
                
        except Exception as e:
            print(f"[-] Error handling client: {str(e)}")
        finally:
            client.close()
    
    def stop(self):
        """Stop test server"""
        if not self.running:
            return
            
        self.running = False
        
        # Close all connections
        for client, _ in self.connections:
            try:
                client.close()
            except:
                pass
                
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
                
        # Join thread
        if self.thread:
            self.thread.join(timeout=2.0)
            
        print("[*] Test server stopped")

class MockC2Server:
    """Mock C2 server for testing framework integration"""
    
    def __init__(self, host="127.0.0.1", port=8888):
        self.host = host
        self.port = port
        self.proc = None
        
    def start(self, framework_type="mock"):
        """Start mock C2 server"""
        if self.proc:
            print("[*] Mock C2 server already running")
            return
            
        print(f"[+] Starting mock {framework_type.upper()} C2 server on {self.host}:{self.port}")
        
        # Create mock listener
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        server.close()  # Just testing binding, we'll close it right away
        
        # In a real test, we'd start an actual server process here
        self.proc = True
        return True
        
    def stop(self):
        """Stop mock C2 server"""
        if not self.proc:
            return
            
        print("[*] Stopping mock C2 server")
        self.proc = None
        return True
        
@contextmanager
def test_environment():
    """Context manager for test environment"""
    # Set up test environment
    test_server = TestServer()
    test_server.start()
    
    mock_c2 = MockC2Server()
    
    try:
        yield test_server, mock_c2
    finally:
        # Clean up test environment
        test_server.stop()
        mock_c2.stop()

def print_test_header(test_name):
    """Print formatted test header"""
    print("\n" + "=" * 60)
    print(f" {test_name} ".center(60, "="))
    print("=" * 60)

def print_test_result(test_name, success):
    """Print formatted test result"""
    result = "[PASS]" if success else "[FAIL]"
    color = "green" if success else "red"
    print(f"[{color}]{result}[/{color}] {test_name}")

def test_logger():
    """Test Logger functionality"""
    print_test_header("Testing Logger")
    
    # Create temporary log directories
    test_log_dir = "tests/logs"
    os.makedirs(test_log_dir, exist_ok=True)
    
    # Override log dir for testing
    original_log_dir = os.environ.get("LOG_DIR")
    os.environ["LOG_DIR"] = test_log_dir
    
    try:
        # Initialize logger
        logger = Logger()
        
        # Test logging
        logger.log("Test info message", "INFO")
        logger.log("Test warning message", "WARNING")
        logger.log("Test error message", "ERROR")
        
        # Test connection logging
        logger.log_connection("192.168.1.100", 4444, "test_payload", "established")
        
        # Check if log files were created
        log_file_exists = os.path.exists(logger.log_file)
        conn_log_exists = os.path.exists(logger.connection_log)
        
        print_test_result("Log file creation", log_file_exists)
        print_test_result("Connection log creation", conn_log_exists)
        
        return log_file_exists and conn_log_exists
        
    finally:
        # Restore original log dir
        if original_log_dir:
            os.environ["LOG_DIR"] = original_log_dir
        
def test_payload_generator():
    """Test PayloadGenerator functionality"""
    print_test_header("Testing PayloadGenerator")
    
    # Create temporary payload directory
    test_payload_dir = "tests/payloads"
    os.makedirs(test_payload_dir, exist_ok=True)
    
    # Override payload dir for testing
    original_payload_dir = os.environ.get("PAYLOAD_DIR")
    os.environ["PAYLOAD_DIR"] = test_payload_dir
    
    try:
        # Initialize payload generator with config
        config = load_config()
        generator = PayloadGenerator(config)
        
        # Test generating different payload types
        payloads = [
            ("python_reverse_tcp", "127.0.0.1", 4444, True, False),
            ("bash_reverse_tcp", "127.0.0.1", 4444, False, False),
            ("powershell_reverse_tcp", "127.0.0.1", 4444, True, True),
        ]
        
        success = True
        for payload_type, host, port, encode, obfuscate in payloads:
            try:
                payload_path, payload_name = generator.generate(
                    payload_type, host, port, encode, obfuscate
                )
                
                # Check if payload file was created
                if not os.path.exists(payload_path):
                    print(f"[-] Payload file not created: {payload_path}")
                    success = False
                    continue
                    
                # Check if payload metadata was stored
                if payload_name not in generator.payloads:
                    print(f"[-] Payload metadata not stored for: {payload_name}")
                    success = False
                    continue
                    
                print(f"[+] Successfully generated {payload_type} payload: {payload_name}")
                
                # Validate payload content
                with open(payload_path, 'r') as f:
                    content = f.read()
                    if len(content) == 0:
                        print(f"[-] Payload content is empty: {payload_path}")
                        success = False
                
            except Exception as e:
                print(f"[-] Failed to generate {payload_type} payload: {str(e)}")
                success = False
        
        print_test_result("Payload generation", success)
        return success
        
    finally:
        # Restore original payload dir
        if original_payload_dir:
            os.environ["PAYLOAD_DIR"] = original_payload_dir

def test_c2_manager():
    """Test C2Manager functionality"""
    print_test_header("Testing C2Manager")
    
    # Create test directories
    os.makedirs("tests/c2_frameworks", exist_ok=True)
    
    # Override C2 dir for testing
    original_c2_dir = os.environ.get("C2_DIR")
    os.environ["C2_DIR"] = "tests/c2_frameworks"
    
    try:
        # Initialize C2 manager with config
        config = load_config()
        c2_manager = C2Manager(config)
        
        # Use MockC2Server for testing
        with test_environment() as (_, mock_c2):
            # Test starting and stopping framework
            if mock_c2.start("sliver"):
                print("[+] Mock C2 server started successfully")
                
                # Force framework initialization since we're not really starting one
                c2_manager.active_framework = "mock"
                c2_manager.active = True
                
                # Test log queue
                c2_manager.log_queue.put("[TEST] Test log message")
                logs = c2_manager.get_logs()
                
                log_success = len(logs) > 0 and "[TEST] Test log message" in logs
                print_test_result("C2 logging", log_success)
                
                # Test stopping framework
                stop_success = c2_manager.stop_framework()
                print_test_result("C2 shutdown", stop_success)
                
                return log_success and stop_success
            else:
                print("[-] Failed to start mock C2 server")
                return False
                
    finally:
        # Restore original C2 dir
        if original_c2_dir:
            os.environ["C2_DIR"] = original_c2_dir
            
def test_injector():
    """Test Injector functionality"""
    print_test_header("Testing Injector")
    
    # Initialize injector
    injector = Injector()
    
    # Create test payload
    test_payload_content = "echo 'Test payload'"
    test_payload_path = "tests/payloads/test_payload.txt"
    os.makedirs(os.path.dirname(test_payload_path), exist_ok=True)
    
    with open(test_payload_path, "w") as f:
        f.write(test_payload_content)
    
    # Test targets
    targets = [
        "http://127.0.0.1:8000/test1",
        "http://127.0.0.1:8000/test2"
    ]
    
    try:
        # Test injection
        results = injector.professional_inject(targets, test_payload_path, "test_payload")
        
        # Validate results
        results_success = len(results) > 0 and all(
            "target" in r and "vector" in r and "status" in r and "evidence" in r
            for r in results
        )
        
        print_test_result("Injection execution", results_success)
        
        # Test stored payloads
        stored_success = len(injector.deployed_payloads) > 0
        print_test_result("Payload storage", stored_success)
        
        return results_success and stored_success
        
    except Exception as e:
        print(f"[-] Injector test failed: {str(e)}")
        return False
        
def test_vulnerability_scanner():
    """Test VulnerabilityScanner functionality"""
    print_test_header("Testing VulnerabilityScanner")
    
    # Initialize scanner
    scanner = VulnerabilityScanner()
    
    try:
        # Test scanning
        target = "http://127.0.0.1:8000/test"
        findings = scanner.scan_target(target)
        
        # Validate findings
        findings_success = isinstance(findings, list)
        
        if findings:
            print(f"[+] Found {len(findings)} vulnerabilities in test scan")
            fields_success = all(
                "vulnerability" in f and "severity" in f and "cvss_score" in f
                for f in findings
            )
            print_test_result("Finding fields validation", fields_success)
        else:
            fields_success = True
            print("[*] No findings in test scan (expected in simulation)")
            
        print_test_result("Scanner execution", findings_success)
        
        return findings_success and fields_success
        
    except Exception as e:
        print(f"[-] Scanner test failed: {str(e)}")
        return False

def run_all_tests():
    """Run all component tests"""
    print_test_header("REXPLOIT FRAMEWORK TEST SUITE")
    
    # Run all component tests
    tests = [
        ("Logger", test_logger),
        ("PayloadGenerator", test_payload_generator),
        ("C2Manager", test_c2_manager),
        ("Injector", test_injector),
        ("VulnerabilityScanner", test_vulnerability_scanner)
    ]
    
    results = {}
    all_success = True
    
    for name, test_func in tests:
        print(f"\nRunning test: {name}")
        try:
            success = test_func()
            results[name] = success
            if not success:
                all_success = False
        except Exception as e:
            print(f"[-] Test failed with exception: {str(e)}")
            results[name] = False
            all_success = False
    
    # Print summary
    print_test_header("TEST RESULTS SUMMARY")
    
    for name, success in results.items():
        print_test_result(name, success)
        
    overall_text = "ALL TESTS PASSED" if all_success else "SOME TESTS FAILED"
    overall_color = "green" if all_success else "red"
    print(f"\n[{overall_color}]{overall_text}[/{overall_color}]")
    
    return all_success

if __name__ == "__main__":
    # Run all tests
    run_all_tests()