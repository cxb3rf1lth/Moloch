#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RexPloit - Comprehensive End-to-End Validation
This script validates all components of the unified RexPloit framework
"""

import os
import sys
import json
import logging
import unittest
import tempfile
from contextlib import contextmanager
from unittest.mock import patch, MagicMock

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('validation')

# Paths for testing
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, 'config')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
PAYLOADS_DIR = os.path.join(BASE_DIR, 'payloads')
C2_DIR = os.path.join(BASE_DIR, 'c2_frameworks')
TEST_DIR = os.path.join(BASE_DIR, 'tests')

# Ensure all required directories exist
for directory in [CONFIG_DIR, LOGS_DIR, PAYLOADS_DIR, C2_DIR, TEST_DIR]:
    os.makedirs(directory, exist_ok=True)

@contextmanager
def temp_config_file():
    """Create temporary config file for testing"""
    temp_config = {
        "listener_host": "127.0.0.1",
        "listener_port": 4444,
        "default_c2": "sliver",
        "log_level": "DEBUG",
        "auto_install": True,
        "payload_options": {
            "encode": True,
            "obfuscate": False
        }
    }

    temp_path = os.path.join(CONFIG_DIR, 'temp_config.json')

    try:
        with open(temp_path, 'w') as f:
            json.dump(temp_config, f, indent=4)
        yield temp_path
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

class ModuleImportTests(unittest.TestCase):
    """Test module imports to ensure all components are available"""

    def test_core_module_import(self):
        """Test importing core rexploit module"""
        try:
            import rexploit
            self.assertTrue(hasattr(rexploit, 'RexPloitApp'))
            self.assertTrue(hasattr(rexploit, 'C2Manager'))
            self.assertTrue(hasattr(rexploit, 'PayloadGenerator'))
            self.assertTrue(hasattr(rexploit, 'Injector'))
            self.assertTrue(hasattr(rexploit, 'VulnerabilityScanner'))
            self.assertTrue(hasattr(rexploit, 'Logger'))
        except ImportError as e:
            self.fail(f"Failed to import rexploit: {e}")

    def test_enhanced_ui_module_import(self):
        """Test importing enhanced UI module"""
        try:
            import enhanced_ui
            self.assertTrue(hasattr(enhanced_ui, 'run_enhanced_app'))
            self.assertTrue(hasattr(enhanced_ui, 'RexPloitEnhancedApp'))
            self.assertTrue(hasattr(enhanced_ui, 'StatusPanel'))
            self.assertTrue(hasattr(enhanced_ui, 'MainContentArea'))
            self.assertTrue(hasattr(enhanced_ui, 'ToolsPanel'))
        except ImportError as e:
            self.fail(f"Failed to import enhanced_ui: {e}")

    def test_enhancements_module_import(self):
        """Test importing enhancements module"""
        try:
            import enhancements
            self.assertTrue(hasattr(enhancements, 'NetworkScanner'))
            self.assertTrue(hasattr(enhancements, 'ReportGenerator'))
            self.assertTrue(hasattr(enhancements, 'SecurityUtils'))
        except ImportError as e:
            self.fail(f"Failed to import enhancements: {e}")

    def test_dependency_manager_import(self):
        """Test importing dependency_manager module"""
        try:
            import dependency_manager
            self.assertTrue(hasattr(dependency_manager, 'DependencyManager'))
        except ImportError as e:
            self.fail(f"Failed to import dependency_manager: {e}")

    def test_unified_rexploit_import(self):
        """Test importing unified_rexploit module"""
        try:
            import unified_rexploit
            self.assertTrue(hasattr(unified_rexploit, 'main'))
        except ImportError as e:
            self.fail(f"Failed to import unified_rexploit: {e}")

class CoreFunctionalityTests(unittest.TestCase):
    """Test core functionality of the RexPloit framework"""

    def setUp(self):
        """Set up test environment"""
        # Import modules
        import rexploit
        self.rexploit = rexploit

        # Use temp config
        self.config = {
            "listener_host": "127.0.0.1",
            "listener_port": 4444,
            "default_c2": "sliver",
            "log_level": "DEBUG",
            "payload_options": {
                "encode": True,
                "obfuscate": False
            }
        }

        # Create instances for testing
        self.logger = self.rexploit.Logger()
        self.payload_generator = self.rexploit.PayloadGenerator(self.config)
        self.c2_manager = self.rexploit.C2Manager(self.config)
        self.injector = self.rexploit.Injector()
        self.scanner = self.rexploit.VulnerabilityScanner()

    def test_logger_functionality(self):
        """Test logger functionality"""
        with patch('rexploit.open', unittest.mock.mock_open()) as mocked_open:
            # Log some test messages
            self.logger.log("Test info message", "INFO")
            self.logger.log("Test error message", "ERROR")

            # Check if log file was opened
            mocked_open.assert_called()

    def test_payload_generator(self):
        """Test payload generator functionality"""
        with patch('rexploit.open', unittest.mock.mock_open()) as mocked_open:
            with patch('os.path.exists', return_value=True):
                # Generate test payload
                payload_type = "python_reverse_tcp"
                host = "127.0.0.1"
                port = 4444
                encode = True
                obfuscate = False

                payload_path, payload_name = self.payload_generator.generate(
                    payload_type, host, port, encode, obfuscate
                )

                # Check if file was created
                mocked_open.assert_called()
                self.assertIn("rexploit", payload_name)

    def test_c2_manager(self):
        """Test C2 manager functionality"""
        # Create a mock process
        mock_process = MagicMock()

        # Directly set the framework_process
        self.c2_manager.framework_process = mock_process
        self.c2_manager.active = True
        self.c2_manager.active_framework = "sliver"

        # Test stopping framework
        self.c2_manager.stop_framework()

        # Verify that terminate was called
        mock_process.terminate.assert_called_once()

    def test_injector(self):
        """Test injector functionality"""
        # Test injection
        with patch.object(self.injector, '_validate_target', return_value=True):
            with patch.object(self.injector, '_execute_injection', return_value=True):
                result = self.injector.inject_payload(
                    "test_payload.txt",
                    "https://test-target.com",
                    "web_form"
                )
                self.assertTrue(result)

    def test_vulnerability_scanner(self):
        """Test vulnerability scanner functionality"""
        # Test scanning
        with patch.object(self.scanner, '_scan_target_impl', return_value=[
            {
                "vulnerability": "Test Vulnerability",
                "severity": "High",
                "cvss_score": 8.5,
                "description": "Test vulnerability for unit testing"
            }
        ]):
            results = self.scanner.scan_target("https://test-target.com")

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["vulnerability"], "Test Vulnerability")
            self.assertEqual(results[0]["severity"], "High")

class EnhancementsTests(unittest.TestCase):
    """Test enhancements module functionality"""

    def setUp(self):
        """Set up test environment"""
        import enhancements
        self.enhancements = enhancements

    def test_network_scanner(self):
        """Test network scanner functionality"""
        scanner = self.enhancements.NetworkScanner()

        with patch('os.system', return_value=0):  # Mock successful ping
            live_hosts = scanner.scan_network("192.168.1.0/30")
            self.assertTrue(isinstance(live_hosts, list))

    def test_report_generator(self):
        """Test report generator functionality"""
        with tempfile.TemporaryDirectory() as tmpdirname:
            report_gen = self.enhancements.ReportGenerator(output_dir=tmpdirname)

            # Create test report data
            report_data = {
                "findings": [
                    {
                        "vulnerability": "Test Vulnerability",
                        "severity": "High",
                        "cvss_score": 8.5,
                        "target": "example.com",
                        "description": "Test vulnerability description"
                    }
                ]
            }

            # Generate report
            report_path = report_gen.create_report(report_data)

            # Check if report was created
            self.assertTrue(os.path.exists(report_path))

            # Check report content
            with open(report_path, 'r') as f:
                content = json.load(f)
                self.assertIn("data", content)
                self.assertIn("findings", content["data"])

            # Generate HTML report
            html_path = report_gen.generate_html_report(report_path)

            # Check if HTML report was created
            self.assertTrue(os.path.exists(html_path))
            self.assertTrue(html_path.endswith(".html"))

class DependencyManagerTests(unittest.TestCase):
    """Test dependency manager functionality"""

    def setUp(self):
        """Set up test environment"""
        import dependency_manager
        self.dependency_manager = dependency_manager

    def test_dependency_manager_creation(self):
        """Test dependency manager creation"""
        manager = self.dependency_manager.DependencyManager()
        self.assertIsNotNone(manager)

    def test_check_python_packages(self):
        """Test checking Python packages"""
        manager = self.dependency_manager.DependencyManager()

        with patch.object(manager, '_check_python_package', return_value=True):
            result = manager.check_python_packages(auto_install=False)
            self.assertTrue(result)

    def test_check_c2_frameworks(self):
        """Test checking C2 frameworks"""
        manager = self.dependency_manager.DependencyManager()

        with patch.object(manager, '_check_c2_framework', return_value=True):
            result = manager.check_c2_frameworks(auto_install=False)
            self.assertTrue(result)

    def test_check_system_tools(self):
        """Test checking system tools"""
        manager = self.dependency_manager.DependencyManager()

        with patch.object(manager, '_check_system_tool', return_value=True):
            result = manager.check_system_tools(auto_install=False)
            self.assertTrue(result)

class UnifiedRexploitTests(unittest.TestCase):
    """Test unified RexPloit framework"""

    def test_command_line_args(self):
        """Test command line argument parsing"""
        import unified_rexploit

        # Test with --version argument
        with patch('sys.argv', ['unified_rexploit.py', '--version']):
            with self.assertRaises(SystemExit):
                unified_rexploit.main()

        # Test with --help argument
        with patch('sys.argv', ['unified_rexploit.py', '--help']):
            with self.assertRaises(SystemExit):
                unified_rexploit.main()

    def test_cli_mode(self):
        """Test CLI mode operation"""
        import unified_rexploit

        # Test CLI mode with payload generation
        with patch('sys.argv', ['unified_rexploit.py', '--cli', '--payload', 'python', '--lhost', '127.0.0.1', '--lport', '4444']):
            with patch('unified_rexploit.check_authorization', return_value=True):
                with patch('unified_rexploit.check_dependencies', return_value=True):
                    with patch('unified_rexploit.handle_cli_mode', return_value=True):
                        result = unified_rexploit.main()
                        self.assertTrue(result)

class IntegrationTests(unittest.TestCase):
    """Integration tests for the entire framework"""

    def test_master_integrator(self):
        """Test master integrator functionality"""
        import master_integrator

        # Create integrator
        integrator = master_integrator.MasterIntegrator()

        # Test module loading
        with patch.object(integrator, 'load_module', return_value=MagicMock()):
            result = integrator.load_all_modules()
            self.assertTrue(result)

        # Test integration validation
        integrator.modules = {
            "core": MagicMock(),
            "ui": MagicMock(),
            "dependencies": MagicMock(),
            "enhancements": MagicMock(),
            "unified": MagicMock()
        }

        # Set up mocks for validation
        integrator.modules["core"].__name__ = "rexploit"
        for cls in ["Logger", "PayloadGenerator", "C2Manager", "Injector", "VulnerabilityScanner", "RexPloitApp"]:
            setattr(integrator.modules["core"], cls, MagicMock())

        integrator.modules["ui"].__name__ = "enhanced_ui"
        integrator.modules["ui"].run_enhanced_app = MagicMock()

        integrator.modules["dependencies"].__name__ = "dependency_manager"
        integrator.modules["dependencies"].DependencyManager = MagicMock

        integrator.modules["unified"].__name__ = "unified_rexploit"
        integrator.modules["unified"].main = MagicMock()

        with patch.object(integrator, 'validate_integration', return_value=True):
            with patch.object(integrator, 'create_workspace_symlinks', return_value=True):
                with patch.object(integrator, 'install_missing_dependencies', return_value=True):
                    result = integrator.integrate()
                    self.assertTrue(result)

def run_all_tests():
    """Run all validation tests"""
    logger.info("Starting comprehensive validation tests")

    # Create test suite
    suite = unittest.TestSuite()

    # Create test loader
    loader = unittest.TestLoader()

    # Add test cases
    suite.addTest(loader.loadTestsFromTestCase(ModuleImportTests))
    suite.addTest(loader.loadTestsFromTestCase(CoreFunctionalityTests))
    suite.addTest(loader.loadTestsFromTestCase(EnhancementsTests))
    suite.addTest(loader.loadTestsFromTestCase(DependencyManagerTests))
    suite.addTest(loader.loadTestsFromTestCase(UnifiedRexploitTests))
    suite.addTest(loader.loadTestsFromTestCase(IntegrationTests))

    # Create test runner
    runner = unittest.TextTestRunner(verbosity=2)

    # Run tests
    result = runner.run(suite)

    # Log results
    logger.info(f"Tests run: {result.testsRun}")
    logger.info(f"Errors: {len(result.errors)}")
    logger.info(f"Failures: {len(result.failures)}")

    # Return True if all tests passed
    return len(result.errors) == 0 and len(result.failures) == 0

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
