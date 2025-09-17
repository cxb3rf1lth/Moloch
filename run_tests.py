#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RexPloit Test Runner
"""

import os
import sys
import argparse
from tests.test_environment import run_all_tests, test_logger, test_payload_generator, test_c2_manager, test_injector, test_vulnerability_scanner

def main():
    """Run RexPloit tests"""
    parser = argparse.ArgumentParser(description="RexPloit Test Runner")
    parser.add_argument("-a", "--all", action="store_true", help="Run all tests")
    parser.add_argument("-l", "--logger", action="store_true", help="Test Logger component")
    parser.add_argument("-p", "--payloads", action="store_true", help="Test PayloadGenerator component")
    parser.add_argument("-c", "--c2", action="store_true", help="Test C2Manager component")
    parser.add_argument("-i", "--injector", action="store_true", help="Test Injector component")
    parser.add_argument("-v", "--vulnerability", action="store_true", help="Test VulnerabilityScanner component")

    args = parser.parse_args()

    # Run requested tests
    if args.all or not any([args.logger, args.payloads, args.c2, args.injector, args.vulnerability]):
        run_all_tests()
    else:
        if args.logger:
            test_logger()
        if args.payloads:
            test_payload_generator()
        if args.c2:
            test_c2_manager()
        if args.injector:
            test_injector()
        if args.vulnerability:
            test_vulnerability_scanner()

if __name__ == "__main__":
    main()