#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

"""
Unit Test Runner for Malcolm Installer

Tests individual methods and classes in isolation to ensure they work as expected.
"""
import argparse
import logging
import os
import sys
import unittest
from scripts.installer.utils.logger_utils import InstallerLogger

# Add the project root to Python path
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def setup_logging(debug=False):
    """Setup logging configuration for tests."""
    if debug:
        # Enable debug logging for all installer modules
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
            datefmt="%H:%M:%S",
        )
        # Set specific loggers to debug
        for module in [
            "scripts.installer",
            "scripts.malcolm_config",
            "scripts.malcolm_utils",
        ]:
            logging.getLogger(module).setLevel(logging.DEBUG)
    else:
        # Suppress most logging during tests
        logging.basicConfig(level=logging.WARNING)


def main():
    """Run all unit tests."""
    parser = argparse.ArgumentParser(description="Run Malcolm installer unit tests")
    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        help="Enable debug logging to see detailed test execution",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Increase test runner verbosity"
    )
    args = parser.parse_args()

    # Setup logging based on arguments
    setup_logging(debug=args.debug)
    # Silence installer console logs during unit tests unless debugging
    if not args.debug:
        try:
            InstallerLogger.set_console_output(False)
        except Exception:
            pass

    print("Malcolm Installer Unit Tests")
    print("=" * 50)
    print("Testing individual methods and classes...")
    if args.debug:
        print("DEBUG LOGGING ENABLED - detailed execution info will be shown")
    print()

    # Discover and run unit tests
    loader = unittest.TestLoader()
    test_dir = os.path.dirname(__file__)
    suite = loader.discover(start_dir=test_dir, pattern="test_*.py")

    verbosity = 2 if args.verbose else 2
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)

    print(f"\nUnit Tests Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"  - {test}")

    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"  - {test}")

    return result.wasSuccessful()


# allow running via `python -m unittest scripts/installer/tests/unit/run_unit_tests.py`
# by exposing a load_tests hook that returns the discovered suite
def load_tests(loader, tests, pattern):
    test_dir = os.path.dirname(__file__)
    return loader.discover(start_dir=test_dir, pattern="test_*.py")


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
