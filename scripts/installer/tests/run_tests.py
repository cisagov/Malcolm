#!/usr/bin/env python3
"""
Malcolm Installer Test Runner

Runs all tests (unit and mock/integration) or specific test types.

Usage:
    python run_tests.py           # Run all tests
    python run_tests.py --unit    # Run unit tests only
    python run_tests.py --mock    # Run mock/integration tests only
"""
import os
import sys
import unittest
import argparse

# Add the project root to Python path
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def run_unit_tests():
    """Run unit tests from unit/ subdirectory."""
    print("Running Unit Tests...")
    print("-" * 30)

    loader = unittest.TestLoader()
    unit_test_dir = os.path.join(os.path.dirname(__file__), "unit")
    suite = loader.discover(start_dir=unit_test_dir, pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


def run_mock_tests():
    """Run mock/integration tests from mock/ subdirectory."""
    print("Running Mock/Integration Tests...")
    print("-" * 30)

    loader = unittest.TestLoader()
    mock_test_dir = os.path.join(os.path.dirname(__file__), "mock")
    suite = loader.discover(start_dir=mock_test_dir, pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


def main():
    """Main test runner."""
    parser = argparse.ArgumentParser(description="Run Malcolm installer tests")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--unit", action="store_true", help="Run unit tests only")
    group.add_argument(
        "--mock", action="store_true", help="Run mock/integration tests only"
    )

    args = parser.parse_args()

    # Silence installer console logs during test runs; tests assert functionality, not log output
    try:
        from scripts.installer.utils.logger_utils import InstallerLogger

        InstallerLogger.set_console_output(False)
    except Exception:
        pass

    print("Malcolm Installer Test Suite")
    print("=" * 50)

    results = []

    if args.unit:
        results.append(run_unit_tests())
    elif args.mock:
        results.append(run_mock_tests())
    else:
        # Run both unit and mock tests
        results.append(run_unit_tests())
        print("\n" + "=" * 50 + "\n")
        results.append(run_mock_tests())

    # Calculate overall results
    total_tests = sum(r.testsRun for r in results)
    total_failures = sum(len(r.failures) for r in results)
    total_errors = sum(len(r.errors) for r in results)
    all_successful = all(r.wasSuccessful() for r in results)

    print("\n" + "=" * 50)
    print("OVERALL SUMMARY")
    print("=" * 50)
    print(f"Total tests run: {total_tests}")
    print(f"Total failures: {total_failures}")
    print(f"Total errors: {total_errors}")

    success_rate = (
        ((total_tests - total_failures - total_errors) / total_tests * 100)
        if total_tests > 0
        else 0
    )
    print(f"Success rate: {success_rate:.1f}%")

    if total_failures > 0:
        print("\nFailures occurred in test suite")
    if total_errors > 0:
        print("\nErrors occurred in test suite")

    if all_successful:
        print("\n✅ All tests passed!")
    else:
        print("\n❌ Some tests failed")

    return all_successful


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
