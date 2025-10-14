# Malcolm Installer Tests

This directory contains tests for the Malcolm installer, organized into two main categories:

## Directory Structure

```
tests/
├── run_tests.py              # Main test runner (runs both unit and mock tests)
├── unit/                     # Unit tests (individual methods/classes)
│   ├── run_unit_tests.py     # Unit test runner
│   └── test_*.py             # Unit test files
├── mock/                     # Mock/integration tests (components with mocks)
│   ├── run_mock_tests.py     # Mock test runner
│   └── test_*.py             # Mock test files
├── test_framework.py         # Shared test framework and utilities
├── test_runner.py            # Advanced test runner with phase support
└── demo_test_framework.py    # Demo showing test framework capabilities
```

## Test Types

### Unit Tests (`unit/`)
Tests for individual methods and classes in isolation:
- `test_config_item_keys.py` - Config item key constants
- `test_env_file_import_existing.py` - Environment file import
- `test_env_file_roundtrip.py` - Environment file roundtrip
- `test_value_dependencies.py` - Configuration value dependencies
- `test_individual_tweaks.py` - Individual system tweaks

### Mock/Integration Tests (`mock/`)
Tests that validate components work in isolation with mocks:
- `test_docker_compose_integration.py` - Docker Compose integration
- `test_final_install.py` - Final installation logic
- `test_installation_ui.py` - Installation user interface
- `test_orchestrator.py` - Installation orchestrator
- `test_platform_mocking.py` - Platform-specific operations
- `test_steps.py` - Individual installation steps
- `test_system_tweaks.py` - System tweaks orchestration

## Running Tests

The examples below assume running from the repository root so module paths
resolve correctly. The provided runners add the project root to `PYTHONPATH`,
so they also work when invoked from other directories.

### Run All Tests
Command: python scripts/installer/tests/run_tests.py

### Run Specific Test Types
Commands:
- Unit only: python scripts/installer/tests/run_tests.py --unit
- Mock only: python scripts/installer/tests/run_tests.py --mock

### Run Tests from Subdirectories
Commands:
- Unit: python scripts/installer/tests/unit/run_unit_tests.py
- Mock: python scripts/installer/tests/mock/run_mock_tests.py

Alternative (unittest discovery; run from repo root):
- Unit: python -m unittest discover -s scripts/installer/tests/unit -p "test_*.py"
- Mock: python -m unittest discover -s scripts/installer/tests/mock -p "test_*.py"

### Run Individual Tests
Notes:
- Run from the repository root when using `python -m unittest ...` module paths.
- Examples:
  - Single file: python -m unittest scripts.installer.tests.unit.test_env_mapper_set_coverage -v
  - Single test: python -m unittest scripts.installer.tests.unit.test_env_mapper_set_coverage.TestEnvMapperCoverage.test_env_key_constants_present_in_example_files -v

## Test Counts

- **Unit Tests**: ~28 tests (individual methods/classes)
- **Mock Tests**: ~20-30 tests (component integration)
- **Total**: ~50-60 tests

## Key Features

- **No Interactive Prompts**: All tests use mocking to avoid user input
- **Clear Separation**: Unit and mock tests are in separate directories
- **Comprehensive Mocking**: Mock framework handles platform operations, UI, filesystem
- **Focused Testing**: Each test type serves a specific purpose
- **Easy Execution**: Simple runners for different test scenarios

## Adding New Tests

### For Unit Tests:
1. Add to `unit/` directory
2. Test individual methods/functions
3. Use minimal external dependencies

### For Mock Tests:
1. Add to `mock/` directory  
2. Use `BaseInstallerTest` for comprehensive mocking
3. Test component interactions and workflows

This structure ensures clean separation between unit tests (fast, isolated) and mock tests (component integration with mocking), making the test suite more maintainable and easier to run selectively.
