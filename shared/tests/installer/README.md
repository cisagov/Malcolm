# Installer tests

Tests for the Malcolm installer (`scripts/install.py` and `scripts/installer/`). They used to live in
`scripts/installer/tests/` with their own runners; they run with the rest of `shared/tests` now.

From the repository root:

```
pip install -r shared/tests/requirements.txt
python -m pytest shared/tests/installer
```

`python -m pytest shared/tests` runs them along with everything else.

Most of these are `unittest.TestCase` classes, which pytest runs as they are. `installer_mocks.py`
holds the shared mocks (`MockPlatform`, `BaseInstallerTest`, and so on); it isn't named `test_*`
so pytest doesn't collect it as a test module.

`conftest.py` puts the repository root on `sys.path` and turns off the installer's console output.
To see that output, with debug logging for the installer modules, set `MALCOLM_INSTALLER_TEST_DEBUG=1`.
