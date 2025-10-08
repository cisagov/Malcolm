#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import tempfile
import unittest

from scripts.installer.utils.env_file_utils import apply_extra_env_settings


class TestExtraEnvSettings(unittest.TestCase):
    def test_apply_extra_env_writes_value(self):
        # Create a temporary directory to act as the config dir
        with tempfile.TemporaryDirectory() as tmpdir:
            dummy_env = os.path.join(tmpdir, "dummy.env")

            # Pre-create an empty .env file
            with open(dummy_env, "w", encoding="utf-8") as f:
                f.write("")

            # Apply an extra setting to the dummy.env file
            extras = ["dummy.env:FOO=bar"]
            apply_extra_env_settings(tmpdir, extras, env_mapper=None)

            # Verify that the value was written
            with open(dummy_env, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("FOO=bar", content)


if __name__ == "__main__":
    unittest.main()

