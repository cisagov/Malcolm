import os
import tempfile
import unittest

from scripts.malcolm_constants import OrchestrationFramework
from scripts.installer.configs.constants.configuration_item_keys import (
    KEY_CONFIG_ITEM_LIVE_ZEEK,
    KEY_CONFIG_ITEM_LIVE_SURICATA,
    KEY_CONFIG_ITEM_REVERSE_DNS,
    KEY_CONFIG_ITEM_LOGSTASH_HOST,
    KEY_CONFIG_ITEM_PROCESS_USER_ID,
    KEY_CONFIG_ITEM_PROCESS_GROUP_ID,
    KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
    KEY_CONFIG_ITEM_RUNTIME_BIN,
    KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE,
    KEY_CONFIG_ITEM_VTOT_API_KEY,
    KEY_CONFIG_ITEM_INDEX_PRUNE_SIZE_LIMIT,
)
from scripts.installer.configs.constants.config_env_var_keys import (
    KEY_ENV_ZEEK_VTOT_API2_KEY,
    KEY_ENV_OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT,
)
from scripts.installer.core.malcolm_config import MalcolmConfig


class TestEnvFileRoundtrip(unittest.TestCase):

    def setUp(self):
        self.config = MalcolmConfig()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        # clean up the temporary directory
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.temp_dir)

    def _roundtrip_and_load(self, config: MalcolmConfig):
        # write env files from config and load them into a fresh config instance
        config.generate_env_files(self.temp_dir)
        new_config = MalcolmConfig()
        new_config.load_from_env_files(self.temp_dir)
        return new_config

    def test_roundtrip_defaults(self):
        new_config = self._roundtrip_and_load(self.config)
        for key in self.config.all_keys():
            if key in {KEY_CONFIG_ITEM_LIVE_ZEEK, KEY_CONFIG_ITEM_LIVE_SURICATA}:
                # these derive from rotated-pcap flags; ignore for equality
                continue
            self.assertEqual(
                self.config.get_value(key),
                new_config.get_value(key),
                f"default roundtrip mismatch for {key}",
            )

    def test_roundtrip_bool(self):
        # toggle a simple boolean mapping
        self.config.set_value(KEY_CONFIG_ITEM_REVERSE_DNS, True)
        cfg_true = self._roundtrip_and_load(self.config)
        self.assertTrue(cfg_true.get_value(KEY_CONFIG_ITEM_REVERSE_DNS))

        self.config.set_value(KEY_CONFIG_ITEM_REVERSE_DNS, False)
        cfg_false = self._roundtrip_and_load(self.config)
        self.assertFalse(cfg_false.get_value(KEY_CONFIG_ITEM_REVERSE_DNS))

    def test_roundtrip_string(self):
        host = "logstash.example.org:5044"
        self.config.set_value(KEY_CONFIG_ITEM_LOGSTASH_HOST, host)
        cfg2 = self._roundtrip_and_load(self.config)
        self.assertEqual(host, cfg2.get_value(KEY_CONFIG_ITEM_LOGSTASH_HOST))

    def test_roundtrip_int(self):
        uid = 12345
        gid = 23456
        self.config.set_value(KEY_CONFIG_ITEM_PROCESS_USER_ID, uid)
        self.config.set_value(KEY_CONFIG_ITEM_PROCESS_GROUP_ID, gid)
        cfg2 = self._roundtrip_and_load(self.config)
        self.assertEqual(uid, cfg2.get_value(KEY_CONFIG_ITEM_PROCESS_USER_ID))
        self.assertEqual(gid, cfg2.get_value(KEY_CONFIG_ITEM_PROCESS_GROUP_ID))

    def test_roundtrip_enum_container_runtime(self):
        # k8s -> env 'kubernetes' -> back to enum value
        self.config.set_value(
            KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            OrchestrationFramework.KUBERNETES,
        )
        # leave runtime bin unchanged; transform ignores it for kubernetes
        cfg_k8s = self._roundtrip_and_load(self.config)
        self.assertEqual(
            OrchestrationFramework.KUBERNETES,
            cfg_k8s.get_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE),
        )

        # docker-compose + explicit runtime -> env 'docker' -> back to enum + runtime string
        self.config.set_value(
            KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE,
            OrchestrationFramework.DOCKER_COMPOSE,
        )
        self.config.set_value(KEY_CONFIG_ITEM_RUNTIME_BIN, "docker")
        cfg_dc = self._roundtrip_and_load(self.config)
        self.assertEqual(
            OrchestrationFramework.DOCKER_COMPOSE,
            cfg_dc.get_value(KEY_CONFIG_ITEM_DOCKER_ORCHESTRATION_MODE),
        )
        self.assertEqual("docker", cfg_dc.get_value(KEY_CONFIG_ITEM_RUNTIME_BIN))

    def test_roundtrip_enum_like_opensearch_mode(self):
        # set primary mode to a labeled value and ensure it persists
        self.config.set_value(
            KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE, "opensearch-remote"
        )
        cfg2 = self._roundtrip_and_load(self.config)
        self.assertEqual(
            "opensearch-remote", cfg2.get_value(KEY_CONFIG_ITEM_OPENSEARCH_PRIMARY_MODE)
        )

    def test_env_sentinel_zero_values(self):
        # Seed a temp env with sentinel '0' values and verify proper import
        ref = MalcolmConfig()
        mapper = ref.get_env_mapper()

        # Write VTOT_API2_KEY=0 and OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT=0 to correct files
        vt_env = mapper.env_var_by_map_key[KEY_ENV_ZEEK_VTOT_API2_KEY]
        prune_env = mapper.env_var_by_map_key[KEY_ENV_OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT]

        with open(os.path.join(self.temp_dir, vt_env.file_name), "a") as f:
            f.write(f"{vt_env.variable_name}=0\n")
        with open(os.path.join(self.temp_dir, prune_env.file_name), "a") as f:
            f.write(f"{prune_env.variable_name}=0\n")

        cfg2 = MalcolmConfig()
        cfg2.load_from_env_files(self.temp_dir)

        # Expect both to be treated as unset/empty
        vtot = cfg2.get_value(KEY_CONFIG_ITEM_VTOT_API_KEY)
        prune = cfg2.get_value(KEY_CONFIG_ITEM_INDEX_PRUNE_SIZE_LIMIT)
        self.assertTrue(vtot is None or vtot == "")
        self.assertTrue(prune is None or prune == "")

    def test_generate_writes_zero_for_empty_prune_limit(self):
        # By default the prune limit is empty; generation should write '0'
        cfg = MalcolmConfig()
        cfg.generate_env_files(self.temp_dir)

        # Find dashboards-helper.env and assert OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT=0
        ref = MalcolmConfig()
        mapper = ref.get_env_mapper()
        prune_env = mapper.env_var_by_map_key[KEY_ENV_OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT]
        path = os.path.join(self.temp_dir, prune_env.file_name)
        with open(path, "r") as f:
            content = f.read()
        self.assertIn("OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT=0", content)


if __name__ == "__main__":
    unittest.main()
