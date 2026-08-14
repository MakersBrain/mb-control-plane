#!/usr/bin/env python3
"""Regression tests for the machine-readable control-plane contract gate."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "validate_contract", TOOLS / "validate_contract.py"
)
assert SPEC is not None and SPEC.loader is not None
validate_contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validate_contract)


class RustModuleSourceTests(unittest.TestCase):
    def test_driver_security_scan_includes_every_extracted_child_module(self) -> None:
        source = validate_contract.rust_production_module_source(
            validate_contract.CONTROL / "src/docker_driver.rs"
        )
        for marker in (
            "release_fleet",
            "create_remote_recovery_set",
            "docker_create_container",
            "ensure_database",
            "ensure_oidc_clients",
            "restrict_capability",
            "privacy export is not authorized",
        ):
            self.assertIn(marker, source)

    def test_unit_test_source_is_excluded_from_security_scan(self) -> None:
        source = validate_contract.rust_production_module_source(
            validate_contract.CONTROL / "src/docker_driver.rs"
        )
        self.assertNotIn("physical_database_names_are_strictly_opaque", source)


class RuntimeEnvironmentContractTests(unittest.TestCase):
    specification = {
        "required_environment": {"fixture_worker": ["CONTROL_DATABASE_URL"]},
        "runtime_environment": {
            "worker-fixture": {
                "process": "fixture_worker",
                "variables": [
                    "CONTROL_DATABASE_URL",
                    "CONTROL_RELEASE_ID",
                ],
            }
        },
    }
    compose = """\
x-worker-env: &worker-env
  CONTROL_RELEASE_ID: fixture-release
services:
  worker-fixture:
    environment:
      <<: *worker-env
      CONTROL_DATABASE_URL: postgresql://fixture
    restart: no
networks: {}
"""

    def test_environment_anchor_and_direct_values_match_exact_contract(self) -> None:
        self.assertEqual(
            validate_contract.validate_runtime_environment(
                self.specification, self.compose
            ),
            [],
        )

    def test_undeclared_runtime_capability_fails_the_contract(self) -> None:
        compose = self.compose.replace(
            "      CONTROL_DATABASE_URL: postgresql://fixture\n",
            "      CONTROL_DATABASE_URL: postgresql://fixture\n"
            "      CONTROL_RAUTHY_ADMIN_KEY: recognizable-canary\n",
        )
        errors = validate_contract.validate_runtime_environment(
            self.specification, compose
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("extra=['CONTROL_RAUTHY_ADMIN_KEY']", errors[0])

    def test_missing_required_runtime_setting_fails_the_contract(self) -> None:
        compose = self.compose.replace(
            "      CONTROL_DATABASE_URL: postgresql://fixture\n", ""
        )
        errors = validate_contract.validate_runtime_environment(
            self.specification, compose
        )
        self.assertTrue(
            any("omits required fixture_worker settings" in error for error in errors)
        )


class RuntimeSecretMountContractTests(unittest.TestCase):
    compose = """\
services:
  worker-fixture:
    image: fixture
    secrets: [database_url, provider_token]
  api-fixture:
    image: fixture
    secrets:
      - source: database_url
        target: /app/config.toml
secrets:
  database_url: {file: ./database-url}
  provider_token: {file: ./provider-token}
"""

    def test_inline_and_multiline_mounts_match_exact_ownership(self) -> None:
        specification = {
            "runtime_secret_mounts": {
                "worker-fixture": ["database_url", "provider_token"],
                "api-fixture": ["database_url"],
            }
        }
        self.assertEqual(
            validate_contract.validate_secret_mounts(
                specification, [self.compose]
            ),
            [],
        )

    def test_extra_secret_mount_is_a_capability_leak(self) -> None:
        specification = {
            "runtime_secret_mounts": {
                "worker-fixture": ["database_url"],
                "api-fixture": ["database_url"],
            }
        }
        errors = validate_contract.validate_secret_mounts(
            specification, [self.compose]
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("extra=['provider_token']", errors[0])


if __name__ == "__main__":
    unittest.main()
