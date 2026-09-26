"""Regression tests for reference-template BKPS configuration generation."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

from bkps_configure import materialize_reference_configuration  # noqa: E402


REFERENCE = {
    "name": "Sample configuration for AGILEX B",
    "pufType": "EFUSE",
    "overbuild": {"max": -1},
    "testModeSecrets": True,
    "corimUrl": "https://reference.example/agilexb.corim",
    "confidentialData": {
        "importMode": "ENCRYPTED",
        "aesKey": {"value": "reference-aes"},
        "encryptedAesKey": "reference-encrypted-aes",
        "qek": {"value": "reference-qek", "keyName": "qek_encryption_key"},
        "encryptedQek": "reference-encrypted-qek",
    },
    "attestationConfig": {
        "blackList": {
            "romVersions": [112, 155],
            "sdmBuildIdStrings": ["SDMBuildString#1", "SDMBuildString#22"],
            "sdmSvns": [15, 30],
        },
        "efusesPublic": {"mask": "reference-mask", "value": "reference-value"},
    },
}


class ReferenceConfigurationTests(unittest.TestCase):
    @staticmethod
    def _write_json(path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def test_legacy_working_file_is_rebuilt_from_complete_reference(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            template = directory / "sample_AgilexB.json"
            working = directory / "aes_config_agilex5.json"
            self._write_json(template, REFERENCE)

            stale = copy.deepcopy(REFERENCE)
            stale["testModeSecrets"] = False
            stale["attestationConfig"]["efusesPublic"]["mask"] = "stale-mask"
            stale["confidentialData"]["aesKey"]["value"] = "old-generated-aes"
            stale["confidentialData"]["qek"]["value"] = "old-generated-qek"
            stale["corimUrl"] = "https://old.example/generated.corim"
            self._write_json(working, stale)

            rebuilt = materialize_reference_configuration(
                str(template),
                str(working),
                aes_hex="A1B2",
                qek_hex="C3D4",
                corim_url="https://new.example/generated.corim",
            )

            expected = copy.deepcopy(REFERENCE)
            expected["confidentialData"]["aesKey"]["value"] = "a1b2"
            expected["confidentialData"]["qek"]["value"] = "c3d4"
            expected["corimUrl"] = "https://new.example/generated.corim"
            actual = json.loads(working.read_text(encoding="utf-8"))

            self.assertTrue(rebuilt)
            self.assertEqual(actual, expected)
            self.assertTrue(actual["testModeSecrets"])
            self.assertEqual(
                actual["attestationConfig"], REFERENCE["attestationConfig"]
            )

    def test_existing_generated_values_survive_legacy_migration(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            template = directory / "sample_AgilexB.json"
            working = directory / "aes_config_agilex5.json"
            self._write_json(template, REFERENCE)

            stale = copy.deepcopy(REFERENCE)
            stale["testModeSecrets"] = False
            stale["confidentialData"]["aesKey"]["value"] = "AABB"
            stale["confidentialData"]["qek"]["value"] = "CCDD"
            stale["corimUrl"] = "https://saved.example/generated.corim"
            self._write_json(working, stale)

            materialize_reference_configuration(str(template), str(working))
            actual = json.loads(working.read_text(encoding="utf-8"))

            self.assertTrue(actual["testModeSecrets"])
            self.assertEqual(
                actual["confidentialData"]["aesKey"]["value"], "aabb"
            )
            self.assertEqual(actual["confidentialData"]["qek"]["value"], "ccdd")
            self.assertEqual(
                actual["corimUrl"], "https://saved.example/generated.corim"
            )

    def test_current_marker_preserves_deliberate_operator_edits(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            template = directory / "sample_AgilexB.json"
            working = directory / "aes_config_agilex5.json"
            self._write_json(template, REFERENCE)
            materialize_reference_configuration(
                str(template), str(working), force=True
            )

            edited = json.loads(working.read_text(encoding="utf-8"))
            edited["testModeSecrets"] = False
            edited["name"] = "Operator-selected real-OWNED configuration"
            self._write_json(working, edited)

            rebuilt = materialize_reference_configuration(
                str(template), str(working)
            )

            self.assertFalse(rebuilt)
            self.assertEqual(
                json.loads(working.read_text(encoding="utf-8")), edited
            )

    def test_reference_template_change_refreshes_policy_and_keeps_generated_data(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            template = directory / "sample_AgilexB.json"
            working = directory / "aes_config_agilex5.json"
            self._write_json(template, REFERENCE)
            materialize_reference_configuration(
                str(template),
                str(working),
                aes_hex="1122",
                qek_hex="3344",
                corim_url="https://generated.example/agilexb.corim",
            )

            updated_reference = copy.deepcopy(REFERENCE)
            updated_reference["overbuild"]["max"] = 10
            self._write_json(template, updated_reference)

            rebuilt = materialize_reference_configuration(
                str(template), str(working)
            )
            actual = json.loads(working.read_text(encoding="utf-8"))

            self.assertTrue(rebuilt)
            self.assertEqual(actual["overbuild"]["max"], 10)
            self.assertEqual(
                actual["confidentialData"]["aesKey"]["value"], "1122"
            )
            self.assertEqual(actual["confidentialData"]["qek"]["value"], "3344")
            self.assertEqual(
                actual["corimUrl"], "https://generated.example/agilexb.corim"
            )


if __name__ == "__main__":
    unittest.main()
