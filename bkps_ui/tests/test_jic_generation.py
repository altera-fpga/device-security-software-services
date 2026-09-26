"""Regression tests for template-driven JIC generation."""

import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT / "gui"
for entry in (str(GUI), str(ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import bkps_device  # noqa: E402
from utils.ui_helpers import resolve_jic_output_dir as _resolve_jic_output_dir  # noqa: E402


class JicGenerationTests(unittest.TestCase):
    @staticmethod
    def _cfg():
        return SimpleNamespace(profile_name="agilex5")

    @staticmethod
    def _quartus_stub(commands):
        def run(command, cwd=None, **_kwargs):
            commands.append(command)
            if "output_files.pfg" in command:
                (Path(cwd) / "output_files.jic").write_bytes(b"jic")
            elif "output_file.pfg" in command:
                (Path(cwd) / "output_file.jic").write_bytes(b"jic")
        return run

    def test_empty_output_dir_resolves_below_current_project(self):
        cfg = SimpleNamespace(cm_provisioning_dir=str(ROOT / "project" / "cm"))

        resolved = _resolve_jic_output_dir(cfg, "")

        self.assertEqual(
            resolved,
            str((ROOT / "project" / "cm" / "device_onboarding").resolve()),
        )

    def test_explicit_output_dir_overrides_project_default(self):
        cfg = SimpleNamespace(cm_provisioning_dir=str(ROOT / "project" / "cm"))
        selected = ROOT / "custom-output"

        resolved = _resolve_jic_output_dir(cfg, str(selected))

        self.assertEqual(resolved, str(selected.resolve()))

    def test_sof_is_converted_plain_then_packaged_with_shared_template(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            work = Path(tmp)
            sof = work / "top.sof"
            sof.write_bytes(b"sof")
            out = work / "output"
            commands = []

            with patch.object(
                bkps_device, "_ps_run", self._quartus_stub(commands)
            ):
                result = bkps_device.generate_jic(
                    self._cfg(), str(sof), str(out),
                    "QSPI512", "A5ED013BM16ACS",
                )

            self.assertEqual(
                commands[0], f'quartus_pfg -c "{sof}" "design.rbf"'
            )
            self.assertEqual(
                commands[1], f'quartus_pfg -c "{out / "output_files.pfg"}"'
            )
            self.assertNotIn("quartus_encrypt", " ".join(commands))
            self.assertNotIn("quartus_sign", " ".join(commands))
            self.assertNotIn("finalize_encryption_later", " ".join(commands))
            self.assertEqual(result, str(out / "output_files.jic"))

            root = ET.parse(out / "output_files.pfg").getroot()
            output = root.find("./output_files/output_file")
            self.assertEqual(output.attrib["name"], "output_files")
            self.assertEqual(
                root.findtext("./bitstreams/bitstream/path"), "design.rbf"
            )
            assignment = root.find("./assignments/assignment")
            self.assertEqual(assignment.attrib["page"], "0")
            self.assertEqual(assignment.attrib["partition_id"], "P1")

    def test_existing_rbf_is_staged_unchanged_and_not_protected(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            work = Path(tmp)
            rbf = work / "input.rbf"
            rbf.write_bytes(b"plain-or-externally-protected-rbf")
            out = work / "output"
            commands = []

            with patch.object(
                bkps_device, "_ps_run", self._quartus_stub(commands)
            ):
                result = bkps_device.generate_jic(
                    self._cfg(), None, str(out),
                    "QSPI512", "A5ED013BM16ACS", rbf=str(rbf),
                )

            self.assertEqual(commands, [f'quartus_pfg -c "{out / "output_files.pfg"}"'])
            self.assertEqual((out / "design.rbf").read_bytes(), rbf.read_bytes())
            self.assertEqual(result, str(out / "output_files.jic"))

    def test_other_device_families_keep_their_existing_output_name(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            work = Path(tmp)
            rbf = work / "input.rbf"
            rbf.write_bytes(b"rbf")
            out = work / "output"
            commands = []
            cfg = SimpleNamespace(profile_name="agilex")

            with patch.object(
                bkps_device, "_ps_run", self._quartus_stub(commands)
            ):
                result = bkps_device.generate_jic(
                    cfg, None, str(out),
                    "MT25QU02G", "AGFB014R24B2E2V", rbf=str(rbf),
                )

            self.assertEqual(commands, [f'quartus_pfg -c "{out / "output_file.pfg"}"'])
            self.assertEqual(result, str(out / "output_file.jic"))
            self.assertTrue((out / "dummy.puf").is_file())


if __name__ == "__main__":
    unittest.main()
