#!/usr/bin/env python3
"""Unit tests for bkps_device JTAG/CoRIM/JIC helpers beyond JIC regression."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

TOOL_ROOT = Path(__file__).resolve().parents[1]
if str(TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOL_ROOT))

import bkps_device as device  # noqa: E402


def setUpModule():
    # Progress messages contain Unicode glyphs; a narrow console codec (cp1252)
    # would turn an incidental print into a UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(errors="replace")


def _cfg(tmp: Path, **extra) -> SimpleNamespace:
    cfg = SimpleNamespace(
        device_part="AGFB014R24B2E2V",
        jtag_cable_num="1",
        cm_provisioning_dir=str(tmp / "cm"),
        quartus_keys_dir=str(tmp / "keys"),
        profile_name="agilex5",
    )
    for k, v in extra.items():
        setattr(cfg, k, v)
    return cfg


class JtagTests(unittest.TestCase):
    def test_check_jtag_connection_branches(self):
        cfg = SimpleNamespace(device_part="DEV123")
        with patch.object(device, "get_output", return_value=""):
            self.assertFalse(device.check_jtag_connection(cfg))
        with patch.object(
            device, "get_output", return_value="cable\nDEV123\n"
        ):
            self.assertTrue(device.check_jtag_connection(cfg))
        with patch.object(
            device, "get_output", return_value="cable\nother\n"
        ):
            self.assertFalse(device.check_jtag_connection(cfg))

    def test_check_jtag_status_and_fuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            with patch.object(device, "_ps_run") as ps:
                device.check_jtag_status(cfg, "PROV")
                device.read_fuse_info(cfg)
            self.assertGreaterEqual(ps.call_count, 2)


class RkhTests(unittest.TestCase):
    def test_owner_rkh_already_provisioned(self):
        cfg = SimpleNamespace(jtag_cable_num="1")
        ok = subprocess.CompletedProcess(
            [], 0, "Owner root public key hash: abc\n", ""
        )
        with patch.object(device, "_ps_run", return_value=ok):
            self.assertTrue(device._owner_rkh_already_provisioned(cfg))
        with patch.object(
            device, "_ps_run", side_effect=RuntimeError("fail")
        ):
            self.assertFalse(device._owner_rkh_already_provisioned(cfg))
        miss = subprocess.CompletedProcess([], 0, "no hash", "")
        with patch.object(device, "_ps_run", return_value=miss):
            self.assertFalse(device._owner_rkh_already_provisioned(cfg))

    def test_provision_rkh_skip_and_program(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = _cfg(root, profile_name="agilex5")
            with patch.object(
                device, "_owner_rkh_already_provisioned", return_value=True
            ), patch.object(device, "_ps_run") as ps:
                device.provision_rkh_virtual(cfg)
            ps.assert_not_called()

            keys = root / "keys"
            keys.mkdir()
            (keys / "root0.qky").write_bytes(b"qky")
            cfg2 = _cfg(root, profile_name="stratix10")
            with patch.object(
                device, "_owner_rkh_already_provisioned", return_value=True
            ), patch.object(device, "_ps_run") as ps2:
                device.provision_rkh_virtual(cfg2)
            ps2.assert_called()

            cfg3 = _cfg(root, profile_name="agilex")
            (root / "keys2").mkdir(exist_ok=True)
            cfg3.quartus_keys_dir = str(root / "emptykeys")
            Path(cfg3.quartus_keys_dir).mkdir()
            with patch.object(
                device, "_owner_rkh_already_provisioned", return_value=False
            ):
                with self.assertRaises(FileNotFoundError):
                    device.provision_rkh_virtual(cfg3)


class ThinWrapperTests(unittest.TestCase):
    def test_bkp_and_program_wrappers(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp))
            Path(cfg.cm_provisioning_dir).mkdir(parents=True)
            with patch.object(device, "_ps_run") as ps:
                device.run_bkp(cfg)
                device.program_helper_image(cfg)
                device.program_jic(cfg, "/tmp/x.jic")
                device.bkp_prefetch(cfg)
                device.bkp_puf_activate(cfg, "UDS_EFUSE")
                device.bkp_set_authority(cfg, "UDS_EFUSE", slot_id=1)
            self.assertGreaterEqual(ps.call_count, 8)


class CorimTests(unittest.TestCase):
    def test_generate_provision_helper_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg(Path(tmp), cm_provisioning_dir="")
            with self.assertRaises(RuntimeError):
                device.generate_provision_helper_rbf(cfg)
            cfg2 = _cfg(Path(tmp), device_part="")
            with self.assertRaises(RuntimeError):
                device.generate_provision_helper_rbf(cfg2)

    def test_generate_provision_helper_success_and_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = _cfg(root)
            with patch.object(device, "_ps_run"):
                with self.assertRaises(RuntimeError):
                    device.generate_provision_helper_rbf(cfg)

            def make_rbf(*_a, **kw):
                Path(kw.get("cwd") or cfg.cm_provisioning_dir, "provision.rbf").write_bytes(
                    b"rbf"
                )

            with patch.object(device, "_ps_run", side_effect=make_rbf):
                path = device.generate_provision_helper_rbf(cfg)
            self.assertTrue(Path(path).is_file())

    def test_extract_corim_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rbf = root / "provision.rbf"
            rbf.write_bytes(b"rbf")
            diag = (
                '/ corim.href / 0 : 32( "https://example.com/corim" )\n'
                '/ corim.href / 0 : 32( "https://other.com/x" )\n'
            )

            def pfg(cmd, cwd=None, **_k):
                if cmd.endswith(".diag"):
                    Path(cwd, "provision.diag").write_text(diag)
                elif cmd.endswith(".corim"):
                    Path(cwd, "provision.corim").write_text("corim")

            with patch.object(device, "_ps_run", side_effect=pfg):
                url = device.extract_corim_url(_cfg(root), str(rbf))
            self.assertEqual(url, "https://example.com/corim")

            with self.assertRaises(FileNotFoundError):
                device.extract_corim_url(_cfg(root), "/no/rbf")

            Path(root, "provision.diag").write_text("no urls")
            with patch.object(device, "_ps_run"):
                with self.assertRaises(RuntimeError):
                    device.extract_corim_url(_cfg(root), str(rbf))

    def test_extract_and_save_and_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = _cfg(root)
            with patch.object(
                device, "generate_provision_helper_rbf", return_value="/r.rbf"
            ), patch.object(
                device, "extract_corim_url", return_value="https://x"
            ):
                url = device.extract_and_save_corim_url_from_provision_helper(
                    cfg
                )
            self.assertEqual(url, "https://x")
            self.assertEqual(device.read_saved_corim_url(cfg), "https://x")

            empty = _cfg(root / "other")
            Path(empty.quartus_keys_dir).mkdir(parents=True)
            self.assertEqual(device.read_saved_corim_url(empty), "")

            with patch("builtins.open", side_effect=OSError("x")):
                self.assertEqual(device.read_saved_corim_url(cfg), "")


class PfgBuilderTests(unittest.TestCase):
    def test_build_pfg_profiles(self):
        xml5 = device._build_pfg_agilex5("/out", "QSPI512", "DEV", "design.rbf")
        self.assertIn('name="output_files"', xml5)
        self.assertIn("LITTLEFS", xml5)

        for profile in ("agilex", "easic_n5x", "stratix10", "unknown"):
            cfg = SimpleNamespace(profile_name=profile)
            xml = device._build_pfg(
                cfg, "/out", "MT25QU02G", "DEV", "design.rbf", "dummy.puf"
            )
            self.assertIn('name="output_file"', xml)
            if profile in ("agilex", "stratix10"):
                self.assertIn("PUF", xml)
            if profile == "easic_n5x":
                self.assertIn("LITTLEFS", xml)


class GenerateJicExtraTests(unittest.TestCase):
    def test_validation_errors(self):
        cfg = SimpleNamespace(profile_name="agilex5")
        with self.assertRaises(ValueError):
            device.generate_jic(cfg, None, "/tmp", "QSPI", "DEV")
        with self.assertRaises(FileNotFoundError):
            device.generate_jic(
                cfg, "/no.sof", "/tmp", "QSPI", "DEV"
            )
        with self.assertRaises(FileNotFoundError):
            device.generate_jic(
                cfg, None, "/tmp", "QSPI", "DEV", rbf="/no.rbf"
            )

    def test_unwritable_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rbf = root / "in.rbf"
            rbf.write_bytes(b"r")
            out = root / "out"
            out.mkdir()
            cfg = SimpleNamespace(profile_name="agilex5")
            with patch("builtins.open", side_effect=OSError("ro")):
                with self.assertRaises(RuntimeError):
                    device.generate_jic(
                        cfg, None, str(out), "QSPI", "DEV", rbf=str(rbf)
                    )

    def test_samefile_rbf_skip_and_missing_jic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            out.mkdir()
            rbf = out / "design.rbf"
            rbf.write_bytes(b"rbf")
            cfg = SimpleNamespace(profile_name="easic_n5x")

            with patch.object(device, "_ps_run"):
                with self.assertRaises(RuntimeError):
                    device.generate_jic(
                        cfg, None, str(out), "MT25", "DEV", rbf=str(rbf)
                    )

    def test_samefile_oserror_falls_back_to_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            out.mkdir()
            # Pre-create destination so samefile is attempted
            (out / "design.rbf").write_bytes(b"old")
            rbf = root / "in.rbf"
            rbf.write_bytes(b"rbf")
            cfg = SimpleNamespace(profile_name="agilex5")

            def stub(cmd, cwd=None, **_k):
                if "output_files.pfg" in cmd:
                    Path(cwd, "output_files.jic").write_bytes(b"jic")

            with patch.object(device, "_ps_run", side_effect=stub), patch.object(
                device.os.path, "samefile", side_effect=OSError("x")
            ):
                result = device.generate_jic(
                    cfg, None, str(out), "QSPI", "DEV", rbf=str(rbf)
                )
            self.assertTrue(result.endswith("output_files.jic"))
            self.assertEqual((out / "design.rbf").read_bytes(), b"rbf")

    def test_stratix10_jic_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            rbf = root / "in.rbf"
            rbf.write_bytes(b"rbf")
            cfg = SimpleNamespace(profile_name="stratix10")

            def stub(cmd, cwd=None, **_k):
                if "output_file.pfg" in cmd:
                    Path(cwd, "output_file.jic").write_bytes(b"jic")

            with patch.object(device, "_ps_run", side_effect=stub):
                result = device.generate_jic(
                    cfg, None, str(out), "MT25", "DEV", rbf=str(rbf)
                )
            self.assertTrue(result.endswith("output_file.jic"))
            self.assertTrue((out / "dummy.puf").is_file())


if __name__ == "__main__":
    unittest.main()
