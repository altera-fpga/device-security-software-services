#!/usr/bin/env python3
"""Regression tests for the bkp_options.txt generation guards."""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

TOOL_DIR = Path(__file__).resolve().parents[1]
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

import bkps_configure


def _write_pem(path: Path, body: bytes) -> str:
    """Write a PEM certificate whose DER payload is *body*; return its SHA-1."""
    encoded = base64.b64encode(body).decode("ascii")
    path.write_text(
        "-----BEGIN CERTIFICATE-----\n"
        f"{encoded}\n"
        "-----END CERTIFICATE-----\n",
        encoding="ascii",
    )
    return hashlib.sha1(body).hexdigest().upper()


class ThumbprintParsingTests(unittest.TestCase):
    def test_single_thumbprint_is_returned_uppercase(self):
        parsed = bkps_configure._parse_imported_thumbprint(
            "\n9e07558ebec1fe9342fbe2e10626e594b8b0a640\n", "demo.pfx"
        )
        self.assertEqual(parsed, "9E07558EBEC1FE9342FBE2E10626E594B8B0A640")

    def test_chain_pfx_emitting_two_thumbprints_is_rejected(self):
        stdout = (
            "9E07558EBEC1FE9342FBE2E10626E594B8B0A640\n"
            "336D25273D75378638A087CF6052C71F6C1D3A85\n"
        )
        with self.assertRaises(RuntimeError) as ctx:
            bkps_configure._parse_imported_thumbprint(stdout, "demo.pfx")
        self.assertIn("found 2", str(ctx.exception))

    def test_empty_output_is_rejected(self):
        with self.assertRaises(RuntimeError):
            bkps_configure._parse_imported_thumbprint("", "demo.pfx")


class CreateBkpConfigGuardTests(unittest.TestCase):
    def _project(self, tmp: str, *, cert_der: bytes, recorded_id: str | None):
        project = Path(tmp) / "project"
        quartus_keys = Path(tmp) / "quartus_keys"
        cm_dir = Path(tmp) / "cm"
        ssl_dir = project / "keys" / "bkps_ssl_cert"
        ssl_dir.mkdir(parents=True)
        quartus_keys.mkdir()
        cm_dir.mkdir()

        _write_pem(ssl_dir / "bkps_ssl_cert.crt", b"ca-cert-der")
        expected = _write_pem(
            quartus_keys / "programmer_bkps_signed.crt", cert_der
        )
        (quartus_keys / "programmer_private.pem").write_text("key", encoding="utf-8")
        (quartus_keys / "programmer.pfx").write_bytes(b"pfx")
        if recorded_id is not None:
            (project / "config_id.txt").write_text(recorded_id, encoding="utf-8")

        cfg = SimpleNamespace(
            bkps_dir=str(project),
            quartus_keys_dir=str(quartus_keys),
            cm_provisioning_dir=str(cm_dir),
            bkps_server_ip="localhost",
            bkps_server_port="8082",
            profile_name="agilex5",
            device_part="A5ED013BM16AE4SCS",
            programmer_cert_password="programmer_cert_password",
        )
        return cfg, cm_dir, expected

    def test_supplied_config_id_disagreeing_with_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg, cm_dir, _ = self._project(
                tmp, cert_der=b"current-cert", recorded_id="1151"
            )
            with self.assertRaises(RuntimeError) as ctx:
                bkps_configure.create_bkp_config(cfg, "1152")
            self.assertIn("1152", str(ctx.exception))
            self.assertIn("1151", str(ctx.exception))
            self.assertFalse((cm_dir / "bkp_options.txt").exists())

    def test_non_numeric_config_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg, _, _ = self._project(
                tmp, cert_der=b"current-cert", recorded_id="1151"
            )
            with self.assertRaises(ValueError):
                bkps_configure.create_bkp_config(cfg, "1151x")

    def test_stale_pfx_thumbprint_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg, cm_dir, expected = self._project(
                tmp, cert_der=b"current-cert", recorded_id="1151"
            )
            stale = hashlib.sha1(b"previous-run-cert").hexdigest().upper()
            with (
                mock.patch.object(bkps_configure.sys, "platform", "win32"),
                mock.patch.object(
                    bkps_configure,
                    "_ps_run",
                    return_value=subprocess.CompletedProcess([], 0, stale, ""),
                ),
            ):
                with self.assertRaises(RuntimeError) as ctx:
                    bkps_configure.create_bkp_config(cfg, "1151")
            message = str(ctx.exception)
            self.assertIn(stale, message)
            self.assertIn(expected, message)
            self.assertFalse((cm_dir / "bkp_options.txt").exists())

    def test_matching_thumbprint_writes_expected_options(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg, cm_dir, expected = self._project(
                tmp, cert_der=b"current-cert", recorded_id="1151"
            )
            with (
                mock.patch.object(bkps_configure.sys, "platform", "win32"),
                mock.patch.object(
                    bkps_configure,
                    "_ps_run",
                    return_value=subprocess.CompletedProcess([], 0, expected, ""),
                ),
            ):
                bkps_configure.create_bkp_config(cfg, "1151")

            written = (cm_dir / "bkp_options.txt").read_text(encoding="utf-8")
            self.assertIn("bkp_cfg_id = 1151\n", written)
            self.assertIn(
                f'bkp_tls_prog_cert = "CurrentUser\\MY\\{expected}"\n', written
            )
            self.assertEqual(written.count("bkp_tls_prog_cert"), 1)

    def test_blank_override_falls_back_to_recorded_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg, cm_dir, expected = self._project(
                tmp, cert_der=b"current-cert", recorded_id="1151"
            )
            with (
                mock.patch.object(bkps_configure.sys, "platform", "win32"),
                mock.patch.object(
                    bkps_configure,
                    "_ps_run",
                    return_value=subprocess.CompletedProcess([], 0, expected, ""),
                ),
            ):
                bkps_configure.create_bkp_config(cfg, None)

            written = (cm_dir / "bkp_options.txt").read_text(encoding="utf-8")
            self.assertIn("bkp_cfg_id = 1151\n", written)


if __name__ == "__main__":
    unittest.main()
