#!/usr/bin/env python3
"""Regression tests for installing the generated demo CA on Windows."""

from __future__ import annotations

import os
import subprocess
import hashlib
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


TOOL_DIR = Path(__file__).resolve().parents[1]
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

import bkps_server_setup


class WindowsDemoCaTrustTests(unittest.TestCase):
    def test_missing_pkcs12_marks_certificate_step_incomplete(self):
        outputs = (
            "bkps_ssl_cert.crt",
            "bkps_ssl_private.pem",
            "bkps_ssl.p12",
            "super_admin_cert.crt",
            "tsci_altera_com.pem",
        )
        with mock.patch.object(
            bkps_server_setup.os.path,
            "isfile",
            side_effect=lambda path: path != "bkps_ssl.p12",
        ):
            complete = bkps_server_setup._ssl_certificate_outputs_complete(outputs)
        self.assertFalse(complete)

    def test_thumbprint_hashes_der_bytes_without_second_base64_decode(self):
        der = b"\x30\x03\x02\x01\x01"
        with (
            mock.patch("builtins.open", mock.mock_open(read_data="PEM")),
            mock.patch.object(
                bkps_server_setup.ssl,
                "PEM_cert_to_DER_cert",
                return_value=der,
            ),
        ):
            thumbprint = bkps_server_setup._certificate_sha1_thumbprint(
                "demo.crt"
            )
        self.assertEqual(thumbprint, hashlib.sha1(der).hexdigest().upper())

    def test_non_windows_is_noop(self):
        with (
            mock.patch.object(bkps_server_setup.sys, "platform", "linux"),
            mock.patch.object(bkps_server_setup.os.path, "isfile") as isfile,
        ):
            bkps_server_setup._install_windows_demo_ca("missing.crt")
        isfile.assert_not_called()

    def test_existing_thumbprint_is_not_imported_again(self):
        with (
            mock.patch.object(bkps_server_setup.sys, "platform", "win32"),
            mock.patch.object(bkps_server_setup.os.path, "isfile", return_value=True),
            mock.patch.object(
                bkps_server_setup,
                "_certificate_sha1_thumbprint",
                return_value="AABBCC",
            ),
            mock.patch.object(
                bkps_server_setup,
                "_windows_current_user_root_contains",
                return_value=True,
            ),
            mock.patch.object(bkps_server_setup.subprocess, "run") as run,
        ):
            bkps_server_setup._install_windows_demo_ca("demo.crt")
        run.assert_not_called()

    def test_missing_thumbprint_is_imported_and_verified(self):
        with (
            mock.patch.object(bkps_server_setup.sys, "platform", "win32"),
            mock.patch.object(bkps_server_setup.os.path, "isfile", return_value=True),
            mock.patch.object(
                bkps_server_setup,
                "_certificate_sha1_thumbprint",
                return_value="AABBCC",
            ),
            mock.patch.object(
                bkps_server_setup,
                "_windows_current_user_root_contains",
                side_effect=[False, True],
            ),
            mock.patch.object(
                bkps_server_setup.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, "", ""),
            ) as run,
        ):
            bkps_server_setup._install_windows_demo_ca("demo.crt")

        command = run.call_args.args[0]
        abs_cert = str(Path("demo.crt").resolve())
        self.assertEqual(command[0], "powershell")
        self.assertIn("-NonInteractive", command)
        self.assertEqual(command[-2], "-Command")
        script = command[-1]
        self.assertIn("X509Store", script)
        self.assertIn("StoreLocation]::CurrentUser", script)
        self.assertIn("StoreName]::Root", script)
        self.assertIn(f"'{abs_cert}'", script)
        self.assertNotIn("param([string] $CertificatePath)", script)

    def test_existing_certificate_path_still_checks_windows_trust(self):
        cfg = SimpleNamespace(bkps_dir=r"D:\demo")
        openssl_result = subprocess.CompletedProcess(
            [], 0, "X509v3 Basic Constraints: critical\n    CA:TRUE", ""
        )
        with (
            mock.patch.object(bkps_server_setup.os.path, "isfile", return_value=True),
            mock.patch.object(
                bkps_server_setup.subprocess, "run", return_value=openssl_result
            ),
            mock.patch.object(
                bkps_server_setup, "_install_windows_demo_ca"
            ) as install,
        ):
            bkps_server_setup.create_ssl_certificates(cfg)
        install.assert_called_once_with(
            os.path.join(cfg.bkps_dir, "keys", "bkps_ssl_cert", "bkps_ssl_cert.crt")
        )


if __name__ == "__main__":
    unittest.main()
