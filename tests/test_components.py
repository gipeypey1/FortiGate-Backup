"""
Unit & Component Tests for Fortinet Backup Tool.
Validates:
1. Baseline size validation (Gotcha #1 protection)
2. Smart ENC noise filtering (Gotcha #3 protection)
3. Inventory loader (devices.yaml)
"""

import unittest
from pathlib import Path
from src.drift import calculate_sha256, analyze_drift
from src.devices.base import TruncatedBackupError, BaseFortinetDevice
from src.config_loader import load_devices_config


class DummyDevice(BaseFortinetDevice):
    def pull_config(self) -> bytes:
        return b"dummy"


class TestFortinetBackup(unittest.TestCase):

    def test_sha256(self):
        data = b"config system global\n    set hostname FGT-TEST\nend\n"
        sha = calculate_sha256(data)
        self.assertEqual(len(sha), 64)

    def test_baseline_truncation_detection(self):
        """Tests Gotcha #1: Backup below minimum size or lines raises TruncatedBackupError."""
        dev = DummyDevice({
            "name": "TEST-FGT",
            "host": "10.0.0.1",
            "min_size_bytes": 1000,
            "min_lines": 50
        })

        small_payload = b"config system global\n    set hostname FGT-TEST\nend\n"
        with self.assertRaises(TruncatedBackupError):
            dev.validate_baseline(small_payload)

        # Valid payload
        valid_lines = [f"set rule_{i} enable" for i in range(100)]
        valid_payload = ("\n".join(valid_lines) * 20).encode("utf-8")
        # Should not raise
        dev.validate_baseline(valid_payload)

    def test_enc_noise_filtering(self):
        """Tests Gotcha #3: Pure ENC IV re-encryption changes should NOT trigger real drift."""
        old_config = (
            "config user local\n"
            "    edit \"admin\"\n"
            "        set type password\n"
            "        set passwd ENC fgt123abc456old==\n"
            "    next\n"
            "end\n"
            "config vpn ipsec phase1-interface\n"
            "    edit \"to_branch\"\n"
            "        set psksecret ENC secretIVold987==\n"
            "    next\n"
            "end\n"
        )

        # New export: same config, but FortiOS generated new IV for the passwords
        new_config = (
            "config user local\n"
            "    edit \"admin\"\n"
            "        set type password\n"
            "        set passwd ENC fgt999xyz888new==\n"
            "    next\n"
            "end\n"
            "config vpn ipsec phase1-interface\n"
            "    edit \"to_branch\"\n"
            "        set psksecret ENC secretIVnew111==\n"
            "    next\n"
            "end\n"
        )

        result = analyze_drift(old_config, new_config)
        self.assertTrue(result.has_raw_diff, "Raw diff should exist due to string change")
        self.assertFalse(result.has_real_drift, "Real drift must be FALSE because only ENC tokens changed!")
        self.assertEqual(result.enc_noise_count, 2, "Expected 2 ENC tokens filtered")

    def test_real_config_drift_detection(self):
        """Tests that genuine changes (firewall rule, IP, route) are correctly flagged."""
        old_config = (
            "config firewall policy\n"
            "    edit 1\n"
            "        set name \"Allow_Web\"\n"
            "        set srcintf \"port1\"\n"
            "        set dstintf \"port2\"\n"
            "        set action accept\n"
            "    next\n"
            "end\n"
        )

        new_config = (
            "config firewall policy\n"
            "    edit 1\n"
            "        set name \"Allow_Web\"\n"
            "        set srcintf \"port1\"\n"
            "        set dstintf \"port2\"\n"
            "        set action deny\n"  # Changed from accept to deny!
            "    next\n"
            "end\n"
        )

        result = analyze_drift(old_config, new_config)
        self.assertTrue(result.has_raw_diff)
        self.assertTrue(result.has_real_drift, "Real drift must be TRUE!")
        self.assertTrue(any("deny" in change for change in result.real_changes))

    def test_load_devices_yaml(self):
        """Tests reading and parsing config/devices.yaml."""
        yaml_path = Path("config/devices.yaml")
        self.assertTrue(yaml_path.exists(), "config/devices.yaml must exist")
        devices = load_devices_config(str(yaml_path))
        self.assertGreaterEqual(len(devices), 1, "Expected at least 1 device configured")
        names = [d["name"] for d in devices]
        self.assertIn("FGT-CORE-01", names)

    def test_fortiweb_base64_auth(self):
        """Tests FortiWeb Base64 authorization header generation from credentials."""
        import base64
        import json
        from src.devices.fortiweb import FortiWebDevice

        # Test case 1: Auto-generate from username and password
        fwb = FortiWebDevice({
            "name": "FWB-TEST",
            "host": "10.0.0.2",
            "username": "admin",
            "password": "fortinet",
            "vdom": "root"
        })
        token = fwb._get_auth_header_value()
        # Decode and verify JSON structure
        decoded = json.loads(base64.b64decode(token.encode("utf-8")).decode("utf-8"))
        self.assertEqual(decoded["username"], "admin")
        self.assertEqual(decoded["password"], "fortinet")
        self.assertEqual(decoded["vdom"], "root")
        # Ensure it matches standard reference: eyJ1c2VybmFtZSI6ImFkbWluIiwicGFzc3dvcmQiOiJmb3J0aW5ldCIsInZkb20iOiJyb290In0=
        self.assertEqual(token, "eyJ1c2VybmFtZSI6ImFkbWluIiwicGFzc3dvcmQiOiJmb3J0aW5ldCIsInZkb20iOiJyb290In0=")

        # Test case 2: Provided raw Base64 token with accidental 'Bearer ' prefix
        fwb_token = FortiWebDevice({
            "name": "FWB-TEST-2",
            "host": "10.0.0.2",
            "token": "Bearer eyJ1c2VybmFtZSI6ImFkbWluIiwicGFzc3dvcmQiOiJmb3J0aW5ldCIsInZkb20iOiJyb290In0="
        })
        clean_token = fwb_token._get_auth_header_value()
        self.assertFalse(clean_token.startswith("Bearer"))
        self.assertEqual(clean_token, "eyJ1c2VybmFtZSI6ImFkbWluIiwicGFzc3dvcmQiOiJmb3J0aW5ldCIsInZkb20iOiJyb290In0=")

    def test_fortiweb_zip_naming_and_extraction(self):
        """Tests FortiWeb backup ZIP filename convention and smart text extraction."""
        import io
        import zipfile
        from src.devices.fortiweb import FortiWebDevice

        fwb = FortiWebDevice({
            "name": "FWB-AM62-HO",
            "host": "10.0.0.2",
            "username": "admin",
            "password": "pwd"
        })

        # Test filename convention: FWB-AM62-HO_20260918144020_system.conf.zip
        fname = fwb.get_filename("20260918T144020Z", "d6ad5c76f590")
        self.assertEqual(fname, "FWB-AM62-HO_20260918144020_system.conf.zip")

        # Create mock FortiWeb ZIP with fwb_system.conf
        mock_conf = (
            "[header]\n"
            "file_split=-------FV-VMB-7.66-------2026-09-18 14:40:20-------FF7C23--------- \n"
            "[/header]\n"
            "config server-policy policy\n"
            "    edit \"P-CR\"\n"
            "        set ssl enable\n"
            "    next\n"
            "end\n"
            "[file]\n"
            "name=/tmp/extend_tar_file\n"
            "BINARY_TAR_DATA_SHOULD_BE_IGNORED\n"
        ).encode("utf-8")

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("fwb_system.conf", mock_conf)
        zip_bytes = buf.getvalue()

        # Test smart text extraction
        extracted = fwb.extract_text_for_drift(zip_bytes)
        self.assertIn("edit \"P-CR\"", extracted)
        self.assertNotIn("BINARY_TAR_DATA_SHOULD_BE_IGNORED", extracted)
        self.assertNotIn("file_split=-------", extracted)


if __name__ == "__main__":
    unittest.main()


