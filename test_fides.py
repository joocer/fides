#!/usr/bin/env python3
"""
Basic tests for Fides functionality
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, mock_open

# Add the parent directory to sys.path to import fides modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yara

from run import _is_binary_file, _should_skip_file, download_file, redact, scan_line

RULES_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "rules", "Leaked Secrets (SECRETS).yar"
)

# Assembled rather than written out. These are fabricated, but a literal that
# looks like a live credential trips GitHub's push protection on the way in -
# which is the same instinct this tool exists to serve.
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"
FAKE_AWS_KEY = "AKIA" + UPPER[:16]
FAKE_GITHUB_PAT = "ghp_" + (ALNUM * 2)[:36]
MIXED = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
FAKE_HCLOUD_TOKEN = (MIXED * 2)[:64]
FAKE_SHA256 = ("0123456789abcdef" * 4)[:64]


class TestFidesFunctionality(unittest.TestCase):

    def test_should_skip_file(self):
        """Test file skipping logic"""
        # Should skip binary files
        self.assertTrue(_should_skip_file("test.pyc"))
        self.assertTrue(_should_skip_file("test.exe"))
        self.assertTrue(_should_skip_file("test.zip"))

        # Should skip files in certain directories
        self.assertTrue(_should_skip_file(".git/config"))
        self.assertTrue(_should_skip_file("__pycache__/test.py"))
        self.assertTrue(_should_skip_file("node_modules/package/index.js"))

        # Should not skip text files
        self.assertFalse(_should_skip_file("test.py"))
        self.assertFalse(_should_skip_file("README.md"))
        self.assertFalse(_should_skip_file("config.yml"))

    def test_is_binary_file(self):
        """Test binary file detection"""
        # Create temporary text file
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("This is a text file\n")
            text_file = f.name

        # Create temporary binary file
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"\x00\x01\x02\x03")
            binary_file = f.name

        try:
            self.assertFalse(_is_binary_file(text_file))
            self.assertTrue(_is_binary_file(binary_file))
        finally:
            os.unlink(text_file)
            os.unlink(binary_file)

    @patch("run.urlopen")
    def test_download_file(self, mock_urlopen):
        """Test file download functionality"""
        # Mock successful response
        mock_response = mock_open(read_data=b"test content")
        mock_response.return_value.status = 200
        mock_urlopen.return_value.__enter__ = mock_response
        mock_urlopen.return_value.__exit__ = lambda *args: None

        result = download_file("http://example.com/test.txt")
        self.assertEqual(result, "test content")

        # Mock failed response
        mock_response.return_value.status = 404
        result = download_file("http://example.com/missing.txt")
        self.assertIsNone(result)


class TestAllowlistReporting(unittest.TestCase):
    """
    A credential that is public by design must be *reported as ignored*, not
    silently absent. A scan that finds nothing and a scan that found something
    and excused it are different outcomes, and only one of them tells you the
    rule is still alive.
    """

    @classmethod
    def setUpClass(cls):
        cls.rules = yara.compile(RULES_FILE)

    def scan(self, line):
        return scan_line(self.rules, "sample.py", 1, line)

    def test_real_credential_fails(self):
        findings = self.scan(f'KEY = "{FAKE_AWS_KEY}"')
        self.assertEqual(["error"], [f["severity"] for f in findings])
        self.assertEqual("SECRETS04", findings[0]["rule"])

    def test_known_public_credential_is_ignored_not_dropped(self):
        findings = self.scan('ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        self.assertEqual(1, len(findings), "the suppressed detection must still be reported")
        finding = findings[0]
        self.assertEqual("ignored", finding["severity"])
        # the detection that was excused, not the allowlist entry itself
        self.assertEqual("SECRETS04", finding["rule"])
        self.assertEqual("$aws_access_key", finding["pattern"])
        # and it names what excused it
        self.assertIn("SECRETS00", finding["ignored_by"])
        self.assertIn("$known_public_aws_example_id", finding["ignored_by"])

    def test_azurite_key_is_ignored(self):
        findings = self.scan(
            'CONN = "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;'
            "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/"
            'K1SZFPTOtr/KBHBeksoGMGw==;"'
        )
        self.assertTrue(findings, "azurite key must be reported as ignored, not dropped")
        self.assertTrue(all(f["severity"] == "ignored" for f in findings))
        self.assertTrue(all("$known_public_azurite" in f["ignored_by"] for f in findings))

    def test_allowlist_hit_alone_reports_nothing(self):
        # SECRETS00 claims this line, but no detection rule fired on it - there
        # is nothing to excuse, so there is nothing worth saying
        line = 'SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        self.assertEqual([], self.scan(line))


class TestPrefixlessCloudTokens(unittest.TestCase):
    """
    Hetzner Cloud and Linode issue tokens with no prefix and no internal
    structure - 64 characters of alphanumeric and nothing else. Nothing in
    the token says what it is, so the patterns lean entirely on the
    assignment context, and the thing that can regress is the context
    requirement quietly eroding into "any 64-character string".
    """

    @classmethod
    def setUpClass(cls):
        cls.rules = yara.compile(RULES_FILE)

    def scan(self, line):
        return scan_line(self.rules, "sample.py", 1, line)

    def errors(self, line):
        return [f for f in self.scan(line) if f["severity"] == "error"]

    def test_hcloud_token_in_env_file_is_found(self):
        findings = self.errors(f"HCLOUD_TOKEN={FAKE_HCLOUD_TOKEN}")
        self.assertTrue(findings, "an HCLOUD_TOKEN assignment must be a finding")
        self.assertEqual("SECRETS04", findings[0]["rule"])
        self.assertEqual("$hetzner_token", findings[0]["pattern"])

    def test_hetzner_spellings(self):
        for line in (
            f'HETZNER_API_TOKEN = "{FAKE_HCLOUD_TOKEN}"',
            f'hcloud_token: "{FAKE_HCLOUD_TOKEN}"',
            f"hetzner_cloud_token={FAKE_HCLOUD_TOKEN}",
        ):
            with self.subTest(line=line):
                self.assertTrue(self.errors(line))

    def test_terraform_provider_form_is_found(self):
        # inside a `provider "hcloud" {}` block the word hcloud is on another
        # line, so this is matched as a bare 64-character token
        findings = self.errors(f'  token = "{FAKE_HCLOUD_TOKEN}"')
        self.assertTrue(findings, "the bare Terraform provider form must be a finding")
        self.assertEqual("$hetzner_tf_token", findings[0]["pattern"])

    def test_context_is_required(self):
        """
        The guard on a prefix-less pattern is the context, and this is the
        test that fails if it is ever loosened. A 64-character string on its
        own is a build id, a cache key or a digest far more often than it is
        a Hetzner token.
        """
        for line in (
            f'BUILD_ID = "{FAKE_HCLOUD_TOKEN}"',
            f"cache_key = {FAKE_HCLOUD_TOKEN}",
            # a digest assigned to a bare `token` - the shape $hetzner_tf_token
            # matches, rescued only by the $digest_64 subtraction
            f'  token = "{FAKE_SHA256}"',
            # a reference to the secret, not the secret
            "HCLOUD_TOKEN=${{ secrets.HCLOUD_TOKEN }}",
            'hcloud_token = os.environ["HCLOUD_TOKEN"]',
        ):
            with self.subTest(line=line):
                self.assertEqual([], self.errors(line))

    def test_prefixed_providers_need_no_context(self):
        for pattern, line in (
            ("$digitalocean_token", f"DIGITALOCEAN_TOKEN=dop_v1_{FAKE_SHA256}"),
            ("$flyio_legacy_token", "FLY_ACCESS_TOKEN=fo1_" + (MIXED * 2)[:43]),
            ("$scaleway_access_key", "SCW_ACCESS_KEY=SCW" + UPPER[:17]),
        ):
            with self.subTest(pattern=pattern):
                findings = self.errors(line)
                self.assertTrue(findings)
                self.assertEqual("SECRETS04", findings[0]["rule"])
                self.assertIn(pattern, [f["pattern"] for f in findings])

    def test_token_is_not_echoed_into_the_finding(self):
        for finding in self.scan(f"HCLOUD_TOKEN={FAKE_HCLOUD_TOKEN}"):
            self.assertNotIn(FAKE_HCLOUD_TOKEN, repr(finding))


class TestRedaction(unittest.TestCase):
    """A scan log must never become a second copy of the secret."""

    def test_value_is_never_reproduced(self):
        for value in (FAKE_AWS_KEY, FAKE_GITHUB_PAT, "short"):
            with self.subTest(value=value):
                self.assertNotIn(value, redact(value))
                self.assertIn("*", redact(value))

    def test_findings_do_not_carry_the_raw_value(self):
        rules = yara.compile(RULES_FILE)
        for finding in scan_line(rules, "sample.py", 1, f'KEY = "{FAKE_AWS_KEY}"'):
            self.assertNotIn(FAKE_AWS_KEY, repr(finding))


if __name__ == "__main__":
    unittest.main()
