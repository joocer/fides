#!/usr/bin/env python3
"""
Rule-level tests for the Fides YARA ruleset.

Why this file exists
--------------------
A malformed YARA pattern does not raise -- it compiles cleanly and then
silently never matches. Six of the original thirteen patterns in SECRETS02
were dead this way (a trailing `\\b` after a quote can never match, and
Python-style escaping of `\\s` inside a character class turned "whitespace"
into the literal letter `s`).

So every named pattern in the ruleset must have at least one positive
sample here. test_every_pattern_is_covered() fails the build if a new
pattern is added without one.

All credentials below are structurally valid but fabricated.
"""

import os
import re
import unittest

import yara

RULES_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "rules",
    "Leaked Secrets (SECRETS).yar",
)

# The entropy rule is advisory (reported as WARN, not FAIL) and fires on
# plenty of innocuous strings, so it is excluded from negative assertions.
ADVISORY_RULES = {"SECRETS01"}


def _fill(alphabet: str, length: int) -> str:
    """Deterministically build a token body of an exact length."""
    return (alphabet * (length // len(alphabet) + 1))[:length]


HEX = "0123456789abcdef"
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
B64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"

# pattern identifier -> a line that must trigger it
POSITIVE_SAMPLES = {
    # --- SECRETS00 : allowlist ------------------------------------------
    # These are real, published, and owned by nobody. They are here so a
    # typo in an allowlist entry fails the build instead of quietly
    # un-excusing a credential every downstream repo expects to be excused.
    "known_public_azurite": "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1"
    "OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
    "known_public_aws_example_id": 'ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"',
    "known_public_aws_example_secret": 'SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    # --- SECRETS02 : legacy formats -------------------------------------
    "slack_token": "SLACK = 'xoxb-123456789012-123456789012-123456789012-" + _fill("abcdefghijklmnopqrstuvwxyz0123456789", 32) + "'",
    "slack_webhook": "https://hooks.slack.com/services/T00000000/B00000000/" + _fill(ALNUM, 24),
    "facebook_oauth": 'facebook_app_secret = "' + _fill(HEX, 32) + '"',
    "twitter_oauth": 'twitter_consumer_key = "' + _fill(ALNUM, 40) + '"',
    "github_context": 'github_oauth_token = "' + _fill(ALNUM, 38) + '"',
    "heroku_API_key": 'heroku_api_key = "0123ABCD-4567-89AB-CDEF-0123456789AB"',
    "oath_token": "token = ya29." + _fill(ALNUM, 40),
    "jwt_token": (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    ),
    # --- SECRETS03 : key file markers -----------------------------------
    "RSA_private_key": "-----BEGIN RSA PRIVATE KEY-----",
    "OPENSSH_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----",
    "DSA_private_key": "-----BEGIN DSA PRIVATE KEY-----",
    "EC_private_key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP_private_key": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "PKCS8_private_key": "-----BEGIN PRIVATE KEY-----",
    "PKCS8_encrypted_key": "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "SSH2_private_key": "-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----",
    "PuTTY_private_key": "PuTTY-User-Key-File-2: ssh-rsa",
    "age_secret_key": "AGE-SECRET-KEY-1" + _fill(UPPER, 58),
    # --- SECRETS04 : cloud providers ------------------------------------
    # Deliberately not AWS's documented example pair - SECRETS00 allowlists
    # that pair by name, so using it here would test the allowlist, not the
    # pattern. Built from _fill rather than written out: a literal that looks
    # like a live AWS key trips GitHub's push protection on the way in.
    "aws_access_key": "AKIA" + _fill(UPPER, 16),
    "aws_secret_key": 'aws_secret_access_key = "' + _fill(ALNUM, 40) + '"',
    "aws_mws_token": "amzn.mws.01234567-89ab-cdef-0123-456789abcdef",
    "gcp_api_key": "GOOGLE_API_KEY=AIza" + _fill(ALNUM, 35),
    "gcp_oauth_client_secret": "GOCSPX-" + _fill(ALNUM, 28),
    "gcp_service_account": '  "type": "service_account",',
    "gcp_private_key_id": '  "private_key_id": "' + _fill(HEX, 40) + '",',
    "gcp_legacy_oauth_secret": '{"client_secret": "' + _fill(ALNUM, 24) + '"}',
    "azure_storage_key": "AccountKey=" + _fill(B64, 86) + "==",
    "azure_sas_token": "https://x.blob.core.windows.net/c?sig=" + _fill(ALNUM, 45) + "%3D",
    "azure_ad_secret": "AZURE_CLIENT_SECRET=abc8Q~" + _fill(ALNUM, 34),
    "hetzner_token": "HCLOUD_TOKEN=" + _fill(ALNUM, 64),
    # the Terraform provider form: no "hcloud" on the line to anchor to
    "hetzner_tf_token": '  token = "' + _fill(ALNUM, 64) + '"',
    "digitalocean_token": "DIGITALOCEAN_TOKEN=dop_v1_" + _fill(HEX, 64),
    "digitalocean_spaces_key": "SPACES_KEY=DO00" + _fill(UPPER, 16),
    "linode_token": 'linode_token = "' + _fill(HEX, 64) + '"',
    "scaleway_access_key": "SCW_ACCESS_KEY=SCW" + _fill(UPPER, 17),
    "scaleway_secret_key": "SCW_SECRET_KEY=01234567-89ab-cdef-0123-456789abcdef",
    "cloudflare_origin_ca_key": "v1.0-" + _fill(HEX, 24) + "-" + _fill(ALNUM, 120),
    "flyio_token": "FLY_API_TOKEN=FlyV1 fm2_" + _fill(ALNUM, 60),
    "flyio_legacy_token": "FLY_ACCESS_TOKEN=fo1_" + _fill(ALNUM, 43),
    # --- SECRETS05 : SCM and package registries -------------------------
    "github_token": "ghp_" + _fill(ALNUM, 36),
    "github_fine_grained_pat": "github_pat_" + _fill(ALNUM, 22) + "_" + _fill(ALNUM, 59),
    "github_app_jwt": "ghs_" + _fill(ALNUM, 36),
    "gitlab_pat": "glpat-" + _fill(ALNUM, 20),
    "gitlab_other_token": "gldt-" + _fill(ALNUM, 20),
    "npm_token": "//registry.npmjs.org/:_authToken=npm_" + _fill(ALNUM, 36),
    "pypi_token": "pypi-AgEIcHlwaS5vcmc" + _fill(ALNUM, 55),
    "rubygems_token": "rubygems_" + _fill(HEX, 48),
    "crates_io_token": "cio" + _fill(ALNUM, 32),
    "docker_hub_pat": "dckr_pat_" + _fill(ALNUM, 27),
    "terraform_cloud_token": _fill(ALNUM, 14) + ".atlasv1." + _fill(ALNUM, 65),
    "vault_service_token": "VAULT_TOKEN=hvs." + _fill(ALNUM, 30),
    # --- SECRETS06 : AI providers ---------------------------------------
    "anthropic_key": "ANTHROPIC_API_KEY=sk-ant-api03-" + _fill(ALNUM, 95),
    "openai_project_key": "OPENAI_API_KEY=sk-proj-" + _fill(ALNUM, 50),
    "openai_legacy_key": "OPENAI_API_KEY=sk-" + _fill(ALNUM, 48),
    "huggingface_token": "HF_TOKEN=hf_" + _fill(ALNUM, 34),
    "replicate_token": "REPLICATE_API_TOKEN=r8_" + _fill(ALNUM, 37),
    "groq_key": "GROQ_API_KEY=gsk_" + _fill(ALNUM, 52),
    "perplexity_key": "PERPLEXITY_API_KEY=pplx-" + _fill(ALNUM, 40),
    # --- SECRETS07 : payment --------------------------------------------
    "stripe_secret_key": "STRIPE_SECRET=sk_live_" + _fill(ALNUM, 30),
    "stripe_webhook_secret": "STRIPE_WEBHOOK_SECRET=whsec_" + _fill(ALNUM, 32),
    "square_access_token": "sq0atp-" + _fill(ALNUM, 22),
    "square_oauth_secret": "sq0csp-" + _fill(ALNUM, 43),
    "braintree_access_token": "access_token$production$" + _fill("abcdefghijklmnopqrstuvwxyz0123456789", 16) + "$" + _fill(HEX, 32),
    "shopify_access_token": "shpat_" + _fill(HEX, 32),
    # --- SECRETS08 : SaaS -----------------------------------------------
    "sendgrid_key": "SG." + _fill(ALNUM, 22) + "." + _fill(ALNUM, 43),
    "twilio_api_key": "TWILIO_API_KEY=SK" + _fill(HEX, 32),
    "mailgun_key": "MAILGUN_API_KEY=key-" + _fill(HEX, 32),
    "mailchimp_key": "MAILCHIMP=" + _fill(HEX, 32) + "-us12",
    "new_relic_key": "NEW_RELIC_KEY=NRAK-" + _fill(UPPER, 27),
    "grafana_cloud_token": "GRAFANA=glc_" + _fill(B64, 40),
    "grafana_service_account": "glsa_" + _fill(ALNUM, 32) + "_" + _fill(HEX, 8),
    "doppler_token": "DOPPLER_TOKEN=dp.pt." + _fill(ALNUM, 43),
    "postman_key": "PMAK-" + _fill(HEX, 24) + "-" + _fill(HEX, 34),
    "linear_key": "LINEAR_API_KEY=lin_api_" + _fill(ALNUM, 40),
    "telegram_bot_token": "TELEGRAM=123456789:AA" + _fill(ALNUM, 33),
    "discord_webhook": "https://discord.com/api/webhooks/12345678901234567890/" + _fill(ALNUM, 68),
    "sentry_dsn": "SENTRY_DSN=https://" + _fill(HEX, 32) + "@o123.ingest.sentry.io/1234567",
    "datadog_key": 'DATADOG_API_KEY = "' + _fill(HEX, 32) + '"',
    "cloudflare_key": 'cloudflare_api_token = "' + _fill(ALNUM, 40) + '"',
    # --- SECRETS09 : connection strings ---------------------------------
    "password_in_uri": "DATABASE_URL=postgresql://opteryx:Kj8mNp2qRvXwTz@db.internal.net:5432/prod",
    "odbc_password": "Server=db;Database=prod;Uid=svc_app;Pwd=Kj8mNp2qRvXwTz;",
    "mongodb_uri": "mongodb+srv://appuser:Kj8mNp2qRvXwTz@cluster0.mongodb.net/test",
}

# $placeholder* strings exist to subtract documentation examples, not to
# detect secrets, so they are exempt from the positive-sample requirement.
# $digest_64 is a subtraction, not a detection: it exists so a SHA-256 digest
# on a `token = "..."` line does not read as a Hetzner Terraform token.
NON_DETECTION_PATTERNS = {"token", "digest_64"}  # $token drives the entropy rule

# Lines that must NOT trigger any non-advisory rule. These are drawn from
# patterns that genuinely appear across the mabel-dev repositories.
NEGATIVE_SAMPLES = [
    # Stripe publishable keys are public by design
    "STRIPE_PUBLISHABLE_KEY=pk_live_" + _fill(ALNUM, 30),
    # ordinary source
    "import os, sys",
    "def get_secret(name: str) -> str:",
    'parser.add_argument("--rules-url", default=RULE_URL, help="URL to download rules")',
    # URLs without credentials
    "https://github.com/mabel-dev/opteryx-core",
    "https://raw.githubusercontent.com/joocer/fides/main/rules/",
    "postgresql://localhost:5432/opteryx",
    "mongodb://127.0.0.1:27017/test",
    # env var references, not values
    'AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")',
    "GOOGLE_APPLICATION_CREDENTIALS: ${{ secrets.GCP_KEY }}",
    'password = config.get("password")',
    # hashes and ids that are not credentials
    "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    # --- prefix-less 64-character strings -------------------------------
    # The Hetzner patterns are the only ones in the ruleset that can match a
    # token carrying no marker of its own. These lines prove the context
    # requirement is doing the work: without it, every digest and build id
    # in the estate is a finding.
    'BUILD_ID = "' + _fill(ALNUM, 64) + '"',
    "cache_key = " + _fill(ALNUM, 64),
    'image_digest = "' + _fill(HEX, 64) + '"',
    # a SHA-256 digest assigned to a bare `token`, which is what
    # $hetzner_tf_token would otherwise claim
    '  token = "' + _fill(HEX, 64) + '"',
    # env var references, not values
    "HCLOUD_TOKEN=${{ secrets.HCLOUD_TOKEN }}",
    'hcloud_token = os.environ["HCLOUD_TOKEN"]',
    "commit 94dd038a1b2c3d4e5f60718293a4b5c6d7e8f900",
    "uuid = 550e8400-e29b-41d4-a716-446655440000",
    # documentation placeholders
    "AWS_ACCESS_KEY_ID=<your-access-key-id>",
    'api_key = "REDACTED"',
    "Set your token with: export GITHUB_TOKEN=ghp_xxx",
    # --- connection-string placeholders -------------------------------
    # Every line below was flagged by an earlier revision of SECRETS09
    # during a scan of the mabel-dev repositories. They are all docs.
    "opteryx://<client_id>:<client_secret>@opteryx.app:443/default?ssl=true",
    "opteryx://YOUR_CLIENT_ID:YOUR_CLIENT_SECRET@opteryx.app:443/default?ssl=true",
    'conn_str = f"opteryx://{client_id}:{client_secret}@opteryx.app:443/default?ssl=true"',
    'conn_str = f"opteryx://{client_id}:{BEARER_TOKEN}@opteryx.app:443/default?ssl=true"',
    'engine = create_engine(f"opteryx://{user}:{password}@{host}:{port}/{database}")',
    "postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:5432/${DB_NAME}",
    'DATABASE_URL="postgres://user:pass@localhost:5432/mydb"',
    "mongodb+srv://admin:changeme@cluster0.mongodb.net/test",
    "Server=myserver;Database=mydb;Uid=myuser;Pwd=<password>;",
    "redis://:%s@%s:%d/0" % ("pw", "host", 6379),
    # From the opteryx-sqlalchemy README and dialect docstring
    "- **Opteryx Cloud (with token)**: `opteryx://myusername:mytoken@opteryx.app:443/default?ssl=true`",
    "opteryx://user:mytoken@jobs.opteryx.app:443/default?ssl=true",
    'url = make_url("opteryx://user:token123@opteryx.app:443/mydb?ssl=true&timeout=60")',
    # --- ordinary code that merely mentions a password ------------------
    # From third_party/curl in opteryx-core: an assignment is not a
    # connection string, so $odbc_password requires a ; or quote first.
    "  u->password = passwdp;",
    "  u->password = NULL;",
    "  *password = passphrase;",
    "  identity->Password = dup_passwd.tbyte_ptr;",
    "self.password = password",
    # NOTE: published-but-credential-shaped constants (Azurite's emulator
    # key, AWS's documented example pair) are deliberately NOT here. They
    # *do* match at the rule level, by design - SECRETS00 marks them and the
    # scanner reports the suppression. See test_fides.py for those cases.
]


def compile_rules():
    return yara.compile(RULES_FILE)


def declared_pattern_names():
    """Every $identifier declared in the ruleset."""
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        source = f.read()
    # strip comments so commented-out examples are not counted
    source = re.sub(r"//[^\n]*", "", source)
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return set(re.findall(r"^\s*\$(\w+)\s*=", source, re.M))


class TestRuleCoverage(unittest.TestCase):
    """Guards against the silent-death failure mode."""

    def test_every_pattern_is_covered(self):
        declared = declared_pattern_names() - NON_DETECTION_PATTERNS
        declared = {n for n in declared if not n.startswith("placeholder")}
        tested = set(POSITIVE_SAMPLES)
        missing = declared - tested
        self.assertEqual(
            missing,
            set(),
            "These patterns have no positive sample in POSITIVE_SAMPLES. A pattern "
            "with no test can be silently dead:\n  " + "\n  ".join(sorted(missing)),
        )

    def test_no_stale_samples(self):
        declared = declared_pattern_names()
        stale = set(POSITIVE_SAMPLES) - declared
        self.assertEqual(
            stale, set(), f"Samples reference patterns that no longer exist: {sorted(stale)}"
        )


class TestPositiveMatches(unittest.TestCase):
    """Each pattern must fire on its own sample."""

    @classmethod
    def setUpClass(cls):
        cls.rules = compile_rules()

    def test_patterns_fire(self):
        failures = []
        for name, sample in sorted(POSITIVE_SAMPLES.items()):
            matched = set()
            for match in self.rules.match(data=sample):
                for s in match.strings:
                    matched.add(s.identifier.lstrip("$"))
            if name not in matched:
                failures.append(f"  ${name}: did not match its own sample")
        self.assertEqual([], failures, "Dead or mis-escaped patterns:\n" + "\n".join(failures))


class TestNegativeMatches(unittest.TestCase):
    """Non-secrets must not trip the scanner."""

    @classmethod
    def setUpClass(cls):
        cls.rules = compile_rules()

    def test_clean_lines_do_not_match(self):
        failures = []
        for sample in NEGATIVE_SAMPLES:
            for match in self.rules.match(data=sample):
                if match.rule in ADVISORY_RULES:
                    continue
                ids = ", ".join(sorted({s.identifier for s in match.strings}))
                failures.append(f"  {match.rule} ({ids}) matched: {sample[:80]}")
        self.assertEqual([], failures, "False positives:\n" + "\n".join(failures))


if __name__ == "__main__":
    unittest.main(verbosity=2)
