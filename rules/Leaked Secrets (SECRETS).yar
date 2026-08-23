/*
    Tests for passwords, hashes and secrets.

    Original pattern RegExes mostly from
    https://raw.githubusercontent.com/dxa4481/truffleHog/dev/scripts/searchOrg.py

    NOTE ON REGEX STYLE
    -------------------
    These patterns are matched by YARA, not Python. Two rules of thumb:

      1. Do not escape quotes or backslashes as if this were a Python string
         literal. A class written `['\\"\\\\s]` is read by YARA as the set
         { ' , \ , " , s } -- it does NOT include whitespace.

      2. Never end a pattern with `\b` immediately after a non-word character
         (a quote, `=`, whitespace). A word boundary cannot exist between two
         non-word characters, so the pattern can never match.

    Both mistakes silently disable a rule rather than erroring, so new
    patterns must ship with a sample in tests/samples/.

    YARA's regex engine has no lookahead/lookbehind -- do not use (?=) or (?<=).
*/

import "math"

/*
    Credentials that are structurally real but belong to nobody: vendors
    publish them in their own documentation, so they turn up in any repo
    that has a test exercising that vendor.

    This rule detects rather than hides. A line it matches is still scanned
    by every other rule; the scanner suppresses those findings and reports
    the suppression, so an allowlisted line is visibly accounted for instead
    of silently absent. Putting the exclusion in a rule condition would make
    a dead pattern and a deliberately ignored credential look identical.

    An `importance` of "ignored" is what marks a rule as an allowlist.
*/
rule SECRETS00 : KNOWN_PUBLIC
{
    meta:
        author = "Joocer"
        description = "Known Public Credential"
        timestamp = "2026-08-23"
        version = "0.01"
        importance = "ignored"

    strings:
        /*
            Azurite (the Azure Storage emulator) ships one hard-coded account
            key, published in Microsoft's own documentation and identical in
            every install. It is structurally a storage key but is not a
            secret, and it appears in any repo that runs storage tests.
        */
        $known_public_azurite = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="

        /*
            The credential pair AWS publishes in its own SigV4 documentation.
            Every signing test in every language reproduces it, because the
            documented test vectors only verify against these exact values.
            Structurally a key pair, but not anyone's key pair.
        */
        $known_public_aws_example_id = "AKIAIOSFODNN7EXAMPLE"
        $known_public_aws_example_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    condition:
        any of them
}

rule SECRETS01 : HIGH_ENTROPY_STRING
{
    meta:
        author = "Joocer"
        description = "Token Appears to be a Random String"
        timestamp = "2020-10-27"
        version = "0.01"
        importance = "medium"
    strings:
        $token = /[A-Z0-9\=\_\-]{8,64}/ nocase
    condition:
        math.entropy(@token, !token) > 6
}

rule SECRETS02 : SECRETS
{
    meta:
        author = "Joocer"
        description = "Token Matches Known Secret Format"
        timestamp = "2026-08-15"
        version = "0.03"
        importance = "high"

    strings:
        $slack_token = /\bxox[pboas]-[0-9]{10,14}-[0-9]{10,14}-[0-9]{10,14}-[a-z0-9]{32}\b/
        $slack_webhook = /\bhttps:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,12}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24}/
        $facebook_oauth = /facebook.{0,30}['"][0-9a-f]{32}['"]/ nocase
        $twitter_oauth = /twitter.{0,30}['"][0-9A-Za-z]{35,44}['"]/ nocase
        $github_context = /github.{0,30}['"][0-9A-Za-z]{35,40}['"]/ nocase
        $heroku_API_key = /heroku.{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/ nocase
        $oath_token = /\bya29\.[0-9A-Za-z_\-]{20,}/
        $jwt_token = /\beyJ[0-9A-Za-z_\-]{8,}\.eyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{16,}/

    condition:
        any of them
}

rule SECRETS03 : KEY_FILES
{
    meta:
        author = "Joocer"
        description = "Token Matches Known Secret File Marker"
        timestamp = "2026-08-15"
        version = "0.02"
        importance = "high"

    strings:
        $RSA_private_key = "-----BEGIN RSA PRIVATE KEY-----"
        $OPENSSH_private_key = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $DSA_private_key = "-----BEGIN DSA PRIVATE KEY-----"
        $EC_private_key = "-----BEGIN EC PRIVATE KEY-----"
        $PGP_private_key = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        $PKCS8_private_key = "-----BEGIN PRIVATE KEY-----"
        $PKCS8_encrypted_key = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
        $SSH2_private_key = "-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----"
        $PuTTY_private_key = "PuTTY-User-Key-File-"
        $age_secret_key = /\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b/

    condition:
        any of them
}

rule SECRETS04 : CLOUD_CREDENTIALS
{
    meta:
        author = "Joocer"
        description = "Cloud Provider Credential"
        timestamp = "2026-08-15"
        version = "0.01"
        importance = "high"

    strings:
        // Amazon Web Services
        $aws_access_key = /\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/
        $aws_secret_key = /aws_?secret_?access_?key['"]?[\s:=]{1,10}['"]?[0-9A-Za-z\/+]{40}/ nocase
        $aws_mws_token = /\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/ nocase

        // Google Cloud Platform
        $gcp_api_key = /\bAIza[0-9A-Za-z_\-]{35}\b/
        $gcp_oauth_client_secret = /\bGOCSPX-[0-9A-Za-z_\-]{28}\b/
        $gcp_service_account = /"type"\s*:\s*"service_account"/
        $gcp_private_key_id = /"private_key_id"\s*:\s*"[0-9a-f]{40}"/
        $gcp_legacy_oauth_secret = /"client_secret"\s*:\s*"[0-9A-Za-z_\-]{24}"/

        // Microsoft Azure
        $azure_storage_key = /AccountKey\s*=\s*[0-9A-Za-z+\/]{86}==/
        $azure_sas_token = /\bsig=[0-9A-Za-z%]{43,53}%3D/
        $azure_ad_secret = /\b[0-9A-Za-z_\-~.]{3}8Q~[0-9A-Za-z_\-~.]{34}\b/

    condition:
        any of ($aws*, $gcp*, $azure*)
}

rule SECRETS05 : SCM_AND_PACKAGE_TOKENS
{
    meta:
        author = "Joocer"
        description = "Source Control or Package Registry Token"
        timestamp = "2026-08-15"
        version = "0.01"
        importance = "high"

    strings:
        // GitHub - classic PAT, OAuth, user-to-server, server-to-server, refresh
        $github_token = /\bgh[pousr]_[0-9A-Za-z]{36,255}\b/
        $github_fine_grained_pat = /\bgithub_pat_[0-9A-Za-z]{22}_[0-9A-Za-z]{59}\b/
        $github_app_jwt = /\bghs_[0-9A-Za-z]{36}\b/

        // GitLab
        $gitlab_pat = /\bglpat-[0-9A-Za-z_\-]{20,}/
        $gitlab_other_token = /\bgl(dt|rt|soat|ptt|cbt|ft|imt)-[0-9A-Za-z_\-]{20,}/

        // Package registries
        $npm_token = /\bnpm_[0-9A-Za-z]{36}\b/
        $pypi_token = /\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_\-]{50,}/
        $rubygems_token = /\brubygems_[0-9a-f]{48}\b/
        $crates_io_token = /\bcio[0-9A-Za-z]{32}\b/
        $docker_hub_pat = /\bdckr_pat_[0-9A-Za-z_\-]{27}\b/

        // Infrastructure tooling
        $terraform_cloud_token = /\b[0-9A-Za-z]{14}\.atlasv1\.[0-9A-Za-z_\-]{60,}/
        $vault_service_token = /\bhv[sb]\.[0-9A-Za-z_\-]{24,}/

    condition:
        any of them
}

rule SECRETS06 : AI_PROVIDER_TOKENS
{
    meta:
        author = "Joocer"
        description = "AI Provider API Key"
        timestamp = "2026-08-15"
        version = "0.01"
        importance = "high"

    strings:
        $anthropic_key = /\bsk-ant-(api|admin)[0-9]{2}-[0-9A-Za-z_\-]{80,}/
        $openai_project_key = /\bsk-proj-[0-9A-Za-z_\-]{40,}/
        $openai_legacy_key = /\bsk-[0-9A-Za-z]{48}\b/
        $huggingface_token = /\bhf_[0-9A-Za-z]{34,}\b/
        $replicate_token = /\br8_[0-9A-Za-z]{37,}\b/
        $groq_key = /\bgsk_[0-9A-Za-z]{52}\b/
        $perplexity_key = /\bpplx-[0-9A-Za-z]{40,}\b/

    condition:
        any of them
}

rule SECRETS07 : PAYMENT_TOKENS
{
    meta:
        author = "Joocer"
        description = "Payment Provider Secret Key"
        timestamp = "2026-08-15"
        version = "0.01"
        importance = "high"

    strings:
        // Stripe -- restricted and live secret keys, and webhook signing secrets.
        // pk_live_ (publishable) is deliberately excluded: it is public by design.
        $stripe_secret_key = /\b[sr]k_live_[0-9A-Za-z]{24,}/
        $stripe_webhook_secret = /\bwhsec_[0-9A-Za-z]{32,}/

        // Square
        $square_access_token = /\bsq0atp-[0-9A-Za-z_\-]{22}\b/
        $square_oauth_secret = /\bsq0csp-[0-9A-Za-z_\-]{43}\b/

        // PayPal / Braintree
        $braintree_access_token = /\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b/

        // Shopify
        $shopify_access_token = /\bshp(at|ca|pa|ss)_[0-9a-f]{32}\b/

    condition:
        any of them
}

rule SECRETS08 : SAAS_TOKENS
{
    meta:
        author = "Joocer"
        description = "Third Party Service Token"
        timestamp = "2026-08-15"
        version = "0.01"
        importance = "high"

    strings:
        $sendgrid_key = /\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b/
        $twilio_api_key = /\bSK[0-9a-f]{32}\b/
        $mailgun_key = /\bkey-[0-9a-f]{32}\b/
        $mailchimp_key = /\b[0-9a-f]{32}-us[0-9]{1,2}\b/
        $new_relic_key = /\bNRAK-[0-9A-Z]{27}\b/
        $grafana_cloud_token = /\bglc_[0-9A-Za-z+\/=]{32,}/
        $grafana_service_account = /\bglsa_[0-9A-Za-z]{32}_[0-9a-f]{8}\b/
        $doppler_token = /\bdp\.(pt|st|sa|scim|audit)\.[0-9A-Za-z]{40,}/
        $postman_key = /\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b/
        $linear_key = /\blin_api_[0-9A-Za-z]{40}\b/
        $telegram_bot_token = /\b[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}\b/
        $discord_webhook = /\bhttps:\/\/discord(app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[0-9A-Za-z_\-]{60,}/
        $sentry_dsn = /\bhttps:\/\/[0-9a-f]{32}(:[0-9a-f]{32})?@[0-9A-Za-z.\-]+\/[0-9]{1,10}\b/
        $datadog_key = /(datadog|dd)_?api_?key['"]?[\s:=]{1,10}['"]?[0-9a-f]{32}\b/ nocase
        $cloudflare_key = /cloudflare.{0,30}['"][0-9A-Za-z_\-]{37,40}['"]/ nocase

    condition:
        any of them
}

rule SECRETS09 : CREDENTIALS_IN_URI
{
    meta:
        author = "Joocer"
        description = "Credential Embedded in Connection String"
        timestamp = "2026-08-15"
        version = "0.02"
        importance = "high"

    /*
        Documentation is full of connection strings, so this rule has to
        separate a real credential from an illustrative one. Two defences:

          1. The credential character class excludes the interpolation and
             bracket characters -- { } < > $ % ( ) * ` -- so templated forms
             such as {client_secret}, <password> and ${DB_PASS} never match.

          2. The condition subtracts $placeholder*, which catches the wordy
             stand-ins (YOUR_SECRET, CHANGEME, REDACTED) that are otherwise
             indistinguishable from a real value.

        run.py matches a line at a time, so the subtraction is scoped to the
        line carrying the connection string, not the whole file.
    */

    strings:
        // scheme://user:password@host -- the replacement for the original
        // $password_in_URL, which could never match (trailing \b).
        $password_in_uri = /\b[a-z][a-z0-9+.\-]{2,15}:\/\/[^\/\s:@"'{}<>$%()*`\\]{1,64}:[^\/\s:@"'{}<>$%()*`\\]{3,64}@[a-z0-9.\-]{1,256}/ nocase

        // Named credentials in ODBC / ADO / libpq style connection strings.
        // The leading [;"'] anchors this to a key=value;key=value chain --
        // without it the pattern matches ordinary code such as the C
        // statement `u->password = passwdp;`.
        $odbc_password = /[;"']\s*(pwd|password)\s*=\s*[^;\s"'{}<>$%()*`\\]{4,64};/ nocase
        $mongodb_uri = /\bmongodb(\+srv)?:\/\/[^\/\s:@"'{}<>$%()*`\\]{1,64}:[^\/\s:@"'{}<>$%()*`\\]{3,64}@/ nocase

        // "your_secret", "YOUR_CLIENT_ID", "mytoken", "myusername"
        $placeholder_your = /\b(your|my)[_\-]?(client[_\-]?|api[_\-]?|access[_\-]?)?(secret|password|passwd|token|key|id|user(name)?)\b/ nocase
        $placeholder_generic = /\b(changeme|change[_\-]me|redacted|placeholder|insert[_\-]?your|s3cr3t|hunter2|xxxx|\.\.\.)/ nocase
        // "user:password", "admin:secret", "user:token123"
        $placeholder_example = /\b(user(name)?|login|admin|example|sample|dummy|test|foo|bar):(pass(word|wd)?|secret|token|key|cred(ential)?s?)[0-9]{0,4}\b/ nocase

    condition:
        any of ($password_in_uri, $odbc_password, $mongodb_uri)
        and not any of ($placeholder*)
}
