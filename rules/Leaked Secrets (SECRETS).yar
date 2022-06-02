/*
    Tests for passwords, hashes and secrets.

    Pattern RegExes mostly from
    https://raw.githubusercontent.com/dxa4481/truffleHog/dev/scripts/searchOrg.py
*/

import "math"

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
        timestamp = "2022-01-12"
        version = "0.02"
        importance = "high"
                
    strings: 
        $slack_token = /\b(xox[p|b|o|a]\-[0-9]{12}\-[0-9]{12}\-[0-9]{12}\-[a-z0-9]{32})\b/
        $facebook_oauth = /\bfacebook.{0,30}['\\"\\\\s][0-9a-f]{32}['\\"\\\\s]\b/ nocase
        $twitter_oauth = /\btwitter.{0,30}['\\"\\\\s][0-9A-Z]{35,44}['\\"\\\\s]\b/ nocase
        $github = /\bgithub.{0,30}['\\"\\\\s][0-9A-Z]{35,40}['\\"\\\\s]\b/ nocase
        $github_pat = /\bghp_[0-9A-Z]{36}\b/ nocase
        $google_oauth = /\b(\\"client_secret\\":\\"[a-zA-Z0-9-_]{24}\\")\b/
        $AWS_API_key = /\bAKIA[0-9A-Z]{16}\b/
        $heroku_API_key = /\bheroku.{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b/ nocase
        $slack_webhook = /\bhttps:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}\b/
        $google_service_account = /\b\\"type\\": \\"service_account\\"\b/
        $password_in_URL = /\b[a-zA-Z]{3,10}:\/\/[^\/\\\\s:@]{3,20}:[^\/\\\\s:@]{3,20}@.{1,100}[\\"'\\\\s]\b/
        $oath_token = /\bya29\.[\w-]+\b/ nocase
        $jwt_token = /\beyJ[0-9A-Z_-]{8,}\.eyJ[0-9A-Z_-]{8,}\.[0-9A-Z_-]{16,}\b/ nocase
        
    condition: 
        any of them
}

rule SECRETS03 : KEY_FILES
{
    meta:
        author = "Joocer"
        description = "Token Matches Known Secret File Marker" 
        timestamp = "2020-10-27"
        version = "0.01"
        importance = "high"
                
    strings: 
        $RSA_private_key = "-----BEGIN RSA PRIVATE KEY-----"
        $OPENSSH_private_key = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $DSA_private_key = "-----BEGIN DSA PRIVATE KEY-----"
        $EC_private_key = "-----BEGIN EC PRIVATE KEY-----"
        $PGP_private_key = "-----BEGIN PGP PRIVATE KEY BLOCK-----"

    condition: 
        any of them
}
