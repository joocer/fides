/*
    Tests for passwords, hashes and secrets.

    Pattern RegExes mostly from
    https://raw.githubusercontent.com/dxa4481/truffleHog/dev/scripts/searchOrg.py
*/

import "math"

rule SECRETS01 : HIGH_ENTROPY_STRING 
{
    meta:
        author = "390516"
        description = "Token with a high degree of randomness"
        timestamp = "2020-10-27"
        version = "0.01"
        importance = "medium"
    strings:
        $token = /[A-Z0-9\=\_\-]{8,64}/ nocase
    condition:
        math.entropy(@token, !token) > 3.2
}

rule SECRETS02 : SECRETS
{
    meta:
        author = "390516"
        description = "Known Secret Formats" 
        timestamp = "2020-10-27"
        version = "0.01"
        importance = "high"
                
    strings: 
        $slack_token = /(xox[p|b|o|a]\-[0-9]{12}\-[0-9]{12}\-[0-9]{12}\-[a-z0-9]{32})/
        $facebook_oauth = /facebook.{0,30}['\\"\\\\s][0-9a-f]{32}['\\"\\\\s]/ nocase
        $twitter_oauth = /twitter.{0,30}['\\"\\\\s][0-9A-Z]{35,44}['\\"\\\\s]/ nocase
        $github = /github.{0,30}['\\"\\\\s][0-9A-Z]{35,40}['\\"\\\\s]/ nocase
        $google_oauth = /(\\"client_secret\\":\\"[a-zA-Z0-9-_]{24}\\")/
        $AWS_API_key = /AKIA[0-9A-Z]{16}/
        $heroku_API_key = /heroku.{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/ nocase
        $slack_webhook = /https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/
        $google_service_account = /\\"type\\": \\"service_account\\"/
        $twilio_API_key = /SK[a-z0-9]{32}/
        $password_in_URL = /[a-zA-Z]{3,10}:\/\/[^\/\\\\s:@]{3,20}:[^\/\\\\s:@]{3,20}@.{1,100}[\\"'\\\\s]/
        
    condition: 
        any of them
}

rule SECRETS03 : KEY_FILES
{
    meta:
        author = "390516"
        description = "Keyfile Markers Found" 
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