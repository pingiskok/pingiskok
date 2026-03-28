---
title: "JWT, Part 10: JWE - encrypted tokens and how to break them"
date: 2026-03-28T10:10:00+03:00
number: 10
tags: ["jwt", "security", "web", "auth"]
summary: "JWE is the encrypted side of JWT that almost nobody talks about: five parts, two encryption layers, and a full zoo of attacks - Invalid Curve on ECDH-ES, Bleichenbacher on RSA1_5, Padding Oracle on AES-CBC, PBES2 DoS with one request, and the forbidden attack on AES-GCM."
---

**Table of contents:**
- [How to tell JWE from JWS](#how-to-tell-jwe-from-jws)
- [Two-layer encryption: why two algorithms](#two-layer-encryption-why-two-algorithms)
- [JWE format: five parts](#jwe-format-five-parts)
- [Invalid Curve Attack on ECDH-ES](#invalid-curve-attack-on-ecdh-es)
- [Bleichenbacher on RSA1_5](#bleichenbacher-on-rsa1_5)
- [Padding Oracle on AES-CBC](#padding-oracle-on-aes-cbc)
- [PBES2 DoS: taking down a server with one request](#pbes2-dos-taking-down-a-server-with-one-request)
- [AES-GCM: reused IV = catastrophe](#aes-gcm-reused-iv--catastrophe)
- [What else breaks in JWE](#what-else-breaks-in-jwe)
- [Where you'll find JWE in the wild](#where-youll-find-jwe-in-the-wild)
- [Tools](#tools)
- [JWE attack checklist](#jwe-attack-checklist)
- [What's next](#whats-next)

Up until now we've been dealing with JWS - signed tokens. Three parts separated by dots. The payload is visible to anyone, the signature guarantees integrity but not confidentiality. Anyone can Base64url-decode it and read the contents - remember the examples from article 2?

JWE works differently. The payload is **encrypted**. You can't just decode it and read the claims. Five parts instead of three, two layers of encryption, and a set of crypto attacks that almost nobody talks about.

## How to tell JWE from JWS

Quick way: count the dots.

```bash
# 2 dots, 3 parts = JWS (signature) header.payload.signature
# 4 dots, 5 parts = JWE (encryption) header.key.iv.ciphertext.tag
```

Or decode the header (the first part before the first dot - it decodes the same way for both JWS and JWE):

```bash
# base64url vs base64: character substitution + padding
echo "$TOKEN" | cut -d. -f1 | tr -- '-_' '+/' | \
  awk '{while(length%4)$0=$0"=";print}' | base64 -d
```

JWS: `{"alg":"RS256"}` - just the signing algorithm.
JWE: `{"alg":"RSA-OAEP","enc":"A256GCM"}` - two algorithms. If you see an `enc` field, it's JWE.

## Two-layer encryption: why two algorithms

JWE uses hybrid encryption. The idea is straightforward: asymmetric algorithms (RSA, ECDH) can only encrypt small chunks of data - RSA-OAEP with a 2048-bit key and SHA-1 tops out at 214 bytes, RSA-OAEP-256 with SHA-256 at 190 bytes - while a JWT payload can be significantly larger. Symmetric algorithms (AES) encrypt any amount of data quickly, but require a shared secret.

The solution: combine both approaches.

1. Generate a random symmetric key - the **CEK** (Content Encryption Key). For example, 32 random bytes for AES-256-GCM. For AES-CBC-HMAC modes, the CEK is longer: 256 bits for A128CBC-HS256 (128 for encryption + 128 for MAC), 512 bits for A256CBC-HS512.
2. Use the CEK to encrypt the payload with AES. Fast, works with any data size.
3. Protect the CEK itself: encrypt it (RSA-OAEP), wrap it (AES Key Wrap), or derive it through key agreement (ECDH-ES). This is safe because the CEK is small.

The recipient extracts the CEK with their private key and decrypts the payload. Two layers - hence two fields in the header: `alg` for CEK protection (key management), `enc` for payload encryption (content encryption).

## JWE format: five parts

```
Header.EncryptedKey.IV.Ciphertext.Tag
```

**Header** - JSON with the algorithms, Base64url-encoded. Example: `{"alg":"RSA-OAEP","enc":"A256GCM"}`. This header is **not encrypted** (same as in JWS), but it's protected against modification: it's included in the Additional Authenticated Data (AAD) during encryption. If someone tampers with the header, the Authentication Tag won't verify.

**Encrypted Key** - the CEK encrypted by the algorithm specified in `alg`. For direct encryption (algorithm `dir`) or ECDH-ES (direct key agreement), this field is empty - the CEK isn't transmitted but rather computed or used directly.

**IV** (Initialization Vector) - the initialization vector for symmetric encryption. 12 bytes for AES-GCM, 16 bytes for AES-CBC.

**Ciphertext** - the encrypted payload. Your claims live here, but you can't read them without the key.

**Tag** (Authentication Tag) - the authentication tag. Guarantees that neither the ciphertext nor the header has been modified. 16 bytes for AES-GCM.

## Invalid Curve Attack on ECDH-ES

March 2017. Antonio Sanso finds a bug in five JWT libraries simultaneously: go-jose, node-jose, jose2go, Nimbus JOSE+JWT, jose4j. Every single one allows full recovery of the server's private key.

**Context.** ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static) is a key agreement algorithm. The client generates an ephemeral (one-time) key pair and sends its ephemeral public key in the JWE header via the `epk` (ephemeral public key) parameter. The server takes that key and computes a shared secret: `shared_secret = server_private_key * client_ephemeral_public_key`. The CEK is derived from this shared secret.

**The problem.** An elliptic curve is defined by the equation `y^2 = x^3 + ax + b (mod p)`. The point addition and doubling formulas use parameter `a` but **ignore `b`**. That means if you substitute a point that lies not on P-256 (the correct curve) but on a curve with a different `b`, the server will still perform the computation without errors. The libraries weren't checking that the point in `epk` actually lay on the correct curve.

**The attack, step by step:**

The attacker finds alternative curves (same `a` and `p`, but a different `b'`) that have small-order subgroups. Small order means - say, 7 or 11 elements. Take a point from such a subgroup and put it in `epk`:

```json
{
  "alg": "ECDH-ES",
  "enc": "A128GCM",
  "epk": {
    "kty": "EC", "crv": "P-256",
    "x": "<point on an invalid curve>",
    "y": "<...>"
  }
}
```

The server computes `d * P`, where `d` is its private key and `P` is our point from the small-order subgroup `n_i`. The result falls within that subgroup. You iterate through all `n_i` candidates, craft a JWE for each, send it to the server, and infer the correct one from the response (200 vs 400). That gives you `d mod n_i`.

Repeat this for different curves with different small subgroups. Once you've collected enough values `d mod n_1`, `d mod n_2`, ..., `d mod n_k`, apply CRT (the Chinese Remainder Theorem) to recover the full private key `d`.

How many requests? Jager et al. (2015) estimated for a similar attack on TLS-ECDH: ~3,300 against Oracle/SunEC, ~17,000 against Bouncy Castle. For JWE libraries, it's in the same ballpark - thousands of requests, not millions. Full private key recovery. Decryption of all past and future JWEs. And if the key is shared between signing and encryption (cross-protocol key reuse) - signature forgery on top of that.

Vulnerable versions: go-jose < 1.0.5, node-jose < 0.9.3, Nimbus JOSE+JWT < 4.34.2, jose4j < 0.5.1, jose2go (fixed without a version number). The same attack works on ECDH-ES+A128KW and ECDH-ES+A256KW - same libraries, same problem.

**Fix:** validate `y^2 == x^3 + ax + b (mod p)` for every point received in `epk` before doing ECDH. All five libraries added this check after disclosure.

## Bleichenbacher on RSA1_5

A 1998 attack that keeps finding victims.

`alg: "RSA1_5"` encrypts the CEK using PKCS#1 v1.5 padding. The format is: `0x00 || 0x02 || [random non-zero bytes] || 0x00 || CEK`. During decryption, the server checks that the first two bytes are `0x00 0x02`. If the server responds differently to valid vs. invalid padding, that's an oracle.

**CVE-2026-28490 (Authlib)** - a fresh example. Python's `cryptography` library returns random bytes when padding is invalid (as RFC 3218 recommends for Bleichenbacher protection). But Authlib checked the length of the received CEK **before** AES-GCM decryption:

- Padding valid, but MAC doesn't verify: `InvalidTag` (AES-GCM error)
- Padding invalid, random CEK of wrong length: `ValueError` (length error)

Different exceptions led to different HTTP status codes. Two distinct server responses - and you have an oracle. ~14,500 requests to decrypt the CEK.

```bash
# Testing: flip bits in encrypted_key one at a time
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $JWE_ORIGINAL" \
  https://target/api
# vs
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $JWE_MODIFIED" \
  https://target/api
# Different HTTP codes = oracle exists
```

**Fix:** use RSA-OAEP instead of RSA1_5. OAEP is resistant to classic Bleichenbacher, but it's not invincible: Manger (2001) demonstrated an attack on RSA-OAEP by distinguishing decoding errors - ~1,000 requests. The golden rule for any `alg`: a single, unified error response for all cryptographic failures. The attacker must not be able to distinguish "bad padding" from "bad MAC" from "bad OAEP".

## Padding Oracle on AES-CBC

`enc: "A128CBC-HS256"` is AES in CBC mode with HMAC for authentication. AES-CBC requires PKCS#7 padding: the final block is padded with bytes whose value equals the number of bytes added (for example, 4 bytes each with value `0x04`).

If the server differentiates between "invalid padding" and "invalid MAC" - that's the classic Vaudenay attack (2002):

1. Take a ciphertext block and change one byte in the preceding block
2. Send it to the server. 256 possibilities per byte
3. "Invalid MAC" instead of "Invalid padding" = you've guessed the correct padding
4. Use CBC's XOR properties to recover the plaintext byte

4,096 requests per 16-byte block. The entire payload decrypts block by block.

RFC 7518 (Section 5.2.2.2) protects against this: HMAC is verified **first**. If HMAC fails, padding is never checked at all. The attack breaks when an implementation checks padding **before** HMAC, or returns different error codes for each.

**Fix:** use AES-GCM (`A128GCM`, `A256GCM`). GCM is native AEAD (Authenticated Encryption with Associated Data). No separate padding, no separate MAC check. Encryption and authentication in a single operation. Padding oracle is impossible by design.

## PBES2 DoS: taking down a server with one request

The simplest attack of the bunch. CVE-2023-52428 (Nimbus JOSE+JWT).

`alg: "PBES2-HS256+A128KW"` uses PBKDF2 (Password-Based Key Derivation Function 2). The algorithm derives a key from a password through repeated hashing. The `p2c` parameter in the JWE header controls the iteration count. And this parameter is **controlled by the attacker**:

```python
import json, base64

def b64url(d):
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

header = {
    "alg": "PBES2-HS256+A128KW",
    "enc": "A128GCM",
    "p2s": b64url(b"salt"),
    "p2c": 2147483647  # 2^31-1 iterations
}
h = b64url(json.dumps(header).encode())
print(f"{h}.AAAA.AAAA.AAAA.AAAA")
```

2.1 billion iterations of HMAC-SHA256. On a single core, that's ~1,000 seconds of CPU time. One request = server busy for 16 minutes on one core. A few parallel requests = complete DoS.

**Fix:** cap `p2c`. The draft-ietf-oauth-rfc8725bis recommends no more than 1,200,000 iterations (more on this in article 19). If `p2c` exceeds the limit, reject the token before any computation starts.

## AES-GCM: reused IV = catastrophe

Using AES-GCM with the same IV (nonce) and key across two different messages is one of the most underestimated mistakes you can make. Here's what happens:

1. **XOR of plaintexts.** GCM encrypts via CTR mode: `ciphertext = plaintext XOR keystream`. Two messages with the same IV produce the same keystream. XOR the two ciphertexts together and you get the XOR of the two plaintexts. That's not the plaintexts directly, but if one of them is partially known - and JWT payloads are predictable (`{"sub":"`, `{"iss":"`) - the other one can be recovered.

2. **Authentication key leak.** Joux (2006, "forbidden attack") showed that with a repeated nonce you can recover the GHASH key H. With that key, the attacker can forge the Authentication Tag for **arbitrary** messages. Integrity protection is gone.

How to check: collect a few JWE tokens from the server and decode the third part (IV) from Base64url. A match means the server is using a static or predictable IV. This happens when a developer hardcodes a nonce or uses a counter that resets on restart.

## What else breaks in JWE

**Algorithm downgrade.** Same trap as with JWS (article 4). If the server accepts `alg` from the header without an allowlist: RSA-OAEP -> RSA1_5 opens up Bleichenbacher, -> PBES2 opens up DoS, -> `dir` lets you substitute your own key directly.

**Compression bomb.** JWE supports `"zip":"DEF"` - compressing the payload before encryption. An attacker crafts a token where the compressed data expands to gigabytes (CVE-2024-33664, CVE-2024-21319). One request = OOM on the server.

**JWE-JWS confusion.** What if a plaintext JWT with `alg: "none"` is nested inside an encrypted JWE? CVE-2026-29000 (pac4j-jwt, CVSS 10.0) - the server decrypts the JWE, gets the nested JWT, and accepts it without signature verification. Full auth bypass.

**Header injection.** Everything from article 6 (kid, jku, x5u, jwk) works for JWE too. But the blast radius is higher: a kid injection in JWE can extract the decryption private key, not just swap out the verification key.

## Where you'll find JWE in the wild

Less common than JWS, but it shows up in serious places: Azure AD Token Encryption, ADFS, OpenID Connect (encrypted ID Tokens), PSD2/Open Banking (PSD2 SCA), Apple APNs. If you see a token with five parts during a pentest, don't scroll past it.

## Tools

- `jwt_tool -E` - JWE token manipulation, algorithm selection
- `PadBuster` - automated padding oracle on AES-CBC
- `ROBOT scanner` / `marvin-toolkit` - Bleichenbacher oracle detection on RSA
- `jose` (panva/jose CLI) - JWE encoding/decoding for manual testing

## JWE attack checklist

1. Decode the header, identify `alg` and `enc`
2. **RSA1_5** - test for Bleichenbacher (different error codes when modifying encrypted_key)
3. **RSA-OAEP** - test for Manger (different errors on invalid OAEP decoding)
4. **ECDH-ES / ECDH-ES+AxxxKW** - invalid curve attack (substitute a point from an invalid curve, observe the response)
5. **A128CBC-HS256** - padding oracle (different errors when modifying ciphertext)
6. **PBES2-*** - send `p2c: 2147483647` and check whether the server hangs
7. **AES-GCM** - check for nonce reuse (collect several JWEs, compare IVs - a match means XOR of plaintexts + GHASH key leak)
8. **zip:DEF** - compression bomb
9. **Algorithm downgrade** - swap `alg` to RSA1_5/PBES2/dir and check whether the server accepts it
10. **Header injection** - kid/jku/x5u in the JWE context (article 6)

## What's next

Coming up: JWT library vulnerability rankings, JWT in OAuth/OIDC, tooling, and pentesting methodology. The foundation is in these ten articles.
