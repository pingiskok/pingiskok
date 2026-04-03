---
title: "JWT, Part 19: RFC 8725 - the checklist nobody reads"
date: 2026-04-03T20:19:00+03:00
number: 19
tags: ["jwt", "security", "web", "auth"]
summary: "RFC 8725 — fifteen JWT security rules from the standard's authors. For each — which attack from the series it prevents, which CVEs exist, and why ~65% of applications don't check aud. Plus three new rules from the 2026 bis update."
---

**Table of contents:**
- [3.1 Algorithm Verification](#31-algorithm-verification)
- [3.2 Use Appropriate Algorithms](#32-use-appropriate-algorithms)
- [3.3 Validate All Cryptographic Operations](#33-validate-all-cryptographic-operations)
- [3.4 Validate Cryptographic Inputs](#34-validate-cryptographic-inputs)
- [3.5 HMAC Key Entropy](#35-hmac-key-entropy)
- [3.6 Avoid Compression](#36-avoid-compression)
- [3.7 Use UTF-8](#37-use-utf-8)
- [3.8 Validate Issuer and Subject](#38-validate-issuer-and-subject)
- [3.9 Validate Audience](#39-validate-audience)
- [3.10 Do Not Trust Received Claims](#310-do-not-trust-received-claims)
- [3.11 Explicit Typing](#311-explicit-typing)
- [3.12 Mutually Exclusive Validation](#312-mutually-exclusive-validation)
- [RFC 8725bis (2026)](#rfc-8725bis-2026)
- [Final checklist](#final-checklist)
- [What's next](#whats-next)

We've been attacking. Now - how to defend. RFC 8725 (JSON Web Token Best Current Practices) lays out fifteen JWT security rules: twelve original and three from the 2026 bis update. A compact document: do this, don't do that. In my experience, most applications violate at least one rule. And for most of those violations there's a CVE we've already covered.

![RFC 8725 map](/images/rfc8725-map.png)

## 3.1 Algorithm Verification

**Rule:** the library MUST allow specifying acceptable algorithms server-side. Each key maps to exactly one algorithm. Never trust `alg` from the token header.

**Attack prevented:** algorithm confusion (article 4) and alg:none (article 3). If the server pins `algorithms=["RS256"]`, swapping to HS256 or none is impossible.

**CVE:** CVE-2015-9235 (jsonwebtoken), CVE-2026-22817 (Hono, 11 years later!), CVE-2024-33663 (python-jose).

```python
# CORRECT
jwt.decode(token, key, algorithms=["RS256"])

# VULNERABLE - algorithm taken from the token
header = jwt.get_unverified_header(token)
jwt.decode(token, key, algorithms=[header["alg"]])
```

## 3.2 Use Appropriate Algorithms

**Rule:** use only current algorithms. `none` - don't use. RSA1_5 (RSAES-PKCS1-v1_5) for JWE - don't use.

**Attack prevented:** alg:none (article 3), Bleichenbacher oracle on RSA1_5 (article 10), nonce reuse in ECDSA (article 9).

**2026 recommendation:** EdDSA for signatures (deterministic nonce eliminates nonce reuse - article 9). ECDSA - only with deterministic nonce per RFC 6979 (best practice from article 9, not an RFC 8725 requirement). RSA-OAEP for encryption (resistant to Bleichenbacher).

## 3.3 Validate All Cryptographic Operations

**Rule:** Nested JWT (JWE inside JWS or vice versa) requires validation at every level. Decrypted a JWE - verify the signature of the inner JWS.

**Attack prevented:** authentication bypass via nested tokens.

**CVE:** CVE-2026-29000 (pac4j-jwt, CVSS 10.0) - decrypted JWE, inside was a PlainJWT with `alg=none`. Signature was never verified. Authentication as any user. One layer of nesting - and the entire security stack collapsed.

## 3.4 Validate Cryptographic Inputs

**Rule:** for ECDH-ES you MUST validate that the point from `epk` lies on the correct elliptic curve.

**Attack prevented:** Invalid Curve Attack from article 10. Without validation, an attacker substitutes a point from a weak curve, and over dozens of requests recovers the private key via CRT (Chinese Remainder Theorem).

**CVE:** affected go-jose, node-jose, jose2go, Nimbus, jose4j (all in 2016-2017). Check: `y^2 == x^3 + ax + b (mod p)` for every incoming point.

## 3.5 HMAC Key Entropy

**Rule:** an HS256 key MUST be at least 256 bits from a CSPRNG. Human-readable passwords are FORBIDDEN.

**Attack prevented:** GPU brute-force (article 7) and hardcoded secrets (article 17).

```bash
# Correct: 256 bits of entropy from CSPRNG (64 hex chars = 32 bytes)
python3 -c "import secrets; print(secrets.token_hex(32))"

# Wrong
JWT_SECRET="password123"       # hashcat finds it in seconds
JWT_SECRET="notfound"           # CVE-2025-20188, CVSS 10.0
JWT_SECRET="your-256-bit-secret"  # jwt.io default
```

hashcat on an RTX 4090: ~4 billion HS256 per second (mode 16500). The string "secret" against the rockyou.txt wordlist - instant. 32 random bytes from a CSPRNG - never.

## 3.6 Avoid Compression

**Rule:** don't use `"zip":"DEF"` in JWE.

**Attack prevented:** side channel via compressed ciphertext size (analogous to CRIME/BREACH, but at the JWE payload level, not TLS). Practical risk - decompression bomb: an attacker creates a JWE with data that compresses by a factor of thousands, the server decompresses it and exhausts memory (more details in 3.15 bis).

See `zip` in a JWE header - that's a finding for the report.

## 3.7 Use UTF-8

**Rule:** only UTF-8 for encoding the JOSE Header and JWT Claims Set.

**Attack prevented:** parser differential via different encodings. If one component encodes the header in UTF-16 while another expects UTF-8, the signature is verified against one set of bytes while the payload is interpreted from another. Recall the Unicode traps from article 2: Cyrillic "a" and Latin "a" are visually identical but are different characters to the parser.

## 3.8 Validate Issuer and Subject

**Rule:** the server MUST verify that the signing key belongs to the specified `iss`. Without this, an attacker signs with THEIR key using `"iss":"auth.megabank.example"`, and the server accepts it. The `sub` claim must also be validated: format, user existence, and consistency with the request context.

**CVE:** CVE-2026-23552 (Apache Camel camel-keycloak, not Keycloak itself) - cross-realm tokens. Camel didn't verify the binding of `iss` to specific keys. We covered this in article 12.

## 3.9 Validate Audience

**Rule:** a token for Service A must not be accepted by Service B. The `aud` claim MUST be verified.

**Attack prevented:** cross-service relay from article 12. The most common RFC 8725 violation - in my experience, roughly 65% of applications don't check `aud`.

```python
jwt.decode(token, key, algorithms=["RS256"],
    audience="https://api.payments.megabank.example")
```

## 3.10 Do Not Trust Received Claims

**Rule:** `kid`, `jku`, `x5u` and other header parameters are attacker-controlled. Sanitize them, don't follow blindly.

**Attack prevented:** all attacks from articles 5-6. kid - SQLi, path traversal, command injection. jku/x5u - SSRF + key substitution. CVE-2018-0114 (node-jose) - trusting JWK from the header. CVE-2026-27962 (Authlib) - same mistake, 8 years later.

## 3.11 Explicit Typing

**Rule:** use the `typ` header to distinguish JWT types. An Access Token MUST have `typ: "at+jwt"` (RFC 9068).

**Attack prevented:** token confusion from article 12. Without `typ`, ID Token and Access Token are indistinguishable. An attacker substitutes one for the other.

## 3.12 Mutually Exclusive Validation

**Rule:** when a single IdP issues access, ID, and refresh tokens, validation rules must guarantee mutual exclusion. You can't use a single `verify_token()` function for all token types.

**Attack prevented:** a refresh token gets accepted as an access token. Or vice versa.

## RFC 8725bis (2026)

A standards update. Three new rules for attacks discovered after 2020, plus changes to two existing sections:

**Update 3.1:** algorithm allowlists MUST be case-insensitive (`"rs256"` vs `"RS256"` - both must be handled the same way). The blocklist approach is prohibited - allowlists only.

**Update 3.12:** mandatory `typ` checking added for separating JWE and JWS. Defense against format confusion: a JWE-wrapped PlainJWT must not be accepted as a signed JWT (CVE-2026-29000).

**3.13 Limit PBES2 Iterations.** `p2c` in JWE defines the number of hashing iterations. An attacker sets `p2c=999999999` - the server goes into CPU exhaustion for minutes. CVE-2023-52428 (Nimbus), CVE-2022-36083 (jose/panva). Limit: no more than 1,200,000 iterations (2x the OWASP recommendation of 600K for HMAC-SHA-256).

**3.14 Check JWT Format Type.** JWT in compact serialization contains only `A-Za-z0-9-_.`. Curly braces, quotes, and other characters in Base64url parts - reject. Defense against format confusion: substituting JSON instead of Base64url.

**3.15 Limit Decompression.** JWE with `zip` and no limit on decompressed data size - decompression bomb. CVE-2024-33664 (python-jose), CVE-2024-21319 (System.IdentityModel). Limit: 250 KB for decompressed payload.

## Final checklist

Check every item. An unchecked item = an attack vector.

**Warning:** RFC 8725 doesn't cover all aspects of JWT security. Token storage (article 13), key rotation (article 17), revocation - these are outside the scope of the standard but critical during real pentests.

**RFC 8725 (sections 3.1-3.12):**

1. **3.1** alg pinning server-side (`algorithms=["RS256"]`), alg from the token is ignored
2. **3.2** no none, no RSA1_5, only current algorithms
3. **3.3** nested JWT: signature verified at every nesting level
4. **3.4** EC point validation: incoming point lies on the declared curve
5. **3.5** HMAC key >= 256 bits from CSPRNG, not a human password
6. **3.6** no zip in JWE (side-channel + decompression bomb)
7. **3.7** UTF-8 only for JOSE header and claims
8. **3.8** iss bound to specific keys, sub validated
9. **3.9** aud checked - specific URI, not a wildcard
10. **3.10** kid/jku/x5u sanitized, not trusted blindly
11. **3.11** typ checked (at+jwt for access tokens, RFC 9068)
12. **3.12** token types separated: refresh ≠ access ≠ ID token

**RFC 8725bis (2026):**

13. **3.1+** algorithm allowlist case-insensitive
14. **3.12+** typ mandatory for separating JWE/JWS formats
15. **3.13** p2c limit <= 1,200,000 for PBES2
16. **3.14** only valid Base64url characters in compact serialization
17. **3.15** JWE decompression limit <= 250 KB

**Outside RFC 8725, but critical during pentests:**

18. exp/nbf/iat checked (`verify_exp: True` - don't disable it)
19. token not in localStorage (HttpOnly cookie or Authorization header)
20. keys rotated, kid for versioning (article 5)

Most common violations on real engagements: `aud` unchecked (~65%), weak HMAC secret, missing `typ`, disabled `exp` verification. Full testing methodology - article 16. Tools for each item - article 15.

## What's next

The series finale. In the next article - what awaits JWT in the future. Post-quantum cryptography: ML-DSA signatures at 2.4 KB that don't fit in a cookie. SD-JWT - selective disclosure. And the series wrap-up: key takeaways from twenty articles.
