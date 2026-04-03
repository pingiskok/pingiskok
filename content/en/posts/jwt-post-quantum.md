---
title: "JWT, Part 20: Post-Quantum JWT and the Future of Tokens"
date: 2026-04-03T20:20:00+03:00
number: 20
tags: ["jwt", "security", "web", "auth"]
summary: "The series finale. Shor's algorithm breaks every asymmetric JWT algorithm. ML-DSA signatures at 2.4 KB don't fit in a cookie. SD-JWT for selective disclosure. Harvest Now, Decrypt Later — why migrating JWE to post-quantum cryptography is needed now."
---

The series finale. Twenty articles, from parsing a token byte by byte to lattice attacks on ECDSA. In this final article - what's ahead for JWT in the coming years. Post-quantum cryptography, signature sizes, Selective Disclosure JWT - and wrapping up the series.

## Why post-quantum JWT matters

Shor's algorithm completely breaks RSA and ECDSA. Every asymmetric JWT algorithm we've covered in this series - RS256, PS256, ES256, EdDSA - is vulnerable to a sufficiently powerful quantum computer. HS256 loses half its strength due to Grover's algorithm, but 128 bits of quantum security is still enough - provided the key is a full-entropy 256-bit key from a CSPRNG. A weak password from article 7 gets broken by Grover even faster.

Most experts estimate that quantum computers powerful enough to break RSA-2048 and ECDSA P-256 will arrive in the early-to-mid 2030s (estimates vary). NSA's CNSA 2.0 mandates a full transition to post-quantum cryptography by 2035 for national security systems.

This isn't an academic problem "50 years away." This is a problem for the next decade.

## Three new NIST standards (August 2024)

On August 13, 2024, NIST published three final post-quantum cryptography standards, concluding an eight-year selection and analysis process:

**FIPS 203 - ML-KEM** (standardized based on CRYSTALS-Kyber, with modifications) - a key encapsulation mechanism. Replacement for ECDH-ES and RSA-OAEP in JWE. Protects encryption.

**FIPS 204 - ML-DSA** (standardized based on CRYSTALS-Dilithium, with modifications) - a digital signature. Replacement for RS256, PS256, ES256 in JWS. Protects signing.

**FIPS 205 - SLH-DSA** (based on SPHINCS+) - a hash-based signature. The only PQC standard whose security doesn't depend on lattice problems - NIST standardized it for diversity of mathematical assumptions. Slow, but based on minimal assumptions (hash function resistance).

Plus **FIPS 206 - FN-DSA** (based on FALCON) is expected in late 2026 - early 2027 - the most compact post-quantum signatures.

IETF is already working on integration: draft-ietf-cose-dilithium for ML-DSA, draft-ietf-cose-sphincs-plus for SLH-DSA, draft-ietf-cose-falcon for FN-DSA (all three cover both JOSE and COSE despite `cose` in the name).

## Sizes - the main problem

Here's where post-quantum cryptography breaks the usual mold:

```
Algorithm         Signature size   In Base64url

ES256             64 bytes         ~86 chars
RS256             256 bytes        ~342 chars
EdDSA (Ed25519)   64 bytes         ~86 chars
ML-DSA-44         2,420 bytes      ~3.2 KB
ML-DSA-65         3,309 bytes      ~4.4 KB
FN-DSA-512        666 bytes        ~888 chars
SLH-DSA-128s      7,856 bytes      ~10.5 KB
```

ML-DSA-44 (NIST Security Category 2) produces a 2,420-byte signature. For comparison: ES256 - 64 bytes. A 38x difference.

What this means in practice:
- A JWT with ML-DSA-44 weighs ~3.5 KB. The HTTP cookie limit is 4 KB. On the edge.
- A JWT with ML-DSA-65 (NIST Category 3) - ~4.5 KB. Already doesn't fit in a cookie.
- SLH-DSA-128s - ~10.5 KB for the signature alone. No chance.
- FN-DSA-512 - ~888 chars in Base64url. The only PQC that comfortably fits in a cookie. But the standard isn't ready yet.

HTTP headers are creaking too: Nginx defaults to 8 KB per header line (`large_client_header_buffers`). A 4+ KB JWT in `Authorization: Bearer` - that's half the limit for a single token.

## Harvest Now, Decrypt Later

State actors are already intercepting and storing encrypted traffic. When a quantum computer arrives - they'll decrypt everything that was captured.

For JWE (attacks on which we covered in article 10) this is critical: tokens with RSA-OAEP or ECDH-ES containing long-term secrets (medical data, financial transactions) could be exposed in 10-15 years.

For JWS (signatures) the threat is smaller - forging a signature is only useful at the time of the attack. In 10 years a forged token with an expired `exp` is worthless (assuming `exp` is validated and the token is short-lived - and we know from this series that this is far from always the case).

Migration priority: **JWE first, JWS second.**

AWS KMS already supports ML-DSA. Google Cloud KMS - in preview. Tooling is emerging: OpenSSL 3.5 with oqs-provider lets you generate ML-DSA keys from the CLI, liboqs (Open Quantum Safe) - a reference implementation for integration.

## SD-JWT: Selective Disclosure

A parallel JWT evolution, unrelated to the quantum threat. Remember article 2: the JWT payload isn't encrypted, all claims are readable via Base64url decoding. Anyone who sees the token sees ALL the data.

**SD-JWT** (Selective Disclosure JWT, RFC 9901) solves this problem: reveal only the claims you need. Prove you're over 18 without disclosing your date of birth. Show your name without the email. Present the city without the full address.

Technically: each selectively-disclosable claim is replaced by the digest of a Disclosure - a Base64url-encoded JSON array `[salt, claim_name, claim_value]`. The digests are stored in the `_sd` array in the JWT payload. When presenting, the holder appends the needed Disclosures via a tilde separator: `<JWT>~<Disclosure1>~<Disclosure2>~`. The verifier recomputes the hash of each Disclosure and checks it against `_sd`. A Key Binding JWT ties the presentation to a specific holder.

SD-JWT is one of the key formats for the European EUDI Wallet (digital identity wallet). Numerous attack classes are described in RFC 9901 Section 11: recovering low-entropy claims via rainbow tables on hashes, replay without Key Binding, disclosure manipulation, salt entropy guessing, credential forwarding. Each class is a potential vector on a real engagement.

## Hybrid/composite signatures

The transition to PQC won't happen overnight. The main strategy for the transition period: **hybrid (composite) signatures** - simultaneously using a classical and a post-quantum algorithm. One signature = Ed25519 + ML-DSA-44. If in 5 years lattice cryptography turns out to be vulnerable - the classical signature protects you. If a quantum computer appears tomorrow - the PQC signature protects you.

IETF is developing draft-ietf-lamps-pq-composite-sigs for standardization. For JWT this means a new `alg` identifier in JOSE, increased signature size (sum of both), and two verifications instead of one.

For the pentester: hybrid mode creates new attack surfaces. What if the server accepts a token signed with only one of the two algorithms? Partial verification bypass - a classic mistake when implementing composite signatures.

## What to break: PQC attack surface

Post-quantum JWTs aren't in production yet. But the transition period has already begun, and here's what to test:

**Algorithm downgrade.** The server supports both RS256 and ML-DSA-44. An attacker sends a token with `alg:RS256` - does the server accept it? This is the same algorithm confusion from article 4, but in a new context. If the JWKS contains keys of both types without strict binding of the algorithm to the key - downgrade is possible.

**Implementation timing.** PQC implementations are immature. KyberSlash (2024) - a timing vulnerability in the reference implementation of ML-KEM. FN-DSA requires FFT-based Gaussian sampling - a complex operation vulnerable to timing side-channels. That's exactly why NIST delayed FIPS 206. For the pentester: timing tests on PQC endpoints, fingerprinting PQC libraries via response time variance.

**Key confusion.** During the transition period, a JWKS may contain RSA, EC, and ML-DSA keys simultaneously. kid collision between classical and PQC keys, incorrect kid-to-algorithm mapping - the same attacks from articles 5-6, new context.

```bash
# Generate ML-DSA keys via OpenSSL 3.5 + oqs-provider
openssl genpkey -algorithm ml-dsa-44 -out ml-dsa-44-private.pem
openssl pkey -in ml-dsa-44-private.pem -pubout -out ml-dsa-44-public.pem

# Public key size - 1,312 bytes (vs 294 for RSA-2048)
openssl pkey -in ml-dsa-44-public.pem -pubin -text -noout | head -5
```

## What to do now

Preparing for the post-quantum transition - not in 10 years, but now:

**For developers:**

1. **Crypto agility on the server** - algorithms configurable server-side (not by the client! RFC 8725 3.1 prohibits trusting the `alg` from the token - article 19). When ML-DSA-44 is production-ready, replacing RS256 should be a config change.

2. **Prepare JWKS for large keys.** ML-DSA-44 public key - 1,312 bytes (vs 294 bytes for RSA-2048). The JWKS endpoint must serve this without issues.

3. **Increase HTTP header limits.** Nginx `large_client_header_buffers`, Node.js `--max-http-header-size`. A 4+ KB JWT is the new reality.

4. **Consider JWT in HTTP body instead of header.** If the token doesn't fit in `Authorization: Bearer`, pass it in the POST request body.

**For pentesters:**

5. **Assess PQC readiness.** Does the target support crypto agility? Is RS256 hardcoded? Is the JWKS endpoint ready for large keys? Findings: "No algorithm agility - hardcoded RS256", "JWKS endpoint rejects keys > 1 KB". Severity in 2026: LOW-MEDIUM (informational/future risk). For systems with HNDL-sensitive data (healthcare, finance, government): bump to MEDIUM-HIGH.

6. **Frame HNDL risk.** In the report: "JWE tokens encrypted with RSA-OAEP are vulnerable to Harvest Now, Decrypt Later. Intercepted tokens containing [medical records / financial data] may be decryptable within 10-15 years. Recommend migration to ML-KEM for JWE key establishment."

## Wrapping up the series

Twenty articles (almost). From JWT anatomy to post-quantum cryptography.

Here's what we covered:

**Foundation:** why JWT is broken by design, token structure byte by byte, all claims and header parameters.

**Classic attacks:** alg:none, algorithm confusion, kid injection (path traversal, SQLi, command injection), jku/x5u/jwk/x5c header injection, GPU brute-forcing secrets, psychic signatures on Java.

**Cryptography:** HMAC, RSA, ECDSA, nonce reuse, EdDSA. JWE: invalid curve attack, Bleichenbacher oracle, AES-GCM IV reuse, JWE-JWS confusion, padding oracle, PBES2 DoS.

**Ecosystem:** library rankings, OAuth/OIDC token confusion and cross-realm attacks, XSS + JWT = account takeover, lattice attacks on ECDSA nonce, side-channel attacks, fault injection.

**Practice:** hardcoded secrets.

**Defense and the future:** alternatives to JWT, RFC 8725 checklist, post-quantum cryptography.

JWT is not a perfect standard. Dozens of CVEs over ten years. The same bug (algorithm confusion) gets rediscovered every two years. But JWT is embedded in every API on the planet and it's not going anywhere.

Thanks to everyone who read the series all the way through. I'll be happy if you enjoyed the ride!
