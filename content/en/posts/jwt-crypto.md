---
title: "JWT, Part 9: JWT Cryptography for Hackers"
date: 2026-03-28T10:09:00+03:00
number: 9
tags: ["jwt", "security", "web", "auth"]
summary: "The math behind HMAC, RSA, and ECDSA from an attacker's perspective: why Sony lost the PlayStation 3 to a single repeated number, and how leaking just a few nonce bits is enough to recover a private key."
---

**Table of contents:**
- [HMAC: why two passes](#hmac-why-two-passes)
- [RSA: RS256 vs PS256](#rsa-rs256-vs-ps256)
- [ECDSA: one signature, one nonce](#ecdsa-one-signature-one-nonce)
- [How Sony lost the PlayStation 3](#how-sony-lost-the-playstation-3)
- [Applying this to JWT](#applying-this-to-jwt)
- [EdDSA: solves the nonce problem by design](#eddsa-solves-the-nonce-problem-by-design)
- [Even a partial nonce leak is dangerous](#even-a-partial-nonce-leak-is-dangerous)
- [Summary](#summary)
- [What's next](#whats-next)

In 2010, Sony lost control of the PlayStation 3 - because of a single repeated number in their cryptographic code. In 2019, researchers extracted a VPN server's private key in five hours by leaking just a few bits. Both attacks have one thing in common: understanding the math hiding under the hood of digital signatures.

In articles 3 through 8 we attacked JWT. Now we'll break down **why** those attacks work - the math behind HMAC, RSA, and ECDSA, and where it breaks.

## HMAC: why two passes

HS256 is HMAC-SHA256. The formula:

```
HMAC(K, msg) = SHA256(
  (K xor opad) ||
  SHA256((K xor ipad) || msg)
)
```

Two SHA256 passes. Two different padding values: ipad (each byte of the key XOR'd with 0x36) and opad (each byte XOR'd with 0x5C). Looks like unnecessary complexity. Why not just do `SHA256(key || message)`?

Because the naive version is vulnerable to a **length extension attack**. SHA-256 is built on the Merkle-Damgård construction - think of a hash as a pipeline: each block of input gets processed in sequence, and the output of each block becomes the initial state for the next. The final hash is just the pipeline's state after the last block. Knowing that state and the input length, an attacker can "continue the pipeline" with new data - and compute `SHA256(K || msg || padding || extension)` without knowing K. If HMAC were the naive `SHA256(key || message)`, an attacker could append extra data to the payload (say, `,"role":"admin"`) and compute a valid MAC without the secret.

The two passes of HMAC break this attack. The inner hash (`SHA256((K xor ipad) || msg)`) produces an intermediate value of fixed length - 32 bytes. The outer hash (`SHA256((K xor opad) || inner_hash)`) "seals" the result: it includes the secret key (via opad), and without knowing the key an attacker can't continue or reproduce the outer hash.

HMAC's security is mathematically proven (Bellare, Canetti, Krawczyk, 1996): it reduces to the requirement that the hash's **compression function** is a good pseudorandom function (PRF) - indistinguishable from random when the key is unknown. This property doesn't require collision resistance. That's why HMAC-MD5 has no known practical attacks, even though MD5 collisions have been findable since 2004. That said, NIST deprecated MD5 (SP 800-131A) and RFC 6151 recommends against HMAC-MD5 in new protocols - so for JWT this is an academic footnote, not a call to action.

As covered in article 7, RFC 7518 requires an HS256 key of at least 256 bits (32 bytes), and RFC 8725 tightens this further: the key must come from a cryptographically secure random generator (CSPRNG), not a human-readable password. The string `"secret"` is 6 bytes, capping out at 2^48 combinations for a random 6-byte brute-force. But the actual entropy is even lower - it's a dictionary word, and a dictionary attack finds it in fractions of a second, as we saw in article 7 with hashcat. If the key is 6 truly random bytes from a CSPRNG, 2^48 is correct. If it's `"secret"` - forget about 2^48.

The extreme case is an empty key (0 bytes). It gets padded to 64 zero bytes. `K' XOR ipad` = `ipad`, `K' XOR opad` = `opad`. HMAC becomes a deterministic function of the message alone - anyone can compute the "signature" without the secret.

## RSA: RS256 vs PS256

JWT supports two RSA signature variants, and the difference between them matters.

**RS256 (PKCS#1 v1.5)** is a deterministic signature. The same message with the same key always produces the same signature. The internal format:

```
EM = 0x00 || 0x01 || [0xFF repeated as padding] || 0x00 || DigestInfo
```

DigestInfo contains the message hash. No random component at all. RS256 has a security proof in the random oracle model (Jonsson, 2002), but not in the standard model - the model without idealized assumptions about the hash function. In practice, this means RS256 has worked for 30 years and nobody has broken it with strong keys, but if an attack is found tomorrow, there's no unconditional mathematical argument for why it should be impossible.

**PS256 (RSA-PSS)** is a randomized signature. Every signing operation adds a random salt (32 bytes for PS256, 48 for PS384, 64 for PS512). Result: a **different** signature every time for the same message.

```
M' = 0x00*8 || Hash(msg) || salt
EM = maskedDB || Hash(M') || 0xBC
```

Bellare and Rogaway proved PSS security in 1996 - also in the random oracle model, but with a tighter reduction. The difference between RS256 and PS256 isn't "proven vs unproven" - both have proofs in the random oracle model. PS256 got its proof earlier and with better parameters, plus has constructive advantages.

**Why this matters for attacks:**

First, RS256 is deterministic: sign the same message twice and you get identical signatures. An attacker can detect this and use it for analysis. PS256 is randomized - every signature is unique.

Second, RS256 has historically been vulnerable to the Bleichenbacher signature forgery attack (Bleichenbacher, 2006) with a small public exponent (e=3) and a weak DigestInfo parser. The idea: the attacker crafts a value whose cube root, when the padding is parsed, looks like a valid signature. If the parser doesn't check all the DigestInfo bytes all the way to the end, "garbage" in the tail goes unnoticed. PSS is immune to this by design - its padding is verified fully, including salt recovery and mask checking.

Separately, recall the algorithm confusion attack from article 4. That attack isn't a property of RS256 or PS256 - it's an architectural problem: a single `verify()` function that picks the algorithm from the token header. The attacker changes `alg` from any asymmetric algorithm (RS256, PS256, ES256) to HS256, and the public key (a PEM string) gets fed in as the HMAC secret. Exploiting this requires the exact PEM file format, because HMAC operates on its raw bytes as the key. If the library doesn't pin the algorithm, the vulnerability works regardless of which RSA variant you're using.

## ECDSA: one signature, one nonce

ECDSA is the digital signature algorithm I covered in the context of Psychic Signatures (article 8). Let's go deeper now.

The ECDSA signature: `s = k^(-1) * (Hash(msg) + r * d) mod n`, where:
- `k` - a random nonce (a one-time number)
- `d` - the private key
- `r` - the x-coordinate of the point `k*G` on the curve (G is the generator point)
- `n` - the order of the generator point (number of points in the subgroup; for P-256 this is ~2^256)

The critical rule: **every signature requires a unique random nonce k**. If k is known, the private key can be computed trivially - just rearrange the signature formula:

```
s = k^(-1) * (Hash(msg) + r * d) mod n
# Multiply both sides by k:
s * k = Hash(msg) + r * d
# Isolate d:
r * d = s * k - Hash(msg)
d = r^(-1) * (s * k - Hash(msg)) mod n
```

Three lines of algebra - and the private key is yours.

## How Sony lost the PlayStation 3

December 29, 2010. The 27th Chaos Communication Congress (27C3). The fail0verflow group takes the stage and demonstrates the recovery of Sony's private keys used to sign PlayStation 3 firmware. One cryptographic mistake - and the entire security system collapsed.

Sony used ECDSA to sign firmware. And they used **the same value of k** for every signature. A fixed nonce instead of a random one.

Two signatures with the same nonce k share the same `r` (because `r` is computed from `k*G`, and k is constant). fail0verflow spotted this and applied straightforward math:

```
s1 = k^(-1) * (z1 + r*d)     # z1 = Hash(message1)
s2 = k^(-1) * (z2 + r*d)     # z2 = Hash(message2)

# Subtract one from the other:
s1 - s2 = k^(-1) * (z1 - z2)

# Recover k:
k = (z1 - z2) * (s1 - s2)^(-1) mod n

# Knowing k, recover the private key:
d = (s1*k - z1) * r^(-1) mod n
```

A compromised key can't be "revoked" on millions of existing consoles. Sony had to rebuild their security system from scratch in new firmware, adding extra layers of verification. One fixed nonce value - and the private key falls out of two signatures.

## Applying this to JWT

If a server signs JWTs with ES256 and uses a random number generator that allows nonce repetition, the same scenario applies. You intercept ES256-signed JWT tokens. Each token contains a signature (r, s) in its last 64 bytes. Find two tokens with the same r component - the nonce repeated, and the key is recoverable. Here's a function to check:

```python
import base64

def get_r(token):
    sig = base64.urlsafe_b64decode(
        token.split('.')[2] + '==')
    return sig[:32]  # first 32 bytes for ES256

# Collect N tokens, compare r values:
# If get_r(token1) == get_r(token2):
#   nonce was reused, key is recoverable
```

In practice, nonce reuse in JWT signatures is rare - modern libraries use RFC 6979 (deterministic nonce). RFC 6979 computes `k = HMAC(private_key, hash(message))`: different messages get different nonces (because `hash(message)` differs), while the same message always gets the same nonce - which gives you the same signature, but without creating any information leak. In custom implementations and older libraries, though, nonce reuse is a realistic scenario.

One quick test: sign the same message twice with the same key. If the signatures match - the library uses RFC 6979 (deterministic nonce). If they differ - it's using a random nonce, and you should check the generator quality.

Keep the `get_r()` function in mind - we'll need it in article 14 when we get to lattice attacks on ECDSA.

## EdDSA: solves the nonce problem by design

Ed25519 (the EdDSA algorithm for Curve25519) computes the nonce **deterministically**:

```
r = SHA-512(prefix || message)
```

Where `prefix` is the second 32 bytes of `SHA-512(private_seed)`. The nonce is determined by the private key and the message. It can't repeat (different messages produce different r values). It can't be predicted (you need the private key). Nonce reuse and random generator bias are impossible by construction, because a random generator isn't involved in signing at all.

But "by design" doesn't mean "invulnerable in general". A deterministic nonce doesn't protect against fault injection: if a hardware fault (Rowhammer, voltage glitching) corrupts state during the computation of `SHA-512(prefix || message)`, the same message ends up with two different nonces - and we're back to the nonce reuse scenario. More on this in article 14.

In JWT, EdDSA is used with `"alg": "EdDSA"` and `"crv": "Ed25519"` in the JWK. As of 2026, it's the most secure choice for new systems among available signature algorithms: Ed25519 is faster than ECDSA P-256 in software implementations, and an entire class of nonce attacks (reuse, generator bias, timing leaks during generation) simply doesn't exist.  Signature size is 64 bytes - same as ES256.

## Even a partial nonce leak is dangerous

Full nonce reuse is the ideal case. But even leaking **a few bits** of the nonce from each signature is enough to recover the key.

If a random generator has a bias and nonces are systematically short by a few bits, this creates an information leak. Think of each leaked bit as an approximate equation with an unknown (the private key). One equation isn't enough, but from hundreds or thousands of approximate equations you can reconstruct the unknown exactly - mathematically this is known as the Hidden Number Problem, and it's solved with lattice reduction algorithms (LLL/BKZ). A detailed breakdown with code is coming in article 14.

Three real-world examples:

- **Minerva** (CVE-2019-15809): nonce bit-length leak via timing on Athena SCS smart cards. Around 500 signatures in lab conditions, ~2100 on real cards - and the private key is recovered.
- **TPM-FAIL** (CVE-2019-11090): timing attack on Intel fTPM. VPN server key extracted in five hours.
- **EUCLEAK** (CVE-2024-45678): electromagnetic side-channel attack on YubiKey 5 Series. ECDSA key extraction via non-constant-time modular inversion.

All three attacks require physical access or nanosecond-precision measurements - not typical for a standard web pentest against JWT. But they demonstrate the principle: any information leak about the nonce is a path to the private key.

## Summary

| Algorithm               | Type         | Nonce       | Proof (ROM)              | Primary threat                                              |
| ----------------------- | ------------ | ----------- | ------------------------ | ----------------------------------------------------------- |
| **HS256** (HMAC)        | Symmetric    | None        | Yes (PRF)                | Weak key -> hashcat in seconds (article 7)                  |
| **RS256** (PKCS#1 v1.5) | Asymmetric   | None        | Yes (Jonsson '02)        | Bleichenbacher forgery; algorithm confusion (article 4)     |
| **PS256** (RSA-PSS)     | Asymmetric   | Salt        | Yes (Bellare-Rogaway '96)| -                                                           |
| **ES256** (ECDSA)       | Asymmetric   | Random      | Yes                      | Nonce reuse/leak; Psychic Signatures (article 8)            |
| **EdDSA** (Ed25519)     | Asymmetric   | Deterministic| Yes                     | Fault injection (article 14)                                |

More randomness during signing means a wider attack surface. HMAC and RS256 are deterministic. ECDSA demands a perfect nonce for every signature, and any weakness means full compromise. EdDSA eliminates the problem by making the nonce deterministic.

## What's next

All the attacks so far have targeted JWS - signed tokens. The payload is visible to anyone, and the signature guarantees integrity. But there's also JWE - encrypted tokens. Five parts instead of three, two layers of encryption - and an attack where the server decrypts arbitrary ciphertext for you, leaking the correct answer one byte at a time. Next up, we enter JWE territory.
