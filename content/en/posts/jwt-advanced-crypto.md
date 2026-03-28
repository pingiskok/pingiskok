---
title: "JWT, Part 14: Advanced Crypto Attacks - Lattices, Side-Channels, and Fault Injection"
date: 2026-03-28T10:14:00+03:00
number: 14
tags: ["jwt", "security", "web", "auth"]
summary: "Leak three bits of the nonce from each ECDSA signature — and after 100 signatures you have the full private key. Minerva, TPM-FAIL, EUCLEAK: real attacks on real devices, and what's actually applicable on a web pentest right now."
---

**Table of contents:**
- [Reminder: why the nonce is critical in ECDSA](#reminder-why-the-nonce-is-critical-in-ecdsa)
- [Where nonce bits leak from](#where-nonce-bits-leak-from)
- [Hidden Number Problem: even partial leakage is fatal](#hidden-number-problem-even-partial-leakage-is-fatal)
- [Minerva: leaking the nonce length](#minerva-leaking-the-nonce-length)
- [TPM-FAIL: a VPN server's key in five hours](#tpm-fail-a-vpn-servers-key-in-five-hours)
- [EUCLEAK: cloning a YubiKey](#eucleak-cloning-a-yubikey)
- [Fault injection: Rowhammer and RSA-CRT](#fault-injection-rowhammer-and-rsa-crt)
- [Nonce reuse detection: what to check during a pentest](#nonce-reuse-detection-what-to-check-during-a-pentest)
- [What to do for defense](#what-to-do-for-defense)
- [What's next](#whats-next)

This article builds on the math from article 9. Leak three bits of the nonce from each ECDSA signature - and after 100 signatures you have the full private key. Minerva, TPM-FAIL, EUCLEAK - real attacks on real devices.

On a standard web pentest you won't be building lattices. But three things from this article will come in handy: (1) checking for nonce reuse in ECDSA signatures - that's 10 lines of Python and a genuine attack vector, (2) identifying the crypto library version on the server and cross-referencing it with CVEs, (3) understanding why EdDSA is safer than ECDSA - and when it isn't.

## Reminder: why the nonce is critical in ECDSA

In article 9 I broke down the ECDSA signature formula (ES256 in JWT):

```
s = k^(-1) * (H(m) + r * d) mod n
```

Where `k` is the random nonce and `d` is the private key. I also showed nonce reuse using the Sony PS3 as an example: if `k` repeats across two signatures, the private key falls out of two equations. The `get_r()` function from that article lets you detect repetition - the same `r` in two tokens means the same `k`.

Full nonce reuse is the ideal case. But what if it's not the whole nonce leaking - just a few bits?

## Where nonce bits leak from

Through a **timing side-channel**. Scalar multiplication `k * G` on an elliptic curve runs iteratively - the number of operations depends on the bit length of the nonce (where the most significant bit lands). A nonce with leading zero bits is shorter and runs faster - fewer bits, fewer iterations, less time. The difference is measurable: microseconds on a local machine, but over a network (HTTPS, CDN, load balancer) the noise drowns out the signal by orders of magnitude.

In a JWT context, the leak sources are:
- An IdP signing ES256 JWTs on a server running a vulnerable crypto library
- An HSM/TPM with vulnerable firmware signing tokens
- A smart card signing device-bound JWTs

An attacker collects JWTs with ECDSA signatures and measures server response times. From the timing they classify nonces by bit length, build a lattice, run LLL, and recover the private key. In practice, timing measurements through HTTPS with CDN and load balancers are extremely noisy - a realistic scenario requires either local access or network proximity to the signing server. Identifying the library version and checking against CVEs is a more practical approach for web pentesting.

## Hidden Number Problem: even partial leakage is fatal

In article 9 we recovered a key from nonce repetition - two equations, two unknowns. Here the problem is harder: we don't know the nonce in full, but we know a few bits of each one. This gives us approximate equations rather than exact ones - and solving them requires a different mathematical tool.

The **Hidden Number Problem (HNP)** was formulated by Boneh and Venkatesan in 1996. The core idea: given the ECDSA formula `s = k^(-1)(H(m) + r*d) mod n`, approximate knowledge of `k` lets you write an equation with a single unknown `d`. Each signature with a leaking nonce bit contributes one approximate modular equation. When you have enough equations, the private key turns out to be the unique lattice point closest to the known data.

Think of a lattice as a grid of points in a multidimensional space. You have a point that "almost" coincides with one of the lattice points. The task is to find the nearest one. This is the Closest Vector Problem (CVP), and it's solved by the LLL and BKZ algorithms.

**LLL (Lenstra-Lenstra-Lovász)** is a polynomial-time lattice reduction algorithm that makes basis vectors more orthogonal and shorter. For the practical dimensions that arise in HNP from ECDSA, it's usually enough.

**BKZ (Block Korkine-Zolotarev)** is a more powerful algorithm that uses LLL as a subroutine, additionally solving the Shortest Vector Problem (SVP) in blocks of size `beta`. With `beta = 20-40` it produces better results for harder cases.

How many signatures and bits of leakage you need:
- 3 bits per signature, P-256 curve: ~90 signatures
- 1 bit (just the nonce length), P-256: ~500-2100 signatures
- 5 bits, P-384: ~150-300 signatures

The core of the attack - building the lattice and running LLL - fits in under 100 lines of Python with the `fpylll` library (a full attack also needs signature collection, timing analysis, and nonce classification):

```python
from fpylll import IntegerMatrix, LLL, CVP

# P-256 curve order
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# N - number of collected signatures
# l - number of known most-significant bits of the nonce
# t[i] = r_i * s_i^(-1) mod n (from each signature)
# u[i] = -H(m_i) * s_i^(-1) mod n
# Computing t[i], u[i] from a JWT:
#   r_i, s_i = first and second 32 bytes of the signature (ES256, IEEE P1363 format)
#   z_i = int.from_bytes(sha256(header.payload), 'big')
#   t[i] = (r_i * pow(s_i, -1, n)) % n   # Python 3.8+
#   u[i] = (-z_i * pow(s_i, -1, n)) % n

B = IntegerMatrix(N+1, N+1)
for i in range(N):
    B[i, i] = n                    # curve group order
    B[N, i] = t[i]                 # computed from the signature
B[N, N] = n // (2 ** (l + 1))     # scaling factor: bias bound

LLL.reduction(B)
target = [u[i] for i in range(N)] + [0]
closest = CVP.closest_vector(B, target)
private_key = (closest[N] * (2 ** (l + 1))) % n
```

As of publication there are no documented lattice attacks specifically targeting JWT infrastructure, but all the individual components have been demonstrated separately - vulnerable libraries, timing channels, lattice reduction. The tools: **SageMath** (the de facto standard for lattice cryptanalysis), **fpylll** (Python wrapper around fplll), **minerva-tool** (GitHub crocs-muni/minerva), **lattice-attack** (ready-to-use HNP solvers).

## Minerva: leaking the nonce length

The Minerva research (2019, Ján Jancar et al.) uncovered a timing side-channel in several crypto libraries and smart cards. The leakage is minimal: just the bit length of the nonce. About 50% of nonces have full length (256 bits for P-256), ~25% are one bit shorter, ~12.5% are two bits shorter. Each missing bit means one fewer iteration in scalar multiplication, so the signature computes faster. The attacker measures the time - a fast signature means a short nonce.

Affected implementations (each has its own CVE):
- libgcrypt (CVE-2019-13627)
- wolfSSL (CVE-2019-13628)
- SunEC/OpenJDK (CVE-2019-2894) - the default ECDSA provider for Java, meaning any Java JWT library (Nimbus, Auth0 java-jwt) running on standard SunEC was vulnerable
- Crypto++ (CVE-2019-14318)
- MatrixSSL (CVE-2019-13629) - never patched
- Athena IDProtect and SafeNet eToken smart cards (CVE-2019-15809)

Signatures needed: ~500 in simulation, ~1200 against a real library, ~2100 against a smart card (more timing noise).

**The JWT scenario**: an IdP running on a server with vulnerable libgcrypt (pre-1.8.5), signing JWTs with ES256. An attacker with network proximity to the server (same data center, no CDN) collects ~1200 signatures while measuring response times with microsecond precision. They classify signatures by timing, build the lattice, run LLL - and recover the signing key. Over HTTPS with a CDN, timing accuracy isn't sufficient - on a standard web pentest it's more practical to identify the library version and check it against CVEs.

## TPM-FAIL (CVE-2019-11090, CVE-2019-16863): a VPN server's key in five hours

Timing leakage in Intel fTPM (firmware-based TPM) and STMicro TPM during ECDSA signing. The execution time of `TPM2_Sign` depends on the nonce.

The numbers:
- Intel fTPM, local: ~1300 signatures, under two minutes to recover the key
- Intel fTPM, remote over the network: ~5 hours (collection + analysis)
- STMicro TPM: ~40,000 signatures (hardware TPM is noisier)

The researchers demonstrated remote key extraction from a VPN server in five hours. If a TPM is used to sign JWTs - which gets recommended as "secure key storage" - the same attack applies.

## EUCLEAK (CVE-2024-45678): cloning a YubiKey

A side-channel in the YubiKey 5 Series. Non-constant-time modular inversion (Extended Euclidean Algorithm) in Infineon's library during ECDSA signing. Electromagnetic emissions during signing leak information about the nonce.

Exploitation requires physical access to the YubiKey and an EM probe. Firmware below 5.7 cannot be updated - the device is permanently vulnerable by design (Yubico considers non-updatable firmware a protection against supply chain attacks on the update mechanism itself).

For JWT: if a YubiKey is used as a FIDO2 factor in a system that issues JWT tokens, cloning the YubiKey lets you pass FIDO authentication and receive legitimate JWTs.

## Fault injection: Rowhammer and RSA-CRT

A separate category of attacks - not passive observation of timing, but actively interfering with the signing process.

**Rowhammer on ECDSA.** Bit flips in DRAM. An attacker on a neighboring virtual machine (co-tenant) in the cloud can trigger a fault during signing. One faulty signature (with a corrupted nonce from a bit flip) plus one normal signature gives you key recovery through the same lattice methods. For a standard web pentest, fault injection isn't applicable - this is a threat model for cloud providers and hardware vendors, requiring co-location on the same physical host and hitting a nanosecond-wide window during nonce computation.

Recent work (2025):
- SLasH-DSA: SLH-DSA signature forgery (NIST post-quantum standard, more in article 20) in 1-8 hours via Rowhammer
- ECC.fail: bypassing ECC memory protection through targeted miscorrection on DDR4 servers
- Phoenix: bypassing TRR (Target Row Refresh) on DDR5 in 109 seconds

**RSA-CRT fault (Boneh-DeMillo-Lipton, 1997).** For RS256/PS256 JWTs there's an analogous threat. If an RSA signature is computed using the Chinese Remainder Theorem (as in most implementations) and one of the two intermediate computations gets corrupted by a fault, **a single** faulty signature exposes the private key via GCD. This is simpler than lattice attacks on ECDSA - one signature instead of dozens or hundreds.

One important point: **deterministic signatures don't protect against fault injection**. RFC 6979 and EdDSA (which I recommended in article 9) compute the nonce deterministically from the private key and the message. But if a fault corrupts the state during nonce computation, the same message gets two different nonces across two signing attempts. The attacker induces a fault, gets a faulty signature, compares it to the normal one - and the lattice attack works. Fault injection is actually more dangerous against deterministic schemes: the attacker can force the server to re-sign the same message and compare the outputs.

## Nonce reuse detection: what to check during a pentest

First, confirm the target is using ECDSA. Check the `alg` field in the JWT header: `ES256`, `ES384`, `ES512`. If you see `RS256` or `EdDSA`, the nonce reuse and timing attacks from this article don't apply (though the RSA-CRT fault does apply to RS256).

```python
import base64

def get_r(token):
    sig = base64.urlsafe_b64decode(
        token.split('.')[2] + '==')
    return sig[:32]  # first 32 bytes for ES256 (JWS IEEE P1363 format)

# Collect N tokens from one server
# authenticate_and_get_jwt() - your authentication function
# Watch out for rate limiting: most IdPs cap at ~100-300 req/min
tokens = [authenticate_and_get_jwt() for _ in range(100)]

# Look for matching r-components
rs = {}
for t in tokens:
    r = get_r(t).hex()
    if r in rs:
        print(f"NONCE REUSE DETECTED!")
        print(f"Token 1: {rs[r][:50]}...")
        print(f"Token 2: {t[:50]}...")
        # Two tokens with the same nonce = private key:
        # d = (z1 - z2) * pow(s1 - s2, -1, n) % n
        # where z = SHA256(header.payload), s from the signature
    rs.setdefault(r, t)
```

In practice, nonce reuse in JWT signatures is rare - modern libraries use RFC 6979 (deterministic nonce). But in custom implementations, older libraries, and embedded systems - it's entirely plausible.

## What to do for defense

**EdDSA instead of ECDSA** - deterministic nonces eliminate random nonce reuse and length bias problems. The catch: fault injection against deterministic schemes is more dangerous (two signatures of the same message with different nonces recovers the key). JWT algorithm `EdDSA`, JWK type `OKP`, curve `Ed25519`. Support: jose (Node.js), PyJWT (>=2.4), golang-jwt, nimbus-jose-jwt (Java). If EdDSA isn't available, PS256 (RSA-PSS) eliminates the nonce problem entirely - RSA-PSS has no nonce.

**Hedged signatures** - combining a deterministic nonce (RFC 6979) with additional entropy: `k = HMAC(d, m || random)`. If the RNG is broken, the deterministic fallback kicks in. If there's fault injection, the randomness prevents predictability. Protection against both classes of attacks. Implemented in: Go crypto/ecdsa (>=1.20), BoringSSL, libsodium Ed25519 hedged mode. Specification: draft-irtf-cfrg-det-sigs-with-noise (CFRG). For deterministic schemes, an additional safeguard is sign-twice-and-compare: sign twice, compare results - if they differ, it's a fault, and neither signature gets released.

**Constant-time libraries** - eliminate timing side-channels. Specifically: OpenSSL (>=1.1.0), BoringSSL, libsodium, ring (Rust), Go crypto/ecdsa (>=1.20). To verify constant-time behavior: dudect, ctgrind, timecop. Minerva and EUCLEAK hit implementations that were believed to be constant-time - trust but verify.

**Key rotation** - limits the window for lattice attacks. If the library is constant-time, the number of signatures is irrelevant. If you suspect timing leakage, rotate every 24-72 hours through a JWKS endpoint with a `kid` in the JWT header. Overlap period: publish both the current and previous key simultaneously so already-issued tokens can still be validated.

**Timing monitoring** - if a histogram of signing times shows multiple distinct peaks (clusters around different values) instead of one, that points to nonce length leakage. Relevant for HSM/TPM-backed signing where you can't inspect the source code. If detected - rotate the key immediately.

## What's next

Across fourteen parts we've accumulated dozens of PoCs and techniques - from `alg:none` to lattice attacks. In the next article I'll round up the tools: jwt_tool, hashcat, Burp JWT Editor, and one-liners for quick checks. A minimal three-tool setup - and an extended kit for harder cases.
