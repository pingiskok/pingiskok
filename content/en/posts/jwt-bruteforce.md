---
title: "JWT, Part 7: Brute-forcing JWT secrets on GPU"
date: 2026-03-21T18:06:00+03:00
number: 7
tags: ["jwt", "security", "web", "auth"]
summary: "JWT contains everything for an offline attack: message and signature. Hashcat on GPU runs through 150 million HS256 per second. The secret 'secret' is cracked in 2 seconds."
---

**Table of contents:**
- [Why JWT is unique for brute-force](#why-jwt-is-unique-for-brute-force)
- [How to determine if the algorithm is symmetric](#how-to-determine-if-the-algorithm-is-symmetric)
- [Hashcat mode 16500](#hashcat-mode-16500)
- [Speeds on specific hardware](#speeds-on-specific-hardware)
- [jwt.secrets.list - wordlist by Wallarm](#jwtsecretslist---wordlist-by-wallarm)
- [jwt_tool - built-in cracker](#jwt_tool---built-in-cracker)
- [What the RFC says](#what-the-rfc-says)
- [Testing checklist](#testing-checklist)
- [What's next](#whats-next)

So far we've been substituting algorithms (articles 3-4) and injecting header parameters (articles 5-6). All these attacks exploit logical errors in token processing. But what if the logic is correct, the signature is verified properly - but the secret is simply weak?

## Why JWT is unique for brute-force

Here's what makes JWT an ideal target for offline attacks: **all the necessary material is contained in a single token**.

When you brute-force a password on a web form, each attempt is a request to the server. Rate limiting, account lockout, CAPTCHA. A thousand attempts per second is the ceiling.

With JWT, everything is different. As I showed in the second article, a token consists of three parts: `header.payload.signature`. Header and payload are the message. Signature is the HMAC of that message with the secret key. You have both the message and the signature. All that's left is to find the key. And **the server isn't needed** for this. All computations happen locally, on your GPU.

## How to determine if the algorithm is symmetric

First step - decode the header and check the algorithm:

```bash
echo -n "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null
```

If you see `"alg": "HS256"`, `"HS384"` or `"HS512"` - the algorithm is symmetric (HMAC). Brute-force is possible. If `"RS256"`, `"ES256"`, `"PS256"` - asymmetric. Nothing to brute-force, the private key doesn't appear in the token. For asymmetric algorithms you need other approaches: algorithm confusion (article 4) or psychic signatures (article 8).

HS256 is the most popular JWT algorithm. It's the only one required for implementation by RFC 7518 (besides `none`). Most tutorials, Stack Overflow examples, and default configurations use HS256. Which means - most JWTs in the wild are vulnerable to brute-force if the secret is weak.

## Hashcat mode 16500

Hashcat is a tool for GPU-based password and key cracking. Mode 16500 is HMAC-SHA256 for JWT.

```bash
# Save the token to a file
echo -n "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYWRtaW4iOmZhbHNlfQ.signature_here" > jwt.txt

# Dictionary attack
hashcat -a 0 -m 16500 jwt.txt \
  /usr/share/wordlists/jwt.secrets.list

# With mutation rules - hashcat modifies each word
# from the dictionary (adds numbers, changes case, etc.)
hashcat -a 0 -m 16500 jwt.txt wordlist.txt \
  -r /usr/share/hashcat/rules/best64.rule

# Mask: all 6-character lowercase combinations
hashcat -a 3 -m 16500 jwt.txt ?l?l?l?l?l?l

# Mask: 8 characters, letters + digits + special characters
hashcat -a 3 -m 16500 jwt.txt ?a?a?a?a?a?a?a?a
```

## Speeds on specific hardware

Here are real numbers to show just how fast this is:

- **RTX 4090 (GPU):** ~150 million HS256/sec
- **RTX 3090 (GPU):** ~100 million HS256/sec
- **i9-13900K (CPU):** ~5 million HS256/sec
- **jwt_tool on Python:** ~50 thousand HS256/sec

And here's what these speeds mean for cracking a secret on an RTX 4090:

- 6 characters, lowercase only [a-z]: 308 million variants = **2 seconds**
- 8 characters, lowercase only [a-z]: 208 billion = **23 minutes**
- 8 characters, letters + digits [a-zA-Z0-9]: 218 trillion = **17 days**
- 32 bytes from a cryptographically secure generator: you'll **never** crack it

The difference between "secret" and 32 random bytes is the difference between 2 seconds and infinity.

## jwt.secrets.list - wordlist by Wallarm

The first thing I run when testing JWT is a dictionary attack with the specialized wordlist `jwt.secrets.list`, compiled by the Wallarm team. It contains real secrets from leaks, default configs, and CVEs:

- `secret`, `password`, `123456` - classics
- `your-256-bit-secret` - default from jwt.io that developers copy to production
- `django-insecure-*` - framework default secrets
- `changeme`, `test`, `development` - secrets that were supposed to be "changed later"
- `notfound` - that very secret from CVE-2025-20188 (Cisco IOS XE, CVSS 10.0)

A dictionary attack with this wordlist takes a fraction of a second and often works. If it doesn't help - add mutation rules, then masks. And only then move to full brute-force.

## jwt_tool - built-in cracker

If you don't have a GPU or hashcat - jwt_tool has a built-in cracking function:

```bash
python3 jwt_tool.py "$TOKEN" -C \
  -d /usr/share/wordlists/jwt.secrets.list
```

Runs on CPU, speed is orders of magnitude lower than hashcat, but for dictionary attacks against weak secrets it's more than sufficient.

## What the RFC says

RFC 7518 Section 3.2 contains a normative requirement: the key for HS256 **MUST** be at least 256 bits (32 bytes). For HS384 - 384 bits. For HS512 - 512 bits.

RFC 8725 strengthens this: the key **MUST NOT** be a human password. Only a cryptographically secure random number generator (CSPRNG). That means `openssl rand -base64 32`, not `mysupersecretkey`.

Reality: developers set `"secret"`, `"password"`, `process.env.JWT_SECRET || "fallback"` (where fallback is the default value if the environment variable isn't set). And the secret `"fallback"` ends up in production.

## Testing checklist

1. Intercepted a JWT with HS256 - immediately into hashcat with jwt.secrets.list
2. Nothing found? jwt.secrets.list + best64.rule (mutation rules)
3. Check default secrets for the specific framework (Next.js, Django, Spring Boot)
4. If .env file is accessible (via LFI, git leak, docker inspect) - look for JWT_SECRET, SECRET_KEY, SIGNING_KEY
5. Docker image available? `docker save image | tar -xO | grep -ri "secret\|jwt\|signing"`
6. Nothing found? Mask for 8 characters [a-zA-Z0-9] - 17 days on a single GPU

## What's next

We've been breaking HMAC (this post) and RSA via algorithm confusion (article 4). ECDSA remains. In the next article - Psychic Signatures: a bug in Java where a signature of all zeros passes verification for any message, with any key. Five lines of Python - and you're admin on any Java service running Java 15-18.
