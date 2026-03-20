---
title: "JWT, Part 1: Why JWT is the most broken standard on the web"
date: 2026-03-20T18:00:00+03:00
number: 1
tags: ["jwt", "security", "web", "auth"]
summary: "70+ CVEs over ten years. A bug from 2015 still fires in 2026. Let's figure out why JWT stubbornly remains broken."
---

If I'm not too lazy, all articles from the screenshot below will be published.

<img src="/images/jwt-series-plan.png" alt="JWT article series plan" style="max-width: 260px;">

**Table of contents:**
- [Why JWT was invented in the first place](#why-jwt-was-invented-in-the-first-place)
- [JWT is not a single standard](#jwt-is-not-a-single-standard)
- [The fundamental design flaw](#the-fundamental-design-flaw)
- [Statistics](#statistics)
- [Three things that make JWT a juicy target](#three-things-that-make-jwt-a-juicy-target)
- [Why this won't get fixed](#why-this-wont-get-fixed)
- [What's next](#whats-next)

JSON Web Token is a token format for authentication and authorization on the web. A compact string of three parts separated by dots that the server issues to the client after login, and the client sends back with every request. The server verifies the signature, reads the contents - and knows who's making the request.

Sounds simple. In practice - it's the most exploited standard in web security.

In 2015, Tim McLean found a way to forge any user's token in any JWT-based service. One field swap in the header - and the server accepts the forged token as genuine. Eleven years later, in 2026, the exact same bug was found in the Hono framework (CVE-2026-22817, CVSS 8.2). Same bug, eleven years.

Let's figure out why JWT stubbornly remains broken.

## Why JWT was invented in the first place

Before JWT, web applications used server-side sessions. User logs in, server creates a session, stores it in Redis or memory, returns a cookie with a session ID. On every request, the server looks up the session by ID to verify who's making the request.

This worked while applications lived on a single server. But when the microservices era arrived, things got painful. Ten microservices, each needing to know who's making the request. Route them all to a single Redis for sessions? Or give each one a copy? Both options scale poorly.

JWT solves this problem. The token contains all the information inside itself: who the user is, what permissions they have, when the token expires. The server signs this data with a cryptographic key. Any microservice can verify the signature and read the token - no database call, no shared storage. This is called stateless authentication.

A beautiful idea. But it has problems baked in that we'll discuss throughout this series.

## JWT is not a single standard

When people say "JWT", they mean one format. In reality, it's a stack of six RFCs called JOSE (JSON Object Signing and Encryption): JWT defines the token format and claims, JWS describes signatures, JWE handles encryption, JWK defines key format, JWA specifies algorithms, and RFC 8725 provides security recommendations. Six specifications, hundreds of pages. Complexity breeds bugs.

## The fundamental design flaw

Here's the key problem I'll keep coming back to throughout the entire series.

The token itself tells the server how to verify it. The JWT header contains an `alg` field - "verify my signature using algorithm X". It's as if a key told a lock "open without checking".

An attacker changes `alg` to `none` - the server skips verification. Changes `RS256` to `HS256` - and the public key becomes the password. I'll show in detail how this works in parts 3 and 4. For now, remember the key point: **trusting the algorithm from the token header is an architectural mistake**, and it's what causes most JWT vulnerabilities.

## Statistics

70+ CVEs over ten years. Breaking them down by category paints a grim picture. Algorithm confusion and `alg:none` are classics found again and again. But here's what's surprising: 17% of recent CVEs from 2024-2026 aren't even cryptographic bugs. They're just hardcoded secrets.

Cisco IOS XE (CVE-2025-20188, CVSS 10.0) signed JWTs with the string `notfound`. Literally the word "notfound" as the signing secret. Dpanel (CVE-2025-30206, CVSS 9.8) - the secret right in the source code on GitHub. A perfect 10 vulnerability because the developer couldn't be bothered to generate a random string.

## Three things that make JWT a juicy target

**The token is self-contained.** With server-side sessions, if they're compromised you can delete the session from Redis - and access is revoked. JWT doesn't work that way. No server-side storage means no instant revocation. Stolen token - use it until `exp` expires. Client-side logout won't help because the server doesn't know the token was stolen.

**Base64 is not encryption.** The JWT payload is encoded, not encrypted. Anyone can read the contents without a single key:

```bash
echo "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcnVzZXIifQ" | base64 -d
```

Result: `{"sub":"admin","role":"superuser"}`. Roles, names, email addresses, identifiers - all in plain text. The signature guarantees integrity (nobody tampered with the data), but not confidentiality (anyone can read it). JWE exists - an encrypted variant of JWT - but in practice 99% of tokens in the wild are JWS, meaning signed but not encrypted.

**Secrets can be brute-forced offline.** JWT contains everything needed for an offline attack: the message (header and payload) and the signature. One intercepted token - and hashcat on a GPU churns through 150 million passwords per second. The secret "password" cracks instantly. You don't need access to the server. You need one token.

## Why this won't get fixed

JWT is deeply embedded in OAuth 2.0, OpenID Connect, and virtually every API. Alternatives exist: PASETO, for example, removes the `alg` field from the token, eliminating an entire class of attacks. But PASETO's ecosystem is a thousand times smaller. JWT libraries exist for every language, documentation is everywhere, Stack Overflow is flooded with examples. Switching to an alternative means rewriting infrastructure.

Fun fact: Google uses regular cookies and server-side sessions for browser sessions, not JWT. If the largest company on the planet decided JWT for sessions is a bad idea, maybe it's worth listening.

But JWT isn't going anywhere. Millions of applications use it right now, and new ones appear every day. Which means - you need to understand how to break it. And how to defend it.

## What's next

This series is a practical guide to attacking JWT. We'll dissect the token down to the last byte, break down every attack vector with concrete PoCs, and by the end of the series you'll have a complete JWT pentest methodology.

In the next article, we take a real token and dissect it like a pathologist: header, payload, signature, Base64url, claims. After reading it, you'll be able to read tokens with your bare eyes.
