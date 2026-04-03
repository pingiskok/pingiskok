---
title: "JWT, Part 18: What Instead of JWT - PASETO, Macaroons, Opaque Tokens, and Server-Side Sessions"
date: 2026-04-03T20:18:00+03:00
number: 18
tags: ["jwt", "security", "web", "auth"]
summary: "JWT isn't perfect — 70+ CVEs over ten years. We break down the alternatives: PASETO without the alg field, Macaroons with unique attenuation, opaque tokens with instant revocation, Google/Netflix server-side sessions. For each — what to break on a pentest."
---

**Table of contents:**
- [Server-side sessions: don't write them off](#server-side-sessions-dont-write-them-off)
- [Opaque tokens + Token Introspection](#opaque-tokens--token-introspection)
- [PASETO - JWT without the alg field](#paseto---jwt-without-the-alg-field)
- [Macaroons - the superpower of attenuation](#macaroons---the-superpower-of-attenuation)
- [The hybrid approach of 2026](#the-hybrid-approach-of-2026)
- [When JWT is the right choice](#when-jwt-is-the-right-choice)
- [Comparison table](#comparison-table)
- [Takeaway](#takeaway)
- [What's next](#whats-next)

We've spent 17 articles breaking JWT. From `alg:none` to lattice attacks on ECDSA nonces. 70+ CVEs over ten years. The logical question: what's the alternative?

## Server-side sessions: don't write them off

Google doesn't use JWT for browser authentication. They use server-side sessions. Opaque session ID in an HttpOnly cookie. User data in Redis. Netflix uses encrypted cookies plus an internal Passport format (HMAC-protected protobuf). GitHub stores sessions in a signed Rails cookie (`_gh_sess`). Implementation details differ, but the idea is the same: the token contains no data, the server holds state.

Why server-side sessions still work:

**Instant revocation.** Ban a user - delete the session from Redis. Instant. With JWT you either wait until exp or build a blacklist (which essentially brings you back to the stateful model JWT was supposed to eliminate).

**Protection against XSS token theft.** Opaque session ID in an HttpOnly cookie. JavaScript can't read the cookie via `document.cookie`. Compare that to JWT in localStorage from article 13 - one line of JavaScript and full account takeover. But this is **not** XSS immunity. As I showed in article 13 (the section on HttpOnly cookies): same-origin XSS allows authenticated requests via fetch/XHR - the browser automatically attaches the HttpOnly cookie. The attacker doesn't steal the session ID but acts on behalf of the victim directly. Session riding, not session theft - but the result is the same.

**CSRF - a fundamental tradeoff.** Cookies are sent by the browser automatically with every request. That's what makes sessions convenient - and it's what makes them vulnerable to CSRF. JWT in the Authorization header is immune to CSRF: the browser doesn't attach it automatically. Switch from JWT to cookies - you get a CSRF problem. Mitigations: `SameSite=Lax` (default since Chrome 80), `Secure`, `__Host-` prefix, CSRF tokens. Article 13: "For full protection you need a CSRF token even with SameSite" (defense in depth).

**Session fixation.** A classic session vulnerability that doesn't apply to JWT. The attacker sets a known session ID before the victim authenticates. The victim logs in - if the application doesn't regenerate the session ID after login, the attacker uses their ID for hijacking. Defense: regenerate the session ID on every privilege level change.

**Always fresh data.** User's role changed? The session reflects the change instantly. JWT stores a snapshot of claims at issuance time - the role won't update until exp.

"Doesn't scale!" - it scales. Redis Cluster handles millions of sessions. Google and Netflix have no scaling problems. But Redis is unauthenticated by default, data isn't encrypted at rest. SSRF to `redis://` = dump all sessions. Compromise Redis = all sessions at once (worse than stealing a single JWT).

## Opaque tokens + Token Introspection

The most practical JWT alternative within existing OAuth infrastructure. Doesn't require a new token format, doesn't require new libraries.

Instead of a JWT access token, the Authorization Server issues an opaque string - a random identifier with no structure. The Resource Server doesn't parse or validate the token itself. Instead, it sends a request to the Authorization Server via **Token Introspection** (RFC 7662):

```
POST /introspect HTTP/1.1
Host: auth.megabank.example
Content-Type: application/x-www-form-urlencoded

token=dGhpcyBpcyBhbiBvcGFxdWUgdG9rZW4&
token_type_hint=access_token
```

The response contains claims, but they're stored on the server, not in the token:

```json
{
  "active": true,
  "sub": "admin",
  "scope": "read write",
  "exp": 1711700000
}
```

Spring Authorization Server, Keycloak, and Auth0 support this out of the box. Switching from JWT to opaque tokens is often a single line in the IdP config.

**What to break:** the introspection endpoint is a high-value target. SSRF to it = validating arbitrary tokens. Missing Resource Server authentication on introspection requests = response spoofing. Cache poisoning introspection responses = extending the life of a revoked token. No offline validation - a single point of failure.

## PASETO - JWT without the alg field

Remember the fundamental flaw from the first article. The token itself tells the server how to verify the signature. The `alg` field in the header is the root of algorithm confusion (article 4), the root of `alg:none` (article 3).

**PASETO** (Platform-Agnostic Security Tokens) is an alternative format designed specifically to eliminate this flaw. No `alg` field. No header with parameters. The token version rigidly determines all cryptographic algorithms:

```
v4.public. - Ed25519 signature, fixed
v4.local.  - XChaCha20 + BLAKE2b-MAC (Encrypt-then-MAC), fixed
```

Four PASETO versions: v1 (RSA+AES-CTR, deprecated), v2 (Ed25519+XChaCha20-Poly1305, deprecated), v3 (P-384+AES-256-CTR-HMAC, **NIST/FIPS-compliant**, current), v4 (Ed25519+XChaCha20+BLAKE2b, recommended). If you encounter `v2.local.` or `v3.public.` - those are legitimate PASETO tokens, not errors. v3 is critical for government/regulated environments that require FIPS compliance.

Algorithm confusion via the alg field? Impossible - the field doesn't exist. `alg:none`? No such field. But "impossible" only applies to `alg`. Version downgrade (v1 instead of v4 when multiple versions are supported) and purpose confusion (local vs public) are real attack surfaces.

PASETO supports `kid` in the footer. The structure is `v4.public.<payload>.<footer>` where the footer can contain `{"kid":"..."}`. PASERK (Platform Agnostic Serialized Keys) standardizes the kid format. The critical difference from JWT: kid doesn't affect algorithm selection. But kid injection (SQLi, path traversal) from article 5? Possible through the footer - if the server uses kid unsafely.

```python
import pyseto
from pyseto import Key

key = Key.new(version=4, purpose="public",
              key=private_key_pem)
token = pyseto.encode(
    key,
    payload=b'{"sub":"admin","exp":"2026-04-01T00:00:00+00:00"}',
    footer=b'{"kid":"key-v4-001"}'
)
# Result: b"v4.public...." - the version is baked into the format
```

PASETO's problems: the ecosystem is 1000x smaller than JWT's. Not a single major IdP (Auth0, Okta, Keycloak, Azure AD) supports PASETO. The IETF draft expired in 2022. And the main thing: PASETO is stateless, which means it has **the same revocation problem** as JWT. Instant revocation? No. Blacklist? The same crutch as with JWT.

**What to break:** version downgrade (force the server to accept v1 instead of v4), purpose confusion (local vs public), footer parsing vulnerabilities (kid injection, information disclosure in the footer), claim validation bugs (missing exp or aud checks).

## Macaroons - the superpower of attenuation

Google Research, 2014. Macaroons can do something JWT fundamentally cannot: **attenuate privileges without contacting the server**.

An analogy: imagine a building access pass. With JWT you get a pass that says "access to all floors" and you can't restrict it - claims are locked by the signature. Want to give someone a pass for "first floor only"? Go back to security for a new pass.

With Macaroons you take your "all floors" pass and **stamp it yourself** with "first floor only." The recipient can add more: "9 AM to 5 PM only." Then: "room 101 only." Anyone can **restrict** rights, but no one can **expand** them. The server's secret key isn't needed for this.

Technically this works through an HMAC chain. The server creates a root macaroon:

```
mac0 = HMAC(root_secret, identifier)
```

Adding a restriction (caveat) doesn't require knowing the root_secret - only the result of the previous HMAC:

```
mac1 = HMAC(mac0, "floor == 1")          # restricted to floor 1
mac2 = HMAC(mac1, "time < 17:00")        # added a time restriction
```

Each subsequent HMAC is computed from the previous one, forming a cryptographic chain. The server recomputes the chain from root_secret and compares the result. Expanding rights is impossible: you'd need to "rewind" the HMAC backward.

These are **first-party caveats** - restrictions the server verifies itself. Macaroons also support **third-party caveats**: delegating verification to an external service. "This macaroon is valid if payment-service confirms payment." A unique capability that neither JWT nor PASETO has.

Fly.io built their authorization on Macaroons. Lightning Network (LND) uses Macaroons for **RPC authentication**: admin.macaroon, invoice.macaroon, readonly.macaroon - three access levels for the node API. Micropayments work through HTLCs and payment channels, not through Macaroons. The L402 protocol (formerly LSAT) combines Macaroons + Lightning invoices for pay-per-request APIs, but that's a separate protocol.

There's no standardization - no RFC, no IETF draft. Libraries exist, but not for every language.

**What to break:** a Macaroon is a bearer token: steal it and you can use it. There's no built-in `exp` - if no time-based caveat is added, the macaroon lives forever. Compromise of the root key = all derived macaroons are compromised (worse than a single JWT, because attenuated macaroons are handed out to third parties). Caveat bypass: if the server incorrectly parses the caveat string, you can circumvent the restriction. Third-party caveat discharge theft: intercepting the discharge macaroon = access. Scope escalation via reorder or injection in the caveat string.

## The hybrid approach of 2026

In practice, what I see most often in 2026 is a hybrid architecture:

**Server-side session + short-lived JWT.**

1. The browser stores a session ID in an HttpOnly cookie (protection against XSS theft, but needs SameSite + CSRF token)
2. On API requests, the frontend obtains a short-lived JWT (5 minutes) through a session-to-JWT exchange endpoint
3. The JWT is passed to microservices, which validate it without a central store
4. Need revocation? Invalidate the session. The next session-to-JWT exchange returns an error. Maximum delay - 5 minutes (the lifetime of the current JWT)

This gives you the best of both worlds: stateless validation for microservices and fast revocation at the session gateway level.

**What to break:** the session-to-JWT exchange endpoint is the highest-value target. Compromise = JWT generation for any session. Race conditions on parallel exchange requests. 5 minutes after revocation isn't "a small delay." In 5 minutes an attacker with an admin JWT can: exfiltrate data, create backdoor accounts, modify ACLs. PCI-DSS and HIPAA may require immediate termination of privileged access. Critical operations (password changes, money transfers) must verify the session in real time, not rely on JWT claims. Stale claims in microservices: the role is revoked, but the current JWT still says `"role":"admin"`.

## When JWT is the right choice

JWT is **good** for:
- Cross-domain authorization (OAuth 2.0, OIDC)
- Microservices with no direct channel to the IdP
- Short-lived tokens (5-15 minutes) + refresh token
- API keys for machine-to-machine communication
- Federated identity (multiple IdPs)

JWT is **bad** for:
- Browser sessions in monolith applications
- Storing in localStorage (article 13)
- Cases where instant revocation is required
- Long-lived tokens without a refresh flow

## Comparison table

| Criterion | JWT | PASETO | Macaroons | Server-side sessions | Opaque + Introspection |
|----------|-----|--------|-----------|---------------------|----------------------|
| Instant revocation | No (blacklist) | No (blacklist) | No (no exp) | Yes | Yes |
| XSS theft (localStorage) | Yes | Yes | N/A | No (HttpOnly) | No (HttpOnly) |
| CSRF risk | No (Authorization header) | No (Authorization header) | Depends | Yes (cookie) | Depends |
| Algorithm confusion | Yes | No (no alg) | N/A | N/A | N/A |
| Offline validation | Yes | Yes | Yes | No | No |
| Attenuation | No | No | Yes | N/A | N/A |
| Ecosystem | Massive | Minimal | Minimal | Mature | OAuth stack |
| Standard | RFC 7519 | Expired draft | None | None (framework) | RFC 7662 |

## Takeaway

JWT isn't perfect. 70+ CVEs. Fundamental design flaws. But it's baked into every API on the planet and isn't going anywhere. Alternatives exist: PASETO eliminates algorithm confusion, Macaroons offer unique attenuation, opaque tokens give you instant revocation without a new format, and server-side sessions remain a solid choice for browsers. But none of these alternatives have JWT's ecosystem.

For a pentester: encounter PASETO - look for version downgrade, purpose confusion, kid injection in the footer. Encounter Macaroons - look for caveat bypass, missing time-based caveats, discharge theft. Encounter a session+JWT hybrid - hit the exchange endpoint and exploit the 5-minute window after revocation. Encounter opaque tokens - look for SSRF to the introspection endpoint. Every alternative has its own attack surface.

The right approach: understand JWT's limitations, choose the right tool for the specific job, and if you do use JWT - configure it properly (that's the next article on RFC 8725).

## What's next

We've been attacking. Now - how to defend. RFC 8725 lays out fifteen specific JWT security rules from the authors of the standard (twelve original plus three from the 2026 bis update). For each rule I'll show which attack from our series it prevents.
