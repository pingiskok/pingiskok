---
title: "JWT, Part 11: JWT Libraries - a Leakiness Ranking"
date: 2026-03-28T10:11:00+03:00
number: 11
tags: ["jwt", "security", "web", "auth"]
summary: "Which library is running on the backend determines which attacks will actually land: a ranked breakdown of the most vulnerable JWT libraries, a tier classification from recommended to dangerous, and passive fingerprinting techniques that identify the stack from the token header alone."
---

**Table of contents:**
- [Why the library matters more than the algorithm](#why-the-library-matters-more-than-the-algorithm)
- [Top 5 most vulnerable](#top-5-most-vulnerable)
- [Tier ranking: what to use and what to rip out](#tier-ranking-what-to-use-and-what-to-rip-out)
- [Fingerprinting: how to identify the library from the token](#fingerprinting-how-to-identify-the-library-from-the-token)
- [What this means for pentesting](#what-this-means-for-pentesting)
- [What's next](#whats-next)

17 million downloads per week. Four CVEs (a fifth was withdrawn by NVD). That's jsonwebtoken for Node.js - the most popular JWT library in the world. Why should you, as a pentester, care which library is running on the backend? Because the library determines which attacks will actually land.

## Why the library matters more than the algorithm

In articles 3-10 I walked through the attacks: alg:none, algorithm confusion, kid injection, psychic signatures. Every single one of them works **on some libraries but not others**. Algorithm confusion (article 4) only works where the `verify()` function trusts the algorithm from the token header. Psychic signatures (article 8) - only on Java 15-18. Kid injection (article 5) - only where kid is used to read a file, run a SQL query, or execute a command.

Identify the library and you immediately narrow down your attack surface. No need to waste time on algorithm confusion if the backend runs jose/panva, which is architecturally immune to it.

## Top 5 most vulnerable

The Top 5 is ranked by the number and severity of historical CVEs. The tier ranking further down evaluates something different: current architecture, patch turnaround, and maintenance activity. A library can appear in both lists - a buggy history doesn't mean a buggy present.

**1. python-jose (Python) - irregular maintenance, critical bugs left open for months**

One unpatched CVE, two fixed in v3.4.0 (February 2025):

- CVE-2024-33663 (CVSS 7.5): algorithm confusion via ECDSA keys. The same attack from article 4, but with EC keys instead of RSA. **Fixed in 3.4.0.**
- CVE-2024-33664 (CVSS 7.5): JWE compression bomb - a nested JWE inflates during decompression, DoS. **Fixed in 3.4.0.**
- CVE-2025-61152: `alg:none` bypass with no verification. The attack from article 3 works straight out of the box. **No patch.**

FastAPI used to recommend python-jose in its official documentation. If you see `from jose import jwt` in a project - that's a gift. Algorithm confusion (article 4) and alg:none (article 3) work on unpatched versions.

**2. jsonwebtoken (Node.js) - 4 CVEs, security rewrite in v9**

CVE-2022-23529 (RCE via secretOrPublicKey) was **withdrawn by NVD** in January 2023 - doesn't count. That leaves four real ones.

Tim McLean's 2015 disclosure (CVE-2015-9235) hit a lot of libraries, including jsonwebtoken - we covered this in articles 3-4. Prior to version 9, the library accepted `alg:none` by default and allowed algorithm confusion.

Three CVEs dropped at once in 2022:
- CVE-2022-23539: insecure key type validation
- CVE-2022-23540: `alg:none` bypass, but only when three conditions align simultaneously - `algorithms` isn't specified in `verify()`, a `key` is passed, and the token is unsigned. Not a simple "default alg:none".
- CVE-2022-23541: algorithm confusion via key retrieval function

Version 9.0.0 was a major security rewrite. Unsigned tokens banned, minimum RSA key size enforced at 2048 bits, algorithm confusion closed off. But if a project is still on v8.x - all the holes are wide open.

```bash
# Check the version in the project
npm ls jsonwebtoken 2>/dev/null || grep '"jsonwebtoken"' package-lock.json
```

**3. Authlib (Python) - 4 Critical CVEs in 2026**

Four bugs - two in JWE, two in JWS/OIDC:

CVE-2026-27962 (CVSS 9.1): JWK Header Injection. Same attack as CVE-2018-0114 from article 6. When `key=None` is passed to the deserialization function, the library takes the key from the `jwk` header in the token itself. An attacker signs the token with their own private key, embeds the corresponding public key in the header - and the server accepts it as valid.

CVE-2026-28490: Bleichenbacher Oracle in JWE RSA1_5, which we covered in article 10. Authlib would intercept the decryption result and check the CEK length before AES-GCM. Two different exceptions (`InvalidTag` vs `ValueError`) created a padding oracle. ~14,500 requests - and the CEK is recovered.

CVE-2026-28498: Fail-Open OIDC Hash Binding - under certain conditions, the hash binding check against the token is skipped entirely.

CVE-2026-28802: `alg:none` signature bypass in v1.6.5-1.6.7. Yes, the same attack from article 3 - in 2026.

Authlib made the Top 5 because of the combination of JWE bugs and a fresh alg:none bypass. The JWS side (except v1.6.5-1.6.7) works fine.

**4. PyJWT (Python) - 3+ CVEs, blocklist approach bypassed twice**

Two algorithm confusion cases via blocklist bypass:
- CVE-2017-11424: the blocklist checked for `BEGIN PUBLIC KEY` but missed `BEGIN RSA PUBLIC KEY` (PKCS#1 format). Fixed in 1.5.1.
- CVE-2022-29217: the blocklist was updated, but missed OpenSSH ECDSA keys (`ecdsa-sha2-nistp256`). Fixed in 2.4.0.
- CVE-2026-32597: fresh CVE.

The problem is architectural: PyJWT took the approach of "block dangerous key formats". Every new format means a new bypass. An allowlist would have been more reliable.

**5. Nimbus JOSE+JWT (Java) - 6+ CVEs, including some familiar ones**

Effectively the standard for the Java ecosystem (Spring Security, Microsoft MSAL):
- CVE-2017-16007: invalid curve attack in ECDH-ES - **full private key recovery**. From article 10.
- CVE-2023-52428: PBES2 DoS - `p2c: 999999999` causes CPU exhaustion. Also from article 10.
- CVE-2025-53864: Nested JSON DoS.
- And a handful of smaller CVEs.

Nimbus is here because of the sheer volume of historical CVEs. But every bug was closed quickly, the library architecture is solid, and maintenance is active - which is exactly why it also sits in Tier 1 below. Many past CVEs don't equal a dangerous library today if patches ship within days.

## Tier ranking: what to use and what to rip out

The tier ranking evaluates **current** security: API architecture (whether dangerous mistakes are even possible to make), patch turnaround, and maintenance activity. This isn't a historical metric - a library with 10 closed CVEs and a solid architecture is more trustworthy than one with 0 CVEs and a dead repository.

**Tier 1 - recommended:**

`jose/panva` (Node.js) - the gold standard. Zero dependencies, Web Crypto API (plus node:crypto for server-side tasks), `alg:none` implemented as a separate `UnsecuredJWT` class that requires explicit opt-in. Algorithm confusion is architecturally impossible: the key type determines the set of allowed algorithms. A few CVEs over its history: padding oracle in AES-CBC-HMAC (CVE-2021-29443 - a crypto attack, not DoS), PBES2 DoS (CVE-2022-36083), JWE decompression DoS (CVE-2024-28176). All patched quickly.

`jjwt` (Java) - builder pattern API. Algorithm confusion is impossible by design: `signWith(key, alg)` hard-binds the key to the algorithm.

`nimbus-jose-jwt` (Java) - powerful, full JOSE stack. 6+ CVEs historically (see Top 5 above), but all patched quickly. Strict algorithm enforcement via JWSKeySelector.

**Tier 2 - acceptable with configuration:**

`jsonwebtoken v9+` (Node.js) - solid after the security rewrite, but you need to explicitly specify `algorithms` in `verify()`.

`PyJWT` (Python) - fine after the fixes, but always specify `algorithms=["RS256"]` when decoding.

`golang-jwt` (Go) - reliable, clean CVE history (only CVE-2025-30204 - DoS, CVSS 7.5). But `WithValidMethods()` is opt-in. Without it, it accepts the algorithm from the token.

`go-jose v4` (Go) - 5+ historical CVEs (including a critical invalid curve attack and CVE-2025-27144), but from v4 the algorithm is required at parse time.

`Microsoft.IdentityModel.JsonWebTokens` (.NET) - the replacement for the deprecated `System.IdentityModel.Tokens.Jwt`. Watch the defaults: `ValidAlgorithms=null` means "all algorithms allowed", and `ClockSkew=5 minutes` is substantially more than the typical 60 seconds. Also CVE-2024-21319 - JWE decompression DoS.

**Tier 3 - dangerous:**

`python-jose` - remove immediately. Migrate to joserfc or PyJWT.

`Authlib` (JWE side) - the JWS part is fine (except v1.6.5-1.6.7 with alg:none), but JWE is dangerous.

`System.IdentityModel.Tokens.Jwt` (.NET) - deprecated. Microsoft itself recommends migrating away from it.

## Fingerprinting: how to identify the library from the token

You don't need access to the source code. Look at the JWT itself.

**By signature size** - this identifies the algorithm (which is already visible in the `alg` header, but the size confirms the header hasn't been swapped):
- ~342 Base64url characters (256 bytes) - RS256 with RSA 2048
- ~86 characters (64 bytes) - ES256 or EdDSA (Ed25519). Ed448 is 114 bytes (~152 characters).
- ~43 characters (32 bytes) - HS256
- 5 parts separated by dots - JWE (article 10)
- Empty third part - `alg:none` (article 3)

**By field order in the header** - this one can actually identify the library:

```bash
echo "$TOKEN" | cut -d. -f1 | tr -- '-_' '+/' | \
  awk '{while(length%4)$0=$0"=";print}' | base64 -d 2>/dev/null
```

PyJWT puts `typ` first: `{"typ":"JWT","alg":"HS256"}`. jsonwebtoken puts `alg` first: `{"alg":"HS256","typ":"JWT"}`. jose/panva may omit `typ` entirely. Passive fingerprinting - works without a single request to the server.

**By the issuer claim - identifies the IdP, which points to the likely stack:**

Knowing the IdP isn't the same as knowing the library. Keycloak issues the token, but your backend - running Python, Go, or Node.js - validates it. Still, the IdP narrows the stack: Azure AD probably means .NET, Keycloak probably means Java, Firebase probably means Node.js.

```bash
echo "$TOKEN" | cut -d. -f2 | tr -- '-_' '+/' | \
  awk '{while(length%4)$0=$0"=";print}' | base64 -d 2>/dev/null \
  | python3 -c "
import json,sys
p=json.load(sys.stdin)
iss=p.get('iss','')
if 'auth0.com' in iss: print('Auth0')
elif 'okta.com' in iss: print('Okta')
elif 'microsoftonline' in iss or 'sts.windows.net' in iss: print('Azure AD')
elif '/realms/' in iss: print('Keycloak')
elif 'cognito-idp' in iss: print('AWS Cognito')
elif 'securetoken.google' in iss: print('Firebase')
else: print(f'Custom: {iss}')
"
```

Every IdP leaves characteristic markers in the claims:
- Auth0: `gty` claim (in native profile) + issuer `*.auth0.com`
- Okta: `cid`, `uid` claims + issuer `*.okta.com/oauth2/*`
- Azure AD: `tid`, `oid` claims + issuer `login.microsoftonline.com` (v2.0) or `sts.windows.net` (v1.0)
- Keycloak: `realm_access` claim with a nested roles object + issuer `*/realms/*`. Plus a non-standard `typ: "Bearer"` in the payload (not the header!)
- AWS Cognito: claims prefixed with `cognito:` + issuer `cognito-idp.*.amazonaws.com`
- Firebase: `firebase` claim with a `sign_in_provider` object

**By error format** - send an invalid token and watch the response:

In production, errors are usually hidden behind a generic 401, but dev/staging environments can be more verbose:

```bash
curl -s -H "Authorization: Bearer invalid" \
  https://target/api/ | head -5
# Java stack trace = Nimbus/jjwt
# "JsonWebTokenError: jwt malformed" = jsonwebtoken (Node.js)
# {"detail":"..."} in Django format = djangorestframework-simplejwt (wrapper around PyJWT)
```

## What this means for pentesting

Once you've identified the library, pick your attack vector:

- **python-jose** - alg:none (article 3), algorithm confusion (article 4) on unpatched versions, JWE compression bomb
- **jsonwebtoken v8** - alg:none, algorithm confusion
- **Authlib + JWE** - Bleichenbacher oracle (article 10), JWK header injection (article 6), alg:none in v1.6.5-1.6.7
- **PyJWT < 2.4** - algorithm confusion via non-standard key formats
- **Nimbus < 9.37.2** - PBES2 DoS (article 10)
- **jose/panva** - harder here; focus on logical bugs in the application, not the library itself

A Tier 1 library doesn't mean immunity. The library can be perfect, but the developer might forget to specify `algorithms` when calling `verify()`. Or set `verify_signature=False` "for debugging" and never remove it.

## What's next

JWT on its own is one thing. JWT inside OAuth 2.0 with a dozen microservices, three IdPs, and five token types is something else entirely. Next up - token confusion, cross-service relay, DPoP, and real CVEs in Keycloak and AWS.
