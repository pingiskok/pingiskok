---
title: "JWT, Part 2: JWT Anatomy - dissecting the token byte by byte"
date: 2026-03-20T18:01:00+03:00
number: 2
tags: ["jwt", "security", "web", "auth"]
summary: "Taking a real token and dissecting it like a pathologist: header, payload, signature, Base64url, claims, edge cases."
---

**Table of contents:**
- [Three chunks separated by dots](#three-chunks-separated-by-dots)
- [Why Base64url and not regular Base64](#why-base64url-and-not-regular-base64)
- [Full example: creating a JWT from JSON to the final string](#full-example-creating-a-jwt-from-json-to-the-final-string)
- [Dissecting the header](#dissecting-the-header)
- [Dissecting the payload and claims](#dissecting-the-payload-and-claims)
- [What a hacker sees when decoding someone's JWT](#what-a-hacker-sees-when-decoding-someones-jwt)
- [Edge cases: where JWT breaks unexpectedly](#edge-cases-where-jwt-breaks-unexpectedly)
- [Decoding JWT with Python](#decoding-jwt-with-python)
- [What's next](#whats-next)

In the previous article, I showed why JWT is broken by design. Now let's take a real token and dissect it like a pathologist - down to the last byte.

## Three chunks separated by dots

JWT is three Base64url strings glued together with dots:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzAwMDAwMDAwfQ.signature
|__________header___________|.|_________________________payload__________________________|.|___sig___|
```

Header. Payload. Signature. The dot (byte 0x2E) was chosen as a delimiter because it's not part of the Base64url alphabet. This means a simple `split('.')` is guaranteed to correctly split the token into three parts - no edge cases.

## Why Base64url and not regular Base64

Regular Base64 uses the characters `+`, `/`, and `=`. The problem is that each of them has special meaning in URLs: `+` turns into a space when parsing parameters, `/` is a path separator, and `=` is used to separate keys and values in query strings.

Base64url solves this with three substitutions:

- `+` is replaced with `-` (hyphen)
- `/` is replaced with `_` (underscore)
- `=` (padding at the end) is simply removed

Here's how it looks with a concrete example. The string `"foobar"` encodes identically in both variants: `Zm9vYmFy`. But the string `"fo"` in standard Base64 gives `Zm8=`, while in Base64url it's `Zm8` (no padding). A string containing bytes with certain values might produce `a+b/c==` in Base64 and `a-b_c` in Base64url.

**How padding works and why it's removed.** Base64 encodes data in groups of 3 bytes into 4 characters. If the input data isn't a multiple of three bytes, `=` or `==` is appended to pad it to four characters. In JWT, padding isn't needed because during decoding, the string length unambiguously determines how many `=` to add: if length mod 4 equals 2 - add `==`, if 3 - add `=`, if 0 - add nothing.

This is important to understand because Base64url decoding will come up in every subsequent article. From here on, I'll just write "decode" - meaning specifically Base64url.

## Full example: creating a JWT from JSON to the final string

Let's walk through the entire path from JSON data to a finished token. This will help you understand exactly what gets signed and how.

**Step 1. Create the JSON header:**

```json
{"alg":"HS256","typ":"JWT"}
```

`alg` specifies the signing algorithm (HMAC-SHA256, symmetric - one secret for both signing and verification). `typ` says "this is a JWT" - the field is optional, but almost everyone includes it.

**Step 2. Encode the header in Base64url:**

```
{"alg":"HS256","typ":"JWT"}  -->  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

**Step 3. Create the payload with user data:**

```json
{"sub":"user123","role":"admin","exp":1700000000}
```

**Step 4. Encode the payload in Base64url:**

```
{"sub":"user123","role":"admin","exp":1700000000}  -->  eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzAwMDAwMDAwfQ
```

**Step 5. Form the signing input.**

Concatenate the encoded header and encoded payload with a dot:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzAwMDAwMDAwfQ
```

This exact string is what gets signed - not the original JSON, but the already-encoded data. This is a critically important point: if you reconstruct the JSON with a different key order (e.g., `{"typ":"JWT","alg":"HS256"}` instead of `{"alg":"HS256","typ":"JWT"}`), the Base64url will be different, and the signature will change. JSON is formally unordered, but the order gets fixed at the moment of encoding.

**Step 6. Compute the signature:**

```
HMAC-SHA256(signing_input, secret_key)
```

The result is 32 bytes, which are encoded in Base64url.

**Step 7. Assemble the final token:**

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzAwMDAwMDAwfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Three chunks separated by dots. The entire token is an ASCII string, every character from the alphabet `A-Z a-z 0-9 - _ .`. URL-safe, fits in an HTTP header, can be placed in a query string.

## Dissecting the header

The minimal header is `{"alg":"HS256"}`. The `alg` field is mandatory. But besides `alg` and `typ`, the JWT header can contain parameters, each of which is potentially vulnerable:

- **kid** - key identifier. An arbitrary string the server uses to find the right key. SQL Injection, path traversal, command injection - all through kid. I'll cover this in article 5.
- **jku** - URL where the server should download the verification key. SSRF and key substitution. Article 6.
- **jwk** - public key embedded directly in the token header. Key substitution. Article 6.
- **x5u** - URL for downloading an X.509 certificate. Similar to jku - SSRF. Article 6.
- **x5c** - X.509 certificate chain directly in the token. Self-signed certificate. Article 6.

Each of these parameters is a separate attack vector. Essentially, the entire JWT header is an attack surface.

## Dissecting the payload and claims

The payload is ordinary JSON. As I said in the first article, it's encoded but not encrypted. Want to read someone's token - just decode it:

```bash
echo -n "eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzAwMDAwMDAwfQ" | base64 -d
```

Result: `{"sub":"user123","role":"admin","exp":1700000000}`

RFC 7519 defines seven standard claims. None of them are required - all are OPTIONAL. But each has clear semantics, and if a claim is present, the server must process it.

**iss (Issuer)** - who issued the token. A string, case-sensitive. Usually the IdP URL: `"iss": "https://auth.example.com"`. If you have multiple IdPs, without checking `iss` the server can't determine which key to use for signature verification.

**sub (Subject)** - who the token is about. Usually the user ID: `"sub": "user123"`. Must be unique within the issuer's context.

**aud (Audience)** - who the token is intended for. The only claim with a hard rule: if `aud` is present and the recipient doesn't find itself in it - the token MUST be rejected. Can be a string or an array:

```json
"aud": "https://api.example.com"
"aud": ["https://api1.example.com", "https://api2.example.com"]
```

The server must support both formats. Supports only strings, receives an array - crash or bypass. Why `aud` is critically important for security - I'll explain shortly below.

**exp (Expiration Time)** - when the token expires. Unix timestamp in seconds. Not milliseconds - that's a common mistake. Example: `"exp": 1700000000` is November 14, 2023, 22:13:20 UTC. Current time must be strictly less than `exp`, otherwise the token is rejected. Servers usually allow a small clock skew - a few minutes of tolerance due to clock desynchronization.

**nbf (Not Before)** - when the token becomes valid. Also a Unix timestamp. Example: `"nbf": 1699900000` means "don't accept this token before November 13, 2023". Note the asymmetry: for `nbf` the check is "greater than or equal to", for `exp` it's strictly "less than".

**iat (Issued At)** - when it was issued. Unix timestamp. Used to determine the token's age, but formally doesn't imply a validation check.

**jti (JWT ID)** - unique token identifier. Designed to protect against replay attacks: the server remembers `jti` values of used tokens and rejects repeats. In practice, this requires storage for tracking - which brings us back to the stateful model that JWT was supposed to save us from.

## What a hacker sees when decoding someone's JWT

Intercepted a token. Decoded it. Now what?

The payload reveals the application's inner workings. Besides standard claims, developers dump everything in there:

```json
{
  "sub": "user_42",
  "email": "admin@company.com",
  "role": "admin",
  "org_id": "org_17",
  "permissions": ["read", "write", "delete"],
  "plan": "enterprise",
  "internal_user_id": 42
}
```

Roles, email addresses, organization identifiers, subscription tiers, internal IDs - all in plain text. This isn't a bug, it's by design: JWT signs data but doesn't encrypt it.

And the header tells you which attacks to try. `"alg": "HS256"` - means a symmetric secret, you can try brute force (article 7). `"alg": "RS256"` - asymmetric signature, look for the public key for algorithm confusion (article 4). There's a `kid` - potential for injection (article 5). There's a `jku` - vector for SSRF (article 6).

## Edge cases: where JWT breaks unexpectedly

**Duplicate keys in JSON.** The JSON RFC says: keys SHOULD be unique. Not MUST, but SHOULD - meaning duplicates are formally acceptable. What happens with this payload?

```json
{"role": "user", "role": "admin"}
```

Depends on the parser. Some take the first value, others take the last. If the proxy sees `"user"` but the backend sees `"admin"`, you get privilege escalation through parser differential. RFC 7515 requires JWT parsers to either reject duplicates or use the last value. But far from everyone follows this.

**Empty payload.** Two consecutive dots - empty payload:

```
eyJhbGciOiJIUzI1NiJ9..signature
```

This is syntactically valid JWS, but not valid JWT, because JWT requires a JSON object in the payload. Some libraries let it through.

**The year 2038 problem.** The `exp` claim is a Unix timestamp. On systems with 32-bit integers, the maximum value is: 2147483647 = January 19, 2038. What if you set `"exp": 2147483648`? Overflow, the value becomes negative, the check `now < exp` is always true. An immortal token.

```python
import struct
val = 2147483648
packed = struct.pack('>i', val & 0xFFFFFFFF)
print(struct.unpack('>i', packed)[0])  # -2147483648
```

**Unicode traps.** `"sub": "cafe\u0301"` (e + combining accent) and `"sub": "caf\u00e9"` (precomposed e) look identical, but they're different byte sequences. Different bytes mean different Base64url, different signatures. Cyrillic "a" (U+0430) and Latin "a" (U+0061) are visually indistinguishable, but for the parser they're different characters. A homoglyph attack on `sub` or `iss` can lead to verification bypass.

## Decoding JWT with Python

Here's a minimal script for parsing any JWT:

```python
import base64, json

token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.xxx"

for i, part in enumerate(token.split(".")):
    pad = part + "=" * (4 - len(part) % 4)
    try:
        data = base64.urlsafe_b64decode(pad)
        print(f"Part {i}: {json.loads(data)}")
    except:
        print(f"Part {i} (raw): {data.hex()}")
```

And a bash one-liner for quick checks:

```bash
echo -n "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | python3 -m json.tool
echo -n "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

## What's next

We've covered the anatomy. You know what JWT is made of, how it's created, what's inside each part. Now - attacks.

Remember, in the first article I said the token itself specifies the verification algorithm? In the next article - concrete exploitation of this flaw: `alg:none`, one line and you're admin.
