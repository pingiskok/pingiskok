---
title: "JWT, Part 3: alg:none - one line and you're admin"
date: 2026-03-21T18:02:00+03:00
number: 3
tags: ["jwt", "security", "web", "auth"]
summary: "The RFC requires every JWT library to support the none algorithm. Change one field in the header - and the server skips signature verification."
---

**Table of contents:**
- [Why alg:none exists](#why-algnone-exists)
- [How it works](#how-it-works)
- [How to check if a server is vulnerable](#how-to-check-if-a-server-is-vulnerable)
- [Case variations: bypassing filters](#case-variations-bypassing-filters)
- [Null byte trick](#null-byte-trick)
- [decode() vs verify()](#decode-vs-verify)
- [CVE: eleven years of the same bug](#cve-eleven-years-of-the-same-bug)
- [Defense](#defense)
- [What's next](#whats-next)

In the first article, I said the token itself tells the server how to verify the signature. In the second, we dissected the `alg` field in the JWT header. Now - a concrete example of how this design breaks.

## Why alg:none exists

RFC 7518 defines the `none` algorithm and requires every JWT library to support it. Why would a standard require implementing tokens without signatures? The RFC authors had a specific idea: Unsecured JWT is needed in situations where integrity is ensured at another level. For example, JWT is transmitted inside a TLS channel and never leaves it. Or JWT is part of another, already signed data structure. In such cases, double signing is unnecessary overhead.

Sounds reasonable in theory. In practice, it created a ticking time bomb. If a library reads `alg` from the token header and sees `none` - it skips verification. And the header is controlled by whoever creates the token. Including the attacker.

## How it works

Let's say we have a legitimate JWT:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ.RSA_signature_here
```

Decode the header: `{"alg":"RS256","typ":"JWT"}`. Decode the payload: `{"sub":"user","role":"user"}`. Signature - RSA-SHA256.

Now the attack. We want to become admin:

1. Create a new payload: `{"sub":"admin","role":"superuser"}`
2. Set the header to: `{"alg":"none","typ":"JWT"}`
3. Encode both in Base64url
4. Concatenate with dots, leaving an empty signature (but keeping the dot): `header.payload.`

Send it to the server. A vulnerable library sees `alg: none`, skips verification, accepts the token. We're admin.

Here's the entire process in Python:

```python
import base64, json

def b64(data):
    return base64.urlsafe_b64encode(
        json.dumps(data, separators=(',',':')).encode()
    ).rstrip(b'=').decode()

h = b64({"alg":"none","typ":"JWT"})
p = b64({"sub":"admin","role":"superuser","exp":1999999999})
print(f'{h}.{p}.')
```

Copy the output, paste it into `Authorization: Bearer <token>` - done.

## How to check if a server is vulnerable

The simplest test: take your legitimate token and flip one bit in the signature. If the server still accepts it - the signature isn't being checked at all. This is even worse than `alg:none` - it's `decode()` instead of `verify()`.

jwt_tool (github.com/ticarpi/jwt_tool) is the standard utility for JWT testing, like sqlmap for SQL injection. If the signature is being verified, try `alg:none`. jwt_tool does this with a single command:

```bash
python3 jwt_tool.py "$TOKEN" -X a
```

The `-X a` flag automatically generates and tests all variations of `none`. If at least one returns 200 instead of 401 - the server is vulnerable.

## Case variations: bypassing filters

The first obvious fix is checking `if alg == "none": reject()`. The problem is that this is a case-sensitive comparison. The string `"None"` is not equal to `"none"` in Python, JavaScript, Go - in most languages. But the library during processing might lowercase the value or handle it case-insensitively.

This creates an amusing situation: the filter rejects `"none"`, but passes `"None"`. The library accepts `"None"` as a valid algorithm and processes it as `none`. Full list for fuzzing:

```
none, None, NONE, nOnE, NoNe, nonE, noNe, nONE, NONe, NOne
```

jwt_tool iterates through all of them automatically.

## Null byte trick

`"alg": "none\x00HS256"` - a null byte in the middle of the string. Why does this work?

In C and C++, strings end with a null byte (null-terminated strings). If the server uses C extensions for JSON parsing or algorithm validation, the native code will read the string up to the null byte and see `none`. The high-level language (Python, JavaScript) sees the full string `none\x00HS256`. The filter checks the full string, doesn't find `none` in it (because there are more characters after `none`), and passes it through. The parser truncates at the null byte and processes it as `none`.

## decode() vs verify()

A classic developer mistake - calling `jwt.decode()` instead of `jwt.verify()`. The decode function extracts the payload but doesn't verify the signature. The developer thinks: "I decoded the token, so it must be valid". No. Decoding is Base64url. Verification is checking the cryptographic signature. Two completely different operations.

Testing for this error is trivial: take any token, change one character in the signature, send it to the server. If accepted - the signature isn't being verified. You don't even need `alg:none`.

## CVE: eleven years of the same bug

**CVE-2015-9235** (jsonwebtoken, Node.js, CVSS 9.8) - this is the very vulnerability that Tim McLean disclosed in 2015. A library with 17 million downloads per week accepted `alg: none` by default. One of the most high-profile security disclosures in web security history.

**CVE-2016-10555** (jwt-simple, Node.js) - the `jwt.decode()` function didn't check the algorithm at all.

**CVE-2026-23993** (HarbourJwt, Go) - year 2026. The library used a switch-case on algorithms, and for an unknown algorithm (including `none`) fell into the default branch, which returned an empty signature. Eleven years after the first CVE - the same bug.

## Defense

The only reliable defense is a server-side algorithm allowlist. Never trust `alg` from the token:

```python
jwt.decode(token, key, algorithms=["RS256"])
```

If a specific algorithm is specified when calling `decode` or `verify`, the library will ignore `alg` from the header and use only the allowed one. `none` not in the list - rejected. `HS256` not in the list - rejected. Only `RS256` - only RSA.

Additionally: block `none` case-insensitively: `alg.lower().strip() == "none"`. And verify that the signature is not empty before processing the payload.

## What's next

`alg:none` is brute force: "don't verify the signature at all". In the next article, I'll show algorithm confusion - a far more elegant attack. You take the server's public key, which is publicly available, sign your token with it - and the server accepts it. The signature exists, the signature is correct, but the token is still forged.
