---
title: "JWT, Part 12: JWT in OAuth 2.0 and OIDC - where it breaks in the real world"
date: 2026-03-28T10:12:00+03:00
number: 12
tags: ["jwt", "security", "web", "auth"]
summary: "At the seams between OAuth and OIDC components, attacks emerge that don't exist in isolation: token confusion, cross-service relay, ALBeast in AWS, and DPoP bypass — with real CVEs and step-by-step pentest checks."
---

**Table of contents:**
- [OAuth 2.0 and OIDC in three paragraphs](#oauth-20-and-oidc-in-three-paragraphs)
- [Token Confusion: ID Token as Access Token](#token-confusion-id-token-as-access-token)
- [Cross-service Relay: aud goes unchecked](#cross-service-relay-aud-goes-unchecked)
- [ALBeast: AWS ALB + Cognito](#albeast-aws-alb--cognito)
- [DPoP: binding the token to the client](#dpop-binding-the-token-to-the-client)
- [OIDC Discovery as a map and an attack vector](#oidc-discovery-as-a-map-and-an-attack-vector)
- [What to check during a pentest](#what-to-check-during-a-pentest)
- [What's next](#whats-next)

JWT on its own is one thing. JWT inside an OAuth 2.0 ecosystem with a dozen microservices, three IdPs, and five token types - Access Token, ID Token, Refresh Token, Authorization Code, Logout Token - is something else entirely. Most of the attacks from articles 3-8 still apply here - a JWT is still a JWT, even if Keycloak issued it. But at the seams between components, new attacks emerge.

## OAuth 2.0 and OIDC in three paragraphs

**OAuth 2.0** is an authorization protocol - not authentication, authorization. It answers the question "should application X be allowed to access user Y's resources?" The result is an Access Token that the application presents to an API. The token format isn't defined by the spec - it can be an opaque string or a JWT.

**OpenID Connect (OIDC)** is a layer on top of OAuth 2.0 that adds authentication: "this is definitely user Y." The result is an ID Token, which is always a JWT. The ID Token carries information about the user and is meant for the client application.

So you end up with two main JWT token types: **Access Token** (for APIs, authorization) and **ID Token** (for the client, authentication). Refresh Tokens can also be JWTs - Keycloak does this, as do some Auth0 configurations - and that's a separate attack surface on its own. Access Tokens and ID Tokens are often signed by the same key from the same issuer, especially in Keycloak. Auth0, Azure AD, and Okta more commonly use separate keys, but you should verify that either way.

## Token Confusion: ID Token as Access Token

The most common mistake in OIDC. An Access Token is for the API ("what permissions does this client have?"). An ID Token is for the client application ("who is this user?"). Different purposes - but both are signed JWTs from the same IdP, verifiable with the same keys.

An attacker grabs the ID Token (it's always available to the client) and sends it to the API instead of the Access Token. If the resource server doesn't validate the token type, it accepts it. This ID-as-AT direction is the most common. The reverse happens too - an AT gets passed off to a client application as an ID Token, and the app trusts its claims as identity data. CVE-2024-10318 (NGINX OIDC) was exactly this - a token confusion bug that allowed authentication bypass.

RFC 9068 fixes the problem: an Access Token must have `typ: "at+jwt"` (or the full form `application/at+jwt`) in its header. Check for it like this:

```bash
echo "$TOKEN" | cut -d. -f1 | tr '-_' '+/' | \
  awk '{while(length%4)$0=$0"=";print}' | base64 -d 2>/dev/null \
  | python3 -c "import json,sys;print(json.load(sys.stdin).get('typ'))"
```

If you get `null` or `"JWT"` instead of `"at+jwt"` - token confusion is possible. Swap in the ID Token where the Access Token goes and see what the API says.

## Cross-service Relay: aud goes unchecked

Remember the `aud` claim from article 2? I said it was critical for security. Here's a concrete example of why.

Microservice architecture. Shared IdP (Keycloak, Auth0, Cognito). Service A and Service B both trust tokens from that IdP. An attacker gets a token for Service A and sends it to Service B. If Service B doesn't check `aud` - the token is accepted. You've got access to a service the token was never meant for.

**Step 1: get a token for service-a** (parameters depend on the IdP; Auth0 uses the non-standard `audience=` instead of `scope`):

```http
POST /token HTTP/1.1
Host: idp.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=my-client&client_secret=secret&scope=service-a
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"access_token":"eyJhbGciOiJSUzI1NiIs...","token_type":"Bearer","expires_in":3600}
```

**Step 2: send service-a's token to service-b:**

```http
GET /api/admin HTTP/1.1
Host: service-b.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"role":"admin","data":"..."}
```

200 OK means service B isn't checking `aud`. A token issued for service-a just got accepted by service-b.

CVE-2026-23552 (CVSS 9.1, Apache Camel 4.15.0-4.17.x): the `KeycloakSecurityPolicy` component in Apache Camel didn't validate `iss` against the configured realm. A service using the Camel integration would accept tokens from a completely different realm. This wasn't a Keycloak bug - it was a bug in how Camel was validating Keycloak's tokens. Fixed in Camel 4.18.0.

For Keycloak specifically, check the non-standard claims `realm_access` and `resource_access` - if `resource_access` is checked without binding it to a specific `client_id`, you can register your own client in the same realm and control the roles.

## ALBeast: AWS ALB + Cognito

A clever attack at the intersection of AWS services, discovered by Miggo Research in 2024. The core issue: all AWS ALBs in a region share a common JWT signing infrastructure. A token signed by any ALB in a region passes cryptographic verification on any other ALB in that same region.

An attacker creates their own Cognito User Pool - no ALB required - and gets a valid JWT. That token contains a `signer` field in the header: the ARN of a specific ALB. The problem: applications behind ALBs weren't validating that field. They verified the signature (valid - shared regional keys) and checked the claims, but never confirmed that the token was actually issued by *their* ALB.

The fix: validate the `signer` field in the JWT header against your own ALB's ARN. This isn't the jku spoofing from article 6 - the attacker isn't loading a key from their own URL. They're using the legitimate, shared AWS infrastructure.

## DPoP: binding the token to the client

Bearer tokens have one fundamental problem: whoever steals one can use it. Grabbed from logs, from Burp history, via XSS (article 13) - and you can use it as your own. **DPoP** (Demonstrating Proof-of-Possession, RFC 9449) is the mechanism designed to break that assumption.

The idea: the token is bound to the client's cryptographic key. On every request, the client proves it holds the private key.

Here's how it works:

1. The client generates an asymmetric key pair (typically ES256)
2. When requesting a token, the client creates a **DPoP proof** - a separate JWT with `typ: "dpop+jwt"`, the public key in the `jwk` header, and fields for `jti` (unique ID for replay protection), `htm` (HTTP method), `htu` (URL), and `iat` (timestamp). When making requests to the resource server, a `ath` field is added - a hash of the Access Token
3. The authorization server issues an Access Token with the claim `cnf.jkt` - a thumbprint of the client's public key
4. On every API request, the client sends both the Access Token (in `Authorization: DPoP <token>`) and a fresh DPoP proof (in the `DPoP` header)
5. The resource server checks that the key in the proof matches the thumbprint in the Access Token

Steal the Access Token? Useless without the client's private key. Can't create a DPoP proof, server rejects the request.

But DPoP isn't a silver bullet:

- **Downgrade DPoP to Bearer**: drop the `DPoP` header and change `Authorization: DPoP <token>` to `Authorization: Bearer <token>`. If the server accepts it - there's no binding. The simplest and most common bug
- **XSS in the browser**: the private key is stored in the CryptoKey API as non-extractable, but an attacker can create DPoP proofs **while the victim is online** by monkey-patching fetch/XHR
- **Pre-generation**: if the server doesn't require a nonce, you can pre-generate proofs with future timestamps
- **Replay window**: without a server-side nonce, a proof can be reused within a time window. RFC 9449 doesn't specify an exact window - Auth0 gives ~120 seconds, Okta ~300 seconds. That's not "a few seconds" - that's minutes of real exploitability
- **ath bypass**: if the server doesn't check `ath` (the Access Token hash) in the proof, you can reuse a single proof with different tokens

## OIDC Discovery as a map and an attack vector

`/.well-known/openid-configuration` is a JSON document containing the IdP's complete configuration. For a pentester, it's a map of everything available:

```http
GET /.well-known/openid-configuration HTTP/1.1
Host: target.example.com
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "issuer": "https://target.example.com",
  "authorization_endpoint": "https://target.example.com/authorize",
  "token_endpoint": "https://target.example.com/token",
  "jwks_uri": "https://target.example.com/.well-known/jwks.json",
  "grant_types_supported": ["authorization_code","client_credentials","implicit"],
  "token_endpoint_auth_methods_supported": ["client_secret_post","client_secret_basic"],
  "code_challenge_methods_supported": ["plain","S256"],
  "response_types_supported": ["code","token","id_token"]
}
```

What to look for:

- `jwks_uri` - the endpoint with public keys. An algorithm confusion vector (article 4): grab the public key and use it to sign a token via HS256. Also a potential SSRF vector - if the server fetches this URL, you can point it at internal services
- `grant_types_supported` - if `implicit` is listed, you get additional vectors (token in URL fragment)
- `token_endpoint_auth_methods_supported` - if `client_secret_post` or `client_secret_basic` are present, look for weak client secrets
- `code_challenge_methods_supported` - if this field is missing, or `plain` is listed, PKCE (RFC 7636) isn't enforced, or a downgrade is possible. PKCE is mandatory in OAuth 2.1, and missing enforcement is one of the most common findings on pentests

The discovery endpoint is both a map and an attack surface: `jwks_uri`, `request_uri`, and `sector_identifier_uri` can all be SSRF entry points if the server fetches them during dynamic client registration.

**Mix-Up Attack** (Fett, Küsters, Schmitz, 2016): the client is working with multiple IdPs. The attacker controls one of them - a malicious IdP. The user starts a flow through the malicious IdP, which redirects to a legitimate one. The user authenticates with the legitimate IdP and gets an authorization code. The client, thinking the flow was through the malicious IdP, sends the code to the malicious token endpoint. The attacker now has the code. Defense: RFC 9207 - check the `iss` in the authorization response so you know which IdP the flow actually went through.

**Issuer Confusion**: a variant of the Mix-Up Attack. A malicious Authorization Server (AS) advertises its token endpoint as being the same as the legitimate AS's endpoint. The result is the same - the code ends up with the attacker.

## What to check during a pentest

**Token Confusion and Cross-service:**

1. Send an ID Token where an Access Token is expected (and vice versa)
2. Send a token for service A to service B
3. Check `typ` in the header - it should be `at+jwt` or `application/at+jwt`
4. Check `aud` - it should be specific, not a wildcard

**OAuth flow:**

5. `redirect_uri`: substitution, open redirect, path traversal in the callback URL
6. PKCE: remove `code_challenge`. If the server accepts the request without it, there's no enforcement
7. `state` parameter: remove or replace. CSRF on the OAuth flow
8. `nonce` in ID Token: remove or reuse. Replay protection
9. `scope`: request elevated scope during token refresh

**Provider-specific:**

10. Keycloak: cross-realm tokens, `resource_access` without binding to `client_id`
11. AWS ALB: validate the `signer` field (ALB ARN) in the JWT header
12. Discovery: `jwks_uri`, `grant_types`, `code_challenge_methods_supported`

**DPoP:**

13. Replace `Authorization: DPoP` with `Bearer`. If it's accepted, there's no binding
14. Reuse a DPoP proof with a different Access Token. Tests `ath` validation
15. Remove the `DPoP` header entirely

## What's next

We've covered how to attack JWT itself (articles 3-8 - signature forgery, articles 9-10 - crypto and JWE) and how all of that plays out in an OAuth/OIDC context (this article). But why forge a token when you can just steal one? Next up - XSS + JWT: how a single Reflected XSS turns into a full account takeover for every user on the platform. localStorage, sessionStorage, HttpOnly cookies - the threat model for each approach.
