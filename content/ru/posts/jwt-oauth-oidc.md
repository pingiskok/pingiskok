---
title: "JWT, часть 12: JWT в OAuth 2.0 и OIDC - где ломается в реальном мире"
date: 2026-03-28T10:12:00+03:00
number: 12
tags: ["jwt", "security", "web", "auth"]
summary: "На стыках компонентов OAuth/OIDC появляются атаки, которых нет в изоляции: token confusion, cross-service relay, ALBeast в AWS и обход DPoP — с конкретными CVE и пошаговыми проверками для пентеста."
---

**Содержание:**
- [OAuth 2.0 и OIDC в трех абзацах](#oauth-20-и-oidc-в-трех-абзацах)
- [Token Confusion: ID Token как Access Token](#token-confusion-id-token-как-access-token)
- [Cross-service Relay: aud не проверяется](#cross-service-relay-aud-не-проверяется)
- [ALBeast: AWS ALB + Cognito](#albeast-aws-alb--cognito)
- [DPoP: привязка токена к клиенту](#dpop-привязка-токена-к-клиенту)
- [OIDC Discovery как карта и вектор](#oidc-discovery-как-карта-и-вектор)
- [Что проверять на пентесте](#что-проверять-на-пентесте)
- [Что дальше](#что-дальше)

JWT сам по себе - одно. JWT в экосистеме OAuth 2.0 с десятком микросервисов, тремя IdP и пятью типами токенов (Access Token, ID Token, Refresh Token, Authorization Code, Logout Token) - совсем другое. Большинство атак из статей 3-8 работают и здесь - JWT остаётся JWT, даже если его выпустил Keycloak. Но на стыках компонентов появляются свои атаки.

## OAuth 2.0 и OIDC в трех абзацах

**OAuth 2.0** - протокол авторизации. Не аутентификации, а именно авторизации: "разрешить приложению X доступ к ресурсам пользователя Y". Результат - Access Token, который приложение предъявляет API. Формат токена стандартом не определен - может быть opaque-строкой, может быть JWT.

**OpenID Connect (OIDC)** - надстройка над OAuth 2.0, которая добавляет аутентификацию: "это точно пользователь Y". Результат - ID Token, который всегда JWT. ID Token содержит информацию о пользователе и предназначен для клиентского приложения.

Итого два основных типа JWT-токенов: **Access Token** (для API, авторизация) и **ID Token** (для клиента, аутентификация). Refresh Token тоже бывает JWT (Keycloak, некоторые конфигурации Auth0) - и это отдельная поверхность атаки. AT и IT часто подписаны одним ключом от одного issuer - особенно в Keycloak. Auth0, Azure AD и Okta чаще используют разные ключи, но проверять стоит в любом случае. И вот тут начинаются проблемы.

## Token Confusion: ID Token как Access Token

Самая частая ошибка в OIDC. Access Token предназначен для API ("какие права у этого клиента"). ID Token предназначен для клиентского приложения ("кто этот пользователь"). Разные назначения, но оба - подписанные JWT от одного IdP, верифицируемые одними ключами.

Атакующий получает ID Token (он всегда доступен клиенту) и отправляет его к API вместо Access Token. Если resource server не проверяет тип токена - он примет его. Это направление ID-как-AT - самое распространённое. Обратное тоже бывает: AT подсовывают вместо ID Token клиентскому приложению, и оно доверяет claims оттуда как identity-данным. CVE-2024-10318 (NGINX OIDC) - как раз token confusion, позволявший обойти аутентификацию.

RFC 9068 решает проблему: Access Token обязан иметь `typ: "at+jwt"` (или полная форма `application/at+jwt`) в заголовке. Проверяем:

```bash
echo "$TOKEN" | cut -d. -f1 | tr '-_' '+/' | \
  awk '{while(length%4)$0=$0"=";print}' | base64 -d 2>/dev/null \
  | python3 -c "import json,sys;print(json.load(sys.stdin).get('typ'))"
```

Результат `null` или `"JWT"` вместо `"at+jwt"` - token confusion возможен. Подставляй ID Token вместо Access Token и смотри, что вернет API.

## Cross-service Relay: aud не проверяется

Помнишь claim `aud` из статьи 2? Я говорил, что он критически важен для безопасности. Вот конкретный пример почему.

Микросервисная архитектура. Общий IdP (Keycloak, Auth0, Cognito). Service A и Service B оба доверяют токенам от этого IdP. Атакующий получает токен для Service A и отправляет его на Service B. Если Service B не проверяет `aud` - токен принят. У тебя доступ к сервису, для которого токен не предназначался.

**Шаг 1: получаем токен для service-a** (параметры зависят от IdP; Auth0 использует нестандартный `audience=` вместо `scope`):

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

**Шаг 2: отправляем токен service-a на service-b:**

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

200 OK = сервис B не проверяет `aud`. Токен, выданный для service-a, принят service-b.

CVE-2026-23552 (CVSS 9.1, Apache Camel 4.15.0-4.17.x): компонент `KeycloakSecurityPolicy` в Apache Camel не валидировал `iss` против сконфигурированного realm. Сервис с Camel-интеграцией принимал токены из чужого realm. Это не баг самого Keycloak - это баг в том, как Camel проверял его токены. Исправлено в Camel 4.18.0.

Для Keycloak в целом проверяем: нестандартные claims `realm_access` и `resource_access` - если проверяется `resource_access` без привязки к конкретному `client_id`, можно зарегистрировать свой client в том же realm и контролировать роли.

## ALBeast: AWS ALB + Cognito

Красивая атака на стыке AWS-сервисов, найденная Miggo Research в 2024 году. Суть: все AWS ALB в одном регионе используют общую инфраструктуру подписи JWT. Токен, подписанный любым ALB, проходит криптографическую верификацию на любом другом ALB в том же регионе.

Атакующий создаёт свой Cognito User Pool (свой ALB не нужен), получает валидный JWT. Этот токен содержит поле `signer` в заголовке - ARN конкретного ALB. Проблема: приложения за ALB не валидировали это поле. Они проверяли подпись (валидна - общие ключи региона) и claims, но не проверяли, что токен выдан именно ИХ ALB.

Фикс: валидация поля `signer` в заголовке JWT против ARN своего ALB. Это не jku spoofing из статьи 6 - здесь ключ не подгружается с URL атакующего, а используется легитимная общая инфраструктура AWS.

## DPoP: привязка токена к клиенту

Bearer token - кто украл, тот и пользуется. Перехватил в логах, в Burp History, через XSS (статья 13) - и используешь как свой. **DPoP** (Demonstrating Proof-of-Possession, RFC 9449) - механизм, который это ломает.

Идея: токен привязан к криптографическому ключу клиента. При каждом запросе клиент доказывает владение приватным ключом.

Как это работает:

1. Клиент генерирует асимметричную пару ключей (обычно ES256)
2. При запросе токена клиент создает **DPoP proof** - отдельный JWT с `typ: "dpop+jwt"`, публичным ключом в заголовке `jwk`, и полями `jti` (уникальный ID для replay protection), `htm` (HTTP method), `htu` (URL), `iat` (timestamp). При запросах к resource server добавляется `ath` - хэш Access Token
3. Authorization server выдает Access Token с claim `cnf.jkt` - thumbprint публичного ключа клиента
4. При каждом API-запросе клиент отправляет и Access Token (в `Authorization: DPoP <token>`), и свежий DPoP proof (в заголовке `DPoP`)
5. Resource server проверяет: ключ в proof совпадает с thumbprint в Access Token

Украл Access Token? Бесполезно без приватного ключа клиента. Не можешь создать DPoP proof - сервер отклонит запрос.

Но DPoP не серебряная пуля:
- **Downgrade DPoP на Bearer**: убери заголовок `DPoP` из запроса и замени `Authorization: DPoP <token>` на `Authorization: Bearer <token>`. Если сервер принимает - привязки нет. Самый простой и частый баг
- **XSS в браузере**: приватный ключ хранится в CryptoKey API как non-extractable, но атакующий может создавать DPoP proof-ы **пока жертва online** через monkey-patch fetch/XHR
- **Pre-generation**: если сервер не требует nonce, можно заранее создать proof-ы с будущими timestamp-ами
- **Replay window**: без серверного nonce proof можно реюзать в пределах временного окна. RFC 9449 не фиксирует точное окно - Auth0 даёт ~120 секунд, Okta ~300 секунд. Это не "несколько секунд", а минуты реальной эксплуатируемости
- **ath bypass**: если сервер не проверяет `ath` (хэш Access Token) в proof, можно реюзать один proof с разными токенами

## OIDC Discovery как карта и вектор

`/.well-known/openid-configuration` - это JSON с полной конфигурацией IdP. Для пентестера - карта всех возможностей:

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

Ищем:
- `jwks_uri` - endpoint с публичными ключами. Вектор для algorithm confusion (статья 4): забираешь публичный ключ и подписываешь им токен через HS256. Также потенциальный SSRF-вектор - если сервер фетчит этот URL, можно направить его на внутренние сервисы
- `grant_types_supported` - если есть `implicit` - дополнительные векторы (токен в URL fragment)
- `token_endpoint_auth_methods_supported` - если `client_secret_post` или `client_secret_basic` - ищи слабые client secrets
- `code_challenge_methods_supported` - если нет или есть `plain` - PKCE (RFC 7636) не enforced или downgrade возможен. PKCE обязателен в OAuth 2.1 и это одна из самых частых находок на пентестах

Discovery endpoint - не только карта, но и вектор: `jwks_uri`, `request_uri`, `sector_identifier_uri` могут быть SSRF-точками, если сервер фетчит их при динамической регистрации клиента.

**Mix-Up Attack** (Fett, Küsters, Schmitz, 2016): клиент работает с несколькими IdP. Атакующий контролирует один из них (вредоносный IdP). Пользователь начинает flow через вредоносный IdP, тот перенаправляет на легитимный. Пользователь авторизуется у легитимного, получает authorization code. Клиент думает, что flow шёл через вредоносный IdP, и отправляет code на его token endpoint. Код у атакующего. Защита: RFC 9207, проверяй `iss` в ответе авторизации, чтобы знать с каким IdP шёл flow.

**Issuer Confusion**: вариант Mix-Up Attack. Вредоносный Authorization Server (AS) объявляет свой token endpoint равным endpoint легитимного AS. Результат тот же: код уходит атакующему.

## Что проверять на пентесте

**Token Confusion и Cross-service:**

1. Отправь ID Token вместо Access Token (и наоборот)
2. Отправь токен для сервиса A на сервис B
3. Проверь `typ` в header: должен быть `at+jwt` или `application/at+jwt`
4. Проверь `aud`: должен быть конкретным, не wildcard

**OAuth flow:**

5. `redirect_uri`: подмена, open redirect, path traversal в callback URL
6. PKCE: убери `code_challenge`. Если сервер принимает без неё, нет enforcement
7. `state` parameter: убери или подмени. CSRF на OAuth flow
8. `nonce` в ID Token: убери или реюзай. Replay protection
9. `scope`: запроси повышенный scope при token refresh

**Провайдер-специфичное:**

10. Keycloak: cross-realm токены, `resource_access` без привязки к `client_id`
11. AWS ALB: валидация поля `signer` (ALB ARN) в заголовке JWT
12. Discovery: `jwks_uri`, `grant_types`, `code_challenge_methods_supported`

**DPoP:**

13. Замени `Authorization: DPoP` на `Bearer`. Если принимает, привязки нет
14. Реюзай DPoP proof с другим Access Token. Проверка `ath`
15. Убери заголовок `DPoP` целиком

## Что дальше

Мы разобрали как атаковать JWT (статьи 3-8 - подделка подписей, статьи 9-10 - крипто и JWE) и как это работает в контексте OAuth/OIDC (эта статья). Но зачем подделывать, если можно просто украсть? В следующей статье - XSS + JWT: как один Reflected XSS превращается в полный захват всех аккаунтов. localStorage, sessionStorage, HttpOnly cookie - threat model каждого варианта.
