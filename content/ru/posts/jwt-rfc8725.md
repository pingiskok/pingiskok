---
title: "JWT, часть 19: RFC 8725 - чеклист который никто не читает"
date: 2026-04-03T20:19:00+03:00
number: 19
tags: ["jwt", "security", "web", "auth"]
summary: "RFC 8725 — пятнадцать правил безопасности JWT от авторов стандарта. Для каждого — какую атаку из серии оно предотвращает, какие CVE существуют, и почему ~65% приложений не проверяют aud. Плюс три новых правила из bis-обновления 2026."
---

**Содержание:**
- [3.1 Algorithm Verification](#31-algorithm-verification)
- [3.2 Use Appropriate Algorithms](#32-use-appropriate-algorithms)
- [3.3 Validate All Cryptographic Operations](#33-validate-all-cryptographic-operations)
- [3.4 Validate Cryptographic Inputs](#34-validate-cryptographic-inputs)
- [3.5 HMAC Key Entropy](#35-hmac-key-entropy)
- [3.6 Avoid Compression](#36-avoid-compression)
- [3.7 Use UTF-8](#37-use-utf-8)
- [3.8 Validate Issuer and Subject](#38-validate-issuer-and-subject)
- [3.9 Validate Audience](#39-validate-audience)
- [3.10 Do Not Trust Received Claims](#310-do-not-trust-received-claims)
- [3.11 Explicit Typing](#311-explicit-typing)
- [3.12 Mutually Exclusive Validation](#312-mutually-exclusive-validation)
- [RFC 8725bis (2026)](#rfc-8725bis-2026)
- [Итоговый чеклист](#итоговый-чеклист)
- [Что дальше](#что-дальше)

Мы атаковали. Теперь - как защититься. RFC 8725 (JSON Web Token Best Current Practices) - пятнадцать правил безопасности JWT: двенадцать оригинальных и три из bis-обновления 2026 года. Компактный документ: делай так, не делай этак. По моему опыту, большинство приложений нарушают хотя бы одно правило. И для большинства нарушений есть CVE, которые мы уже разбирали.

![RFC 8725 map](/images/rfc8725-map.png)

## 3.1 Algorithm Verification

**Правило:** библиотека ОБЯЗАНА позволять указать допустимые алгоритмы серверно. Каждый ключ - ровно один алгоритм. Никогда не доверять `alg` из заголовка токена.

**Какую атаку предотвращает:** algorithm confusion (статья 4) и alg:none (статья 3). Если сервер пинит `algorithms=["RS256"]`, подмена на HS256 или none невозможна.

**CVE:** CVE-2015-9235 (jsonwebtoken), CVE-2026-22817 (Hono, 11 лет спустя!), CVE-2024-33663 (python-jose).

```python
# ПРАВИЛЬНО
jwt.decode(token, key, algorithms=["RS256"])

# УЯЗВИМО - алгоритм берется из токена
header = jwt.get_unverified_header(token)
jwt.decode(token, key, algorithms=[header["alg"]])
```

## 3.2 Use Appropriate Algorithms

**Правило:** использовать только актуальные алгоритмы. `none` - не использовать. RSA1_5 (RSAES-PKCS1-v1_5) для JWE - не использовать.

**Какую атаку предотвращает:** alg:none (статья 3), Bleichenbacher oracle на RSA1_5 (статья 10), nonce reuse в ECDSA (статья 9).

**Рекомендация 2026:** EdDSA для подписей (детерминированный nonce исключает nonce reuse - статья 9). ECDSA - только с детерминированным nonce по RFC 6979 (best practice из статьи 9, не требование RFC 8725). RSA-OAEP для шифрования (устойчив к Bleichenbacher).

## 3.3 Validate All Cryptographic Operations

**Правило:** Nested JWT (JWE внутри JWS или наоборот) требует проверки на каждом уровне. Расшифровал JWE - проверь подпись внутренней JWS.

**Какую атаку предотвращает:** bypass аутентификации через nested tokens.

**CVE:** CVE-2026-29000 (pac4j-jwt, CVSS 10.0) - расшифровка JWE, внутри PlainJWT с `alg=none`. Подпись не проверялась. Аутентификация как любой пользователь. Одно вложение - и весь стек безопасности обрушился.

## 3.4 Validate Cryptographic Inputs

**Правило:** при ECDH-ES ОБЯЗАТЕЛЬНО проверять, что точка из `epk` лежит на правильной эллиптической кривой.

**Какую атаку предотвращает:** Invalid Curve Attack из статьи 10. Без проверки атакующий подставляет точку со слабой кривой, через десятки запросов восстанавливает приватный ключ через CRT (Китайскую теорему об остатках).

**CVE:** затронуты go-jose, node-jose, jose2go, Nimbus, jose4j (все в 2016-2017). Проверка: `y^2 == x^3 + ax + b (mod p)` для каждой входящей точки.

## 3.5 HMAC Key Entropy

**Правило:** ключ HS256 MUST быть не менее 256 бит из CSPRNG. Человеческие пароли ЗАПРЕЩЕНЫ.

**Какую атаку предотвращает:** GPU-брутфорс (статья 7) и захардкоженные секреты (статья 17).

```bash
# Правильно: 256 бит энтропии из CSPRNG (64 hex-символа = 32 байта)
python3 -c "import secrets; print(secrets.token_hex(32))"

# Неправильно
JWT_SECRET="password123"       # hashcat найдет за секунды
JWT_SECRET="notfound"           # CVE-2025-20188, CVSS 10.0
JWT_SECRET="your-256-bit-secret"  # дефолт jwt.io
```

hashcat на RTX 4090: ~4 миллиарда HS256 в секунду (mode 16500). Строка "secret" по словарю rockyou.txt - мгновенно. 32 случайных байта из CSPRNG - никогда.

## 3.6 Avoid Compression

**Правило:** не использовать `"zip":"DEF"` в JWE.

**Какую атаку предотвращает:** побочный канал через размер сжатого ciphertext (аналог CRIME/BREACH, но на уровне JWE payload, а не TLS). Практический риск - decompression bomb: атакующий создаёт JWE с данными, сжимающимися в тысячи раз, сервер распаковывает и исчерпывает память (подробнее в 3.15 bis).

Видишь `zip` в заголовке JWE - это находка для отчета.

## 3.7 Use UTF-8

**Правило:** только UTF-8 для кодирования JOSE Header и JWT Claims Set.

**Какую атаку предотвращает:** parser differential через разные кодировки. Если один компонент кодирует header в UTF-16, а другой ожидает UTF-8 - подпись проверяется по одним байтам, payload интерпретируется по другим. Вспоминаем Unicode-ловушки из статьи 2: кириллическое "а" и латинское "a" визуально неотличимы, но для парсера - разные символы.

## 3.8 Validate Issuer and Subject

**Правило:** сервер ОБЯЗАН проверить, что ключ подписи принадлежит указанному `iss`. Без этого атакующий подписывает СВОИМ ключом с `"iss":"auth.megabank.example"`, и сервер принимает. Claim `sub` также подлежит валидации: формат, существование пользователя, соответствие контексту запроса.

**CVE:** CVE-2026-23552 (Apache Camel camel-keycloak, не сам Keycloak) - cross-realm токены. Camel не проверял привязку `iss` к конкретным ключам. Мы разбирали в статье 12.

## 3.9 Validate Audience

**Правило:** токен для Service A не должен приниматься Service B. Claim `aud` MUST быть проверен.

**Какую атаку предотвращает:** cross-service relay из статьи 12. Самое частое нарушение RFC 8725 - по моему опыту, примерно 65% приложений не проверяют `aud`.

```python
jwt.decode(token, key, algorithms=["RS256"],
    audience="https://api.payments.megabank.example")
```

## 3.10 Do Not Trust Received Claims

**Правило:** `kid`, `jku`, `x5u` и другие параметры из заголовка контролируются атакующим. Санитизировать, не следовать слепо.

**Какую атаку предотвращает:** все атаки из статей 5-6. kid - SQLi, path traversal, command injection. jku/x5u - SSRF + подмена ключей. CVE-2018-0114 (node-jose) - доверие JWK из заголовка. CVE-2026-27962 (Authlib) - та же ошибка, 8 лет спустя.

## 3.11 Explicit Typing

**Правило:** использовать `typ` header для различения типов JWT. Access Token MUST иметь `typ: "at+jwt"` (RFC 9068).

**Какую атаку предотвращает:** token confusion из статьи 12. Без `typ` ID Token и Access Token неразличимы. Атакующий подставляет один вместо другого.

## 3.12 Mutually Exclusive Validation

**Правило:** один IdP выдает access, ID, refresh токены - правила валидации должны гарантировать взаимное исключение. Нельзя использовать одну функцию `verify_token()` для всех типов.

**Какую атаку предотвращает:** refresh token принимается как access token. Или наоборот.

## RFC 8725bis (2026)

Обновление стандарта. Три новых правила для атак, обнаруженных после 2020 года, плюс изменения к двум существующим секциям:

**Обновление 3.1:** allowlists алгоритмов MUST быть case-insensitive (`"rs256"` vs `"RS256"` - оба должны обрабатываться одинаково). Blocklist-подход запрещён - только allowlist.

**Обновление 3.12:** добавлена обязательная проверка `typ` для разделения JWE и JWS. Защита от format confusion: JWE-обёрнутый PlainJWT не должен приниматься как signed JWT (CVE-2026-29000).

**3.13 Limit PBES2 Iterations.** `p2c` в JWE определяет количество итераций хеширования. Атакующий ставит `p2c=999999999` - сервер уходит в CPU exhaustion на минуты. CVE-2023-52428 (Nimbus), CVE-2022-36083 (jose/panva). Лимит: не более 1,200,000 итераций (2× OWASP-рекомендация 600K для HMAC-SHA-256).

**3.14 Check JWT Format Type.** JWT в compact serialization содержит только `A-Za-z0-9-_.`. Фигурные скобки, кавычки и другие символы в Base64url-частях - отклонять. Защита от format confusion: подстановка JSON вместо Base64url.

**3.15 Limit Decompression.** JWE с `zip` без лимита на размер распакованных данных - decompression bomb. CVE-2024-33664 (python-jose), CVE-2024-21319 (System.IdentityModel). Лимит: 250 KB на распакованный payload.

## Итоговый чеклист

Проверь каждый пункт. Непроверенный пункт = вектор атаки.

**⚠️ Важно:** RFC 8725 покрывает не все аспекты JWT-безопасности. Хранение токенов (статья 13), ротация ключей (статья 17), revocation - вне scope стандарта, но критичны на реальных пентестах.

**RFC 8725 (секции 3.1-3.12):**

1. **3.1** alg пиннинг серверно (`algorithms=["RS256"]`), alg из токена игнорируется
2. **3.2** нет none, нет RSA1_5, только актуальные алгоритмы
3. **3.3** nested JWT: подпись проверяется на каждом уровне вложенности
4. **3.4** EC point validation: входящая точка лежит на заявленной кривой
5. **3.5** HMAC ключ >= 256 бит из CSPRNG, не человеческий пароль
6. **3.6** нет zip в JWE (side-channel + decompression bomb)
7. **3.7** только UTF-8 для JOSE header и claims
8. **3.8** iss привязан к конкретным ключам, sub валидируется
9. **3.9** aud проверяется - конкретный URI, не wildcard
10. **3.10** kid/jku/x5u санитизированы, не trusted blindly
11. **3.11** typ проверяется (at+jwt для access tokens, RFC 9068)
12. **3.12** типы токенов разделены: refresh ≠ access ≠ ID token

**RFC 8725bis (2026):**

13. **3.1+** allowlist алгоритмов case-insensitive
14. **3.12+** typ обязателен для разделения JWE/JWS форматов
15. **3.13** p2c лимит <= 1,200,000 для PBES2
16. **3.14** только валидные Base64url символы в compact serialization
17. **3.15** лимит декомпрессии JWE <= 250 KB

**Вне RFC 8725, но критично на пентесте:**

18. exp/nbf/iat проверяются (`verify_exp: True` - не отключай)
19. токен не в localStorage (HttpOnly cookie или Authorization header)
20. ключи ротируются, kid для версионирования (статья 5)

Самые частые нарушения на реальных engagement'ах: `aud` не проверяется (~65%), слабый HMAC-секрет, отсутствие `typ`, отключённая проверка `exp`. Полная методология тестирования - статья 16. Инструменты для каждого пункта - статья 15.

## Что дальше

Финал серии. В следующей статье - что ждет JWT в будущем. Постквантовая криптография: подписи ML-DSA по 2.4 KB, которые не влезают в cookie. SD-JWT - selective disclosure. И итог серии: ключевые выводы из двадцати статей.
