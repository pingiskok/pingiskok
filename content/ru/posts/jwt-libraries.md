---
title: "JWT, часть 11: JWT-библиотеки - рейтинг дырявости"
date: 2026-03-28T10:11:00+03:00
number: 11
tags: ["jwt", "security", "web", "auth"]
summary: "От выбора библиотеки зависит, какие атаки сработают: рейтинг самых уязвимых, tier-классификация от рекомендуемых до опасных, и fingerprinting бэкенда по заголовку токена без единого запроса к серверу."
---

**Содержание:**
- [Почему библиотека важнее алгоритма](#почему-библиотека-важнее-алгоритма)
- [Top-5 самых дырявых](#top-5-самых-дырявых)
- [Tier-рейтинг: что использовать, а что удалять](#tier-рейтинг-что-использовать-а-что-удалять)
- [Fingerprinting: как определить библиотеку по токену](#fingerprinting-как-определить-библиотеку-по-токену)
- [Что это значит для пентеста](#что-это-значит-для-пентеста)
- [Что дальше](#что-дальше)

17 миллионов скачиваний в неделю. Четыре CVE (пятый отозван NVD). Это jsonwebtoken для Node.js - самая популярная JWT-библиотека в мире. Зачем тебе как пентестеру знать, какая библиотека стоит на бэкенде? Потому что от библиотеки зависит, какие атаки сработают.

## Почему библиотека важнее алгоритма

В статьях 3-10 я показывал атаки: alg:none, algorithm confusion, kid injection, psychic signatures. Каждая из них работает **не на всех библиотеках**. Algorithm confusion (статья 4) работает только там, где функция `verify()` принимает алгоритм из заголовка токена. Psychic signatures (статья 8) - только на Java 15-18. Kid injection (статья 5) - только там, где kid используется для чтения файла, SQL-запроса или выполнения команды.

Определил библиотеку - сузил набор атак. Не надо тратить время на algorithm confusion, если на бэкенде jose/panva, которая архитектурно к ней иммунна.

## Top-5 самых дырявых

Top-5 ранжирует по количеству и тяжести исторических CVE. Tier-рейтинг ниже оценивает другое: текущую архитектуру, скорость патчей, активность поддержки. Библиотека может попасть в оба списка - дырявая история не означает дырявое настоящее.

**1. python-jose (Python) - поддержка нерегулярная, критические баги висят месяцами**

Одна незакрытая CVE, две исправлены в v3.4.0 (февраль 2025):

- CVE-2024-33663 (CVSS 7.5): algorithm confusion через ECDSA-ключи. Та самая атака из статьи 4, но с EC-ключами вместо RSA. **Исправлена в 3.4.0.**
- CVE-2024-33664 (CVSS 7.5): JWE compression bomb - вложенный JWE раздувается при распаковке, DoS. **Исправлена в 3.4.0.**
- CVE-2025-61152: `alg:none` bypass без верификации. Атака из статьи 3 работает в лоб. **Без патча.**

FastAPI рекомендовала python-jose в официальной документации. Если видишь `from jose import jwt` в проекте - это подарок для пентестера. Algorithm confusion (статья 4) и alg:none (статья 3) работают на непропатченных версиях.

**2. jsonwebtoken (Node.js) - 4 CVE, security rewrite в v9**

CVE-2022-23529 (RCE через secretOrPublicKey) был **отозван NVD** в январе 2023 - не считаем. Остаётся четыре реальных.

Disclosure Тима Маклина в 2015 году (CVE-2015-9235) затронул множество библиотек, включая jsonwebtoken - мы разбирали это в статьях 3-4. До версии 9 библиотека принимала `alg:none` по умолчанию и позволяла algorithm confusion.

В 2022 году вышли три CVE разом:
- CVE-2022-23539: insecure key type validation
- CVE-2022-23540: `alg:none` обход, но при трёх условиях одновременно - `algorithms` не указан в `verify()`, передан `key`, и токен unsigned. Не просто "дефолтный alg:none".
- CVE-2022-23541: algorithm confusion через key retrieval function

Версия 9.0.0 - major security rewrite. Запрет unsigned-токенов, минимальный размер RSA-ключа 2048 бит, запрет algorithm confusion. Но если на проекте стоит v8.x - все дыры открыты.

```bash
# Проверь версию на проекте
npm ls jsonwebtoken 2>/dev/null || grep '"jsonwebtoken"' package-lock.json
```

**3. Authlib (Python) - 4 Critical CVE в 2026 году**

Четыре бага - два в JWE, два в JWS/OIDC:

CVE-2026-27962 (CVSS 9.1): JWK Header Injection. Та же атака, что CVE-2018-0114 из статьи 6. При передаче `key=None` в функцию десериализации библиотека берет ключ из заголовка `jwk` в самом токене. Атакующий подписывает токен своим приватным ключом, встраивает публичный ключ в заголовок - сервер принимает как валидный.

CVE-2026-28490: Bleichenbacher Oracle в JWE RSA1_5, которую мы разбирали в статье 10. Authlib перехватывала результат расшифровки и проверяла длину CEK до AES-GCM. Два разных исключения (`InvalidTag` vs `ValueError`) создавали padding oracle. ~14500 запросов - и CEK расшифрован.

CVE-2026-28498: Fail-Open OIDC Hash Binding - при определённых условиях проверка привязки хэша к токену пропускается.

CVE-2026-28802: `alg:none` signature bypass в v1.6.5-1.6.7. Да, та самая атака из статьи 3 - в 2026 году.

В Top-5 Authlib попала из-за комбинации JWE-багов и свежего alg:none bypass. JWS-часть (кроме v1.6.5-1.6.7) работает нормально.

**4. PyJWT (Python) - 3+ CVE, blocklist подход дважды обойден**

Два случая algorithm confusion через обход blocklist-а:
- CVE-2017-11424: blocklist проверял `BEGIN PUBLIC KEY`, но забыл `BEGIN RSA PUBLIC KEY` (формат PKCS#1). Исправлено в 1.5.1.
- CVE-2022-29217: blocklist обновили, но забыли OpenSSH ECDSA ключи (`ecdsa-sha2-nistp256`). Исправлено в 2.4.0.
- CVE-2026-32597: свежая CVE.

Проблема архитектурная: PyJWT использовала подход "блокируем опасные форматы ключей". Каждый новый формат - новый обход. Allowlist был бы надежнее.

**5. Nimbus JOSE+JWT (Java) - 6+ CVE, включая наши знакомые**

Фактически стандарт для Java-экосистемы (Spring Security, Microsoft MSAL):
- CVE-2017-16007: invalid curve attack в ECDH-ES - **полное восстановление приватного ключа**. Из статьи 10.
- CVE-2023-52428: PBES2 DoS - `p2c: 999999999` вызывает CPU exhaustion. Тоже из статьи 10.
- CVE-2025-53864: Nested JSON DoS.
- И ещё несколько CVE помельче.

Nimbus тут из-за количества исторических CVE. Но все баги были закрыты быстро, архитектура библиотеки серьёзная, поддержка активная - поэтому она одновременно в Tier 1 ниже. Много CVE в прошлом ≠ опасная библиотека сегодня, если патчи выходят за дни.

## Tier-рейтинг: что использовать, а что удалять

Tier-рейтинг оценивает **текущую** безопасность: архитектуру API (можно ли вообще допустить опасную ошибку), скорость патчей, активность поддержки. Это не историческая метрика - библиотека с 10 закрытыми CVE и хорошей архитектурой надёжнее, чем библиотека с 0 CVE и мёртвым репозиторием.

**Tier 1 - рекомендуется:**

`jose/panva` (Node.js) - эталон безопасности. Ноль зависимостей, Web Crypto API (плюс node:crypto для серверных задач), `alg:none` реализован через отдельный класс `UnsecuredJWT` (нужен осознанный opt-in). Algorithm confusion невозможна архитектурно: тип ключа определяет набор допустимых алгоритмов. Несколько CVE за историю: padding oracle в AES-CBC-HMAC (CVE-2021-29443 - криптоатака, не DoS), PBES2 DoS (CVE-2022-36083), JWE decompression DoS (CVE-2024-28176). Все быстро исправлены.

`jjwt` (Java) - builder pattern API. Algorithm confusion невозможна by design: `signWith(key, alg)` жестко привязывает ключ к алгоритму.

`nimbus-jose-jwt` (Java) - мощная, полный JOSE-стек. 6+ CVE за историю (см. Top-5 выше), но все быстро закрыты. Strict algorithm enforcement через JWSKeySelector.

**Tier 2 - допустимо с настройкой:**

`jsonwebtoken v9+` (Node.js) - после security rewrite нормально, но нужно явно указывать `algorithms` в `verify()`.

`PyJWT` (Python) - после фиксов нормально, но обязательно указывать `algorithms=["RS256"]` при decode.

`golang-jwt` (Go) - надежен, чистая CVE-история (только CVE-2025-30204 - DoS, CVSS 7.5). Но `WithValidMethods()` - opt-in. Без нее принимает алгоритм из токена.

`go-jose v4` (Go) - 5+ CVE в истории (включая critical invalid curve и CVE-2025-27144), но с v4 алгоритм обязателен при парсинге.

`Microsoft.IdentityModel.JsonWebTokens` (.NET) - замена устаревшему `System.IdentityModel.Tokens.Jwt`. Осторожно с дефолтами: `ValidAlgorithms=null` означает "все алгоритмы разрешены", а `ClockSkew=5 минут` - существенно больше типичных 60 секунд. Также CVE-2024-21319 - JWE decompression DoS.

**Tier 3 - опасно:**

`python-jose` - удалять немедленно. Мигрировать на joserfc или PyJWT.

`Authlib` (JWE-часть) - JWS нормальный (кроме v1.6.5-1.6.7 с alg:none), JWE опасен.

`System.IdentityModel.Tokens.Jwt` (.NET) - deprecated. Microsoft сама рекомендует миграцию.

## Fingerprinting: как определить библиотеку по токену

Не нужен доступ к исходному коду. Смотри на сам JWT.

**По размеру подписи** - определяем алгоритм (он и так виден в `alg` header, но размер подтверждает, что заголовок не подменён):
- ~342 символа Base64url (256 байт) - RS256 с RSA 2048
- ~86 символов (64 байта) - ES256 или EdDSA (Ed25519). Если Ed448 - 114 байт (~152 символа).
- ~43 символа (32 байта) - HS256
- 5 частей через точку - JWE (статья 10)
- Пустая третья часть - `alg:none` (статья 3)

**По порядку полей в header** - а вот это реально определяет библиотеку:

```bash
echo "$TOKEN" | cut -d. -f1 | tr -- '-_' '+/' | \
  awk '{while(length%4)$0=$0"=";print}' | base64 -d 2>/dev/null
```

PyJWT ставит `typ` первым: `{"typ":"JWT","alg":"HS256"}`. jsonwebtoken - `alg` первым: `{"alg":"HS256","typ":"JWT"}`. jose/panva может не включать `typ` вообще. Пассивный фингерпринт, работает без единого запроса к серверу.

**По issuer claim - определяем IdP, а через него - вероятный стек:**

Знать IdP ≠ знать библиотеку. Keycloak выпускает токен, но валидирует его твой бэкенд - на Python, Go или Node.js. Однако IdP сужает стек: Azure AD - скорее всего .NET, Keycloak - скорее всего Java, Firebase - скорее всего Node.js.

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

Каждый IdP оставляет характерные маркеры в claims:
- Auth0: claim `gty` (в native profile) + issuer `*.auth0.com`
- Okta: claims `cid`, `uid` + issuer `*.okta.com/oauth2/*`
- Azure AD: claims `tid`, `oid` + issuer `login.microsoftonline.com` (v2.0) или `sts.windows.net` (v1.0)
- Keycloak: claim `realm_access` с вложенным объектом ролей + issuer `*/realms/*`. Плюс нестандартный `typ: "Bearer"` в payload (не в header!)
- AWS Cognito: claims с префиксом `cognito:` + issuer `cognito-idp.*.amazonaws.com`
- Firebase: claim `firebase` с объектом `sign_in_provider`

**По формату ошибки** - отправь невалидный токен и посмотри на ответ:

В production ошибки обычно прячутся за generic 401, но на dev/staging бывает подробнее:

```bash
curl -s -H "Authorization: Bearer invalid" \
  https://target/api/ | head -5
# Java stack trace = Nimbus/jjwt
# "JsonWebTokenError: jwt malformed" = jsonwebtoken (Node.js)
# {"detail":"..."} в Django-формате = djangorestframework-simplejwt (обёртка над PyJWT)
```

## Что это значит для пентеста

Определил библиотеку - выбирай вектор атаки:

- **python-jose** - alg:none (статья 3), algorithm confusion (статья 4) на непропатченных версиях, JWE compression bomb
- **jsonwebtoken v8** - alg:none, algorithm confusion
- **Authlib + JWE** - Bleichenbacher oracle (статья 10), JWK header injection (статья 6), alg:none в v1.6.5-1.6.7
- **PyJWT < 2.4** - algorithm confusion через нестандартные форматы ключей
- **Nimbus < 9.37.2** - PBES2 DoS (статья 10)
- **jose/panva** - тут сложнее, фокусируйся на логических ошибках в приложении, а не в библиотеке

Библиотека Tier 1 не означает неуязвимость. Библиотека может быть идеальной, но разработчик забудет указать `algorithms` при вызове `verify()`. Или поставит `verify_signature=False` "для дебага" и забудет убрать.

## Что дальше

JWT сам по себе - одно. JWT внутри OAuth 2.0 с десятком микросервисов, тремя IdP и пятью типами токенов - совсем другое. В следующей статье - token confusion, cross-service relay, DPoP и реальные CVE в Keycloak и AWS.
