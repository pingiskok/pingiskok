---
title: "JWT, часть 18: Что вместо JWT - PASETO, Macaroons, opaque tokens и server-side sessions"
date: 2026-04-03T20:18:00+03:00
number: 18
tags: ["jwt", "security", "web", "auth"]
summary: "JWT не идеален — 70+ CVE за десять лет. Разбираем альтернативы: PASETO без поля alg, Macaroons с уникальным attenuation, opaque tokens с мгновенным отзывом, серверные сессии Google/Netflix. Для каждой — что ломать на пентесте."
---

**Содержание:**
- [Server-side sessions: не списывайте со счетов](#server-side-sessions-не-списывайте-со-счетов)
- [Opaque tokens + Token Introspection](#opaque-tokens--token-introspection)
- [PASETO - JWT без поля alg](#paseto---jwt-без-поля-alg)
- [Macaroons - суперспособность attenuation](#macaroons---суперспособность-attenuation)
- [Гибридный подход 2026 года](#гибридный-подход-2026-года)
- [Когда JWT - правильный выбор](#когда-jwt---правильный-выбор)
- [Сравнительная таблица](#сравнительная-таблица)
- [Итог](#итог)
- [Что дальше](#что-дальше)

17 статей мы ломали JWT. От `alg:none` до lattice-атак на ECDSA nonce. 70+ CVE за десять лет. Логичный вопрос - а что вместо?

## Server-side sessions: не списывайте со счетов

Google не использует JWT для аутентификации в браузере. Они используют server-side sessions. Opaque session ID в HttpOnly cookie. Данные пользователя в Redis. Netflix использует encrypted cookies + внутренний Passport-формат (HMAC-protected protobuf). GitHub хранит сессию в signed cookie Rails (`_gh_sess`). Детали реализации разные, суть одна: токен не содержит данных, сервер хранит состояние.

Почему серверные сессии до сих пор работают:

**Мгновенный отзыв.** Забанил пользователя - удалил сессию из Redis. Мгновенно. С JWT нужно ждать до exp или городить blacklist (что по сути возвращает нас к stateful-модели, от которой JWT должен был нас избавить).

**Защита от XSS-кражи токена.** Opaque session ID в HttpOnly cookie. JavaScript не может прочитать cookie через `document.cookie`. Сравни с JWT в localStorage из статьи 13 - одна строка JavaScript и полный захват. Но это **не** XSS-иммунность. Как я показывал в статье 13 (секция про HttpOnly cookies): same-origin XSS позволяет выполнять аутентифицированные запросы через fetch/XHR - браузер автоматически прикрепляет HttpOnly cookie. Атакующий не крадёт session ID, но действует от имени жертвы напрямую. Session riding, не session theft - но результат тот же.

**CSRF - фундаментальный tradeoff.** Cookie отправляется браузером автоматически с каждым запросом. Это то, что делает sessions удобными - и это же делает их уязвимыми к CSRF. JWT в Authorization header иммунен к CSRF: браузер не прикрепляет его автоматически. Переходишь с JWT на cookies - получаешь CSRF-проблему. Митигации: `SameSite=Lax` (дефолт с Chrome 80), `Secure`, `__Host-` prefix, CSRF-токены. Статья 13: «Для полной защиты нужен CSRF-токен даже при SameSite» (defense in depth).

**Session fixation.** Классическая уязвимость sessions, неприменимая к JWT. Атакующий устанавливает known session ID до аутентификации жертвы. Жертва логинится - если приложение не регенерирует session ID после логина, атакующий использует свой ID для hijacking. Защита: regenerate session ID при каждой смене уровня привилегий.

**Всегда свежие данные.** Роль пользователя изменилась? Сессия отражает изменение мгновенно. JWT хранит snapshot claims на момент выдачи - до exp роль не обновится.

"Не масштабируется!" - масштабируется. Redis Cluster тянет миллионы сессий. У Google и Netflix нет проблем с масштабом. Но Redis по умолчанию без аутентификации, данные не зашифрованы at rest. SSRF к `redis://` = dump всех сессий. Компрометация Redis = все сессии разом (хуже чем кража одного JWT).

## Opaque tokens + Token Introspection

Самая практичная JWT-альтернатива в существующей OAuth-инфраструктуре. Не требует нового формата токенов, не требует новых библиотек.

Вместо JWT access token Authorization Server выдаёт opaque string - случайный идентификатор без структуры. Resource Server не парсит и не валидирует токен сам. Вместо этого отправляет запрос к Authorization Server через **Token Introspection** (RFC 7662):

```
POST /introspect HTTP/1.1
Host: auth.megabank.example
Content-Type: application/x-www-form-urlencoded

token=dGhpcyBpcyBhbiBvcGFxdWUgdG9rZW4&
token_type_hint=access_token
```

Ответ содержит claims, но хранятся они на сервере, а не в токене:

```json
{
  "active": true,
  "sub": "admin",
  "scope": "read write",
  "exp": 1711700000
}
```

Spring Authorization Server, Keycloak, Auth0 поддерживают из коробки. Переключение с JWT на opaque tokens - часто одна строка в конфиге IdP.

**Что ломать:** introspection endpoint = high-value target. SSRF к нему = валидация произвольных токенов. Отсутствие аутентификации Resource Server при запросе к introspection = подмена ответа. Cache poisoning introspection responses = продление жизни отозванного токена. Нет офлайн-валидации - один point of failure.

## PASETO - JWT без поля alg

Помним фундаментальный дефект из первой статьи. Токен сам указывает серверу, как проверять подпись. Поле `alg` в заголовке - корень algorithm confusion (статья 4), корень `alg:none` (статья 3).

**PASETO** (Platform-Agnostic Security Tokens) - альтернативный формат, созданный специально для устранения этого дефекта. Нет поля `alg`. Нет заголовка с параметрами. Версия токена жёстко определяет все криптографические алгоритмы:

```
v4.public. - Ed25519 подпись, фиксировано
v4.local.  - XChaCha20 + BLAKE2b-MAC (Encrypt-then-MAC), фиксировано
```

Четыре версии PASETO: v1 (RSA+AES-CTR, deprecated), v2 (Ed25519+XChaCha20-Poly1305, deprecated), v3 (P-384+AES-256-CTR-HMAC, **NIST/FIPS-compliant**, current), v4 (Ed25519+XChaCha20+BLAKE2b, recommended). Если встретишь `v2.local.` или `v3.public.` - это легальные PASETO-токены, не ошибка. v3 критичен для government/regulated environments где требуется FIPS compliance.

Algorithm confusion через поле alg? Невозможна - поля нет. `alg:none`? Нет такого поля. Но "невозможна" - это про `alg`. Version downgrade (v1 вместо v4 при поддержке нескольких версий) и purpose confusion (local vs public) - реальные attack surfaces.

PASETO поддерживает `kid` в footer. Структура такая - `v4.public.<payload>.<footer>` где footer может содержать `{"kid":"..."}`. PASERK (Platform Agnostic Serialized Keys) стандартизирует формат kid. Критическая разница с JWT: kid не влияет на выбор алгоритма. А kid injection (SQLi, path traversal) из статьи 5? Возможна через footer - если сервер небезопасно использует kid.

```python
import pyseto
from pyseto import Key

key = Key.new(version=4, purpose="public",
              key=private_key_pem)
token = pyseto.encode(
    key,
    payload=b'{"sub":"admin","exp":"2026-04-01T00:00:00+00:00"}',
    footer=b'{"kid":"key-v4-001"}'
)
# Результат: b"v4.public...." - версия зашита в формат
```

Проблемы PASETO: экосистема в 1000 раз меньше JWT. Ни один крупный IdP (Auth0, Okta, Keycloak, Azure AD) не поддерживает PASETO. IETF draft истёк в 2022 году. И главное: PASETO stateless, а значит имеет **ту же проблему с revocation**, что и JWT. Мгновенный отзыв? Нет. Blacklist? Тот же костыль, что и с JWT.

**Что ломать:** version downgrade (заставь сервер принять v1 вместо v4), purpose confusion (local vs public), footer parsing vulnerabilities (kid injection, information disclosure в footer), claim validation bugs (пропущенная проверка exp, aud).

## Macaroons - суперспособность attenuation

Google Research, 2014. Macaroons умеют то, что JWT принципиально не может: **ослабление привилегий без обращения к серверу**.

Аналогия: представь пропуск в здание. С JWT ты получаешь пропуск "доступ ко всем этажам" и не можешь его ограничить - claims зафиксированы подписью. Хочешь выдать кому-то пропуск "только первый этаж"? Иди к охране за новым пропуском.

С Macaroons ты берёшь свой пропуск "все этажи" и **сам** ставишь печать "только первый этаж". Получатель может добавить ещё: "только с 9 до 17". Дальше: "только комната 101". Каждый может **ограничить** права, но не **расширить**. Секретный ключ сервера для этого не нужен.

Технически это работает через цепочку HMAC. Сервер создаёт корневой macaroon:

```
mac0 = HMAC(root_secret, identifier)
```

Добавление ограничения (caveat) не требует знания root_secret - только результата предыдущего HMAC:

```
mac1 = HMAC(mac0, "floor == 1")          # ограничил до 1 этажа
mac2 = HMAC(mac1, "time < 17:00")        # добавил ограничение по времени
```

Каждый следующий HMAC вычисляется от предыдущего, формируя криптографическую цепочку. Сервер пересчитывает цепочку от root_secret и сверяет результат. Расширить права невозможно: для этого нужно "отмотать" HMAC назад.

Это **first-party caveats** - ограничения, которые сервер проверяет сам. Macaroons также поддерживают **third-party caveats**: делегирование проверки внешнему сервису. "Этот macaroon валиден, если payment-service подтвердит оплату." Уникальная возможность, которой нет ни у JWT, ни у PASETO.

Fly.io построили авторизацию на Macaroons. Lightning Network (LND) использует Macaroons для **RPC-аутентификации**: admin.macaroon, invoice.macaroon, readonly.macaroon - три уровня доступа к API ноды. Микроплатежи работают через HTLCs и payment channels, не через Macaroons. Протокол L402 (бывш. LSAT) комбинирует Macaroons + Lightning invoices для pay-per-request API, но это отдельный протокол.

Стандартизации нет - ни RFC, ни IETF draft. Библиотеки существуют, но не для каждого языка.

**Что ломать:** Macaroon - bearer token: украл = используешь. Нет встроенного `exp` - если не добавлен time-based caveat, macaroon живёт вечно. Компрометация root key = все derived macaroons скомпрометированы (хуже чем один JWT, потому что ослабленные macaroons раздаются третьим лицам). Caveat bypass: если сервер некорректно парсит строку caveat, можно обойти ограничение. Third-party caveat discharge theft: перехват discharge macaroon = доступ. Scope escalation через reorder или injection в caveat string.

## Гибридный подход 2026 года

На практике в 2026 году чаще всего я вижу гибридную архитектуру:

**Server-side session + short-lived JWT.**

1. Браузер хранит session ID в HttpOnly cookie (защита от XSS-кражи, но нужен SameSite + CSRF-токен)
2. При API-запросе frontend получает короткоживущий JWT (5 минут) через session-to-JWT exchange endpoint
3. JWT передаётся микросервисам, которые валидируют его без центрального хранилища
4. Нужен отзыв? Инвалидируем сессию. Следующий обмен session-to-JWT вернёт ошибку. Максимальная задержка - 5 минут (время жизни текущего JWT)

Это даёт лучшее из обоих миров: stateless-валидацию для микросервисов и быстрый отзыв на уровне session gateway.

**Что ломать:** session-to-JWT exchange endpoint - самая ценная цель. Компрометация = генерация JWT для любой сессии. Race conditions при параллельных exchange-запросах. 5 минут после отзыва - это не «небольшая задержка». За 5 минут атакующий с admin-JWT: эксфильтрирует данные, создаёт backdoor-аккаунты, модифицирует ACL. PCI-DSS и HIPAA могут требовать мгновенный terminate привилегированного доступа. Критические операции (смена пароля, перевод денег) должны проверять сессию в реальном времени, не полагаясь на JWT claims. Stale claims в микросервисах: роль отозвана, но текущий JWT всё ещё говорит `"role":"admin"`.

## Когда JWT - правильный выбор

JWT **хорош** для:
- Cross-domain авторизации (OAuth 2.0, OIDC)
- Микросервисов без прямого канала к IdP
- Short-lived tokens (5-15 минут) + refresh token
- API-ключей для machine-to-machine
- Федеративной идентификации (несколько IdP)

JWT **плох** для:
- Браузерных сессий в monolith-приложениях
- Хранения в localStorage (статья 13)
- Случаев, когда нужен мгновенный отзыв
- Long-lived токенов без refresh flow

## Сравнительная таблица

| Критерий | JWT | PASETO | Macaroons | Server-side sessions | Opaque + Introspection |
|----------|-----|--------|-----------|---------------------|----------------------|
| Мгновенный отзыв | Нет (blacklist) | Нет (blacklist) | Нет (нет exp) | Да | Да |
| XSS-кража (localStorage) | Да | Да | N/A | Нет (HttpOnly) | Нет (HttpOnly) |
| CSRF risk | Нет (Authorization header) | Нет (Authorization header) | Зависит | Да (cookie) | Зависит |
| Algorithm confusion | Да | Нет (нет alg) | N/A | N/A | N/A |
| Офлайн-валидация | Да | Да | Да | Нет | Нет |
| Attenuation | Нет | Нет | Да | N/A | N/A |
| Экосистема | Огромная | Минимальная | Минимальная | Зрелая | OAuth-стек |
| Стандарт | RFC 7519 | Expired draft | Нет | Нет (framework) | RFC 7662 |

## Итог

JWT не идеален. 70+ CVE. Фундаментальные дефекты дизайна. Но он встроен в каждый API на планете и никуда не денется. Альтернативы существуют: PASETO устраняет algorithm confusion, Macaroons дают уникальный attenuation, opaque tokens дают мгновенный отзыв без нового формата, серверные сессии остаются надёжным выбором для браузеров. Но ни одна альтернатива не имеет экосистему JWT.

Для пентестера: встретил PASETO - ищи version downgrade, purpose confusion, kid injection в footer. Встретил Macaroons - ищи caveat bypass, отсутствие time-based caveat, discharge theft. Встретил гибрид session+JWT - бей в exchange endpoint и эксплуатируй 5-минутное окно после отзыва. Встретил opaque tokens - ищи SSRF к introspection endpoint. У каждой альтернативы своя attack surface.

Правильный подход: понимать ограничения JWT, выбирать подходящий инструмент для конкретной задачи, и если используешь JWT - настраивать правильно (об этом следующая статья про RFC 8725).

## Что дальше

Мы атаковали. Теперь - как защититься. RFC 8725 - пятнадцать конкретных правил безопасности JWT от авторов стандарта (двенадцать оригинальных плюс три из bis-обновления 2026 года). Для каждого правила я покажу, какую атака из нашей серии оно предотвращает.
