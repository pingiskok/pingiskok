---
title: "JWT, часть 20: Постквантовый JWT и будущее токенов"
date: 2026-04-03T20:20:00+03:00
number: 20
tags: ["jwt", "security", "web", "auth"]
summary: "Финал серии. Алгоритм Шора ломает все асимметричные JWT-алгоритмы. ML-DSA подписи по 2.4 KB не влезают в cookie. SD-JWT для selective disclosure. Harvest Now, Decrypt Later — почему миграция JWE на постквантовую криптографию нужна уже сейчас."
---

Финал серии. Двадцать статей (почти), от разбора токена побайтово до lattice-атак на ECDSA. В этой последней статье - что ждет JWT в ближайшие годы. Постквантовая криптография, размеры подписей, Selective Disclosure JWT - и итоги серии.

## Зачем нужен постквантовый JWT

Алгоритм Шора полностью ломает RSA и ECDSA. Все асимметричные JWT-алгоритмы, которые мы разбирали в этой серии - RS256, PS256, ES256, EdDSA - уязвимы перед достаточно мощным квантовым компьютером. HS256 теряет половину стойкости из-за алгоритма Гровера, но 128 бит квантовой безопасности все еще хватает - при условии полноэнтропийного 256-битного ключа из CSPRNG. Слабый пароль из статьи 7 Гровер ломает ещё быстрее.

Большинство экспертов оценивают появление квантовых компьютеров достаточной мощности для взлома RSA-2048 и ECDSA P-256 на начало-середину 2030-х (оценки варьируются). NSA в рамках CNSA 2.0 требует полный переход на постквантовую криптографию к 2035 году для систем национальной безопасности.

Это не академическая проблема "через 50 лет". Это проблема ближайшего десятилетия.

## Три новых стандарта NIST (август 2024)

13 августа 2024 года NIST опубликовал три финальных стандарта постквантовой криптографии, завершив восьмилетний процесс отбора и анализа:

**FIPS 203 - ML-KEM** (стандартизирован на основе CRYSTALS-Kyber, с модификациями) - механизм инкапсуляции ключей. Замена для ECDH-ES и RSA-OAEP в JWE. Защищает шифрование.

**FIPS 204 - ML-DSA** (стандартизирован на основе CRYSTALS-Dilithium, с модификациями) - цифровая подпись. Замена для RS256, PS256, ES256 в JWS. Защищает подпись.

**FIPS 205 - SLH-DSA** (основан на SPHINCS+) - хеш-основанная подпись. Единственный PQC-стандарт, безопасность которого не зависит от lattice-задач - NIST стандартизировал его для разнообразия математических предположений. Медленный, но основан на минимальных допущениях (стойкость хеш-функции).

Плюс **FIPS 206 - FN-DSA** (основан на FALCON) ожидается в конце 2026 - начале 2027 - самые компактные постквантовые подписи.

IETF уже разрабатывает интеграцию: draft-ietf-cose-dilithium для ML-DSA, draft-ietf-cose-sphincs-plus для SLH-DSA, draft-ietf-cose-falcon для FN-DSA (все три покрывают и JOSE, и COSE несмотря на `cose` в названии).

## Размеры - главная проблема

Вот где постквантовая криптография ломает привычные рамки:

```
Алгоритм         Размер подписи   В Base64url

ES256             64 байта         ~86 символов
RS256             256 байт         ~342 символа
EdDSA (Ed25519)   64 байта         ~86 символов
ML-DSA-44         2,420 байт       ~3.2 KB
ML-DSA-65         3,309 байт       ~4.4 KB
FN-DSA-512        666 байт         ~888 символов
SLH-DSA-128s      7,856 байт       ~10.5 KB
```

ML-DSA-44 (NIST Security Category 2) дает подпись в 2,420 байт. Для сравнения: ES256 - 64 байта. Разница в 38 раз.

Что это значит на практике:
- JWT с ML-DSA-44 весит ~3.5 KB. Лимит HTTP cookie - 4 KB. На грани.
- JWT с ML-DSA-65 (NIST Category 3) - ~4.5 KB. Уже не влезает в cookie.
- SLH-DSA-128s - ~10.5 KB только подпись. Без шансов.
- FN-DSA-512 - ~888 символов в Base64url. Единственный PQC, комфортно влезающий в cookie. Но стандарт еще не готов.

HTTP headers тоже трещат: Nginx по умолчанию 8 KB на одну header line (`large_client_header_buffers`). JWT на 4+ KB в `Authorization: Bearer` - это половина лимита на один токен.

## Harvest Now, Decrypt Later

Государственные акторы уже перехватывают и сохраняют зашифрованный трафик. Когда появится квантовый компьютер - расшифруют все, что было перехвачено.

Для JWE (атаки на которые мы разбирали в статье 10) это критично: токены с RSA-OAEP или ECDH-ES, содержащие долгосрочные секреты (медицинские данные, финансовые транзакции), могут быть раскрыты через 10-15 лет.

Для JWS (подписи) угроза меньше - подделка подписи актуальна только в момент атаки. Через 10 лет подделанный токен с истекшим `exp` бесполезен (при условии, что `exp` проверяется и токен short-lived - а мы знаем из этой серии, что это далеко не всегда так).

Приоритет миграции: **JWE сначала, JWS потом.**

AWS KMS уже поддерживает ML-DSA. Google Cloud KMS - в preview. Инструментарий появляется: OpenSSL 3.5 с oqs-provider позволяет генерировать ML-DSA ключи из CLI, liboqs (Open Quantum Safe) - reference-реализация для интеграции.

## SD-JWT: Selective Disclosure

Параллельная эволюция JWT, не связанная с квантовой угрозой. Вспомни статью 2: payload JWT не зашифрован, все claims читаются через Base64url-декодирование. Каждый, кто видит токен, видит ВСЕ данные.

**SD-JWT** (Selective Disclosure JWT, RFC 9901) решает эту проблему: показывай только нужные claims. Доказать, что тебе больше 18, не раскрывая дату рождения. Показать имя без email-а. Предъявить город без полного адреса.

Технически: каждый selectively-disclosable claim заменяется дайджестом Disclosure - Base64url-encoded JSON-массива `[salt, claim_name, claim_value]`. Дайджесты хранятся в массиве `_sd` в payload JWT. При предъявлении держатель добавляет нужные Disclosures через tilde-разделитель: `<JWT>~<Disclosure1>~<Disclosure2>~`. Верификатор пересчитывает хеш каждого Disclosure и сверяет с `_sd`. Key Binding JWT привязывает предъявление к конкретному holder'у.

SD-JWT - один из ключевых форматов европейского EUDI Wallet (цифровой кошелек для ID). Множество классов атак описаны в RFC 9901 Section 11: recovery low-entropy claims через радужные таблицы на хеши, replay без Key Binding, disclosure manipulation, salt entropy guessing, credential forwarding. Каждый класс - потенциальный вектор на реальном engagement'е.

## Hybrid/composite signatures

Переход на PQC не будет мгновенным. Главная стратегия transition period: **hybrid (composite) signatures** - одновременное использование классического и постквантового алгоритма. Одна подпись = Ed25519 + ML-DSA-44. Если через 5 лет lattice-криптография окажется уязвимой - classical подпись защищает. Если завтра появится квантовый компьютер - PQC подпись защищает.

IETF разрабатывает draft-ietf-lamps-pq-composite-sigs для стандартизации. Для JWT это означает что новый `alg` identifier в JOSE, увеличенный размер подписи (сумма обеих), две верификации вместо одной.

Для пентестера: hybrid mode создает новые attack surfaces. Что если сервер принимает токен, подписанный только одним из двух алгоритмов? Partial verification bypass - классическая ошибка при внедрении composite signatures.

## Что ломать: PQC attack surface

Постквантовые JWT пока не в production. Но transition period уже начался, и вот что тестировать:

**Algorithm downgrade.** Сервер поддерживает и RS256, и ML-DSA-44. Атакующий отправляет токен с `alg:RS256` - сервер принимает? Это та же algorithm confusion из статьи 4, но в новом контексте. Если JWKS содержит ключи обоих типов без strict binding алгоритма к ключу - downgrade возможен.

**Implementation timing.** PQC-реализации immature. KyberSlash (2024) - timing vulnerability в reference-реализации ML-KEM. FN-DSA требует FFT-based Gaussian sampling - сложная операция, уязвимая к timing side-channels. Именно поэтому NIST задержал FIPS 206. Для пентестера: timing-тесты на PQC endpoints, fingerprinting PQC-библиотек через response time variance.

**Key confusion.** В transition period JWKS может содержать RSA, EC и ML-DSA ключи одновременно. kid collision между classical и PQC ключами, неправильный маппинг kid - algorithm - те же атаки из статей 5-6, новый контекст.

```bash
# Генерация ML-DSA ключей через OpenSSL 3.5 + oqs-provider
openssl genpkey -algorithm ml-dsa-44 -out ml-dsa-44-private.pem
openssl pkey -in ml-dsa-44-private.pem -pubout -out ml-dsa-44-public.pem

# Размер публичного ключа - 1,312 байт (vs 294 для RSA-2048)
openssl pkey -in ml-dsa-44-public.pem -pubin -text -noout | head -5
```

## Что делать сейчас

Подготовка к постквантовому переходу - не через 10 лет, а сейчас:

**Для разработчиков:**

1. **Crypto agility на сервере** - алгоритмы конфигурируемые серверно (не клиентом! RFC 8725 3.1 запрещает доверять `alg` из токена - статья 19). Когда ML-DSA-44 будет готов для продакшна, замена RS256 должна быть сменой конфига.

2. **Подготовить JWKS к большим ключам.** ML-DSA-44 публичный ключ - 1,312 байт (vs 294 байта для RSA-2048). JWKS endpoint должен отдавать это без проблем.

3. **Увеличить лимиты HTTP headers.** Nginx `large_client_header_buffers`, Node.js `--max-http-header-size`. JWT в 4+ KB - новая реальность.

4. **Рассмотреть JWT в HTTP body вместо header.** Если токен не влезает в `Authorization: Bearer`, передавать в теле POST-запроса.

**Для пентестеров:**

5. **Оценивать PQC readiness.** Поддерживает ли target crypto agility? Захардкожен ли RS256? JWKS endpoint готов к большим ключам? Findings: «No algorithm agility - hardcoded RS256», «JWKS endpoint rejects keys > 1 KB». Severity в 2026: LOW-MEDIUM (informational/future risk). Для систем с HNDL-sensitive данными (медицина, финансы, государство): повышай до MEDIUM-HIGH.

6. **Фреймить HNDL risk.** В отчете «JWE tokens encrypted with RSA-OAEP are vulnerable to Harvest Now, Decrypt Later. Intercepted tokens containing [medical records / financial data] may be decryptable within 10-15 years. Recommend migration to ML-KEM for JWE key establishment.»

## Закрытие серии

Двадцать статей (почти). От анатомии JWT до постквантовой криптографии.

Вот что мы прошли:

**Фундамент:** почему JWT дырявый по дизайну, структура токена побайтово, все claims и параметры заголовка.

**Классические атаки:** alg:none, algorithm confusion, kid injection (path traversal, SQLi, command injection), jku/x5u/jwk/x5c header injection, GPU-брутфорс секретов, psychic signatures на Java.

**Криптография:** HMAC, RSA, ECDSA, nonce reuse, EdDSA. JWE: invalid curve attack, Bleichenbacher oracle, AES-GCM IV reuse, JWE-JWS confusion, padding oracle, PBES2 DoS.

**Экосистема:** рейтинг библиотек, OAuth/OIDC token confusion и cross-realm атаки, XSS + JWT = account takeover, lattice-атаки на ECDSA nonce, side-channel attacks, fault injection.

**Практика:** захардкоженные секреты.

**Защита и будущее:** альтернативы JWT, RFC 8725 чеклист, постквантовая криптография.

JWT - не идеальный стандарт. Десятки CVE за десять лет. Один и тот же баг (algorithm confusion) переоткрывается каждые два года. Но JWT встроен в каждый API на планете и никуда не денется.

Спасибо всем, кто дочитал серию до конца. Буду доволен если вы остались довольны после прочтения!
