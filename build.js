// 평문 원본을 AES-256-GCM 으로 암호화해 index.html(로더) 를 만든다.
// 평문은 저장소 밖에 둔다.  사용: node build.js   (비밀번호는 숨김 입력)
const fs = require('fs'), crypto = require('crypto'), readline = require('readline');

const SRC = process.env.SRC || `${process.env.HOME}/home/.osaka-kyoto-private/index.html`;
const ITER = 600000;                       // OWASP 권고치
// 평문에서 무작위 조각을 뽑아 산출물에 섞여 나갔는지 검사한다 (스크립트에 평문을 남기지 않기 위함)

function askHidden(q) {                    // 셸 히스토리·프로세스 환경에 남기지 않는다
  return new Promise(res => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const onData = c => { if (![10,13,4].includes(c[0])) process.stdout.write('\x1B[2K\x1B[200D' + q); };
    process.stdin.on('data', onData);
    rl.question(q, a => { process.stdin.off('data', onData); rl.close(); process.stdout.write('\n'); res(a); });
  });
}

(async () => {
  const pw = (process.env.PW || await askHidden('비밀번호: ')).normalize('NFC');
  if (pw.length < 12) { console.error('비밀번호가 너무 짧습니다'); process.exit(1); }

  const plain = fs.readFileSync(SRC);
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(pw, salt, ITER, 32, 'sha256');
  const c = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);   // WebCrypto: ciphertext || tag

  // 왕복 검증 — 복호화해서 원문과 바이트 단위로 같은지 확인
  const dc = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  dc.setAuthTag(ct.subarray(ct.length - 16));
  const back = Buffer.concat([dc.update(ct.subarray(0, ct.length - 16)), dc.final()]);
  if (!back.equals(plain)) { console.error('왕복 검증 실패'); process.exit(1); }

  const P = JSON.stringify({ s: salt.toString('base64'), i: iv.toString('base64'),
                             c: ct.toString('base64'), n: ITER });

  const SCRIPT = `
const P=${P};
const d=s=>Uint8Array.from(atob(s),x=>x.charCodeAt(0));
async function unlock(pw){
  const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw.normalize('NFC')),'PBKDF2',false,['deriveKey']);
  const k=await crypto.subtle.deriveKey({name:'PBKDF2',salt:d(P.s),iterations:P.n,hash:'SHA-256'},
    km,{name:'AES-GCM',length:256},false,['decrypt']);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:d(P.i),tagLength:128},k,d(P.c));
  return new TextDecoder().decode(pt);
}
function render(html){
  const doc=new DOMParser().parseFromString(html,'text/html');
  doc.querySelectorAll('script,iframe,object,embed,base').forEach(n=>n.remove());
  doc.querySelectorAll('*').forEach(n=>[...n.attributes].forEach(a=>{
    if(/^on/i.test(a.name)||/^\\s*javascript:/i.test(a.value)) n.removeAttribute(a.name);}));
  document.replaceChild(doc.documentElement,document.documentElement);
  scrollTo(0,0);
}
const F=document.getElementById('f'),B=document.getElementById('b'),E=document.getElementById('e');
F.addEventListener('submit',async ev=>{
  ev.preventDefault(); B.disabled=true; B.textContent='여는 중…'; E.textContent='';
  try{
    const pw=document.getElementById('p').value;
    const html=await unlock(pw);
    if(document.getElementById('r').checked) sessionStorage.setItem('ok',pw);
    render(html);
  }catch(_){ E.textContent='비밀번호가 맞지 않습니다'; B.disabled=false; B.textContent='열기';
    document.getElementById('p').select(); }
});
(async()=>{const s=sessionStorage.getItem('ok');
  if(s){try{render(await unlock(s));}catch(_){sessionStorage.removeItem('ok');}}})();`;

  const hash = crypto.createHash('sha256').update(SCRIPT, 'utf8').digest('base64');
  const CSP = `default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; ` +
              `script-src 'sha256-${hash}'; object-src 'none'; base-uri 'none'; form-action 'none'`;

  const out = `<!DOCTYPE html>
<html lang="ko"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${CSP}">
<title>OSAKA &amp; KYOTO</title>
<meta name="robots" content="noindex,nofollow">
<meta property="og:type" content="website">
<meta property="og:title" content="OSAKA &amp; KYOTO">
<meta property="og:description" content="비밀번호가 필요한 페이지입니다.">
<meta property="og:image" content="https://jiyolla.github.io/osaka-kyoto-2026/og.png">
<meta property="og:url" content="https://jiyolla.github.io/osaka-kyoto-2026/">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
<meta name="theme-color" content="#1c1917">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
 font-family:-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Pretendard",sans-serif;
 background:linear-gradient(135deg,#1c1917 0%,#3f2e28 55%,#7c2d12 100%);color:#fff}
.box{width:100%;max-width:340px;text-align:center}
svg{width:56px;height:56px;margin:0 auto 22px;display:block;opacity:.9}
h1{font-size:24px;font-weight:800;letter-spacing:-.02em;margin-bottom:7px}
p{font-size:13.5px;opacity:.6;margin-bottom:24px}
input[type=password]{width:100%;padding:14px 16px;font-size:16px;border-radius:11px;
 border:1px solid rgba(255,255,255,.22);background:rgba(255,255,255,.1);color:#fff;text-align:center;outline:none}
input[type=password]::placeholder{color:rgba(255,255,255,.4)}
input[type=password]:focus{border-color:#f59e0b;background:rgba(255,255,255,.15)}
button{width:100%;margin-top:10px;padding:14px;font-size:15px;font-weight:700;border:0;
 border-radius:11px;background:#f59e0b;color:#1c1917;cursor:pointer}
button:disabled{opacity:.55}
.e{margin-top:14px;font-size:13px;color:#fca5a5;min-height:19px}
label{display:flex;align-items:center;justify-content:center;gap:7px;margin-top:16px;font-size:12.5px;opacity:.55}
</style></head><body>
<div class="box">
  <svg viewBox="0 0 32 32"><g fill="#f59e0b">
  <rect x="2.4" y="5.2" width="27.2" height="3.4" rx="1.3"/><rect x="5.8" y="12.6" width="20.4" height="2.7" rx="1"/>
  <path d="M9.9 8.6 L13.2 8.6 L12.4 27.2 L8.5 27.2 Z"/><path d="M18.8 8.6 L22.1 8.6 L23.5 27.2 L19.6 27.2 Z"/></g></svg>
  <h1>OSAKA &amp; KYOTO</h1><p>비밀번호를 입력하세요</p>
  <form id="f"><input id="p" type="password" placeholder="비밀번호" autocomplete="off"
   autocapitalize="off" autocorrect="off" spellcheck="false" autofocus>
  <button id="b" type="submit">열기</button>
  <label><input type="checkbox" id="r"> 이 탭에서만 기억</label></form>
  <div class="e" id="e"></div>
</div>
<script>${SCRIPT}</script></body></html>
`;
  const txt = plain.toString('utf8');
  for (let i = 0; i < 24; i++) {
    const at = crypto.randomInt(0, Math.max(1, txt.length - 40));
    const probe = txt.slice(at, at + 40);
    if (probe.trim().length > 20 && out.includes(probe)) { console.error('평문 누출 감지'); process.exit(1); }
  }
  fs.writeFileSync('index.html.tmp', out);
  fs.renameSync('index.html.tmp', 'index.html');
  console.log(`index.html · 평문 ${(plain.length/1024)|0}KB → 암호문 ${(ct.length/1024)|0}KB · PBKDF2 ${ITER.toLocaleString()}회`);
  console.log(`왕복 검증 통과 · 평문 sentinel 검사 통과 · CSP script hash ${hash.slice(0,12)}…`);
})();
