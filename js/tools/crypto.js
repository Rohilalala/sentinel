/* Sentinel tool file: Hash & Encode. Registers with the core; pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, loading, demoButton, badge } = S.ui;
const resolveA = n => api.resolveA(n);
S.register({ id:'toolkit', name:'Hash & Encode', group:'Crypto', icon:'tool', tag:'local',
  tile:'Hashing, Base64/hex/URL, ROT13 and a JWT decoder — the everyday crypto bench, fully offline.',
  blurb:'Convert, hash and decode data locally. Nothing here touches the network — it all runs in your browser.',
  why:`Half of practical security is reading data in the right encoding. ${t('hash','Hashes')} verify integrity and store passwords; ${t('Base64')} hides in tokens and data URLs (it is not encryption!); a ${t('JWT')}'s payload is just Base64 anyone can read. Knowing these on sight is a core skill.`,
  render(mount){
    mount.innerHTML=`<div class="grid">
      <div class="card full"><h2>${t('hash','Hash')} (SHA, live)</h2>
        <textarea id="hin" rows="2" style="width:100%;font:14px var(--mono)" placeholder="type anything…">hello</textarea>
        <div class="kv" style="margin-top:10px">
          <div class="k">${t('SHA-256')}</div><div class="v" id="h256"></div>
          <div class="k">SHA-1</div><div class="v" id="h1"></div>
          <div class="k">SHA-512</div><div class="v" id="h512" style="font-size:12px"></div></div></div>

      <div class="card"><h2>${t('Base64')}</h2>
        <textarea id="b64in" rows="3" style="width:100%;font:14px var(--mono)" placeholder="plain text"></textarea>
        <div class="bar" style="margin:8px 0"><button class="btn ghost" id="b64e">Encode →</button><button class="btn ghost" id="b64d">← Decode</button></div>
        <textarea id="b64out" rows="3" style="width:100%;font:14px var(--mono)" placeholder="base64"></textarea></div>

      <div class="card"><h2>URL · Hex · ROT13</h2>
        <textarea id="xin" rows="3" style="width:100%;font:14px var(--mono)" placeholder="input">Hello, World!</textarea>
        <div class="bar" style="margin:8px 0;gap:6px">
          <button class="btn ghost" data-x="urle">URL enc</button><button class="btn ghost" data-x="urld">URL dec</button>
          <button class="btn ghost" data-x="hexe">→ Hex</button><button class="btn ghost" data-x="hexd">Hex →</button>
          <button class="btn ghost" data-x="rot">ROT13</button></div>
        <textarea id="xout" rows="3" style="width:100%;font:14px var(--mono)" placeholder="output"></textarea></div>

      <div class="card"><h2>Subnet / CIDR calculator</h2>
        <input id="cidrin" style="width:100%" placeholder="192.168.1.0/24" value="10.0.0.0/24">
        <div class="kv" id="cidrout" style="margin-top:12px"></div></div>

      <div class="card full"><h2>${t('JWT')} decoder</h2>
        <textarea id="jin" rows="3" style="width:100%;font:13px var(--mono)" placeholder="paste a JWT: header.payload.signature"></textarea>
        <div class="grid two" style="margin-top:10px">
          <div><div class="mut" style="font-size:12px;margin-bottom:4px">HEADER</div><pre id="jh" class="mono" style="background:var(--surface-2);padding:10px;border-radius:7px;overflow:auto;margin:0;font-size:12px"></pre></div>
          <div><div class="mut" style="font-size:12px;margin-bottom:4px">PAYLOAD</div><pre id="jp" class="mono" style="background:var(--surface-2);padding:10px;border-radius:7px;overflow:auto;margin:0;font-size:12px"></pre></div>
        </div>
        <div class="mut" style="font-size:12px;margin-top:8px">${svg('info')} The signature is NOT verified here — the payload is readable because it is only ${t('Base64')}, not encrypted. Never put secrets in a JWT payload.</div></div>
    </div>`;
    wireToolkit(mount);
  }});
const b64enc=s=>btoa(String.fromCharCode(...new TextEncoder().encode(s)));
const b64dec=s=>new TextDecoder().decode(Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)));
const rot13=s=>s.replace(/[a-z]/gi,c=>String.fromCharCode((c<='Z'?90:122)>=(c=c.charCodeAt(0)+13)?c:c-26));
function cidrInfo(s){
  const m=(s||'').trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/); if(!m) return null;
  const o=m.slice(1,5).map(Number), bits=+m[5];
  if(o.some(x=>x>255)||bits>32) return null;
  const ip=((o[0]<<24)|(o[1]<<16)|(o[2]<<8)|o[3])>>>0;
  const mask=bits===0?0:(0xffffffff<<(32-bits))>>>0;
  const net=(ip&mask)>>>0, bc=(net|(~mask>>>0))>>>0, toIp=n=>[n>>>24,(n>>16)&255,(n>>8)&255,n&255].join('.');
  const total=2**(32-bits);
  return {network:toIp(net),broadcast:toIp(bc),mask:toIp(mask),bits,
    first:toIp(bits>=31?net:net+1),last:toIp(bits>=31?bc:bc-1),
    total,usable:bits===32?1:bits===31?2:Math.max(total-2,0)};
}
const toHex=s=>[...new TextEncoder().encode(s)].map(b=>b.toString(16).padStart(2,'0')).join(' ');
const fromHex=s=>new TextDecoder().decode(Uint8Array.from(s.trim().split(/\s+/).filter(Boolean),h=>parseInt(h,16)));
function wireToolkit(m){
  const hin=$('#hin',m);
  const rehash=async()=>{ const v=hin.value; $('#h256',m).textContent=await S.sha('SHA-256',v);
    $('#h1',m).textContent=await S.sha('SHA-1',v); $('#h512',m).textContent=await S.sha('SHA-512',v); };
  hin.addEventListener('input',rehash); rehash();
  $('#b64e',m).onclick=()=>{ try{$('#b64out',m).value=b64enc($('#b64in',m).value);}catch(e){S.toast('encode failed');} };
  $('#b64d',m).onclick=()=>{ try{$('#b64in',m).value=b64dec($('#b64out',m).value);}catch(e){S.toast('not valid Base64');} };
  m.querySelectorAll('[data-x]').forEach(b=>b.onclick=()=>{ const i=$('#xin',m).value,o=$('#xout',m);
    try{ o.value={urle:encodeURIComponent(i),urld:decodeURIComponent(i),hexe:toHex(i),hexd:fromHex(i),rot:rot13(i)}[b.dataset.x]; }
    catch(e){ S.toast('conversion failed'); } });
  const ci=$('#cidrin',m), co=$('#cidrout',m);
  const recidr=()=>{ const r=cidrInfo(ci.value); co.innerHTML = r ?
    `<div class="k">Network</div><div class="v">${r.network}/${r.bits}</div>
     <div class="k">Netmask</div><div class="v">${r.mask}</div>
     <div class="k">Broadcast</div><div class="v">${r.broadcast}</div>
     <div class="k">Host range</div><div class="v">${r.first} – ${r.last}</div>
     <div class="k">Usable hosts</div><div class="v">${r.usable.toLocaleString()} <span class="mut">of ${r.total.toLocaleString()}</span></div>`
    : `<div class="k">—</div><div class="v mut">enter an IPv4 CIDR, e.g. 192.168.1.0/24</div>`; };
  ci.addEventListener('input',recidr); recidr();
  const ji=$('#jin',m); ji.addEventListener('input',()=>{ const parts=ji.value.trim().split('.');
    const show=(el,p)=>{ try{ $(el,m).textContent=JSON.stringify(JSON.parse(b64dec(p)),null,2);}catch(e){ $(el,m).textContent=p?'(invalid)':''; } };
    show('#jh',parts[0]); show('#jp',parts[1]); });
}
Object.assign(S.lib, { cidrInfo, b64enc, b64dec, rot13, toHex, fromHex });

})();
