/* Sentinel tool file: Credentials. Registers with the core; pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, loading, demoButton, badge } = S.ui;
const resolveA = n => api.resolveA(n);
S.register({ id:'pwned', name:'Password Exposure', group:'Credentials', icon:'key',
  tile:'Check if a password appears in known breaches — safely, without ever sending it.',
  blurb:'Test any password against billions of breached credentials using privacy-preserving k-anonymity.',
  why:`Attackers don't guess passwords, they reuse ones leaked in a ${t('breach')}. If your password appears in "Have I Been Pwned", it is already in attackers' wordlists. This checks using ${t('k-anonymity')}: your password is hashed in your browser and only the first 5 characters of the hash are ever sent.`,
  render(mount){
    const {out}=searchTool(mount,{ placeholder:'type a password to test', type:'password', wide:true, cta:'Check safely',
      examples:['password123','Tr0ub4dour&3'],
      demo:{ input:'password123', narrate:'Hashing in-browser, sending only 5 hex chars, matching the rest locally. Nothing secret leaves this page.' },
      run:runPwned });
  }});
async function runPwned(pw,out){
  loading(out); S.say('Hashing locally…');
  try{
    const hex=(await S.sha('SHA-1',pw)).toUpperCase();
    const prefix=hex.slice(0,5), suffix=hex.slice(5);
    S.say(`Sending only ${prefix}… (k-anonymity)`);
    const body=await api.hibpRange(prefix);
    const hit=body.split('\n').map(l=>l.trim().split(':')).find(([suf])=>suf===suffix);
    const count=hit?parseInt(hit[1],10):0;
    const str=strength(pw);
    const cls=count?'danger':(str.score<3?'warn':'safe');
    out.innerHTML=`
      <div class="card verdict ${cls} full"><h2>Breach check</h2>
        <div class="big">${svg(count?'x':'check')}${count?`Seen ${count.toLocaleString()} times`:'Not found in breaches'}</div>
        <div class="sub">${count?`This exact password appears in <b>${count.toLocaleString()}</b> known ${t('breach','breaches')}. Never use it — attackers try leaked passwords first.`:`This password wasn't in the ${t('breach','breach')} corpus. That doesn't mean it's strong — see below.`}</div></div>
      <div class="card"><h2>Strength</h2>
        <div class="meter"><i style="width:${(str.score+1)*20}%;background:${str.color}"></i></div>
        <div class="mut" style="font-size:13px">${str.label} · ${pw.length} chars · ${str.bits} bits of entropy (rough)</div>
        <ul class="signals" style="margin-top:10px">${str.tips.map(x=>`<li>${svg('info')}<span>${x}</span></li>`).join('')}</ul></div>
      <div class="card"><h2>How this stayed private</h2><div class="sub" style="color:var(--muted)">
        SHA-1 of your password = <span class="mono">${prefix}…</span><br>Only those first 5 chars were sent. The server returned ${body.split('\n').length} candidate suffixes; the match happened here in your browser. The server never learned which one was yours — that's ${t('k-anonymity')}.</div></div>`;
    S.say('');
  }catch(e){ out.innerHTML=''; S.say('⚠ '+e.message,true); }
}
function strength(pw){
  const sets=[/[a-z]/,/[A-Z]/,/\d/,/[^A-Za-z0-9]/].filter(r=>r.test(pw)).length;
  const pool=[/[a-z]/.test(pw)&&26,/[A-Z]/.test(pw)&&26,/\d/.test(pw)&&10,/[^A-Za-z0-9]/.test(pw)&&33].filter(Boolean).reduce((a,b)=>a+b,0)||1;
  const bits=Math.round(pw.length*Math.log2(pool));
  let score=0; if(pw.length>=8)score++; if(pw.length>=12)score++; if(sets>=3)score++; if(sets>=4&&pw.length>=14)score++;
  if(/^(password|123456|qwerty|admin)/i.test(pw))score=0;
  const labels=['very weak','weak','fair','strong','very strong'];
  const colors=['var(--danger)','var(--danger)','var(--warn)','var(--safe)','var(--safe)'];
  const tips=[]; if(pw.length<12)tips.push('Use 12+ characters — length beats complexity.');
  if(sets<3)tips.push('Mix upper, lower, digits and symbols.');
  if(bits<60)tips.push('Aim for 60+ bits; a 4-word passphrase gets there easily.');
  if(!tips.length)tips.push('Solid. Use a password manager so every site gets a unique one.');
  return {score,bits,color:colors[score],label:labels[score],tips};
}
S.lib.strength = strength;

})();
