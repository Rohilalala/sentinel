/* Sentinel tool file: Email Headers. Registers with the core; pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, loading, demoButton, badge } = S.ui;
const resolveA = n => api.resolveA(n);
const SAMPLE_HEADERS=`Delivered-To: you@example.com
Received: by 10.200.1.1 with SMTP id x1; Mon, 13 Oct 2026 09:00:02 -0700 (PDT)
Received: from mail.sketchy-sender.ru (mail.sketchy-sender.ru. [45.11.22.33]) by mx.google.com with ESMTPS id ab7 for <you@example.com>; Mon, 13 Oct 2026 09:00:01 -0700 (PDT)
Received-SPF: fail (google.com: domain of billing@paypal.com does not designate 45.11.22.33 as permitted sender)
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=billing@paypal.com; dkim=none; dmarc=fail (p=REJECT) header.from=paypal.com
From: PayPal Billing <billing@paypal.com>
To: you@example.com
Subject: Your account has been limited - verify now
Date: Mon, 13 Oct 2026 16:00:00 +0000
Message-ID: <abc123@sketchy-sender.ru>`;
S.register({ id:'emailhdr', name:'Email Headers', group:'Web & email', icon:'mail', tag:'local',
  tile:'Paste raw email headers to trace the delivery path and read SPF/DKIM/DMARC results.',
  blurb:'Paste the raw headers of an email to see every server it passed through and whether it passed anti-spoofing checks. Runs entirely in your browser.',
  why:`Email headers are a message's forensic trail. The ${t('Received header','Received: lines')} show every server it passed through (read bottom-up for the origin), and Authentication-Results shows ${t('SPF')} / ${t('DKIM')} / ${t('DMARC')} pass or fail — the fastest way to tell a phish from the real thing.`,
  render(mount){
    mount.innerHTML=`
      <div class="field"><label for="hdrin">Raw email headers</label><textarea id="hdrin" rows="7" style="width:100%;font:13px var(--font-mono)" placeholder="Paste raw headers. Gmail: More → Show original. Outlook: File → Properties."></textarea></div>
      <div id="out" class="grid"></div>`;
    const ta=$('#hdrin',mount), out=$('#out',mount);
    const run=()=>renderHeaders(ta.value,out);
    ta.addEventListener('input',run);
    const fill=()=>{ ta.value=SAMPLE_HEADERS; run(); S.toast('Parsed a sample phishing-style header set — note SPF & DMARC fail.'); };
    demoButton(fill);
  }});
function parseHeaders(raw){
  const lines=raw.replace(/\r/g,'').split('\n'), hdrs=[];
  for(const ln of lines){ if(/^\s/.test(ln)&&hdrs.length) hdrs[hdrs.length-1].v+=' '+ln.trim();
    else{ const m=ln.match(/^([!-9;-~]+):\s?(.*)$/); if(m) hdrs.push({k:m[1],v:m[2]}); } }
  const get=k=>{const h=hdrs.find(x=>x.k.toLowerCase()===k.toLowerCase());return h&&h.v;};
  const all=k=>hdrs.filter(x=>x.k.toLowerCase()===k.toLowerCase()).map(x=>x.v);
  const auth=(get('Authentication-Results')||'')+' '+all('Received-SPF').join(' ');
  const res=n=>{const m=auth.match(new RegExp(n+'=(\\w+)','i'));return m?m[1].toLowerCase():null;};
  const hop=v=>({from:(v.match(/from\s+([^\s]+)/i)||[])[1],by:(v.match(/by\s+([^\s]+)/i)||[])[1],date:(v.split(';').pop()||'').trim()});
  return { get, hops:all('Received').map(hop).reverse(), spf:res('spf'), dkim:res('dkim'), dmarc:res('dmarc') };
}
function renderHeaders(raw,out){
  if(!raw.trim()){ out.innerHTML=''; return; }
  const h=parseHeaders(raw);
  const fail=[h.spf,h.dkim,h.dmarc].includes('fail');
  const allpass=h.spf==='pass'&&h.dmarc==='pass';
  const cls=fail?'danger':allpass?'safe':'warn';
  const authBadge=v=>v==='pass'?badge('b-safe','check','pass'):v==='fail'?badge('b-danger','x','fail'):badge('b-mut','info',v||'—');
  out.innerHTML=`
    <div class="card verdict ${cls} full">
      <h2 class="big">${svg(fail?'x':allpass?'check':'alert')}${fail?'Failed anti-spoofing':allpass?'Passed anti-spoofing':'Partial / unverified'}</h2>
      <div class="sub">${fail?'One or more of SPF/DKIM/DMARC <b>failed</b> — this message is very likely forged (phishing).':allpass?'SPF and DMARC passed — the sender is authorized.':'Not all checks were present or passing. Inspect below.'}</div></div>
    <div class="card"><h2>Checks</h2><div class="kv">
      <div class="k">${t('SPF')}</div><div class="v">${authBadge(h.spf)}</div>
      <div class="k">${t('DKIM')}</div><div class="v">${authBadge(h.dkim)}</div>
      <div class="k">${t('DMARC')}</div><div class="v">${authBadge(h.dmarc)}</div></div></div>
    <div class="card"><h2>Message</h2><div class="kv">
      <div class="k">From</div><div class="v">${esc(h.get('From')||'—')}</div>
      <div class="k">Subject</div><div class="v">${esc(h.get('Subject')||'—')}</div>
      <div class="k">Return-Path</div><div class="v">${esc(h.get('Return-Path')||'—')}</div>
      <div class="k">Message-ID</div><div class="v">${esc(h.get('Message-ID')||'—')}</div></div></div>
    <div class="card full"><h2>Delivery path <span class="mut">(origin first)</span></h2>${h.hops.length?`<table><thead><tr><th>#</th><th>From</th><th>By</th><th>When</th></tr></thead><tbody>${
      h.hops.map((x,i)=>`<tr><td class="num">${i+1}</td><td class="mono">${esc(x.from||'—')}</td><td class="mono">${esc(x.by||'—')}</td><td class="mut">${esc(x.date||'')}</td></tr>`).join('')}</tbody></table>`:'<span class="mut">No Received: lines found.</span>'}</div>`;
}
S.lib.parseHeaders = parseHeaders;

})();
