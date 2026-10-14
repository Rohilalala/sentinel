/* Sentinel tool file: DNS & Email. Registers with the core; pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, loading, demoButton, badge } = S.ui;
const resolveA = n => api.resolveA(n);
S.register({ id:'dns', name:'DNS & Email', group:'Recon', icon:'dns',
  tile:'Read any domain\'s DNS records, check DNSSEC, and see whether its email can be spoofed.',
  blurb:'Look up a domain\'s DNS records over encrypted DNS, and audit its anti-spoofing email setup.',
  why:`${t('DNS')} is the internet's phone book. Reading it reveals a domain's mail servers, hosting and verification tokens. It also tells you whether the domain protects its email: a domain without ${t('SPF')} and ${t('DMARC')} can be impersonated by anyone sending phishing "from" it.`,
  render(mount){
    searchTool(mount,{ placeholder:'cloudflare.com', wide:true, examples:['cloudflare.com','google.com','github.com'],
      demo:{ input:'cloudflare.com', narrate:'Pulling A/MX/TXT records, checking DNSSEC, and auditing email anti-spoofing.' },
      run:runDNS });
  }});
async function runDNS(domain,out){
  domain=domain.replace(/^https?:\/\//,'').replace(/\/.*$/,'');
  loading(out); S.say('Querying DNS over HTTPS…');
  try{
    const types=['A','AAAA','MX','NS','TXT','CAA'];
    const [recs, dnssec, dmarc] = await Promise.all([
      Promise.all(types.map(ty=>api.doh(domain,ty).then(d=>[ty,(d.Answer||[]).map(a=>a.data)]).catch(()=>[ty,[]]))),
      api.doh(domain,'A',true).then(d=>d.AD).catch(()=>false),
      api.doh('_dmarc.'+domain,'TXT').then(d=>(d.Answer||[]).map(a=>a.data).find(x=>/v=DMARC1/i.test(x))).catch(()=>null),
    ]);
    const byType=Object.fromEntries(recs);
    const spf=(byType.TXT||[]).map(x=>x.replace(/^"|"$/g,'')).find(x=>/^v=spf1/i.test(x));
    const dmarcPol=(dmarc||'').match(/p=(\w+)/i); const pol=dmarcPol?dmarcPol[1].toLowerCase():null;
    const spoofable = !spf || !dmarc || pol==='none';
    const emailCls = (!spf||!dmarc)?'danger':(pol==='none'?'warn':'safe');

    const recRows = types.flatMap(ty=>(byType[ty]||[]).map(v=>`<tr><td class="mono">${ty}</td><td class="mono">${esc(v.replace(/^"|"$/g,''))}</td></tr>`)).join('')
      || '<tr><td colspan="2" class="mut">No records returned.</td></tr>';

    out.innerHTML=`
      <div class="card verdict ${emailCls} full">
        <h2 class="big">${svg(emailCls==='safe'?'check':emailCls==='warn'?'alert':'x')}${emailCls==='safe'?'Protected':emailCls==='warn'?'Weak (p=none)':'Spoofable'}</h2>
        <div class="sub">${spf?`Has ${t('SPF')}`:`<b style="color:var(--bad)">No ${t('SPF')}</b>`} · ${dmarc?`${t('DMARC')} policy <b>${esc(pol)}</b>`:`<b style="color:var(--bad)">No ${t('DMARC')}</b>`}. ${spoofable?'An attacker could send phishing email that appears to come from this domain.':'Anti-spoofing is enforced.'}</div></div>
      <div class="card"><h2>Security flags</h2><div class="kv">
        <div class="k">${t('DNSSEC')}</div><div class="v">${dnssec?badge('b-safe','check','SIGNED'):badge('b-warn','alert','unsigned')}</div>
        <div class="k">${t('SPF')}</div><div class="v">${spf?badge('b-safe','check','present'):badge('b-danger','x','missing')}</div>
        <div class="k">${t('DMARC')}</div><div class="v">${dmarc?badge(pol==='none'?'b-warn':'b-safe',pol==='none'?'alert':'check','p='+esc(pol)):badge('b-danger','x','missing')}</div>
        <div class="k">${t('MX record','Mail')}</div><div class="v">${(byType.MX||[]).length?esc((byType.MX[0]).split(' ').pop()):'<span class="mut">none</span>'}</div>
      </div></div>
      <div class="card full"><h2>All DNS records</h2><div style="overflow:auto"><table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>${recRows}</tbody></table></div></div>`;
    S.say('');
  }catch(e){ out.innerHTML=''; S.say('⚠ '+e.message,true); }
}

})();
