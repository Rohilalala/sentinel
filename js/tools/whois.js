/* Sentinel tool file: Domain / IP Intel. Registers with the core; pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, loading, demoButton, badge } = S.ui;
const resolveA = n => api.resolveA(n);
S.register({ id:'whois', name:'Domain / IP Intel', group:'Recon', icon:'whois',
  tile:'Who registered a domain or owns an IP block, when, and through whom — the modern WHOIS.',
  blurb:'Look up registration and ownership facts for any domain or IP using RDAP (structured WHOIS).',
  why:`Before trusting a site, analysts check its ${t('WHOIS')} record. A domain registered three days ago, or an IP that belongs to a hosting provider in a different country than the brand claims, is a classic phishing red flag. ${t('RDAP')} returns this as clean data.`,
  render(mount){
    searchTool(mount,{ placeholder:'github.com · 8.8.8.8', wide:false, examples:['github.com','paypal.com','8.8.8.8'],
      demo:{ input:'github.com', narrate:'Fetching registrar, key dates, status locks and nameservers via RDAP.' },
      run:runWhois });
  }});
function vcardMap(entity){ const arr=(entity&&entity.vcardArray&&entity.vcardArray[1])||[]; const m={};
  for(const row of arr){ if(Array.isArray(row)) m[row[0]]=row[3]; } return m; }
async function runWhois(input,out){
  loading(out); S.say('Querying RDAP…');
  try{
    if(S.isIP(input)){
      const d=await api.rdapIp(input);
      out.innerHTML=`
        <div class="card verdict full"><h2>IP block</h2><div class="big">${svg('globe')}${esc(d.name||input)}</div>
          <div class="sub">${esc(d.handle||'')} · ${esc(d.country||'')} · ${esc(d.type||'')}</div></div>
        <div class="card full"><h2>Details</h2><div class="kv">
          <div class="k">Range</div><div class="v">${esc(d.startAddress||'')} – ${esc(d.endAddress||'')}</div>
          <div class="k">CIDR</div><div class="v">${esc((d.cidr0_cidrs||[]).map(c=>c.v4prefix?c.v4prefix+'/'+c.length:'').join(', ')||'—')}</div>
          <div class="k">Country</div><div class="v">${esc(d.country||'—')}</div>
          <div class="k">Status</div><div class="v">${esc((d.status||[]).join(', ')||'—')}</div>
        </div></div>`;
      S.say(''); return;
    }
    const d=await api.rdapDomain(input.replace(/^https?:\/\//,'').replace(/\/.*$/,''));
    const ev=Object.fromEntries((d.events||[]).map(e=>[e.eventAction,e.eventDate]));
    const registrar=(d.entities||[]).find(e=>(e.roles||[]).includes('registrar'));
    const regName=vcardMap(registrar).fn;
    const ns=(d.nameservers||[]).map(n=>n.ldhName);
    const created=ev.registration?new Date(ev.registration):null;
    const ageDays=created?Math.floor((Date.now()-created)/864e5):null;
    const young = ageDays!=null && ageDays<90;
    const cls=young?'warn':'safe';
    out.innerHTML=`
      <div class="card verdict ${cls} full"><h2>Domain</h2>
        <div class="big">${svg(young?'alert':'check')}${esc(d.ldhName||input)}</div>
        <div class="sub">${regName?`Registered via <b>${esc(regName)}</b>`:''}${ageDays!=null?` · ${ageDays} days old`:''}. ${young?'Recently registered domains are disproportionately used for phishing — treat with caution.':'Established registration.'}</div></div>
      <div class="card"><h2>Registration</h2><div class="kv">
        <div class="k">${t('registrar','Registrar')}</div><div class="v">${esc(regName||'—')}</div>
        <div class="k">Created</div><div class="v">${esc(ev.registration||'—')}</div>
        <div class="k">Expires</div><div class="v">${esc(ev.expiration||'—')}</div>
        <div class="k">Updated</div><div class="v">${esc(ev['last changed']||'—')}</div>
      </div></div>
      <div class="card"><h2>Locks & nameservers</h2><div class="kv">
        <div class="k">Status</div><div class="v">${(d.status||[]).map(s=>badge('b-info','info',esc(s))).join(' ')||'—'}</div>
        <div class="k">${t('nameserver','Nameservers')}</div><div class="v">${ns.map(n=>esc(n)).join('<br>')||'—'}</div>
      </div></div>`;
    S.say('');
  }catch(e){ out.innerHTML=''; S.say('⚠ RDAP: '+e.message+' (some TLDs don\'t publish RDAP)',true); }
}

})();
