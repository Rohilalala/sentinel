/* Sentinel tool file: Cert Transparency. Registers with the core; pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, loading, demoButton, badge } = S.ui;
const resolveA = n => api.resolveA(n);
S.register({ id:'ct', name:'Cert Transparency', group:'Recon', icon:'cert',
  tile:'Discover a company\'s subdomains from public TLS certificate logs — real attack-surface mapping.',
  blurb:'Search Certificate Transparency logs to enumerate every subdomain a domain has gotten a TLS cert for.',
  why:`Every ${t('TLS certificate')} ever issued is written to public ${t('Certificate Transparency')} logs. Searching them reveals ${t('subdomain','subdomains')} you would never guess — dev, staging, vpn, internal tools — which is exactly how attackers (and bug-bounty hunters) map a target's attack surface.`,
  render(mount){
    searchTool(mount,{ placeholder:'example.com', wide:true, cta:'Enumerate', examples:['tesla.com','github.com','stripe.com'],
      demo:{ input:'github.com', narrate:'Pulling GitHub\'s certificates from public CT logs and extracting every subdomain.' },
      run:runCT });
  }});
async function runCT(domain,out){
  domain=domain.replace(/^https?:\/\//,'').replace(/\/.*$/,'');
  loading(out); S.say('Searching Certificate Transparency logs…');
  try{
    const data=await api.certspotter(domain);
    const names=new Set(); const certs=[];
    for(const iss of data){ (iss.dns_names||[]).forEach(n=>names.add(n.replace(/^\*\./,'*.')));
      certs.push({issuer:(iss.issuer&&iss.issuer.name)||'',not_after:iss.not_after,names:(iss.dns_names||[]).length}); }
    const subs=[...names].filter(n=>n.endsWith(domain)).sort();
    out.innerHTML=`
      <div class="card verdict full"><h2>Attack surface</h2>
        <div class="big">${svg('cert')}${subs.length} name${subs.length===1?'':'s'} found</div>
        <div class="sub">Across ${certs.length} certificates in public CT logs for <b>${esc(domain)}</b>. Each is a host that may be reachable. (Free CT feeds show recent issuances; a full history needs an API key.)</div></div>
      <div class="card"><h2>Subdomains</h2><div style="max-height:360px;overflow:auto">${
        subs.map(s=>`<div class="mono" style="padding:3px 0">${esc(s)}</div>`).join('')||'<span class="mut">none</span>'}</div></div>
      <div class="card"><h2>Recent certificates</h2><div style="overflow:auto"><table><thead><tr><th>Issuer</th><th class="num">Names</th><th>Expires</th></tr></thead><tbody>${
        certs.slice(0,15).map(c=>`<tr><td>${esc(c.issuer.replace(/.*O=/,'').slice(0,28))}</td><td class="num">${c.names}</td><td class="mono">${esc((c.not_after||'').slice(0,10))}</td></tr>`).join('')}</tbody></table></div></div>`;
    S.say('');
  }catch(e){ out.innerHTML=''; S.say('⚠ '+e.message,true); }
}

})();
