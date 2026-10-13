/* Sentinel tool file: IP Reputation. Registers with the core; pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, loading, demoButton, badge } = S.ui;
const resolveA = n => api.resolveA(n);
const DNSBLS=[['Barracuda','b.barracudacentral.org'],['SpamCop','bl.spamcop.net'],['UCEPROTECT','dnsbl-1.uceprotect.net'],['DroneBL','dnsbl.dronebl.org']];
S.register({ id:'blocklist', name:'IP Reputation', group:'Threat intel', icon:'ban',
  tile:'Check an IP against real spam/abuse blocklists (DNSBLs) that mail servers use worldwide.',
  blurb:'Look up an IP across multiple DNS blocklists to see if it is flagged for spam or abuse.',
  why:`Mail servers and firewalls reject traffic from IPs on a ${t('DNSBL')}. If your server's IP is listed your email silently fails to deliver; a listed IP is also a strong sign of a compromised or abusive host.`,
  render(mount){ searchTool(mount,{placeholder:'8.8.8.8 · or a domain', wide:true, examples:['8.8.8.8','1.1.1.1'],
    demo:{input:'8.8.8.8',narrate:'Checking this IP across 4 blocklists over DNS.'}, run:runBlocklist }); }});
async function runBlocklist(input,out){
  loading(out); S.say('Resolving…');
  try{
    const ip=S.isIP(input)?input:await resolveA(input);
    if(!S.isIP(ip)) throw new Error('Need an IPv4 address.');
    const rev=ip.split('.').reverse().join('.');
    S.say('Querying blocklists…');
    const rows=await Promise.all(DNSBLS.map(([name,zone])=>
      api.doh(rev+'.'+zone,'A').then(d=>({name,listed:(d.Answer||[]).length>0,code:(d.Answer||[]).map(a=>a.data).join(', ')})).catch(()=>({name,listed:false,code:'error'}))));
    const listed=rows.filter(r=>r.listed).length;
    out.innerHTML=`
      <div class="card verdict ${listed?'danger':'safe'} full"><h2>Reputation</h2>
        <div class="big">${svg(listed?'x':'check')}${listed?`Listed on ${listed} of ${rows.length}`:'Clean on all lists'}</div>
        <div class="sub">${esc(ip)} ${listed?`appears on ${listed} ${t('DNSBL','blocklist')}(s) — mail from it may be rejected, and it may be a compromised or abusive host.`:`is not on any of the ${rows.length} checked ${t('DNSBL','blocklists')}.`}</div></div>
      <div class="card full"><h2>Blocklists checked</h2><table><thead><tr><th>List</th><th>Result</th><th>Return code</th></tr></thead><tbody>${
        rows.map(r=>`<tr><td>${esc(r.name)}</td><td>${r.listed?badge('b-danger','x','LISTED'):badge('b-safe','check','clean')}</td><td class="mono mut">${esc(r.code||'—')}</td></tr>`).join('')}</tbody></table></div>`;
    S.say('');
  }catch(e){ out.innerHTML=''; S.say('⚠ '+e.message,true); }
}
S.lib.DNSBLS = DNSBLS;

})();
