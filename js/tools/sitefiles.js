/* Sentinel tool file: Site Files. Registers with the core; pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, loading, demoButton, badge } = S.ui;
const resolveA = n => api.resolveA(n);
const prox=u=>`https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`;
S.register({ id:'sitefiles', name:'Site Files', group:'Web & email', icon:'file',
  tile:'Read a site\'s robots.txt and security.txt — disallowed paths and the security contact.',
  blurb:'Fetch a domain\'s robots.txt and security.txt. Disallowed paths often point at hidden areas; security.txt names who to report issues to.',
  why:`${t('robots.txt')} tells crawlers which paths to skip — which is exactly where admin and staging areas often live, so recon always reads it. ${t('security.txt')} names the security contact. A browser can't read other sites directly, so this fetches through a public proxy, or through the ${t('companion')} when it's running. Use it on public sites only.`,
  render(mount){ searchTool(mount,{placeholder:'github.com', wide:false, cta:'Fetch', examples:['github.com','google.com'],
    demo:{input:'google.com',narrate:'Fetching robots.txt and security.txt via a public proxy.'}, run:runSiteFiles }); }});
async function runSiteFiles(domain,out){
  domain=S.cleanHost(domain);
  if(!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)){ out.innerHTML='';
    S.say('Enter a public domain name, like github.com. IP addresses, ports and local names are not supported here.',true); return; }
  const viaCompanion=!!S.companion();
  loading(out); S.say(viaCompanion?'Fetching from your computer…':'Fetching via proxy…');
  // null = file not found; an Error = the fetch path itself failed (proxy down), which is not a verdict about the site
  const grab=async path=>{ const url=`https://${domain}${path}`;
    try{
      if(viaCompanion){ const r=await S.native('/api/http',{url}); return r.status===200&&!/^\s*</.test(r.bodySample)?r.bodySample.slice(0,4000):null; }
      const r=await fetch(prox(url)); if(r.status>=500) throw new Error('proxy '+r.status); const txt=await r.text();
      if(!txt||/^\s*<|error code/i.test(txt.slice(0,40))) return null; return txt.slice(0,4000);
    }catch(e){ return e instanceof Error?e:new Error(String(e)); } };
  let [robots,sec]=await Promise.all([grab('/robots.txt'),grab('/.well-known/security.txt')]);
  if(robots instanceof Error&&sec instanceof Error){ out.innerHTML='';
    S.say(viaCompanion?`Couldn't fetch from ${domain}: ${robots.message}. Check the domain and try again.`
      :'The public proxy (allorigins) is not responding, so nothing could be fetched. Try again later, or run the companion (node companion/server.mjs) to fetch these files directly.',true); return; }
  if(robots instanceof Error) robots=null; if(sec instanceof Error) sec=null;
  const disallow=(robots||'').split('\n').filter(l=>/^disallow:/i.test(l.trim())).map(l=>l.split(/:(.+)/)[1]?.trim()).filter(Boolean);
  out.innerHTML=`
    <div class="card verdict full">
      <h2 class="big">${svg('file')}${esc(domain)}</h2>
      <div class="sub">${robots?`robots.txt found with <b>${disallow.length}</b> disallowed path(s). `:'No robots.txt. '}${sec?'security.txt present.':'No security.txt.'} <span class="mut">${viaCompanion?'Fetched by the companion from your computer.':'Fetched via a public proxy (allorigins). Public sites only.'}</span></div></div>
    <div class="card"><h2>${t('robots.txt')} — disallowed paths</h2>${disallow.length?`<div class="mono" style="max-height:300px;overflow:auto;font-size:12px;line-height:1.8">${disallow.map(esc).join('<br>')}</div>`:'<span class="mut">'+(robots?'none listed':'not found')+'</span>'}</div>
    <div class="card"><h2>${t('security.txt')}</h2>${sec?`<pre style="white-space:pre-wrap;font-size:12px;max-height:300px;overflow:auto;margin:0">${esc(sec)}</pre>`:'<span class="mut">not found</span>'}</div>`;
  S.say('');
}

})();
