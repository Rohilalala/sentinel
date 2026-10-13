/* Sentinel tool file: Site Files. Registers with the core; pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, loading, demoButton, badge } = S.ui;
const resolveA = n => api.resolveA(n);
const prox=u=>`https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`;
S.register({ id:'sitefiles', name:'Site Files', group:'Web & email', icon:'file',
  tile:'Read a site\'s robots.txt and security.txt — disallowed paths and the security contact.',
  blurb:'Fetch a domain\'s robots.txt and security.txt. Disallowed paths often point at hidden areas; security.txt names who to report issues to.',
  why:`${t('robots.txt')} tells crawlers which paths to skip — which is exactly where admin and staging areas often live, so recon always reads it. ${t('security.txt')} names the security contact. Fetched through a public proxy, since a browser can't read other sites directly — use on public sites only.`,
  render(mount){ searchTool(mount,{placeholder:'github.com', wide:false, cta:'Fetch', examples:['github.com','google.com'],
    demo:{input:'google.com',narrate:'Fetching robots.txt and security.txt via a public proxy.'}, run:runSiteFiles }); }});
async function runSiteFiles(domain,out){
  domain=domain.replace(/^https?:\/\//,'').replace(/\/.*$/,'');
  loading(out); S.say('Fetching via proxy…');
  const grab=async path=>{ try{ const r=await fetch(prox(`https://${domain}${path}`)); const txt=await r.text();
    if(!txt||/^\s*<|error code/i.test(txt.slice(0,40))) return null; return txt.slice(0,4000); }catch(e){ return null; } };
  const [robots,sec]=await Promise.all([grab('/robots.txt'),grab('/.well-known/security.txt')]);
  const disallow=(robots||'').split('\n').filter(l=>/^disallow:/i.test(l.trim())).map(l=>l.split(/:(.+)/)[1]?.trim()).filter(Boolean);
  out.innerHTML=`
    <div class="card verdict full"><h2>Site files</h2>
      <div class="big">${svg('file')}${esc(domain)}</div>
      <div class="sub">${robots?`robots.txt found with <b>${disallow.length}</b> disallowed path(s). `:'No robots.txt. '}${sec?'security.txt present.':'No security.txt.'} <span class="mut">Fetched via a public proxy (allorigins) — public sites only.</span></div></div>
    <div class="card"><h2>${t('robots.txt')} — disallowed paths</h2>${disallow.length?`<div class="mono" style="max-height:300px;overflow:auto;font-size:12px;line-height:1.8">${disallow.map(esc).join('<br>')}</div>`:'<span class="mut">'+(robots?'none listed':'not found')+'</span>'}</div>
    <div class="card"><h2>${t('security.txt')}</h2>${sec?`<pre style="white-space:pre-wrap;font-size:12px;max-height:300px;overflow:auto;margin:0">${esc(sec)}</pre>`:'<span class="mut">not found</span>'}</div>`;
  S.say('');
}

})();
