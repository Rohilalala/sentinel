/* Sentinel tool file: Routing & RPKI. Registers with the core; pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, loading, demoButton, badge } = S.ui;
const resolveA = n => api.resolveA(n);
const rpkiBadge = s => s==='valid' ? ['b-safe','check','VALID'] : /invalid/.test(s) ? ['b-danger','x',s.toUpperCase().replace('_',' ')] : ['b-mut','info','NO ROA'];
let rmap, rlayer;
S.register({ id:'routing', name:'Routing & RPKI', group:'Recon', icon:'route',
  tile:'Check who announces a prefix in BGP and whether RPKI says it is legit — the anatomy of a prefix hijack.',
  blurb:'Trace any domain, IP or network back through the global routing system and check it against RPKI.',
  why:`Every website lives inside an ${t('IP address')} ${t('prefix')} that some ${t('ASN','network')} announces to the world over ${t('BGP')}. ${t('BGP')} trusts whatever it is told, so a malicious or fat-fingered network can claim someone else's addresses — a ${t('prefix hijack')}. ${t('RPKI')} is the cryptographic fix. This tool shows the real announcement and the real verdict.`,
  render(mount){
    const {out}=searchTool(mount,{ placeholder:'youtube.com · 1.1.1.1 · AS15169', wide:false,
      examples:['youtube.com','1.1.1.1','AS15169'],
      demo:{ input:'invalid.rpki.cloudflare.com', narrate:'Running a deliberately INVALID route (Cloudflare\'s test host) — watch the verdict turn red.' },
      run:runRouting });
    rmap=rlayer=null;
  }});

async function runRouting(input,out){
  loading(out); S.say('Resolving…');
  try{
    if(S.isASN(input)) return await runASN(input.replace(/^as/i,''),out);
    const ip = S.isIP(input) ? input : await resolveA(input);
    S.say('Fetching origin & RPKI…');
    const [po,g] = await Promise.all([api.prefixOverview(ip), api.geo(ip)]);
    if(!po.announced) throw new Error(`${ip} is not in any announced prefix (a ${'bogon'} or unrouted address).`);
    const prefix=po.resource, origins=(po.asns||[]).map(a=>({asn:String(a.asn),holder:a.holder}));
    const rpkis=await Promise.all(origins.map(o=>api.rpki(o.asn,prefix).then(d=>[o.asn,d.status]).catch(()=>[o.asn,'unknown'])));
    const byAsn=Object.fromEntries(rpkis);
    renderRouting(out,{input,ip,prefix,origins,byAsn,geo:g,less:po.is_less_specific});
    S.say('Fetching live AS paths…');
    const lg=await api.lookingGlass(prefix).catch(()=>({rrcs:[]}));
    renderPaths(origins.map(o=>o.asn));
    S.say('');
  }catch(e){ out.innerHTML=''; S.say('⚠ '+e.message,true); }
}

function renderRouting(out,{input,ip,prefix,origins,byAsn,geo,less}){
  const statuses=origins.map(o=>byAsn[o.asn]||'unknown');
  const bad=statuses.some(s=>/invalid/.test(s)), moas=origins.length>1, allUnk=statuses.every(s=>!/valid|invalid/.test(s));
  let cls='safe',ic='check',big='RPKI valid',sub='The origin is authorized by a signed ROA. This route looks legitimate.';
  if(bad){cls='danger';ic='x';big='RPKI INVALID';sub=`The announced ${'origin'} or prefix length contradicts the signed ${'ROA'} — the signature of a ${'prefix hijack'}.`;}
  else if(moas){cls='warn';ic='alert';big='Multiple origins';sub='This prefix is announced by more than one network — legitimate multihoming, or a hijack. Inspect the origins below.';}
  else if(allUnk){cls='';ic='info';big='No ROA';sub='This prefix has no RPKI ROA, so origin validation cannot protect it. Common, but unverifiable.';}

  const originsHtml=origins.map(o=>{const[b,i,x]=rpkiBadge(byAsn[o.asn]||'unknown');
    return `<div>AS${esc(o.asn)} <span class="mut">${esc(o.holder||'')}</span> ${badge(b,i,x)}</div>`;}).join('');

  out.innerHTML=`
    <div class="card verdict ${cls}">
      <h2 class="big">${svg(ic)}${big}</h2><div class="sub">${sub}</div></div>
    <div class="card"><h2>Resource</h2><div class="kv">
      <div class="k">Query</div><div class="v">${esc(input)}</div>
      <div class="k">Resolved IP</div><div class="v">${esc(ip)}</div>
      <div class="k">${t('prefix','Prefix')}</div><div class="v">${esc(prefix)}${less?' <span class="mut">(less-specific)</span>':''}</div>
      <div class="k">${t('origin AS','Origin AS')}</div><div class="v">${originsHtml}</div>
      ${geo&&geo.success?`<div class="k">Geo</div><div class="v">${esc((geo.city?geo.city+', ':'')+(geo.country||''))}</div>`:''}
      ${geo&&geo.connection?`<div class="k">Network</div><div class="v">${esc(geo.connection.org||'')}</div>`:''}
    </div></div>
    <div class="card full"><h2>Origin geolocation</h2><div id="map"></div></div>
    <div class="card full"><h2>Live ${t('AS path','AS paths')} <span class="mut" id="pathmeta"></span></h2>
      <div style="overflow:auto"><table id="paths"><thead><tr><th>${t('route collector','Collectors')} see</th><th>AS path (→ origin)</th><th>Origin</th><th>Example peer</th></tr></thead><tbody></tbody></table></div></div>
    <div class="card full"><h2>Signals</h2><ul class="signals" id="sig"></ul></div>`;
  window.__lg_prefix=prefix;
  // map
  const cssVar=v=>getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  if(!rmap){ rmap=L.map('map',{attributionControl:!!(window.SENTINEL_BASEMAP&&window.SENTINEL_BASEMAP.attribution)}).setView([20,0],1);
    const bm=window.SENTINEL_BASEMAP; // set in config.js (your raster basemap); else keyless OSM
    L.tileLayer(bm&&bm.url ? bm.url : 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
      { maxZoom:(bm&&bm.maxZoom)||19, subdomains:(bm&&bm.subdomains)||'abc', attribution:(bm&&bm.attribution)||'© OpenStreetMap' }).addTo(rmap); }
  if(rlayer) rlayer.remove();
  if(geo&&geo.success&&geo.latitude){ const col=cls==='danger'?cssVar('--danger'):cls==='warn'?cssVar('--warn'):cssVar('--safe');
    rlayer=L.circleMarker([geo.latitude,geo.longitude],{radius:10,color:col,fillColor:col,fillOpacity:.5,weight:3}).addTo(rmap);
    rlayer.bindPopup(`<b>${esc(prefix)}</b><br>AS${esc(origins[0]?.asn||'?')}`); rmap.setView([geo.latitude,geo.longitude],4); }
  setTimeout(()=>rmap&&rmap.invalidateSize(),60);
  // base signals
  const sig=$('#sig'); const li=(ic,txt)=>`<li>${svg(ic)}<span>${txt}</span></li>`;
  sig.innerHTML = (bad?li('x',`This prefix fails ${'RPKI'} origin validation — treat any traffic to it as suspect.`):
                   allUnk?li('info','No ROA exists, so a hijack here could not be caught by origin validation.'):
                   li('check','Origin authorized by RPKI.'))
    + (moas?li('alert',`Announced by ${origins.length} different networks.`):'');
}
function renderPaths(announced){
  const lg=window.__lg_cache; // set below
  api.lookingGlass(window.__lg_prefix).then(lg=>{
    const peers=(lg.rrcs||[]).flatMap(r=>(r.peers||[]).map(p=>({...p,loc:r.location})));
    const byPath={}; for(const p of peers){ (byPath[p.as_path] ||= {count:0,origin:p.asn_origin,peer:p.peer,loc:p.loc}).count++; }
    const rows=Object.entries(byPath).sort((a,b)=>b[1].count-a[1].count).slice(0,12);
    const origins=new Set(peers.map(p=>p.asn_origin));
    $('#pathmeta').textContent=`— ${peers.length} collector peers, ${origins.size} distinct origin${origins.size>1?'s':''}`;
    $('#paths').querySelector('tbody').innerHTML = rows.map(([path,info])=>{
      const hops=path.split(' '); const pretty=hops.map((h,i)=>i===hops.length-1?`<span class="orig">${esc(h)}</span>`:esc(h)).join(' → ');
      const rogue=!announced.includes(info.origin);
      return `<tr><td class="num">${info.count}× <span class="mut">${esc(info.loc||'')}</span></td><td class="path">${pretty}</td>
        <td class="path">AS${esc(info.origin)}${rogue?' '+badge('b-warn','alert','unexpected'):''}</td><td class="path mut">${esc(info.peer)}</td></tr>`;
    }).join('') || `<tr><td colspan="4" class="mut">No live paths seen for this prefix.</td></tr>`;
    if(origins.size>1){ const l=document.createElement('li');
      l.innerHTML=`${svg('alert')}<span>${t('route collector','Collectors')} see <b>${origins.size}</b> different ${t('origin AS','origin ASes')} for this prefix: ${[...origins].map(o=>'AS'+esc(o)).join(', ')}. Possible ongoing ${t('MOAS')} / hijack.</span>`;
      $('#sig').prepend(l); }
  }).catch(()=>{ const pm=$('#pathmeta'); if(pm) pm.textContent='— live paths unavailable'; });
}
async function runASN(n,out){
  loading(out); S.say('Fetching AS & announcements…');
  try{
    const [ov,ann]=await Promise.all([api.asOverview(n), api.announced(n).catch(()=>({prefixes:[]}))]);
    const prefixes=(ann.prefixes||[]).map(p=>p.prefix).slice(0,20);
    S.say(`Validating ${prefixes.length} prefixes…`);
    const rows=await Promise.all(prefixes.map(p=>api.rpki(n,p).then(d=>[p,d.status]).catch(()=>[p,'unknown'])));
    const bad=rows.filter(([,s])=>/invalid/.test(s)).length;
    out.innerHTML=`
      <div class="card verdict ${bad?'danger':'safe'} full">
        <h2 class="big">${svg(bad?'alert':'check')}${esc(ov.holder||('AS'+n))}</h2>
        <div class="sub">AS${esc(n)} announces <b>${rows.length}</b> prefixes (showing up to 20) · ${bad?`<span style="color:var(--bad)">${bad} RPKI-invalid</span>`:'none RPKI-invalid'}.</div></div>
      <div class="card full"><h2>Announced prefixes</h2><table><thead><tr><th>${t('prefix','Prefix')}</th><th>RPKI</th></tr></thead><tbody>${
        rows.map(([p,s])=>{const[b,i,x]=rpkiBadge(s);return `<tr><td class="path">${esc(p)}</td><td>${badge(b,i,x)}</td></tr>`;}).join('')}</tbody></table></div>`;
    S.say('');
  }catch(e){ out.innerHTML=''; S.say('⚠ '+e.message,true); }
}

})();
