/* Sentinel tool file: Learn (Guided Recon + How it works). Registers with the core; pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, loading, demoButton, badge } = S.ui;
const resolveA = n => api.resolveA(n);
S.register({ id:'mission', name:'Guided Recon', group:'Learn', icon:'play', tag:'',
  tile:'Run a full beginner recon pass on one domain — DNS, WHOIS, certs, routing, reputation — as one report.',
  blurb:'Enter a domain and watch a complete recon pass run across the tools, step by step, with a plain-English summary of each result.',
  why:`Real investigations chain tools together. This runs a beginner-friendly recon sequence on one target, explains each result, and links you to the full tool for detail. Everything it does, you can do by hand in the individual tools.`,
  render(mount){ searchTool(mount,{placeholder:'github.com', wide:true, cta:'Run recon', examples:['github.com','stripe.com'],
    demo:{input:'github.com',narrate:'Running DNS, WHOIS, certificates, routing and reputation in sequence.'}, run:runMission }); }});
async function runMission(domain,out){
  domain=domain.replace(/^https?:\/\//,'').replace(/\/.*$/,'');
  loading(out); out.innerHTML='';
  const push=html=>out.insertAdjacentHTML('beforeend',html);
  const step=(ic,title,state,body,link)=>`<div class="card full"><h2>${svg(ic)} ${title} &nbsp;${state}</h2>${body}${link?`<div style="margin-top:8px"><a href="#/${link}">Open full tool →</a></div>`:''}</div>`;
  try{
    S.say('1/5 DNS…');
    const a=await api.doh(domain,'A'); const ip=(a.Answer||[]).filter(x=>x.type===1).map(x=>x.data).pop();
    const dmarc=await api.doh('_dmarc.'+domain,'TXT').then(d=>(d.Answer||[]).map(x=>x.data).find(x=>/v=DMARC1/i.test(x))).catch(()=>null);
    push(step('dns','DNS & email', ip?badge('b-safe','check','resolves'):badge('b-danger','x','no A record'),
      `<div class="kv"><div class="k">Resolves to</div><div class="v">${esc(ip||'—')}</div><div class="k">${t('DMARC')}</div><div class="v">${dmarc?badge('b-safe','check','present'):badge('b-warn','alert','missing — spoofable')}</div></div>`,'dns'));
    if(!ip){ S.say(''); return; }
    S.say('2/5 WHOIS…');
    const d=await api.rdapDomain(domain).catch(()=>null);
    let age='—',reg='—'; if(d){ const ev=Object.fromEntries((d.events||[]).map(e=>[e.eventAction,e.eventDate]));
      if(ev.registration) age=Math.floor((Date.now()-new Date(ev.registration))/864e5).toLocaleString()+' days';
      const r=(d.entities||[]).find(e=>(e.roles||[]).includes('registrar')); const fn=r&&(r.vcardArray&&r.vcardArray[1]||[]).find(x=>x[0]==='fn'); reg=fn?fn[3]:'—'; }
    push(step('whois','Registration', d?badge('b-info','info','found'):badge('b-mut','info','n/a'),
      `<div class="kv"><div class="k">Registrar</div><div class="v">${esc(reg)}</div><div class="k">Age</div><div class="v">${esc(age)}</div></div>`,'whois'));
    S.say('3/5 Certificates…');
    const cs=await api.certspotter(domain).catch(()=>[]); const names=new Set(); cs.forEach(i=>(i.dns_names||[]).forEach(n=>n.endsWith(domain)&&names.add(n)));
    push(step('cert','Attack surface', badge('b-info','info',names.size+' names'),
      `<div class="mono mut" style="font-size:12px;max-height:120px;overflow:auto">${[...names].slice(0,24).map(esc).join(' · ')||'none found'}</div>`,'ct'));
    S.say('4/5 Routing…');
    const po=await api.prefixOverview(ip).catch(()=>null);
    let rpki='unknown',prefix='—',asn='—'; if(po&&po.announced){ prefix=po.resource; asn=(po.asns||[])[0]&&(po.asns||[])[0].asn; const rv=await api.rpki(asn,prefix).catch(()=>({status:'unknown'})); rpki=rv.status; }
    const rc=/invalid/.test(rpki)?'b-danger':rpki==='valid'?'b-safe':'b-mut';
    push(step('route','Routing & RPKI', badge(rc,rpki==='valid'?'check':/invalid/.test(rpki)?'x':'info',String(rpki).toUpperCase()),
      `<div class="kv"><div class="k">${t('prefix','Prefix')}</div><div class="v">${esc(prefix)}</div><div class="k">${t('origin AS','Origin')}</div><div class="v">AS${esc(asn)}</div></div>`,'routing'));
    S.say('5/5 Reputation…');
    const rev=ip.split('.').reverse().join('.');
    const bl=await Promise.all(S.lib.DNSBLS.map(([n,z])=>api.doh(rev+'.'+z,'A').then(d=>(d.Answer||[]).length>0).catch(()=>false)));
    const listed=bl.filter(Boolean).length;
    push(step('ban','IP reputation', listed?badge('b-danger','x',listed+' lists'):badge('b-safe','check','clean'),
      `<div class="sub" style="color:var(--muted)">${listed?`Listed on ${listed} ${t('DNSBL','blocklist')}(s).`:'Not on any checked blocklist.'}</div>`,'blocklist'));
    S.say('');
  }catch(e){ push(`<div class="why" style="border-left-color:var(--danger)">Mission stopped: ${esc(e.message)}</div>`); S.say(''); }
}

S.register({ id:'explain', name:'How it works', group:'Learn', icon:'book', tag:'',
  tile:'Animated explainers: prefix hijacks, RPKI, DNS spoofing, k-anonymity, certificate transparency.',
  blurb:'Short visual walkthroughs of the ideas behind every tool. No jargon left undefined.',
  render(mount){
    const scene=(n,title,stage,desc)=>`<div class="scene"><h3><span class="step">${n}</span>${title}</h3>
      <div class="stage">${stage}</div><p>${desc}</p></div>`;
    const label=(x,y,txt,sub)=>`<text x="${x}" y="${y}" fill="var(--ink)" font-size="12" font-weight="700" text-anchor="middle">${txt}</text>${sub?`<text x="${x}" y="${y+15}" fill="var(--muted)" font-size="10" text-anchor="middle">${sub}</text>`:''}`;
    const box=(x,y,w,h,stroke)=>`<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="8" fill="var(--surface)" stroke="${stroke||'var(--border-strong)'}" stroke-width="1.5"/>`;

    mount.innerHTML=`
      <p class="explain-intro">Five one-minute explainers. Read the picture, then open the matching tool and hit <b>Run example</b> to see it on live data. Every ${t('BGP','underlined term')} is defined on hover.</p>

      ${scene(1,`What a ${t('prefix hijack')} is`,
        `<svg viewBox="0 0 520 170">
          ${box(20,60,110,50)} ${label(75,88,'You',' a user')}
          ${box(200,20,120,50,'var(--safe)')} ${label(260,48,'AS100 — real owner',' owns 203.0.113.0/24')}
          ${box(200,110,120,50,'var(--danger)')} ${label(260,138,'AS400 — attacker',' claims the same IPs')}
          <line x1="130" y1="78" x2="200" y2="48" stroke="var(--border-strong)" stroke-width="1.5"/>
          <line x1="130" y1="92" x2="200" y2="132" stroke="var(--danger)" stroke-width="2" class="flow-dash"/>
          <circle r="5" fill="var(--danger)" class="pkt"><animateMotion dur="3s" repeatCount="indefinite" path="M130,92 L200,132"/></circle>
          ${label(410,80,'Traffic goes',' to the attacker')}
        </svg>`,
        `${t('BGP')} is how networks announce which ${t('IP address','IP')} blocks they own. It trusts whatever it's told — so AS400 can announce AS100's ${t('prefix')} and steal the traffic. This took YouTube offline globally in 2008. → Open <b>Routing &amp; RPKI</b>.`)}

      ${scene(2,`How ${t('RPKI')} stops it`,
        `<svg viewBox="0 0 520 160">
          ${box(20,55,120,50,'var(--danger)')} ${label(80,83,'AS400 announces',' 203.0.113.0/24')}
          ${box(200,55,120,50)} ${label(260,78,'Router checks',' the ROA')}
          <line x1="140" y1="80" x2="200" y2="80" stroke="var(--border-strong)" stroke-width="1.5" class="flow-dash"/>
          ${box(380,20,120,45,'var(--safe)')} ${label(440,47,'ROA: only AS100')}
          ${box(380,95,120,45,'var(--danger)')} ${label(440,118,'✕ REJECTED')}
          <line x1="320" y1="72" x2="380" y2="43" stroke="var(--safe)" stroke-width="1.5"/>
          <line x1="320" y1="88" x2="380" y2="117" stroke="var(--danger)" stroke-width="2"/>
        </svg>`,
        `The real owner signs a ${t('ROA')} — "only AS100 may announce this prefix". Routers with ${t('RPKI')} validation check every announcement against it and drop the ones that don't match. The <b>Routing</b> tool shows this verdict (valid / invalid) on real routes.`)}

      ${scene(3,`${t('DNS')} lookups &amp; email ${('spoofing')}`,
        `<svg viewBox="0 0 520 150">
          ${box(20,50,110,50)} ${label(75,78,'Browser')}
          ${box(190,50,130,50)} ${label(255,73,'DNS over HTTPS',' encrypted')}
          ${box(380,20,120,45)} ${label(440,47,'A record → IP')}
          ${box(380,95,120,45,'var(--warn)')} ${label(440,116,'SPF / DMARC?')}
          <line x1="130" y1="75" x2="190" y2="75" stroke="var(--accent)" stroke-width="2" class="flow-dash"/>
          <line x1="320" y1="68" x2="380" y2="43" stroke="var(--border-strong)" stroke-width="1.5"/>
          <line x1="320" y1="82" x2="380" y2="117" stroke="var(--border-strong)" stroke-width="1.5"/>
        </svg>`,
        `${t('DNS')} turns names into IPs; ${t('DoH')} does it over an encrypted request. The same records reveal whether a domain published ${t('SPF')} and ${t('DMARC')} — without them, anyone can send phishing that looks like it came from that domain. → Open <b>DNS &amp; Email</b>.`)}

      ${scene(4,`Why the password check is private (${t('k-anonymity')})`,
        `<svg viewBox="0 0 520 150">
          ${box(20,50,120,50)} ${label(80,73,'Your password',' hashed locally')}
          ${box(200,50,90,50,'var(--accent)')} ${label(245,78,'send 5 chars')}
          ${box(350,50,150,50)} ${label(425,73,'server returns ~2000',' candidate hashes')}
          <line x1="140" y1="75" x2="200" y2="75" stroke="var(--border-strong)" stroke-width="1.5"/>
          <line x1="290" y1="75" x2="350" y2="75" stroke="var(--accent)" stroke-width="2" class="flow-dash"/>
          <text x="260" y="125" fill="var(--safe)" font-size="11" font-weight="700" text-anchor="middle">match happens in your browser — password never leaves</text>
        </svg>`,
        `Your password is hashed in the browser; only the first 5 characters of the hash are sent. The server replies with every leak whose hash starts with those 5 chars, and the match happens locally. The server never learns your password. → Open <b>Password Exposure</b>.`)}

      ${scene(5,`${t('Certificate Transparency')} reveals ${t('subdomain','subdomains')}`,
        `<svg viewBox="0 0 520 150">
          ${box(20,50,110,50)} ${label(75,78,'Any CA issues',' a cert')}
          ${box(190,50,120,50,'var(--accent)')} ${label(250,73,'public CT log',' append-only')}
          ${box(370,30,130,40)} ${label(435,54,'mail.site.com')}
          ${box(370,80,130,40)} ${label(435,104,'vpn.site.com')}
          <line x1="130" y1="75" x2="190" y2="75" stroke="var(--border-strong)" stroke-width="1.5"/>
          <line x1="310" y1="70" x2="370" y2="50" stroke="var(--accent)" stroke-width="1.5" class="flow-dash"/>
          <line x1="310" y1="80" x2="370" y2="100" stroke="var(--accent)" stroke-width="1.5" class="flow-dash"/>
        </svg>`,
        `Every ${t('TLS certificate')} is written to public ${t('Certificate Transparency')} logs. Searching them reveals hidden ${t('subdomain','subdomains')} — dev, staging, vpn — which is how attackers and bug-bounty hunters map a target's attack surface. → Open <b>Cert Transparency</b>.`)}

      <div class="why"><b>Want these as narrated videos?</b> The scripts for each are in <span class="mono">TUTORIALS.md</span> — record them over this page with any screen recorder for a full explainer series.</div>`;
  }});

})();
