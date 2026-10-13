/* Sentinel tool file: Typosquat Finder. Registers with the core; pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, loading, demoButton, badge } = S.ui;
const resolveA = n => api.resolveA(n);
S.register({ id:'typosquat', name:'Typosquat Finder', group:'Web & email', icon:'target',
  tile:'Generate lookalike domains of a brand and see which are already registered — phishing recon.',
  blurb:'Generate common typo and lookalike variants of a domain, then check which ones actually resolve.',
  why:`Phishers register domains that look like yours — goggle.com, paypa1.com, micros0ft.com — using ${t('homoglyph','lookalike characters')}. This is ${t('typosquatting')}. Generating the variants and checking which already resolve shows you who may be impersonating a brand.`,
  render(mount){ searchTool(mount,{placeholder:'paypal.com', wide:true, cta:'Hunt', examples:['paypal.com','google.com'],
    demo:{input:'paypal.com',narrate:'Generating lookalikes and checking which already resolve.'}, run:runTyposquat }); }});
function genVariants(domain){
  const dot=domain.indexOf('.'), sld=domain.slice(0,dot), tld=domain.slice(dot);
  const set=new Set(), add=s=>{ if(s&&s.length>1&&s!==sld) set.add(s+tld); };
  for(let i=0;i<sld.length;i++) add(sld.slice(0,i)+sld.slice(i+1));                 // omission
  for(let i=0;i<sld.length;i++) add(sld.slice(0,i+1)+sld[i]+sld.slice(i+1));         // doubling
  for(let i=0;i<sld.length-1;i++) add(sld.slice(0,i)+sld[i+1]+sld[i]+sld.slice(i+2)); // swap
  const homo={o:'0',l:'1',i:'1',e:'3',a:'4',s:'5',b:'8',g:'9'};
  for(let i=0;i<sld.length;i++){ const c=sld[i].toLowerCase(); if(homo[c]) add(sld.slice(0,i)+homo[c]+sld.slice(i+1)); }
  if(sld.includes('m')) add(sld.replace('m','rn'));
  for(const tt of ['.com','.net','.org','.co','.io','.info','.xyz']) if(tt!==tld) set.add(sld+tt);
  return [...set].slice(0,30);
}
async function runTyposquat(input,out){
  input=input.replace(/^https?:\/\//,'').replace(/\/.*$/,'').toLowerCase();
  if(!input.includes('.')){ S.say('⚠ Enter a full domain like paypal.com',true); return; }
  loading(out); S.say('Generating & checking variants…');
  const variants=genVariants(input);
  const rows=await Promise.all(variants.map(v=>api.doh(v,'A')
    .then(d=>({v,live:(d.Answer||[]).some(a=>a.type===1),ip:(d.Answer||[]).filter(a=>a.type===1).map(a=>a.data)[0]})).catch(()=>({v,live:false}))));
  const live=rows.filter(r=>r.live).sort((a,b)=>a.v.localeCompare(b.v));
  out.innerHTML=`
    <div class="card verdict ${live.length?'warn':'safe'} full"><h2>Lookalikes</h2>
      <div class="big">${svg(live.length?'alert':'check')}${live.length} of ${variants.length} registered</div>
      <div class="sub">${live.length?`${live.length} ${t('typosquatting','lookalike')} domain(s) of <b>${esc(input)}</b> already resolve — each could host a phishing copy. Review them below.`:`None of the generated lookalikes of ${esc(input)} currently resolve.`}</div></div>
    <div class="card full"><h2>Registered lookalikes</h2>${live.length?`<table><thead><tr><th>Domain</th><th>Resolves to</th></tr></thead><tbody>${
      live.map(r=>`<tr><td class="mono">${esc(r.v)}</td><td class="mono mut">${esc(r.ip||'—')}</td></tr>`).join('')}</tbody></table>`:'<span class="mut">none resolving</span>'}</div>
    <div class="card full"><h2>Also generated (not resolving)</h2><div class="mono mut" style="font-size:12px;line-height:1.9">${rows.filter(r=>!r.live).map(r=>esc(r.v)).join(' · ')||'—'}</div></div>`;
  S.say('');
}
S.lib.genVariants = genVariants;

})();
