/* Sentinel tool file: Code security (Secrets Scanner, IAM Policy Analyzer). Pasted text never leaves the browser.
   Note: the secret patterns and samples here are written so the repo's own secret scan never matches this file. */
(() => {
const S = Sentinel, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { demoButton, badge } = S.ui;

S.addIcons({ // Lucide (ISC): code, user-check
  'd-code': 'M16 18l6-6-6-6M8 6l-6 6 6 6',
  'd-usercheck': 'M9 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8M2 21v-2a4 4 0 0 1 4-4h6a4 4 0 0 1 4 4v2M16 11l2 2 4-4',
});
S.addTerms({
  'API key': 'A long secret string that lets a program use a paid or private service (AWS, Stripe, Google Maps). Whoever holds it can act as you.',
  'git history': 'Every version of every file ever committed. Deleting a secret in a new commit leaves it readable in the older ones.',
  'secret rotation': 'Revoking a leaked key or password and issuing a new one, so the leaked copy stops working.',
  'IAM': 'Identity and Access Management: the AWS service that decides who can do which actions on which resources.',
  'least privilege': 'Giving each user or program only the permissions it needs and nothing more, so a stolen key can do little damage.',
  'ARN': 'Amazon Resource Name: the unique ID of an AWS resource, such as arn:aws:s3:::my-bucket.',
  'principal': 'The "who" in an AWS policy: a user, role, account or service. "*" means anyone, including people who aren\'t signed in.',
  'resource policy': 'A policy attached to a resource, such as an S3 bucket or a KMS key, naming which principals may use it.',
  'iam:PassRole': 'The AWS permission to hand a role to a service. With it on every role, a user can start a server or function that runs as an admin.',
  'policy condition': 'An optional Condition block that limits when a statement applies: only with MFA, only from one network, only for tagged resources.',
  'privilege escalation': 'Turning limited access into more access, such as an account that can grant itself admin rights.',
});
const record = (tool, input, out) => { const v = out.querySelector('.verdict');
  if (v) S.record({ tool, input, cls: ['danger', 'warn', 'safe'].find(c => v.classList.contains(c)) || 'info', title: v.querySelector('.big').textContent.trim().slice(0, 80) }); };
const SEV = { high: ['b-danger', 'x'], medium: ['b-warn', 'alert'], low: ['b-mut', 'info'] };
const sevBadge = s => badge(SEV[s][0], SEV[s][1], s);
// textarea + action button + status + results: the paste-input scaffold both tools share
function pasteTool(mount, { label, rows, placeholder, cta, examples = {}, run, demo }) {
  mount.innerHTML = `<div class="field"><label for="pin">${label}</label>
      <textarea id="pin" rows="${rows}" spellcheck="false" autocomplete="off" placeholder="${esc(placeholder)}"></textarea>
      ${Object.keys(examples).length ? `<p class="try">Try:${Object.keys(examples).map(k => `<button type="button">${esc(k)}</button>`).join('')}</p>` : ''}</div>
    <div class="bar"><button class="btn secondary" id="pgo">${cta}</button></div>
    <div id="status" role="status" aria-live="polite"></div><div id="out" class="grid"></div>`;
  const ta = $('#pin', mount), out = $('#out', mount);
  const go = () => {
    if (!ta.value.trim()) { out.innerHTML = ''; S.say(`Paste something first, or press Run example.`, true); ta.focus(); return; }
    try { S.say(''); run(ta.value, out); } catch (e) { out.innerHTML = ''; S.say(e.message, true); }
  };
  $('#pgo', mount).onclick = go;
  mount.querySelectorAll('.try button').forEach(b => b.onclick = () => { ta.value = examples[b.textContent]; go(); });
  demoButton(() => { ta.value = demo.text(); S.toast(demo.narrate); go(); });
}

/* ---------- Secrets Scanner ---------- */
// [name, severity, regex, fixed display]. The secret is capture group 1 when present, else the whole match.
const SECRET_RULES = [
  ['AWS access key ID', 'high', /\bA[KS]IA[0-9A-Z]{16}\b/g],
  ['GitHub token', 'high', /\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_\w{60,}/g],
  ['Slack token', 'high', /\bxox[baprs]-[A-Za-z0-9-]{10,}/g],
  ['Stripe live key', 'high', /\b[sr]k_live_[0-9a-zA-Z]{20,}/g],
  ['Google API key', 'high', /\bAIza[\w-]{35}/g],
  ['Private key block', 'high', /-----BEGIN [A-Z0-9 ]{0,20}?PRIVATE KEY-----/g, 'key body hidden'],
  ['JSON Web Token', 'medium', /\beyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]{8,}/g],
  ['Hard-coded password or secret', 'medium', /(?:passw(?:or)?d|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret)[\w-]*["']?\s*[:=]>?\s*["']?([^"'\s,;]{6,})/gi],
];
// values that are references or placeholders, not secrets
const PLACEHOLDER = /[()[\]{}<>$%]|^(?:process\.env|os\.(?:environ|getenv))|^(?:null|none|nil|true|false|undefined|changeme|x+|\*+)$/i;
const maskSecret = s => s.slice(0, s.length >= 16 ? 4 : 2) + '•'.repeat(8);
function scanSecrets(text) {
  const hits = []; let inKey = false;
  text.split(/\r?\n/).forEach((line, i) => {
    if (inKey) { inKey = !/-----END [A-Z0-9 ]{0,20}?PRIVATE KEY-----/.test(line); return; } // key body: already reported
    const taken = [], free = (a, z) => !taken.some(([x, y]) => a < y && z > x);
    for (const [rule, sev, re, show] of SECRET_RULES) for (const m of line.matchAll(re)) {
      const secret = m[1] || m[0], at = m.index + m[0].lastIndexOf(secret), end = at + secret.length;
      if (PLACEHOLDER.test(secret) || !free(at, end)) continue;
      taken.push([at, end]); hits.push({ line: i + 1, rule, sev, masked: show || maskSecret(secret) });
      if (show) inKey = !/-----END [A-Z0-9 ]{0,20}?PRIVATE KEY-----/.test(line);
    }
    // Limit: entropy heuristic (4+ bits/char, letters and digits, 20+ chars); per-format rules if it's too noisy
    for (const m of line.matchAll(/[A-Za-z0-9+/=_-]{20,}/g)) {
      const e = S.lib.byteEntropy(new TextEncoder().encode(m[0])); // from forensics.js
      if (e >= 4 && /\d/.test(m[0]) && /[a-z]/i.test(m[0]) && free(m.index, m.index + m[0].length))
        hits.push({ line: i + 1, rule: 'High-entropy string', sev: 'low', masked: maskSecret(m[0]), entropy: e });
    }
  });
  return hits;
}
const SAMPLE_SECRETS = () => [ // assembled at runtime so no key-shaped literal sits in the source; all values are fake or AWS's documented example
  '# settings.py: a sample config with planted fake credentials',
  'DEBUG = False',
  'AWS_ACCESS_KEY_ID = "' + 'AKIA' + 'IOSFODNN7EXAMPLE"',
  'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY' + 'EXAMPLEKEY"',
  'GITHUB_TOKEN = "' + 'gh' + 'p_' + 'EXAMPLE'.padEnd(36, '0') + '"',
  'STRIPE_KEY = "' + 's' + 'k_live_' + 'EXAMPLE'.padEnd(24, '0') + '"',
  'MAPS_KEY = "' + 'AI' + 'za' + 'Sy' + 'EXAMPLE'.padEnd(33, '0') + '"',
  'DB_PASSWORD = "correct-horse-battery-staple"',
  'DB_HOST = process.env.DB_HOST',
  'SESSION = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"',
  'TIMEOUT_SECONDS = 30',
  '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----',
  'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW',
  '-----END ' + 'OPENSSH PRIVATE KEY-----',
].join('\n');
S.register({ id: 'secrets', name: 'Secrets Scanner', group: 'Forensics', icon: 'd-code', tag: 'local',
  tile: 'Paste code or config to find leaked API keys, tokens, private keys and passwords, shown masked.',
  blurb: 'Paste source code or a config file to find credentials that should never be committed. Scanning happens in your browser.',
  why: `Leaked credentials are one of the most common ways attackers get in. An ${t('API key')} pasted into code ends up on GitHub, and bots scan every public push within minutes. Deleting the line isn't enough, because the key stays in ${t('git history')}. The real fix is ${t('secret rotation')}: revoke the key and issue a new one.`,
  render(mount) {
    pasteTool(mount, { label: 'Code or config to scan', rows: 10, cta: 'Scan', placeholder: 'Paste source code, a .env file or a config file…',
      demo: { text: SAMPLE_SECRETS, narrate: 'Scanning a sample config with planted fake keys. Every match is masked: the scanner never shows a full secret.' },
      run: (text, out) => { renderSecrets(scanSecrets(text), out); record('secrets', `${text.split('\n').length} pasted lines`, out); } });
  } });
function renderSecrets(hits, out) {
  const high = hits.filter(h => h.sev === 'high').length, n = hits.length;
  out.innerHTML = `<div class="card verdict ${high ? 'danger' : n ? 'warn' : 'safe'} full">
      <h2 class="big">${svg(high ? 'x' : n ? 'alert' : 'check')}${high ? `${n} secret${n > 1 ? 's' : ''} found` : n ? 'Possible secrets found' : 'No secrets found'}</h2>
      <div class="sub">${high ? `Treat every key below as stolen: rotate it now, then remove it from the code.` : n ? 'Nothing matched a known key format, but some values look like passwords or random tokens. Check each one.'
        : 'Nothing matched the known key formats. Pattern scanners miss custom formats, so still keep secrets out of code.'}</div></div>
    ${n ? `<div class="card full"><h2>Findings <span class="mut">(${n})</span></h2><div class="table-wrap"><table>
      <thead><tr><th class="num">Line</th><th>Finding</th><th>Severity</th><th>Value (masked)</th></tr></thead><tbody>${hits.map(h => `<tr>
        <td class="num">${h.line}</td><td>${esc(h.rule)}${h.entropy ? ` <span class="mut">(${h.entropy.toFixed(1)} bits/char)</span>` : ''}</td><td>${sevBadge(h.sev)}</td><td class="mono">${esc(h.masked)}</td></tr>`).join('')}</tbody></table></div></div>` : ''}
    <div class="card full"><h2>If a real secret leaked</h2><ul class="signals">
      <li>${svg('key')}<span><b>Rotate it first.</b> Revoke the key in the provider's console (AWS IAM, GitHub settings, Stripe dashboard) and issue a new one. Until then, the leaked copy works for anyone.</span></li>
      <li>${svg('file')}<span><b>Move it out of the code</b> into an environment variable or a secrets manager, and add files like <span class="mono">.env</span> to <span class="mono">.gitignore</span>.</span></li>
      <li>${svg('alert')}<span><b>It's still in ${t('git history')}.</b> Anyone with the repo can run <span class="mono">git log -p</span> and read it. Rewriting history (<span class="mono">git filter-repo</span>) reduces exposure, but only rotation makes the old key useless.</span></li>
      <li>${svg('shield')}<span><b>Stop the next one:</b> run a scanner such as gitleaks as a pre-commit hook, and turn on GitHub secret scanning and push protection.</span></li></ul></div>`;
}

/* ---------- IAM Policy Analyzer ---------- */
const SENSITIVE = ['iam:PassRole', 'iam:CreateUser', 'iam:CreateAccessKey', 'iam:AttachUserPolicy', 'iam:AttachRolePolicy', 'iam:PutUserPolicy', 'iam:PutRolePolicy',
  'iam:CreatePolicyVersion', 'iam:UpdateAssumeRolePolicy', 'sts:AssumeRole', 'kms:Decrypt', 's3:DeleteBucket', 's3:PutBucketPolicy', 'lambda:UpdateFunctionCode', 'secretsmanager:GetSecretValue'];
const arr = v => v == null ? [] : Array.isArray(v) ? v : [v];
const wild = (pat, name) => new RegExp('^' + String(pat).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i').test(name);
function analyzeIam(text) {
  let pol; try { pol = JSON.parse(text); } catch (e) { throw new Error(`That isn't valid JSON (${e.message}). Paste the whole policy, from the first { to the last }.`); }
  const sts = arr(pol && pol.Statement);
  if (!sts.length) throw new Error('No "Statement" found. An IAM policy looks like {"Version": "2012-10-17", "Statement": [ ... ]}.');
  const out = [];
  sts.forEach((s, i) => {
    if (!s || s.Effect !== 'Allow') return; // Deny statements only take permissions away
    const where = s.Sid ? `Statement "${s.Sid}"` : `Statement ${i + 1}`, found = [], add = (sev, issue, fix) => found.push({ sev, where, issue, fix });
    const acts = arr(s.Action), anyRes = arr(s.Resource).includes('*'), cond = s.Condition && Object.keys(s.Condition).length > 0;
    const admin = acts.some(a => a === '*' || a === '*:*'), pr = s.Principal;
    if (admin) add('high', anyRes ? 'Allows every action on every resource: full administrator access.' : 'Allows every action in every AWS service.', 'List only the actions this identity actually calls, such as "s3:GetObject".');
    if (s.NotAction) add('high', 'Uses Allow with NotAction: it grants everything except the listed actions, including services AWS adds later.', 'Rewrite it as Action with an explicit list of the allowed actions.');
    if (anyRes && acts.some(a => /^s3:\*$/i.test(a))) add('high', 's3:* on every resource: can read, delete and make public every bucket in the account.', 'Grant only the S3 actions needed, on the one bucket that needs them.');
    if (!admin && anyRes && acts.some(a => wild(a, 'iam:PassRole'))) add('high', 'iam:PassRole on "*": can hand any role, including admin roles, to an EC2 server or Lambda function and then act as it.', 'Limit Resource to the ARNs of the specific roles this identity must pass.');
    const sens = admin ? [] : SENSITIVE.filter(n => acts.some(a => wild(a, n)) && !(n === 'iam:PassRole' && anyRes)); // PassRole on "*" is reported above
    if (sens.length && !cond) add('medium', `Sensitive actions with no Condition: ${sens.join(', ')}.`, 'Add a Condition, such as requiring MFA ("aws:MultiFactorAuthPresent": "true"), a source network, or a resource tag.');
    if (pr === '*' || arr(pr && pr.AWS).includes('*')) add(cond ? 'medium' : 'high',
      cond ? 'Principal is "*" (anyone), limited only by a Condition.' : 'Principal is "*": anyone on the internet, signed in or not, gets these permissions.',
      cond ? 'Check the Condition really narrows access, e.g. aws:PrincipalOrgID or aws:SourceVpce.' : 'Name the specific AWS accounts or roles that need access instead of "*".');
    if (anyRes && !admin && !found.some(f => f.sev === 'high')) add('medium', 'Resource is "*": the allowed actions work on every matching resource in the account.', 'Scope Resource to specific ARNs, such as "arn:aws:s3:::my-bucket/*".');
    out.push(...found);
  });
  return out;
}
const policy = o => JSON.stringify({ Version: '2012-10-17', Statement: o }, null, 2);
const SAMPLE_POLICIES = {
  'Over-permissive role': policy([
    { Sid: 'AppData', Effect: 'Allow', Action: 's3:*', Resource: '*' },
    { Sid: 'LaunchWorkers', Effect: 'Allow', Action: ['ec2:RunInstances', 'iam:PassRole'], Resource: '*' },
    { Sid: 'EverythingButIam', Effect: 'Allow', NotAction: 'iam:*', Resource: '*' },
    { Sid: 'NoBilling', Effect: 'Deny', Action: 'aws-portal:*', Resource: '*' }]),
  'Public bucket policy': policy([{ Sid: 'PublicRead', Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }]),
  'Least-privilege policy': policy([{ Sid: 'ReadReports', Effect: 'Allow', Action: ['s3:GetObject', 's3:ListBucket'], Resource: ['arn:aws:s3:::example-reports', 'arn:aws:s3:::example-reports/*'] }]),
};
S.register({ id: 'iam', name: 'IAM Policy Analyzer', group: 'Forensics', icon: 'd-usercheck', tag: 'local',
  tile: 'Paste an AWS IAM policy to flag wildcards, public access and privilege escalation, with a fix for each.',
  blurb: 'Paste an AWS IAM or resource policy to find over-broad permissions, each with a plain-English fix. Runs in your browser.',
  why: `In AWS, ${t('IAM')} policies decide who can do what. One wildcard can turn a read-only app into a full administrator, and ${t('iam:PassRole')} on "*" is a well-known ${t('privilege escalation')} path. Good policies follow ${t('least privilege')}: specific actions, specific ${t('ARN', 'resources')}, and a ${t('policy condition', 'Condition')} on anything sensitive. In a ${t('resource policy')}, a ${t('principal')} of "*" means anyone on the internet.`,
  render(mount) {
    pasteTool(mount, { label: 'IAM policy (JSON)', rows: 12, cta: 'Analyze', placeholder: '{ "Version": "2012-10-17", "Statement": [ … ] }', examples: SAMPLE_POLICIES,
      demo: { text: () => SAMPLE_POLICIES['Over-permissive role'], narrate: 'Analyzing a typical over-permissive role: s3:* everywhere, PassRole on any role, and an Allow with NotAction.' },
      run: (text, out) => { renderIam(analyzeIam(text), out); record('iam', 'Pasted IAM policy', out); } });
  } });
function renderIam(f, out) {
  const high = f.filter(x => x.sev === 'high').length;
  out.innerHTML = `<div class="card verdict ${high ? 'danger' : f.length ? 'warn' : 'safe'} full">
      <h2 class="big">${svg(high ? 'x' : f.length ? 'alert' : 'check')}${high ? 'Over-permissive policy' : f.length ? 'Could be tighter' : 'No common risks found'}</h2>
      <div class="sub">${high ? `${high} high-risk finding${high > 1 ? 's' : ''}. A stolen key with this policy could do far more than the app needs.`
        : f.length ? `${f.length} finding${f.length > 1 ? 's' : ''} worth fixing to reach ${t('least privilege')}.`
        : 'None of the common mistakes appear. This checks patterns, not intent: compare the actions with what the app really calls (IAM Access Analyzer can generate that list).'}</div></div>
    ${f.length ? `<div class="card full"><h2>Findings <span class="mut">(${f.length})</span></h2><ul class="signals">${f.map(x => `<li>${svg(SEV[x.sev][1])}<div>
      <div>${sevBadge(x.sev)} <b>${esc(x.where)}</b></div><div>${esc(x.issue)}</div><div class="mut">Fix: ${esc(x.fix)}</div></div></li>`).join('')}</ul></div>` : ''}`;
}
Object.assign(S.lib, { scanSecrets, maskSecret, analyzeIam });

})();
