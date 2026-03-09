import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-workers'

const app = new Hono()

app.use('/api/*', cors())
app.use('/static/*', serveStatic({ root: './public' }))

// ── API: Simulate Port Scan ──────────────────────────────────────────────────
app.post('/api/scan/ports', async (c) => {
  const { target } = await c.req.json()
  await sleep(1200)

  const commonPorts = [
    { port: 21,  service: 'FTP',     status: rand(['open','closed','filtered']), banner: 'vsftpd 3.0.5' },
    { port: 22,  service: 'SSH',     status: rand(['open','open','closed']),     banner: 'OpenSSH_8.9p1' },
    { port: 23,  service: 'Telnet',  status: 'filtered',                         banner: '' },
    { port: 25,  service: 'SMTP',    status: rand(['open','closed','filtered']), banner: 'Postfix 3.6.4' },
    { port: 53,  service: 'DNS',     status: 'open',                             banner: 'BIND 9.18' },
    { port: 80,  service: 'HTTP',    status: 'open',                             banner: 'nginx/1.22.1' },
    { port: 110, service: 'POP3',    status: rand(['open','closed']),             banner: '' },
    { port: 143, service: 'IMAP',    status: rand(['open','closed']),             banner: '' },
    { port: 443, service: 'HTTPS',   status: 'open',                             banner: 'nginx/1.22.1' },
    { port: 445, service: 'SMB',     status: rand(['open','filtered']),           banner: 'Samba 4.17' },
    { port: 3306,service: 'MySQL',   status: rand(['open','filtered','closed']), banner: 'MySQL 8.0.31' },
    { port: 3389,service: 'RDP',     status: rand(['open','filtered']),           banner: '' },
    { port: 5432,service: 'PostgreSQL', status: rand(['open','filtered']),       banner: 'PostgreSQL 15' },
    { port: 6379,service: 'Redis',   status: rand(['open','filtered']),           banner: 'Redis 7.0.7' },
    { port: 8080,service: 'HTTP-Alt',status: rand(['open','closed']),             banner: 'Apache Tomcat' },
    { port: 8443,service: 'HTTPS-Alt',status: rand(['open','closed']),            banner: '' },
    { port: 27017,service:'MongoDB', status: rand(['open','filtered']),           banner: 'MongoDB 6.0' },
  ]

  const open   = commonPorts.filter(p => p.status === 'open').length
  const closed = commonPorts.filter(p => p.status === 'closed').length
  const filt   = commonPorts.filter(p => p.status === 'filtered').length

  return c.json({
    target,
    scan_type: 'TCP SYN Scan',
    total_scanned: 1000,
    results: commonPorts,
    summary: { open, closed, filtered: filt },
    scan_time: (Math.random() * 3 + 1).toFixed(2) + 's',
    timestamp: new Date().toISOString()
  })
})

// ── API: Simulate SSL/TLS Analysis ─────────────────────────────────────────
app.post('/api/scan/ssl', async (c) => {
  const { target } = await c.req.json()
  await sleep(900)

  const expired = Math.random() > 0.85
  const expDate = new Date()
  if (!expired) expDate.setDate(expDate.getDate() + Math.floor(Math.random() * 300 + 30))
  else          expDate.setDate(expDate.getDate() - 10)

  return c.json({
    target,
    certificate: {
      subject:         `CN=${target}`,
      issuer:          rand(['Let\'s Encrypt Authority X3', 'DigiCert Inc', 'Sectigo RSA']),
      valid_from:      new Date(Date.now() - 86400000 * 60).toISOString().split('T')[0],
      valid_to:        expDate.toISOString().split('T')[0],
      days_remaining:  expired ? -10 : Math.floor(Math.random() * 300 + 30),
      expired,
      self_signed:     Math.random() > 0.9,
      wildcard:        Math.random() > 0.7,
      san:             [`${target}`, `www.${target}`, `mail.${target}`],
    },
    protocols: [
      { name: 'TLS 1.3', supported: true,  secure: true  },
      { name: 'TLS 1.2', supported: true,  secure: true  },
      { name: 'TLS 1.1', supported: rand([true,false]) as boolean, secure: false },
      { name: 'TLS 1.0', supported: rand([true,false]) as boolean, secure: false },
      { name: 'SSL 3.0', supported: false, secure: false },
      { name: 'SSL 2.0', supported: false, secure: false },
    ],
    cipher_suites: [
      { name: 'TLS_AES_256_GCM_SHA384',       strength: 'strong',   bits: 256 },
      { name: 'TLS_CHACHA20_POLY1305_SHA256',  strength: 'strong',   bits: 256 },
      { name: 'TLS_AES_128_GCM_SHA256',        strength: 'strong',   bits: 128 },
      { name: 'ECDHE-RSA-AES256-GCM-SHA384',   strength: 'strong',   bits: 256 },
      { name: 'ECDHE-RSA-AES128-GCM-SHA256',   strength: 'strong',   bits: 128 },
      { name: 'DHE-RSA-AES256-SHA',            strength: 'medium',   bits: 256 },
    ],
    vulnerabilities: pickVulns(['BEAST','POODLE','HEARTBLEED','ROBOT','LUCKY13','CRIME']),
    grade: expired ? 'F' : rand(['A+','A','A','B','B']),
    timestamp: new Date().toISOString()
  })
})

// ── API: HTTP Headers Analysis ──────────────────────────────────────────────
app.post('/api/scan/headers', async (c) => {
  const { target } = await c.req.json()
  await sleep(700)

  const allHeaders = [
    { name: 'Strict-Transport-Security', present: rand([true,true,false]) as boolean, value: 'max-age=31536000; includeSubDomains', severity: 'high',   description: 'Forces browsers to use HTTPS' },
    { name: 'Content-Security-Policy',   present: rand([true,false,false]) as boolean,value: "default-src 'self'",                  severity: 'high',   description: 'Prevents XSS and injection attacks' },
    { name: 'X-Frame-Options',           present: rand([true,true,false]) as boolean, value: 'DENY',                               severity: 'medium', description: 'Prevents clickjacking attacks' },
    { name: 'X-Content-Type-Options',    present: rand([true,true,false]) as boolean, value: 'nosniff',                            severity: 'medium', description: 'Prevents MIME type sniffing' },
    { name: 'Referrer-Policy',           present: rand([true,false]) as boolean,      value: 'strict-origin-when-cross-origin',    severity: 'low',    description: 'Controls referrer information' },
    { name: 'Permissions-Policy',        present: rand([true,false]) as boolean,      value: 'geolocation=(), microphone=()',      severity: 'low',    description: 'Controls browser feature permissions' },
    { name: 'X-XSS-Protection',         present: rand([true,true,false]) as boolean, value: '1; mode=block',                      severity: 'medium', description: 'Legacy XSS filter (deprecated)' },
    { name: 'Cache-Control',             present: true,                               value: 'no-store, no-cache',                 severity: 'low',    description: 'Controls caching behavior' },
  ]

  const exposed = [
    { name: 'Server',        present: rand([true,false]) as boolean, value: 'nginx/1.22.1',     risk: 'Exposes server software version' },
    { name: 'X-Powered-By',  present: rand([true,false]) as boolean, value: 'PHP/8.1.12',       risk: 'Exposes backend technology' },
    { name: 'X-AspNet-Version', present: rand([true,false]) as boolean, value: '4.0.30319',    risk: 'Exposes ASP.NET version' },
  ]

  const missing = allHeaders.filter(h => !h.present)
  const score   = Math.round((allHeaders.filter(h => h.present).length / allHeaders.length) * 100)

  return c.json({
    target,
    security_headers: allHeaders,
    exposed_headers:  exposed,
    missing_count:    missing.length,
    score,
    grade: score >= 90 ? 'A' : score >= 70 ? 'B' : score >= 50 ? 'C' : 'D',
    timestamp: new Date().toISOString()
  })
})

// ── API: DNS Enumeration ────────────────────────────────────────────────────
app.post('/api/scan/dns', async (c) => {
  const { target } = await c.req.json()
  await sleep(800)

  const base = target.replace(/^www\./, '')
  const ip   = `${randInt(1,254)}.${randInt(1,254)}.${randInt(1,254)}.${randInt(1,254)}`
  const ip2  = `${randInt(1,254)}.${randInt(1,254)}.${randInt(1,254)}.${randInt(1,254)}`

  return c.json({
    target,
    records: {
      A:    [{ value: ip, ttl: 300 }, { value: ip2, ttl: 300 }],
      AAAA: [{ value: `2606:4700:${randHex()}:${randHex()}::1`, ttl: 300 }],
      MX:   [
        { value: `mail.${base}`, priority: 10, ttl: 3600 },
        { value: `mail2.${base}`, priority: 20, ttl: 3600 },
      ],
      NS:   [
        { value: `ns1.${base}`, ttl: 86400 },
        { value: `ns2.${base}`, ttl: 86400 },
      ],
      TXT: [
        { value: `v=spf1 include:_spf.${base} ~all`, ttl: 300 },
        { value: 'v=DMARC1; p=quarantine; rua=mailto:dmarc@' + base, ttl: 300 },
      ],
      CNAME: [
        { name: `www.${base}`, value: base, ttl: 300 },
        { name: `mail.${base}`, value: `mail.${base}`, ttl: 300 },
      ],
    },
    subdomains: [
      { name: `www.${base}`,       ip,  status: 'active' },
      { name: `mail.${base}`,      ip: ip2, status: 'active' },
      { name: `api.${base}`,       ip,  status: rand(['active','inactive']) as string },
      { name: `admin.${base}`,     ip,  status: rand(['active','inactive']) as string },
      { name: `dev.${base}`,       ip,  status: rand(['active','inactive']) as string },
      { name: `staging.${base}`,   ip,  status: rand(['active','inactive']) as string },
      { name: `ftp.${base}`,       ip,  status: rand(['active','inactive']) as string },
      { name: `vpn.${base}`,       ip,  status: rand(['active','inactive']) as string },
    ],
    zone_transfer: { vulnerable: Math.random() > 0.8, message: 'AXFR refused' },
    timestamp: new Date().toISOString()
  })
})

// ── API: Vulnerability Scan ─────────────────────────────────────────────────
app.post('/api/scan/vuln', async (c) => {
  const { target } = await c.req.json()
  await sleep(1500)

  const vulns = [
    {
      id: 'CVE-2023-44487', name: 'HTTP/2 Rapid Reset Attack',
      severity: 'critical', cvss: 7.5,
      description: 'HTTP/2 protocol vulnerability allowing DoS via stream cancellation.',
      affected: 'Web Server', remediation: 'Update server to latest patched version.',
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-44487']
    },
    {
      id: 'CVE-2022-22965', name: 'Spring4Shell RCE',
      severity: 'critical', cvss: 9.8,
      description: 'Remote code execution in Spring Framework via data binding.',
      affected: 'Java Web Application', remediation: 'Upgrade to Spring Framework 5.3.18+.',
      references: ['https://spring.io/blog/2022/03/31/spring-framework-rce']
    },
    {
      id: 'CVE-2021-44228', name: 'Log4Shell',
      severity: 'critical', cvss: 10.0,
      description: 'JNDI injection via Log4j 2 logging library.',
      affected: 'Java Logging', remediation: 'Upgrade Log4j to 2.17.1 or higher.',
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228']
    },
    {
      id: 'MISC-CORS-001', name: 'CORS Misconfiguration',
      severity: 'high', cvss: 6.5,
      description: 'Access-Control-Allow-Origin set to wildcard (*), allowing cross-origin requests.',
      affected: 'API Endpoints', remediation: 'Restrict CORS to trusted origins only.',
      references: []
    },
    {
      id: 'MISC-COOKIE-001', name: 'Insecure Cookie Flags',
      severity: 'medium', cvss: 4.3,
      description: 'Session cookies missing HttpOnly and Secure flags.',
      affected: 'Session Management', remediation: 'Set Secure, HttpOnly, and SameSite cookie attributes.',
      references: []
    },
    {
      id: 'MISC-DIR-001', name: 'Directory Listing Enabled',
      severity: 'medium', cvss: 5.3,
      description: 'Web server reveals directory contents to unauthenticated users.',
      affected: 'Web Server Config', remediation: 'Disable directory listing in server configuration.',
      references: []
    },
    {
      id: 'MISC-INFO-001', name: 'Server Version Disclosure',
      severity: 'low', cvss: 2.7,
      description: 'Server header reveals exact software version.',
      affected: 'HTTP Response Headers', remediation: 'Configure server to suppress version information.',
      references: []
    },
    {
      id: 'MISC-TLS-001', name: 'Weak TLS Protocol Support',
      severity: 'medium', cvss: 5.9,
      description: 'Server supports deprecated TLS 1.0 and TLS 1.1 protocols.',
      affected: 'SSL/TLS Configuration', remediation: 'Disable TLS 1.0 and TLS 1.1, use TLS 1.2+ only.',
      references: []
    },
  ]

  // randomly exclude some
  const found   = vulns.filter(() => Math.random() > 0.3)
  const critical = found.filter(v => v.severity === 'critical').length
  const high     = found.filter(v => v.severity === 'high').length
  const medium   = found.filter(v => v.severity === 'medium').length
  const low      = found.filter(v => v.severity === 'low').length

  return c.json({
    target,
    vulnerabilities: found,
    summary: { total: found.length, critical, high, medium, low },
    risk_score: Math.min(10, (critical * 3 + high * 2 + medium + low * 0.5)).toFixed(1),
    timestamp: new Date().toISOString()
  })
})

// ── API: Full Scan ──────────────────────────────────────────────────────────
app.post('/api/scan/full', async (c) => {
  const { target } = await c.req.json()
  return c.json({ target, status: 'initiated', message: 'Full scan started. Poll individual endpoints.' })
})

// ── Serve Main HTML ─────────────────────────────────────────────────────────
app.get('/', (c) => {
  return c.html(htmlPage())
})

export default app

// ── Helpers ─────────────────────────────────────────────────────────────────
function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)) }
function rand<T>(arr: T[]): T { return arr[Math.floor(Math.random() * arr.length)] }
function randInt(min: number, max: number) { return Math.floor(Math.random() * (max - min + 1)) + min }
function randHex() { return Math.floor(Math.random() * 0xFFFF).toString(16).padStart(4, '0') }

function pickVulns(names: string[]) {
  return names.map(n => ({
    name: n,
    vulnerable: Math.random() > 0.75
  }))
}

// ── HTML Page ────────────────────────────────────────────────────────────────
function htmlPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>ProScan — Professional Security Scanner</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css"/>
<style>
  :root{--bg:#0a0e17;--card:#111827;--border:#1f2937;--accent:#00d4ff;--accent2:#7c3aed;--green:#10b981;--red:#ef4444;--yellow:#f59e0b;--orange:#f97316;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh;}
  ::-webkit-scrollbar{width:6px;} ::-webkit-scrollbar-track{background:#0a0e17;} ::-webkit-scrollbar-thumb{background:#374151;border-radius:3px;}

  /* Animated background */
  .bg-grid{position:fixed;inset:0;background-image:linear-gradient(rgba(0,212,255,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0;}
  .content{position:relative;z-index:1;}

  /* Cards */
  .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.25rem;}
  .card-glow{box-shadow:0 0 20px rgba(0,212,255,.08);}

  /* Scan input */
  .scan-input{background:#0f172a;border:1.5px solid var(--border);color:#e2e8f0;border-radius:10px;padding:.75rem 1rem;font-size:1rem;width:100%;transition:border-color .2s,box-shadow .2s;outline:none;}
  .scan-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,212,255,.1);}
  .btn-scan{background:linear-gradient(135deg,#00d4ff,#7c3aed);color:#fff;border:none;border-radius:10px;padding:.75rem 2rem;font-size:1rem;font-weight:600;cursor:pointer;transition:opacity .2s,transform .1s;white-space:nowrap;}
  .btn-scan:hover{opacity:.9;transform:translateY(-1px);}
  .btn-scan:active{transform:translateY(0);}
  .btn-scan:disabled{opacity:.5;cursor:not-allowed;transform:none;}

  /* Module tabs */
  .tab{padding:.5rem 1rem;border-radius:8px;cursor:pointer;font-size:.85rem;font-weight:500;transition:all .2s;border:1px solid transparent;color:#9ca3af;}
  .tab:hover{color:#e2e8f0;background:rgba(255,255,255,.05);}
  .tab.active{background:rgba(0,212,255,.1);border-color:rgba(0,212,255,.3);color:var(--accent);}

  /* Status badges */
  .badge{display:inline-flex;align-items:center;gap:.3rem;padding:.2rem .6rem;border-radius:999px;font-size:.75rem;font-weight:600;}
  .badge-open{background:rgba(16,185,129,.15);color:#10b981;}
  .badge-closed{background:rgba(239,68,68,.12);color:#ef4444;}
  .badge-filtered{background:rgba(245,158,11,.12);color:#f59e0b;}
  .badge-critical{background:rgba(239,68,68,.18);color:#ef4444;}
  .badge-high{background:rgba(249,115,22,.18);color:#f97316;}
  .badge-medium{background:rgba(245,158,11,.15);color:#f59e0b;}
  .badge-low{background:rgba(16,185,129,.15);color:#10b981;}
  .badge-info{background:rgba(59,130,246,.15);color:#60a5fa;}
  .badge-strong{background:rgba(16,185,129,.15);color:#10b981;}
  .badge-medium2{background:rgba(245,158,11,.15);color:#f59e0b;}
  .badge-weak{background:rgba(239,68,68,.15);color:#ef4444;}

  /* Progress bar */
  .progress-bar{height:6px;background:#1f2937;border-radius:999px;overflow:hidden;}
  .progress-fill{height:100%;background:linear-gradient(90deg,#00d4ff,#7c3aed);border-radius:999px;transition:width .4s ease;}

  /* Loader */
  .spinner{width:18px;height:18px;border:2px solid rgba(0,212,255,.2);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;display:inline-block;}
  @keyframes spin{to{transform:rotate(360deg)}}

  /* Pulse dot */
  .pulse-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 0 0 rgba(16,185,129,.4);animation:pulse-ring 1.5s infinite;}
  @keyframes pulse-ring{0%{box-shadow:0 0 0 0 rgba(16,185,129,.5)}70%{box-shadow:0 0 0 8px rgba(16,185,129,0)}100%{box-shadow:0 0 0 0 rgba(16,185,129,0)}}

  /* Table */
  .data-table{width:100%;border-collapse:collapse;font-size:.85rem;}
  .data-table th{padding:.6rem .8rem;text-align:left;color:#6b7280;font-weight:500;border-bottom:1px solid var(--border);font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;}
  .data-table td{padding:.6rem .8rem;border-bottom:1px solid rgba(31,41,55,.6);}
  .data-table tr:hover td{background:rgba(255,255,255,.02);}
  .data-table tr:last-child td{border-bottom:none;}

  /* Vulnerability card */
  .vuln-card{border:1px solid var(--border);border-radius:10px;padding:1rem;margin-bottom:.75rem;transition:border-color .2s;}
  .vuln-card:hover{border-color:rgba(0,212,255,.2);}
  .vuln-card.critical{border-left:3px solid #ef4444;}
  .vuln-card.high{border-left:3px solid #f97316;}
  .vuln-card.medium{border-left:3px solid #f59e0b;}
  .vuln-card.low{border-left:3px solid #10b981;}

  /* Grade circle */
  .grade-circle{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:1.5rem;font-weight:700;border:3px solid;}
  .grade-A{border-color:#10b981;color:#10b981;background:rgba(16,185,129,.1);}
  .grade-B{border-color:#60a5fa;color:#60a5fa;background:rgba(96,165,250,.1);}
  .grade-C{border-color:#f59e0b;color:#f59e0b;background:rgba(245,158,11,.1);}
  .grade-D{border-color:#f97316;color:#f97316;background:rgba(249,115,22,.1);}
  .grade-F{border-color:#ef4444;color:#ef4444;background:rgba(239,68,68,.1);}

  /* Scan module status */
  .mod-pending{color:#6b7280;}
  .mod-scanning{color:var(--accent);}
  .mod-done{color:var(--green);}
  .mod-error{color:var(--red);}

  /* Responsive */
  @media(max-width:640px){.scan-row{flex-direction:column;} .tabs-row{overflow-x:auto;} .hide-sm{display:none;}}

  /* Typewriter cursor */
  .typed::after{content:'|';animation:blink 1s step-end infinite;}
  @keyframes blink{50%{opacity:0}}

  /* Floating tag */
  .tag{display:inline-block;background:rgba(124,58,237,.15);color:#a78bfa;border:1px solid rgba(124,58,237,.2);border-radius:6px;padding:.15rem .5rem;font-size:.75rem;font-family:monospace;}
</style>
</head>
<body>
<div class="bg-grid"></div>
<div class="content">

<!-- NAVBAR -->
<nav style="border-bottom:1px solid var(--border);backdrop-filter:blur(8px);background:rgba(10,14,23,.85);position:sticky;top:0;z-index:100;">
  <div style="max-width:1200px;margin:0 auto;padding:.75rem 1.5rem;display:flex;align-items:center;justify-content:space-between;">
    <div style="display:flex;align-items:center;gap:.6rem;">
      <div style="width:32px;height:32px;background:linear-gradient(135deg,#00d4ff,#7c3aed);border-radius:8px;display:flex;align-items:center;justify-content:center;">
        <i class="fas fa-shield-halved" style="font-size:.9rem;color:#fff;"></i>
      </div>
      <span style="font-weight:700;font-size:1.1rem;background:linear-gradient(135deg,#00d4ff,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">ProScan</span>
      <span class="tag">v2.4.1</span>
    </div>
    <div style="display:flex;align-items:center;gap:1.5rem;">
      <div class="hide-sm" style="display:flex;align-items:center;gap:.4rem;font-size:.8rem;color:#6b7280;">
        <div class="pulse-dot"></div>
        <span>System Online</span>
      </div>
      <div style="font-size:.8rem;color:#6b7280;" class="hide-sm">
        <i class="fas fa-clock mr-1"></i><span id="clock"></span>
      </div>
    </div>
  </div>
</nav>

<!-- HERO -->
<div style="max-width:1200px;margin:0 auto;padding:2.5rem 1.5rem 0;">
  <div style="text-align:center;margin-bottom:2.5rem;">
    <div style="display:inline-flex;align-items:center;gap:.5rem;background:rgba(0,212,255,.08);border:1px solid rgba(0,212,255,.15);border-radius:999px;padding:.3rem 1rem;font-size:.8rem;color:var(--accent);margin-bottom:1rem;">
      <i class="fas fa-circle-info"></i>
      Educational / Demonstration Tool — No real attacks are performed
    </div>
    <h1 style="font-size:2.2rem;font-weight:800;line-height:1.2;margin-bottom:.75rem;">
      Professional
      <span style="background:linear-gradient(135deg,#00d4ff,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">Security Scanner</span>
    </h1>
    <p style="color:#9ca3af;max-width:520px;margin:0 auto;line-height:1.6;">
      Simulate comprehensive security assessments including port scanning, SSL analysis, header inspection, DNS enumeration and vulnerability detection.
    </p>
  </div>

  <!-- SCAN BAR -->
  <div class="card card-glow" style="margin-bottom:2rem;">
    <div class="scan-row" style="display:flex;gap:.75rem;align-items:flex-end;">
      <div style="flex:1;">
        <label style="display:block;font-size:.8rem;color:#9ca3af;margin-bottom:.4rem;font-weight:500;">
          <i class="fas fa-crosshairs mr-1" style="color:var(--accent);"></i>Target Domain / IP Address
        </label>
        <input id="targetInput" class="scan-input" type="text" placeholder="example.com  or  192.168.1.1" value="target.com"/>
      </div>
      <div>
        <label style="display:block;font-size:.8rem;color:#9ca3af;margin-bottom:.4rem;font-weight:500;">
          <i class="fas fa-layer-group mr-1" style="color:var(--accent);"></i>Scan Profile
        </label>
        <select id="profileSelect" class="scan-input" style="width:auto;cursor:pointer;">
          <option value="full">Full Scan</option>
          <option value="quick">Quick Scan</option>
          <option value="stealth">Stealth Mode</option>
        </select>
      </div>
      <button id="scanBtn" class="btn-scan" onclick="startFullScan()">
        <i class="fas fa-play mr-2"></i>Start Scan
      </button>
    </div>

    <!-- Progress -->
    <div id="progressSection" style="display:none;margin-top:1.25rem;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem;">
        <div style="display:flex;align-items:center;gap:.5rem;font-size:.85rem;color:var(--accent);">
          <div class="spinner"></div>
          <span id="progressLabel">Initializing scan...</span>
        </div>
        <span id="progressPct" style="font-size:.85rem;color:#9ca3af;">0%</span>
      </div>
      <div class="progress-bar"><div id="progressFill" class="progress-fill" style="width:0%"></div></div>
      <div id="moduleStatus" style="display:flex;flex-wrap:wrap;gap:.5rem;margin-top:.75rem;"></div>
    </div>
  </div>

  <!-- MODULE TABS -->
  <div class="tabs-row" style="display:flex;gap:.5rem;margin-bottom:1.25rem;overflow-x:auto;padding-bottom:.25rem;">
    <button class="tab active" onclick="showTab('overview')"  id="tab-overview">  <i class="fas fa-chart-pie mr-1"></i>Overview</button>
    <button class="tab"        onclick="showTab('ports')"     id="tab-ports">     <i class="fas fa-network-wired mr-1"></i>Port Scan</button>
    <button class="tab"        onclick="showTab('ssl')"       id="tab-ssl">       <i class="fas fa-lock mr-1"></i>SSL/TLS</button>
    <button class="tab"        onclick="showTab('headers')"   id="tab-headers">   <i class="fas fa-code mr-1"></i>Headers</button>
    <button class="tab"        onclick="showTab('dns')"       id="tab-dns">       <i class="fas fa-globe mr-1"></i>DNS</button>
    <button class="tab"        onclick="showTab('vulns')"     id="tab-vulns">     <i class="fas fa-bug mr-1"></i>Vulnerabilities</button>
  </div>

  <!-- PANELS -->
  <div id="panel-overview"> ${overviewPanel()} </div>
  <div id="panel-ports"    style="display:none"> ${emptyPanel('fa-network-wired','Port Scan','Run a scan to see port analysis results')} </div>
  <div id="panel-ssl"      style="display:none"> ${emptyPanel('fa-lock','SSL/TLS Analysis','Run a scan to see SSL/TLS results')} </div>
  <div id="panel-headers"  style="display:none"> ${emptyPanel('fa-code','HTTP Headers','Run a scan to see security headers')} </div>
  <div id="panel-dns"      style="display:none"> ${emptyPanel('fa-globe','DNS Enumeration','Run a scan to see DNS records')} </div>
  <div id="panel-vulns"    style="display:none"> ${emptyPanel('fa-bug','Vulnerability Scan','Run a scan to see vulnerabilities')} </div>

  <div style="height:3rem;"></div>
</div><!-- end content wrap -->

</div><!-- end content -->

<script>
// ── Clock ────────────────────────────────────────────────────────────────────
function updateClock(){
  const n=new Date();
  document.getElementById('clock').textContent=n.toLocaleTimeString('en-US',{hour12:false})+' UTC';
}
setInterval(updateClock,1000); updateClock();

// ── Tab management ───────────────────────────────────────────────────────────
const tabs=['overview','ports','ssl','headers','dns','vulns'];
function showTab(name){
  tabs.forEach(t=>{
    document.getElementById('panel-'+t).style.display = t===name?'block':'none';
    document.getElementById('tab-'+t).classList.toggle('active',t===name);
  });
}

// ── Scan orchestrator ────────────────────────────────────────────────────────
let scanRunning=false;
async function startFullScan(){
  if(scanRunning) return;
  const target = document.getElementById('targetInput').value.trim();
  if(!target){alert('Please enter a target domain or IP address.');return;}

  scanRunning=true;
  const btn=document.getElementById('scanBtn');
  btn.disabled=true;
  btn.innerHTML='<i class="fas fa-circle-stop mr-2"></i>Scanning...';

  // show progress
  document.getElementById('progressSection').style.display='block';

  const modules=[
    {key:'ports',   label:'Port Scan',           icon:'fa-network-wired', url:'/api/scan/ports'},
    {key:'ssl',     label:'SSL/TLS Analysis',     icon:'fa-lock',          url:'/api/scan/ssl'},
    {key:'headers', label:'HTTP Headers',         icon:'fa-code',          url:'/api/scan/headers'},
    {key:'dns',     label:'DNS Enumeration',      icon:'fa-globe',         url:'/api/scan/dns'},
    {key:'vuln',    label:'Vulnerability Scan',   icon:'fa-bug',           url:'/api/scan/vuln'},
  ];

  // render module pills
  const ms=document.getElementById('moduleStatus');
  ms.innerHTML = modules.map(m=>\`
    <div id="modbadge-\${m.key}" style="display:flex;align-items:center;gap:.35rem;font-size:.78rem;padding:.25rem .7rem;border-radius:999px;background:rgba(31,41,55,.8);border:1px solid var(--border);">
      <i class="fas \${m.icon} mod-pending" id="modicon-\${m.key}"></i>
      <span class="mod-pending" id="modlabel-\${m.key}">\${m.label}</span>
    </div>
  \`).join('');

  const results={};
  const total=modules.length;

  for(let i=0;i<modules.length;i++){
    const m=modules[i];
    const pct=Math.round((i/total)*100);
    setProgress(pct, 'Scanning: '+m.label+'...');
    setModStatus(m.key,'scanning');

    try{
      const r=await fetch(m.url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target})});
      results[m.key]=await r.json();
      setModStatus(m.key,'done');
    }catch(e){
      results[m.key]={error:true};
      setModStatus(m.key,'error');
    }
  }

  setProgress(100,'Scan complete!');
  setTimeout(()=>{ document.getElementById('progressSection').style.display='none'; },2000);

  renderResults(target, results);

  btn.disabled=false;
  btn.innerHTML='<i class="fas fa-rotate-right mr-2"></i>Re-Scan';
  scanRunning=false;
}

function setProgress(pct,label){
  document.getElementById('progressFill').style.width=pct+'%';
  document.getElementById('progressPct').textContent=pct+'%';
  document.getElementById('progressLabel').textContent=label;
}

function setModStatus(key,status){
  const icon=document.getElementById('modicon-'+key);
  const label=document.getElementById('modlabel-'+key);
  if(!icon||!label)return;
  const map={scanning:'mod-scanning',done:'mod-done',error:'mod-error',pending:'mod-pending'};
  icon.className=icon.className.replace(/mod-\\S+/g,'');
  label.className=label.className.replace(/mod-\\S+/g,'');
  icon.classList.add(map[status]||'mod-pending');
  label.classList.add(map[status]||'mod-pending');
  if(status==='scanning') icon.classList.add('fa-spin');
  else icon.classList.remove('fa-spin');
}

// ── Render all results ───────────────────────────────────────────────────────
function renderResults(target, res){
  // Overview
  document.getElementById('panel-overview').innerHTML = renderOverview(target, res);
  // Ports
  if(res.ports) document.getElementById('panel-ports').innerHTML = renderPorts(res.ports);
  // SSL
  if(res.ssl)   document.getElementById('panel-ssl').innerHTML   = renderSSL(res.ssl);
  // Headers
  if(res.headers) document.getElementById('panel-headers').innerHTML = renderHeaders(res.headers);
  // DNS
  if(res.dns)   document.getElementById('panel-dns').innerHTML   = renderDNS(res.dns);
  // Vuln
  if(res.vuln)  document.getElementById('panel-vulns').innerHTML = renderVulns(res.vuln);

  showTab('overview');
}

// ── Overview ─────────────────────────────────────────────────────────────────
function renderOverview(target, res){
  const p=res.ports, s=res.ssl, h=res.headers, d=res.dns, v=res.vuln;
  const critical = v ? v.summary.critical : 0;
  const high      = v ? v.summary.high : 0;
  const riskScore = v ? parseFloat(v.risk_score) : 0;
  const riskColor = riskScore>=7?'#ef4444':riskScore>=4?'#f59e0b':'#10b981';

  return \`
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:1.5rem;">
    \${statCard('fa-crosshairs','Target',target,'var(--accent)')}
    \${statCard('fa-triangle-exclamation','Risk Score',riskScore.toFixed(1)+'/10',riskColor)}
    \${statCard('fa-door-open','Open Ports',p?p.summary.open:'—','#10b981')}
    \${statCard('fa-bug','Vulnerabilities',v?v.summary.total:'—','#f97316')}
    \${statCard('fa-lock','SSL Grade',s?s.grade:'—',s&&(s.grade==='A+'||s.grade==='A')?'#10b981':'#f59e0b')}
    \${statCard('fa-shield-halved','Header Score',h?h.score+'%':'—',h&&h.score>=70?'#10b981':'#f59e0b')}
  </div>

  \${critical>0?\`
  <div style="background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);border-radius:10px;padding:1rem;margin-bottom:1.5rem;display:flex;align-items:center;gap:.75rem;">
    <i class="fas fa-circle-exclamation" style="color:#ef4444;font-size:1.2rem;"></i>
    <div>
      <div style="font-weight:600;color:#ef4444;margin-bottom:.15rem;">Critical Vulnerabilities Detected</div>
      <div style="font-size:.85rem;color:#9ca3af;">\${critical} critical and \${high} high severity issues found. Immediate remediation recommended.</div>
    </div>
  </div>\`:''}

  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:1.25rem;">
    <!-- Vuln breakdown -->
    \${v?\`
    <div class="card">
      <div style="font-weight:600;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem;">
        <i class="fas fa-bug" style="color:var(--accent);"></i>Vulnerability Summary
      </div>
      \${['critical','high','medium','low'].map(sev=>\`
        <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:.75rem;">
          <span class="badge badge-\${sev}" style="min-width:70px;justify-content:center;">\${sev.toUpperCase()}</span>
          <div class="progress-bar" style="flex:1;height:8px;">
            <div class="progress-fill" style="width:\${v.summary[sev]/v.summary.total*100||0}%;background:\${sev==='critical'?'#ef4444':sev==='high'?'#f97316':sev==='medium'?'#f59e0b':'#10b981'};"></div>
          </div>
          <span style="min-width:24px;text-align:right;font-weight:600;">\${v.summary[sev]}</span>
        </div>
      \`).join('')}
    </div>\`:''}

    <!-- Port summary -->
    \${p?\`
    <div class="card">
      <div style="font-weight:600;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem;">
        <i class="fas fa-network-wired" style="color:var(--accent);"></i>Port Status Summary
      </div>
      \${[['open','#10b981'],['closed','#ef4444'],['filtered','#f59e0b']].map(([st,col])=>\`
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:.6rem;">
          <div style="display:flex;align-items:center;gap:.5rem;">
            <div style="width:10px;height:10px;border-radius:50%;background:\${col};"></div>
            <span style="text-transform:capitalize;">\${st}</span>
          </div>
          <span style="font-weight:600;">\${p.summary[st]}</span>
        </div>
      \`).join('')}
      <div style="border-top:1px solid var(--border);padding-top:.6rem;margin-top:.2rem;font-size:.8rem;color:#6b7280;">
        Total scanned: \${p.total_scanned.toLocaleString()} ports · \${p.scan_time}
      </div>
    </div>\`:''}

    <!-- SSL quick -->
    \${s?\`
    <div class="card">
      <div style="font-weight:600;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem;">
        <i class="fas fa-lock" style="color:var(--accent);"></i>SSL/TLS Overview
      </div>
      <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem;">
        <div class="grade-circle grade-\${s.grade[0]}">\${s.grade}</div>
        <div>
          <div style="font-weight:600;">\${s.certificate.issuer}</div>
          <div style="font-size:.82rem;color:\${s.certificate.expired?'#ef4444':'#10b981'};">
            \${s.certificate.expired?'⚠ Certificate EXPIRED':'✓ Valid until '+s.certificate.valid_to}
          </div>
        </div>
      </div>
      <div style="font-size:.82rem;color:#9ca3af;">\${s.vulnerabilities.filter(x=>x.vulnerable).length} SSL vulnerabilities detected</div>
    </div>\`:''}

    <!-- DNS quick -->
    \${d?\`
    <div class="card">
      <div style="font-weight:600;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem;">
        <i class="fas fa-globe" style="color:var(--accent);"></i>DNS Overview
      </div>
      <div style="font-size:.85rem;margin-bottom:.5rem;">
        <span style="color:#6b7280;">A Records:</span> <span>\${d.records.A.map(r=>r.value).join(', ')}</span>
      </div>
      <div style="font-size:.85rem;margin-bottom:.5rem;">
        <span style="color:#6b7280;">Name Servers:</span> <span>\${d.records.NS.map(r=>r.value).join(', ')}</span>
      </div>
      <div style="font-size:.85rem;margin-bottom:.5rem;">
        <span style="color:#6b7280;">Subdomains found:</span> <strong>\${d.subdomains.filter(s=>s.status==='active').length} active</strong>
      </div>
      <div style="font-size:.82rem;">
        Zone Transfer: <span style="color:\${d.zone_transfer.vulnerable?'#ef4444':'#10b981'};">\${d.zone_transfer.vulnerable?'⚠ VULNERABLE':'✓ Protected'}</span>
      </div>
    </div>\`:''}
  </div>
  \`;
}

function statCard(icon,label,value,color){
  return \`
  <div class="card" style="display:flex;align-items:center;gap:.9rem;">
    <div style="width:42px;height:42px;border-radius:10px;background:rgba(0,212,255,.08);display:flex;align-items:center;justify-content:center;flex-shrink:0;">
      <i class="fas \${icon}" style="color:\${color};font-size:1rem;"></i>
    </div>
    <div style="min-width:0;">
      <div style="font-size:.75rem;color:#6b7280;margin-bottom:.1rem;">\${label}</div>
      <div style="font-weight:700;font-size:1.05rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">\${value}</div>
    </div>
  </div>\`;
}

// ── Port Panel ────────────────────────────────────────────────────────────────
function renderPorts(data){
  return \`
  <div class="card card-glow" style="margin-bottom:1rem;">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.5rem;margin-bottom:.75rem;">
      <div style="font-weight:600;display:flex;align-items:center;gap:.5rem;">
        <i class="fas fa-network-wired" style="color:var(--accent);"></i>
        TCP Port Scan — \${data.target}
      </div>
      <div style="display:flex;gap:.5rem;flex-wrap:wrap;">
        <span class="badge badge-open"><i class="fas fa-circle"></i>\${data.summary.open} Open</span>
        <span class="badge badge-closed"><i class="fas fa-circle"></i>\${data.summary.closed} Closed</span>
        <span class="badge badge-filtered"><i class="fas fa-circle"></i>\${data.summary.filtered} Filtered</span>
      </div>
    </div>
    <table class="data-table">
      <thead>
        <tr><th>Port</th><th>Service</th><th>Status</th><th>Banner</th></tr>
      </thead>
      <tbody>
        \${data.results.map(p=>\`
          <tr>
            <td style="font-family:monospace;font-weight:600;">\${p.port}/tcp</td>
            <td>\${p.service}</td>
            <td><span class="badge badge-\${p.status}">\${p.status.toUpperCase()}</span></td>
            <td style="color:#9ca3af;font-size:.82rem;font-family:monospace;">\${p.banner||'—'}</td>
          </tr>
        \`).join('')}
      </tbody>
    </table>
    <div style="margin-top:.75rem;font-size:.8rem;color:#6b7280;">
      <i class="fas fa-info-circle mr-1"></i>
      Scan type: \${data.scan_type} · \${data.total_scanned.toLocaleString()} ports scanned · Completed in \${data.scan_time}
    </div>
  </div>\`;
}

// ── SSL Panel ─────────────────────────────────────────────────────────────────
function renderSSL(data){
  const c=data.certificate;
  return \`
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem;margin-bottom:1rem;">
    <div class="card card-glow">
      <div style="font-weight:600;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem;">
        <i class="fas fa-certificate" style="color:var(--accent);"></i>Certificate Details
      </div>
      <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem;">
        <div class="grade-circle grade-\${data.grade[0]}">\${data.grade}</div>
        <div>
          <div style="font-weight:600;font-size:.9rem;">\${c.issuer}</div>
          <div style="font-size:.8rem;color:#6b7280;">\${c.subject}</div>
        </div>
      </div>
      \${infoRow('Valid From', c.valid_from)}
      \${infoRow('Valid To', '<span style="color:'+( c.expired?'#ef4444':'#10b981')+'">'+(c.expired?'⚠ EXPIRED: ':'')+c.valid_to+'</span>')}
      \${infoRow('Days Remaining', c.expired?'<span style="color:#ef4444;">Expired</span>':c.days_remaining+' days')}
      \${infoRow('Self-Signed', c.self_signed?'<span style="color:#ef4444;">YES ⚠</span>':'<span style="color:#10b981;">No</span>')}
      \${infoRow('Wildcard', c.wildcard?'<span style="color:#f59e0b;">Yes</span>':'No')}
      \${infoRow('SANs', c.san.join(', '))}
    </div>

    <div class="card">
      <div style="font-weight:600;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem;">
        <i class="fas fa-shield-halved" style="color:var(--accent);"></i>Protocol Support
      </div>
      \${data.protocols.map(p=>\`
        <div style="display:flex;align-items:center;justify-content:space-between;padding:.4rem 0;border-bottom:1px solid rgba(31,41,55,.5);">
          <span style="font-family:monospace;">\${p.name}</span>
          <div style="display:flex;gap:.5rem;align-items:center;">
            \${!p.secure?'<span style="font-size:.75rem;color:#f59e0b;">insecure</span>':''}
            <span class="badge \${p.supported?(p.secure?'badge-open':'badge-high'):'badge-closed'}">\${p.supported?'ENABLED':'DISABLED'}</span>
          </div>
        </div>
      \`).join('')}
    </div>

    <div class="card">
      <div style="font-weight:600;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem;">
        <i class="fas fa-key" style="color:var(--accent);"></i>Cipher Suites
      </div>
      \${data.cipher_suites.map(cs=>\`
        <div style="display:flex;align-items:center;justify-content:space-between;padding:.4rem 0;border-bottom:1px solid rgba(31,41,55,.5);">
          <span style="font-family:monospace;font-size:.8rem;">\${cs.name}</span>
          <div style="display:flex;gap:.4rem;align-items:center;">
            <span style="font-size:.78rem;color:#6b7280;">\${cs.bits}-bit</span>
            <span class="badge \${cs.strength==='strong'?'badge-strong':'badge-medium2'}">\${cs.strength}</span>
          </div>
        </div>
      \`).join('')}
    </div>

    <div class="card">
      <div style="font-weight:600;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem;">
        <i class="fas fa-bug" style="color:var(--accent);"></i>SSL Vulnerabilities
      </div>
      \${data.vulnerabilities.map(v=>\`
        <div style="display:flex;align-items:center;justify-content:space-between;padding:.4rem 0;border-bottom:1px solid rgba(31,41,55,.5);">
          <span style="font-family:monospace;">\${v.name}</span>
          <span class="badge \${v.vulnerable?'badge-critical':'badge-open'}">\${v.vulnerable?'VULNERABLE':'SAFE'}</span>
        </div>
      \`).join('')}
    </div>
  </div>\`;
}

// ── Headers Panel ─────────────────────────────────────────────────────────────
function renderHeaders(data){
  return \`
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem;margin-bottom:1rem;">
    <div class="card card-glow">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;">
        <div style="font-weight:600;display:flex;align-items:center;gap:.5rem;">
          <i class="fas fa-shield-check" style="color:var(--accent);"></i>Security Score
        </div>
        <span class="grade-circle grade-\${data.grade}" style="width:48px;height:48px;font-size:1.2rem;">\${data.grade}</span>
      </div>
      <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem;">
        <div class="progress-bar" style="flex:1;height:10px;">
          <div class="progress-fill" style="width:\${data.score}%;background:\${data.score>=70?'#10b981':'#f59e0b'};"></div>
        </div>
        <span style="font-weight:700;font-size:1.1rem;">\${data.score}%</span>
      </div>
      <div style="font-size:.82rem;color:#9ca3af;">\${data.missing_count} security headers missing</div>
    </div>

    <div class="card">
      <div style="font-weight:600;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem;">
        <i class="fas fa-eye-slash" style="color:var(--accent);"></i>Exposed Server Headers
      </div>
      \${data.exposed_headers.map(h=>\`
        <div style="padding:.5rem 0;border-bottom:1px solid rgba(31,41,55,.5);">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.2rem;">
            <span style="font-family:monospace;font-size:.85rem;">\${h.name}</span>
            <span class="badge \${h.present?'badge-high':'badge-open'}">\${h.present?'EXPOSED':'HIDDEN'}</span>
          </div>
          \${h.present?\`<div style="font-family:monospace;font-size:.78rem;color:#9ca3af;">\${h.value}</div>
          <div style="font-size:.75rem;color:#f97316;margin-top:.1rem;">\${h.risk}</div>\`:''}
        </div>
      \`).join('')}
    </div>
  </div>

  <div class="card">
    <div style="font-weight:600;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem;">
      <i class="fas fa-list-check" style="color:var(--accent);"></i>Security Headers Checklist
    </div>
    <table class="data-table">
      <thead><tr><th>Header</th><th>Status</th><th>Severity</th><th>Value / Description</th></tr></thead>
      <tbody>
        \${data.security_headers.map(h=>\`
          <tr>
            <td style="font-family:monospace;font-size:.85rem;">\${h.name}</td>
            <td><span class="badge \${h.present?'badge-open':'badge-closed'}">\${h.present?'✓ Present':'✗ Missing'}</span></td>
            <td><span class="badge badge-\${h.severity}">\${h.severity.toUpperCase()}</span></td>
            <td style="font-size:.82rem;color:\${h.present?'#9ca3af':'#ef4444'}">\${h.present?h.value:h.description}</td>
          </tr>
        \`).join('')}
      </tbody>
    </table>
  </div>\`;
}

// ── DNS Panel ─────────────────────────────────────────────────────────────────
function renderDNS(data){
  const r=data.records;
  return \`
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem;margin-bottom:1rem;">
    \${dnsSection('A Records',r.A.map(x=>x.value+'  <span style="color:#6b7280;font-size:.78rem;">TTL '+x.ttl+'</span>'))}
    \${dnsSection('AAAA Records',r.AAAA.map(x=>x.value+'  <span style="color:#6b7280;font-size:.78rem;">TTL '+x.ttl+'</span>'))}
    \${dnsSection('MX Records',r.MX.map(x=>'['+x.priority+'] '+x.value))}
    \${dnsSection('NS Records',r.NS.map(x=>x.value))}
    \${dnsSection('TXT Records',r.TXT.map(x=>x.value))}
    \${dnsSection('CNAME Records',r.CNAME.map(x=>x.name+' → '+x.value))}
  </div>

  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem;">
    <div class="card">
      <div style="font-weight:600;margin-bottom:.75rem;display:flex;align-items:center;gap:.5rem;">
        <i class="fas fa-sitemap" style="color:var(--accent);"></i>Subdomain Enumeration
      </div>
      <table class="data-table">
        <thead><tr><th>Subdomain</th><th>IP</th><th>Status</th></tr></thead>
        <tbody>
          \${data.subdomains.map(s=>\`
            <tr>
              <td style="font-family:monospace;font-size:.82rem;">\${s.name}</td>
              <td style="font-family:monospace;font-size:.82rem;color:#9ca3af;">\${s.ip}</td>
              <td><span class="badge \${s.status==='active'?'badge-open':'badge-closed'}">\${s.status.toUpperCase()}</span></td>
            </tr>
          \`).join('')}
        </tbody>
      </table>
    </div>

    <div class="card">
      <div style="font-weight:600;margin-bottom:.75rem;display:flex;align-items:center;gap:.5rem;">
        <i class="fas fa-exchange-alt" style="color:var(--accent);"></i>Zone Transfer Test
      </div>
      <div style="display:flex;align-items:center;gap:.75rem;padding:.75rem;border-radius:8px;background:\${data.zone_transfer.vulnerable?'rgba(239,68,68,.08)':'rgba(16,185,129,.08)'};border:1px solid \${data.zone_transfer.vulnerable?'rgba(239,68,68,.2)':'rgba(16,185,129,.2)'};">
        <i class="fas \${data.zone_transfer.vulnerable?'fa-triangle-exclamation':'fa-shield-halved'}" style="font-size:1.4rem;color:\${data.zone_transfer.vulnerable?'#ef4444':'#10b981'};"></i>
        <div>
          <div style="font-weight:600;color:\${data.zone_transfer.vulnerable?'#ef4444':'#10b981'};">
            \${data.zone_transfer.vulnerable?'ZONE TRANSFER VULNERABLE':'Zone Transfer Protected'}
          </div>
          <div style="font-size:.82rem;color:#9ca3af;">\${data.zone_transfer.message}</div>
        </div>
      </div>
    </div>
  </div>\`;
}

function dnsSection(title, items){
  return \`
  <div class="card">
    <div style="font-weight:600;margin-bottom:.75rem;font-size:.9rem;">\${title}</div>
    \${items.map(i=>\`<div style="font-family:monospace;font-size:.82rem;padding:.3rem 0;border-bottom:1px solid rgba(31,41,55,.4);color:#e2e8f0;">\${i}</div>\`).join('')}
  </div>\`;
}

// ── Vuln Panel ────────────────────────────────────────────────────────────────
function renderVulns(data){
  const sevOrder={critical:0,high:1,medium:2,low:3};
  const sorted=[...data.vulnerabilities].sort((a,b)=>sevOrder[a.severity]-sevOrder[b.severity]);
  return \`
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.75rem;margin-bottom:1.5rem;">
    \${['critical','high','medium','low'].map(s=>\`
      <div class="card" style="text-align:center;border-color:\${s==='critical'?'rgba(239,68,68,.25)':s==='high'?'rgba(249,115,22,.2)':s==='medium'?'rgba(245,158,11,.2)':'rgba(16,185,129,.2)'};">
        <div style="font-size:2rem;font-weight:800;color:\${s==='critical'?'#ef4444':s==='high'?'#f97316':s==='medium'?'#f59e0b':'#10b981'};">\${data.summary[s]}</div>
        <div style="font-size:.8rem;text-transform:uppercase;color:#6b7280;letter-spacing:.05em;">\${s}</div>
      </div>
    \`).join('')}
  </div>

  <div>
    \${sorted.map(v=>\`
      <div class="vuln-card \${v.severity}">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:.5rem;margin-bottom:.5rem;">
          <div>
            <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.25rem;">
              <span class="badge badge-\${v.severity}">\${v.severity.toUpperCase()}</span>
              <span style="font-family:monospace;font-size:.8rem;color:#9ca3af;">\${v.id}</span>
            </div>
            <div style="font-weight:600;">\${v.name}</div>
          </div>
          <div style="text-align:right;">
            <div style="font-size:.75rem;color:#6b7280;">CVSS Score</div>
            <div style="font-size:1.3rem;font-weight:700;color:\${v.cvss>=9?'#ef4444':v.cvss>=7?'#f97316':v.cvss>=4?'#f59e0b':'#10b981'};">\${v.cvss.toFixed(1)}</div>
          </div>
        </div>
        <div style="font-size:.85rem;color:#9ca3af;margin-bottom:.6rem;">\${v.description}</div>
        <div style="display:flex;flex-wrap:wrap;gap:.5rem;font-size:.82rem;">
          <div style="background:rgba(31,41,55,.8);border-radius:6px;padding:.2rem .6rem;">
            <span style="color:#6b7280;">Affected:</span> <span>\${v.affected}</span>
          </div>
        </div>
        <div style="margin-top:.6rem;padding:.5rem .75rem;background:rgba(16,185,129,.06);border-radius:6px;border-left:3px solid #10b981;font-size:.82rem;">
          <span style="color:#10b981;font-weight:600;">Remediation: </span>
          <span style="color:#9ca3af;">\${v.remediation}</span>
        </div>
      </div>
    \`).join('')}
  </div>
  <div style="margin-top:1rem;padding:.75rem 1rem;background:rgba(59,130,246,.06);border:1px solid rgba(59,130,246,.15);border-radius:8px;font-size:.82rem;color:#9ca3af;">
    <i class="fas fa-info-circle mr-1" style="color:#60a5fa;"></i>
    <strong style="color:#60a5fa;">Educational Note:</strong> These results are simulated for demonstration purposes. Real vulnerability scanning requires authorized testing tools and explicit permission from the target system owner.
  </div>\`;
}

function infoRow(label, value){
  return \`<div style="display:flex;justify-content:space-between;padding:.35rem 0;border-bottom:1px solid rgba(31,41,55,.5);font-size:.85rem;">
    <span style="color:#6b7280;">\${label}</span>
    <span style="text-align:right;">\${value}</span>
  </div>\`;
}
</script>
</body>
</html>`;
}

function overviewPanel() {
  return `
  <div class="card card-glow" style="text-align:center;padding:3rem 2rem;">
    <div style="width:64px;height:64px;background:linear-gradient(135deg,rgba(0,212,255,.1),rgba(124,58,237,.1));border:1px solid rgba(0,212,255,.2);border-radius:16px;display:flex;align-items:center;justify-content:center;margin:0 auto 1.25rem;">
      <i class="fas fa-radar" style="font-size:1.6rem;color:var(--accent);"></i>
    </div>
    <h2 style="font-size:1.25rem;font-weight:700;margin-bottom:.5rem;">Ready to Scan</h2>
    <p style="color:#9ca3af;max-width:380px;margin:0 auto .75rem;font-size:.9rem;line-height:1.6;">
      Enter a target domain or IP address above and click <strong style="color:#e2e8f0;">Start Scan</strong> to begin the security assessment.
    </p>
    <div style="display:flex;flex-wrap:wrap;gap:.5rem;justify-content:center;font-size:.8rem;">
      <span style="padding:.3rem .8rem;background:rgba(0,212,255,.08);border:1px solid rgba(0,212,255,.15);border-radius:999px;color:var(--accent);">Port Scanning</span>
      <span style="padding:.3rem .8rem;background:rgba(124,58,237,.08);border:1px solid rgba(124,58,237,.15);border-radius:999px;color:#a78bfa;">SSL/TLS Analysis</span>
      <span style="padding:.3rem .8rem;background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.15);border-radius:999px;color:#10b981;">Header Inspection</span>
      <span style="padding:.3rem .8rem;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.15);border-radius:999px;color:#f59e0b;">DNS Enumeration</span>
      <span style="padding:.3rem .8rem;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.15);border-radius:999px;color:#ef4444;">Vuln Detection</span>
    </div>
  </div>`;
}

function emptyPanel(icon: string, title: string, msg: string) {
  return `
  <div class="card card-glow" style="text-align:center;padding:3rem 2rem;">
    <i class="fas ${icon}" style="font-size:2rem;color:#374151;margin-bottom:1rem;display:block;"></i>
    <h3 style="font-size:1.1rem;font-weight:600;color:#6b7280;margin-bottom:.5rem;">${title}</h3>
    <p style="color:#4b5563;font-size:.88rem;">${msg}</p>
  </div>`;
}
