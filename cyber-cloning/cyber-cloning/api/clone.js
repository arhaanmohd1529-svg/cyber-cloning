const cheerio = require('cheerio'), archiver = require('archiver');
const dns = require('dns').promises, net = require('net'), crypto = require('crypto'), path = require('path');
const UA = 'Mozilla/5.0 (compatible; CyberCloning/1.0)';

// Safety: never let the server fetch private/internal addresses (SSRF protection)
function isPrivate(ip) {
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') ||
      (l.startsWith('::ffff:') && isPrivate(l.slice(7)));
  }
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}
async function assertPublic(u) {
  if (!/^https?:$/.test(u.protocol)) throw new Error('Only http/https URLs are allowed');
  const addrs = await dns.lookup(u.hostname, { all: true });
  if (!addrs.length || addrs.some(a => isPrivate(a.address))) throw new Error('This address is not allowed');
}
async function safeFetch(url, max = 3e6) {
  let u = new URL(url);
  for (let i = 0; i < 5; i++) {
    await assertPublic(u);
    const r = await fetch(u, { redirect: 'manual', headers: { 'User-Agent': UA }, signal: AbortSignal.timeout(8000) });
    if (r.status >= 300 && r.status < 400 && r.headers.get('location')) { u = new URL(r.headers.get('location'), u); continue; }
    if (!r.ok) throw new Error('Website returned HTTP ' + r.status);
    const buf = Buffer.from(await r.arrayBuffer());
    if (buf.length > max) throw new Error('File too large');
    return { buf, url: u.href };
  }
  throw new Error('Too many redirects');
}

// Best-effort rate limit (per serverless instance)
const hits = new Map();
function limited(ip) {
  const now = Date.now(), arr = (hits.get(ip) || []).filter(t => now - t < 60000);
  arr.push(now); hits.set(ip, arr); return arr.length > 10;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Use POST' });
  try {
    const ip = String(req.headers['x-forwarded-for'] || 'x').split(',')[0].trim();
    if (limited(ip)) return res.status(429).json({ error: 'Too many requests. Try again in a minute.' });
    let input = String((req.body && req.body.url) || '').trim();
    if (!input) throw new Error('Please enter a URL');
    if (!/^https?:\/\//i.test(input)) input = 'https://' + input;

    const page = await safeFetch(input, 8e6);
    const $ = cheerio.load(page.buf.toString('utf8'));
    $('base').remove(); $('img').removeAttr('srcset');

    const targets = [['link[rel~="stylesheet"]', 'href', '.css'], ['script[src]', 'src', '.js'],
      ['img[src]', 'src', ''], ['link[rel~="icon"]', 'href', '']];
    const jobs = [];
    for (const [sel, attr, defExt] of targets) $(sel).each((_, el) => {
      const v = $(el).attr(attr);
      if (!v || v.startsWith('data:')) return;
      try { jobs.push({ el, attr, defExt, abs: new URL(v, page.url).href }); } catch {}
    });
    const unique = [...new Set(jobs.map(j => j.abs))].slice(0, 60);
    const files = {};
    await Promise.all(unique.map(async abs => { files[abs] = await safeFetch(abs).catch(() => null); }));

    const out = [];
    for (const j of jobs) {
      const f = files[j.abs];
      if (!f) { $(j.el).attr(j.attr, j.abs); continue; } // not downloaded: keep the online link
      const ext = j.defExt || path.extname(new URL(j.abs).pathname).slice(0, 6) || '.png';
      const name = 'assets/' + crypto.createHash('sha1').update(j.abs).digest('hex').slice(0, 10) + ext;
      if (!out.find(o => o.name === name)) {
        let data = f.buf;
        if (ext === '.css') data = Buffer.from(f.buf.toString('utf8').replace(
          /url\((['"]?)(?!data:|https?:|\/\/)([^)'"]+)\1\)/g,
          (m, q, p) => { try { return `url(${q}${new URL(p, j.abs).href}${q})`; } catch { return m; } }));
        out.push({ name, data });
      }
      $(j.el).attr(j.attr, name).removeAttr('integrity').removeAttr('crossorigin');
    }
    const host = new URL(page.url).hostname.replace(/[^a-z0-9.-]/gi, '');
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${host}-clone.zip"`);
    res.setHeader('X-Assets', String(out.length));
    const z = archiver('zip'); z.on('error', () => res.end()); z.pipe(res);
    z.append($.html(), { name: 'index.html' });
    out.forEach(o => z.append(o.data, { name: o.name }));
    z.finalize();
  } catch (e) {
    if (!res.headersSent) res.status(400).json({ error: e.message || 'Something went wrong' });
  }
};
