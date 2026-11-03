const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const PORT = process.env.PORT || 8080;
const RELAY_HOST = process.env.RELAY_HOST || `localhost:${PORT}`;

// Supabase clients
const supaAnon = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY,
  { auth: { persistSession: false } }
);
const supaAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

// Active tunnels: username → { ws, pending: Map<reqId, {resolve, timer}> }
const tunnels = new Map();

const app = express();
app.use(express.json({ limit: '20mb' }));

// =====================================================
// 1) /auth — full credential verification
// =====================================================
app.post('/auth', async (req, res) => {
  const { username, password, token } = req.body || {};
  if (!username || !password || !token) {
    return res.json({ ok: false, error: 'username, password and token are required' });
  }

  try {
    // (a) find profile by username
    const { data: profile, error: pErr } = await supaAdmin
      .from('profiles')
      .select('id, email, username')
      .ilike('username', username)
      .maybeSingle();

    if (pErr) throw pErr;
    if (!profile) return res.json({ ok: false, error: 'User not found' });

    // (b) verify password
    const { data: authData, error: aErr } = await supaAnon.auth.signInWithPassword({
      email: profile.email,
      password,
    });
    if (aErr || !authData?.session) {
      return res.json({ ok: false, error: 'Invalid password' });
    }

    // (c) verify token (service-role RPC)
    const { data: tokenOk, error: tErr } = await supaAdmin.rpc('verify_tunnel_token', {
      p_username: profile.username,
      p_token: token,
    });
    if (tErr) throw tErr;
    if (!tokenOk) {
      return res.json({ ok: false, error: 'Invalid or expired token' });
    }

    // (d) success — return JWT for WS auth
    return res.json({
      ok: true,
      jwt: authData.session.access_token,
      refresh_token: authData.session.refresh_token,
      username: profile.username,
      public_url: `https://${RELAY_HOST}/t/${profile.username}/`,
    });
  } catch (err) {
    console.error('[auth]', err);
    res.status(500).json({ ok: false, error: 'Internal error' });
  }
});

// =====================================================
// 2) WebSocket server for CLI
// =====================================================
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/_ws' });

wss.on('connection', (ws) => {
  let authed = false;
  let username = null;

  const pingTimer = setInterval(() => {
    if (ws.readyState === ws.OPEN) ws.ping();
  }, 30_000);

  ws.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    // ---------- AUTH ----------
    if (msg.type === 'auth' && !authed) {
      try {
        const { data: userData, error: uErr } = await supaAdmin.auth.getUser(msg.jwt);
        if (uErr || !userData?.user) {
          ws.send(JSON.stringify({ type: 'auth_err', error: 'Invalid JWT' }));
          return ws.close();
        }

        const { data: profile } = await supaAdmin
          .from('profiles')
          .select('username')
          .eq('id', userData.user.id)
          .single();

        if (!profile) {
          ws.send(JSON.stringify({ type: 'auth_err', error: 'Profile not found' }));
          return ws.close();
        }

        if (tunnels.has(profile.username)) {
          ws.send(JSON.stringify({ type: 'auth_err', error: 'Tunnel already active from another device' }));
          return ws.close();
        }

        authed = true;
        username = profile.username;
        tunnels.set(username, { ws, pending: new Map() });

        ws.send(JSON.stringify({
          type: 'auth_ok',
          public_url: `https://${RELAY_HOST}/t/${username}/`,
        }));
        console.log(`[+] Tunnel ONLINE: ${username}`);
      } catch (err) {
        console.error('[ws-auth]', err);
        ws.send(JSON.stringify({ type: 'auth_err', error: 'Auth failed' }));
        ws.close();
      }
      return;
    }

    // ---------- RESPONSE from CLI ----------
    if (msg.type === 'response' && authed) {
      const tunnel = tunnels.get(username);
      const p = tunnel?.pending.get(msg.id);
      if (p) {
        clearTimeout(p.timer);
        p.resolve(msg);
        tunnel.pending.delete(msg.id);
      }
      return;
    }

    // ---------- PONG ----------
    if (msg.type === 'pong') return;
  });

  ws.on('close', () => {
    clearInterval(pingTimer);
    if (username) {
      tunnels.delete(username);
      console.log(`[-] Tunnel OFFLINE: ${username}`);
    }
  });

  ws.on('error', (e) => console.error('[ws-err]', e.message));
});

// =====================================================
// 3) Public HTTP proxy  —  /t/<username>/...
// =====================================================
app.use(async (req, res) => {
  const match = req.path.match(/^\/t\/([^/]+)(\/.*)?$/);
  if (!match) {
    return res
      .status(200)
      .send('<h1>AlphaTunnel Relay</h1><p>Use <code>/t/&lt;username&gt;/</code> to access a tunnel.</p>');
  }

  const targetUser = match[1];
  const restPath = match[2] || '/';
  const query = req.url.includes('?') ? '?' + req.url.split('?').slice(1).join('?') : '';

  const tunnel = tunnels.get(targetUser);
  if (!tunnel) {
    return res
      .status(502)
      .type('html')
      .send(`<h1>502 — Tunnel offline</h1><p>User <code>${targetUser}</code> is not connected.</p>`);
  }

  // Collect body
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = Buffer.concat(chunks);

  // Strip hop-by-hop headers
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const lk = k.toLowerCase();
    if (['host', 'connection', 'upgrade', 'keep-alive', 'transfer-encoding'].includes(lk)) continue;
    headers[k] = v;
  }

  const id = crypto.randomUUID();

  // Send request to CLI, wait for response
  const responsePromise = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      tunnel.pending.delete(id);
      reject(new Error('Tunnel timeout'));
    }, 30_000);
    tunnel.pending.set(id, { resolve, timer });
  });

  try {
    tunnel.ws.send(JSON.stringify({
      type: 'request',
      id,
      method: req.method,
      path: restPath + query,
      headers,
      body: body.toString('base64'),
    }));

    const resp = await responsePromise;

    res.status(resp.status || 200);

    for (const [k, v] of Object.entries(resp.headers || {})) {
      const lk = k.toLowerCase();
      if (['connection', 'transfer-encoding', 'content-length'].includes(lk)) continue;

      // Rewrite Location header for redirects
      if (lk === 'location' && typeof v === 'string') {
        if (v.startsWith('/t/')) res.setHeader(k, v);
        else if (v.startsWith('/')) res.setHeader(k, `/t/${targetUser}${v}`);
        else res.setHeader(k, v);
        continue;
      }
      res.setHeader(k, v);
    }

    let respBody = Buffer.from(resp.body || '', 'base64');

    // If HTML, inject <base href> so relative links work
    const ctype = (resp.headers?.['content-type'] || resp.headers?.['Content-Type'] || '').toLowerCase();
    if (ctype.includes('text/html')) {
      const baseTag = `<base href="/t/${targetUser}/">`;
      let html = respBody.toString('utf8');
      if (/<head[^>]*>/i.test(html)) {
        html = html.replace(/<head[^>]*>/i, (m) => m + baseTag);
      } else {
        html = baseTag + html;
      }
      respBody = Buffer.from(html, 'utf8');
    }

    res.send(respBody);
  } catch (err) {
    console.error('[proxy]', err.message);
    if (!res.headersSent) res.status(504).send('Tunnel timeout');
  }
});

// =====================================================
server.listen(PORT, () => {
  console.log(`✅ AlphaTunnel Relay listening on http://localhost:${PORT}`);
  console.log(`   Public URL format: https://${RELAY_HOST}/t/<username>/`);
});
