'use strict';
const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cookieParser());

// ── 環境変数から読む(ソースにもDevToolsにも出ない) ──
const VIP_ID = process.env.VIP_ID;
const VIP_PW = process.env.VIP_PW;
if (!VIP_ID || !VIP_PW) {
  console.error('VIP_ID / VIP_PW が未設定です');
  process.exit(1);
}

// ── サーバー保持のVIP状態 ──
// target: 次に当てる項目 / consume: "consume"|"keep"
const vipState = { target: '', consume: 'consume' };

// ── セッション(メモリ) ──
// Map<token, {expires}>
const sessions = new Map();
const SESSION_TTL = 60 * 60 * 1000; // 1時間

function newToken() {
  return crypto.randomBytes(32).toString('hex');
}
function issueSession(res) {
  const token = newToken();
  sessions.set(token, Date.now() + SESSION_TTL);
  res.cookie('vip_sid', token, {
    httpOnly: true,           // JSから読めない
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: SESSION_TTL,
  });
}
function isAuthed(req) {
  const t = req.cookies.vip_sid;
  if (!t) return false;
  const exp = sessions.get(t);
  if (!exp) return false;
  if (Date.now() > exp) { sessions.delete(t); return false; }
  return true;
}
function requireAuth(req, res, next) {
  if (!isAuthed(req)) return res.status(401).json({ error: 'unauthorized' });
  next();
}

// ── 認証 ──
app.post('/api/vip-login', (req, res) => {
  const { id, pw } = req.body || {};
  // タイミング攻撃対策に固定長比較
  const safeEq = (a, b) => {
    const ab = Buffer.from(String(a)); const bb = Buffer.from(String(b));
    if (ab.length !== bb.length) return false;
    return crypto.timingSafeEqual(ab, bb);
  };
  if (safeEq(id, VIP_ID) && safeEq(pw, VIP_PW)) {
    issueSession(res);
    return res.json({ ok: true });
  }
  return res.status(401).json({ error: 'invalid' });
});

app.post('/api/vip-logout', (req, res) => {
  const t = req.cookies.vip_sid;
  if (t) sessions.delete(t);
  res.clearCookie('vip_sid');
  res.json({ ok: true });
});

app.get('/api/vip-status', (req, res) => {
  res.json({ authed: isAuthed(req) });
});

// ── VIP設定 ──
app.get('/api/vip-settings', requireAuth, (req, res) => {
  res.json({ target: vipState.target, consume: vipState.consume });
});

app.post('/api/vip-settings', requireAuth, (req, res) => {
  const { target, consume } = req.body || {};
  vipState.target = typeof target === 'string' ? target : '';
  vipState.consume = consume === 'keep' ? 'keep' : 'consume';
  res.json({ ok: true, target: vipState.target, consume: vipState.consume });
});

// ── ルーレットが「当選を問い合わせる」API ──
// クライアントは「当選インデックス」をサーバーから受け取る
app.post('/api/spin', (req, res) => {
  const { items } = req.body || {};
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'no items' });
  }
  let idx = Math.floor(Math.random() * items.length);

  // VIP指定があり、リストに含まれるなら当てる
  if (vipState.target && items.includes(vipState.target)) {
    idx = items.indexOf(vipState.target);
    if (vipState.consume === 'consume') {
      vipState.target = '';
    }
  }
  res.json({ idx });
});

// ── 静的ファイル ──
// 今のファイル配置（publicフォルダなし）に合わせる
app.use(express.static(__dirname));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/vip', (req, res) => res.sendFile(path.join(__dirname, 'vip.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('listening on', PORT));