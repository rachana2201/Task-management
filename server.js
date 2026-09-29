const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const db = new Database('tasks.db');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tasks(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, title TEXT NOT NULL,
  description TEXT DEFAULT '', status TEXT DEFAULT 'todo', due TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);

const app = express();
app.use(express.json());
app.use(express.static('public'));

// ---------- WebSocket: push "changed" events to the owner's open tabs ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
const sockets = new Map(); // userId -> Set<ws>
wss.on('connection', (ws, req) => {
  try {
    const token = new URL(req.url, 'http://x').searchParams.get('token');
    const { id } = jwt.verify(token, SECRET);
    if (!sockets.has(id)) sockets.set(id, new Set());
    sockets.get(id).add(ws);
    ws.on('close', () => sockets.get(id)?.delete(ws));
  } catch { ws.close(); }
});
const notify = (uid) =>
  sockets.get(uid)?.forEach((ws) => ws.readyState === 1 && ws.send(JSON.stringify({ type: 'changed' })));

// ---------- Auth ----------
const sign = (u) => jwt.sign({ id: u.id }, SECRET, { expiresIn: '7d' });

app.post('/api/register', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password || password.length < 6)
    return res.status(400).json({ error: 'Email and a 6+ character password are required' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const r = db.prepare('INSERT INTO users(email,password) VALUES(?,?)').run(email.toLowerCase(), hash);
    res.json({ token: sign({ id: r.lastInsertRowid }) });
  } catch { res.status(409).json({ error: 'Email already registered' }); }
});

app.post('/api/login', (req, res) => {
  const { email = '', password = '' } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email.toLowerCase());
  if (!u || !bcrypt.compareSync(password, u.password))
    return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: sign(u) });
});

// Authorization middleware: every route below is scoped to the logged-in user
const auth = (req, res, next) => {
  try {
    req.uid = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET).id;
    next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
};

// ---------- Task CRUD ----------
const STATUSES = ['todo', 'doing', 'done'];

app.get('/api/tasks', auth, (req, res) =>
  res.json(db.prepare('SELECT * FROM tasks WHERE user_id=? ORDER BY id DESC').all(req.uid)));

app.post('/api/tasks', auth, (req, res) => {
  const { title, description = '', due = null } = req.body || {};
  if (!title?.trim()) return res.status(400).json({ error: 'Title is required' });
  const r = db.prepare('INSERT INTO tasks(user_id,title,description,due) VALUES(?,?,?,?)')
    .run(req.uid, title.trim(), description, due);
  notify(req.uid);
  res.status(201).json(db.prepare('SELECT * FROM tasks WHERE id=?').get(r.lastInsertRowid));
});

app.put('/api/tasks/:id', auth, (req, res) => {
  const t = db.prepare('SELECT * FROM tasks WHERE id=? AND user_id=?').get(req.params.id, req.uid);
  if (!t) return res.status(404).json({ error: 'Not found' });
  const n = { ...t, ...req.body };
  if (!n.title?.trim() || !STATUSES.includes(n.status))
    return res.status(400).json({ error: 'Invalid title or status' });
  db.prepare('UPDATE tasks SET title=?,description=?,status=?,due=? WHERE id=?')
    .run(n.title.trim(), n.description, n.status, n.due, t.id);
  notify(req.uid);
  res.json(db.prepare('SELECT * FROM tasks WHERE id=?').get(t.id));
});

app.delete('/api/tasks/:id', auth, (req, res) => {
  const r = db.prepare('DELETE FROM tasks WHERE id=? AND user_id=?').run(req.params.id, req.uid);
  if (!r.changes) return res.status(404).json({ error: 'Not found' });
  notify(req.uid);
  res.status(204).end();
});

server.listen(process.env.PORT || 3000, () => console.log('http://localhost:3000'));
