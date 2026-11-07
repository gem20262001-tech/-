// Сайрам доставка: backend (Express + SQLite)
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");

const PORT = process.env.PORT || 3000;
const db = new Database(process.env.DB_FILE || path.join(__dirname, "data.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS vendors(id INTEGER PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL, emoji TEXT DEFAULT '🍽️',
  address TEXT DEFAULT '', commission REAL DEFAULT 10, open INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, role TEXT NOT NULL, phone TEXT UNIQUE NOT NULL, name TEXT DEFAULT '',
  pass_hash TEXT NOT NULL, vendor_id INTEGER REFERENCES vendors(id) ON DELETE CASCADE, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, vendor_id INTEGER NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
  name TEXT NOT NULL, unit TEXT DEFAULT '', price INTEGER NOT NULL, available INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, vendor_id INTEGER NOT NULL REFERENCES vendors(id),
  customer_name TEXT, phone TEXT, address TEXT, lat REAL, lng REAL, note TEXT, items_json TEXT, subtotal INTEGER, delivery_fee INTEGER,
  commission INTEGER, total INTEGER, pay_method TEXT, pay_status TEXT DEFAULT 'unpaid', status TEXT DEFAULT 'new',
  courier_id INTEGER REFERENCES users(id), created_at TEXT DEFAULT (datetime('now')));
`);
const getSet = (k, d) => { const r = db.prepare("SELECT value FROM settings WHERE key=?").get(k); return r ? r.value : d; };
const putSet = (k, v) => db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(k, String(v));
if (!getSet("jwt_secret")) putSet("jwt_secret", crypto.randomBytes(32).toString("hex"));
if (!getSet("delivery_fee")) putSet("delivery_fee", 500);
if (!getSet("kaspi_phone")) putSet("kaspi_phone", "");
const SECRET = process.env.JWT_SECRET || getSet("jwt_secret");

// Единственный админ создаётся из переменных окружения или с случайным паролем (виден один раз в консоли)
if (!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()) {
  const phone = process.env.ADMIN_PHONE || "admin";
  const pass = process.env.ADMIN_PASSWORD || crypto.randomBytes(6).toString("hex");
  db.prepare("INSERT INTO users(role,phone,name,pass_hash) VALUES('admin',?,?,?)").run(phone, "Админ", bcrypt.hashSync(pass, 10));
  console.log(`\n=== АДМИН СОЗДАН ===\nлогин: ${phone}\nпароль: ${process.env.ADMIN_PASSWORD ? "(из ADMIN_PASSWORD)" : pass}\n====================\n`);
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "100kb" }));
app.use((req, res, next) => { res.set({ "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin" }); next(); });

// простой лимит попыток входа
const tries = new Map();
function limiter(req, res, next) {
  const k = req.ip, now = Date.now(), t = (tries.get(k) || []).filter(x => now - x < 600000);
  if (t.length >= 10) return res.status(429).json({ error: "Слишком много попыток. Подождите 10 минут." });
  t.push(now); tries.set(k, t); next();
}
const wrap = fn => (req, res) => { try { fn(req, res); } catch (e) { console.error(e); res.status(500).json({ error: "Ошибка сервера" }); } };
const str = (v, n = 200) => String(v == null ? "" : v).trim().slice(0, n);
const num = v => Number.isFinite(+v) ? +v : NaN;

function auth(...roles) {
  return (req, res, next) => {
    try {
      const t = (req.headers.authorization || "").replace("Bearer ", "");
      const p = jwt.verify(t, SECRET);
      const u = db.prepare("SELECT * FROM users WHERE id=? AND active=1").get(p.id);
      if (!u || !roles.includes(u.role)) return res.status(403).json({ error: "Нет доступа" });
      req.user = u; next();
    } catch { res.status(401).json({ error: "Войдите заново" }); }
  };
}

app.post("/api/login", limiter, wrap((req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE phone=? AND active=1").get(str(req.body.phone, 40));
  if (!u || !bcrypt.compareSync(String(req.body.password || ""), u.pass_hash)) return res.status(401).json({ error: "Неверный логин или пароль" });
  res.json({ token: jwt.sign({ id: u.id }, SECRET, { expiresIn: "12h" }), role: u.role, name: u.name });
}));

// ---------- публичное (клиент) ----------
app.get("/api/config", wrap((req, res) => res.json({ delivery_fee: +getSet("delivery_fee"), kaspi_phone: getSet("kaspi_phone") })));
app.get("/api/vendors", wrap((req, res) => res.json(db.prepare(
  "SELECT id,type,name,emoji,address FROM vendors WHERE open=1 ORDER BY name").all())));
app.get("/api/vendors/:id/products", wrap((req, res) => res.json(db.prepare(
  "SELECT p.id,p.name,p.unit,p.price FROM products p JOIN vendors v ON v.id=p.vendor_id WHERE v.id=? AND v.open=1 AND p.available=1 ORDER BY p.name").all(+req.params.id))));

app.post("/api/orders", wrap((req, res) => {
  const b = req.body, v = db.prepare("SELECT * FROM vendors WHERE id=? AND open=1").get(+b.vendor_id);
  if (!v) return res.status(400).json({ error: "Заведение закрыто или не найдено" });
  const name = str(b.name, 80), phone = str(b.phone, 30).replace(/[^\d+]/g, ""), address = str(b.address, 250);
  if (!name || phone.replace(/\D/g, "").length < 10 || !address) return res.status(400).json({ error: "Заполните имя, телефон и адрес" });
  const pay = ["cash", "kaspi"].includes(b.pay_method) ? b.pay_method : "cash";
  const lat = num(b.lat), lng = num(b.lng);
  let subtotal = 0; const lines = [];
  for (const it of Array.isArray(b.items) ? b.items.slice(0, 50) : []) {
    const q = Math.floor(num(it.qty));
    if (!(q >= 1 && q <= 50)) continue;
    const p = db.prepare("SELECT * FROM products WHERE id=? AND vendor_id=? AND available=1").get(+it.id, v.id);
    if (!p) continue;
    subtotal += p.price * q; lines.push({ n: p.name, u: p.unit, q, p: p.price });
  }
  if (!lines.length) return res.status(400).json({ error: "Корзина пуста" });
  const fee = +getSet("delivery_fee"), commission = Math.round(subtotal * v.commission / 100), total = subtotal + fee;
  const code = String(crypto.randomInt(100000, 999999));
  db.prepare(`INSERT INTO orders(code,vendor_id,customer_name,phone,address,lat,lng,note,items_json,subtotal,delivery_fee,commission,total,pay_method)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(code, v.id, name, phone, address, Number.isFinite(lat) ? lat : null, Number.isFinite(lng) ? lng : null,
    str(b.note, 300), JSON.stringify(lines), subtotal, fee, commission, total, pay);
  res.json({ code, total, pay_method: pay, kaspi_phone: pay === "kaspi" ? getSet("kaspi_phone") : "" });
}));

app.get("/api/track", wrap((req, res) => {
  const o = db.prepare("SELECT o.code,o.status,o.pay_status,o.total,v.name vendor FROM orders o JOIN vendors v ON v.id=o.vendor_id WHERE o.code=? AND o.phone=?")
    .get(str(req.query.code, 12), str(req.query.phone, 30).replace(/[^\d+]/g, ""));
  o ? res.json(o) : res.status(404).json({ error: "Заказ не найден" });
}));

// ---------- общие запросы заказов ----------
const orderSel = `SELECT o.*, v.name vendor_name, v.address vendor_address, u.name courier_name FROM orders o
  JOIN vendors v ON v.id=o.vendor_id LEFT JOIN users u ON u.id=o.courier_id`;
const parse = rows => rows.map(r => ({ ...r, items: JSON.parse(r.items_json || "[]"), items_json: undefined }));

// ---------- админ (только вы) ----------
const admin = auth("admin");
app.get("/api/admin/stats", admin, wrap((req, res) => res.json(db.prepare(
  `SELECT COUNT(*) orders, COALESCE(SUM(total),0) turnover, COALESCE(SUM(commission),0) commission
   FROM orders WHERE status='delivered'`).get())));
app.get("/api/admin/vendors", admin, wrap((req, res) => res.json(db.prepare(
  `SELECT v.*, (SELECT phone FROM users WHERE vendor_id=v.id AND role='vendor' LIMIT 1) owner_phone FROM vendors v ORDER BY v.id DESC`).all())));
app.post("/api/admin/vendors", admin, wrap((req, res) => {
  const b = req.body, name = str(b.name, 80), phone = str(b.owner_phone, 30), pass = String(b.owner_password || "");
  if (!name || !["fast", "shop"].includes(b.type) || phone.length < 5 || pass.length < 6) return res.status(400).json({ error: "Название, тип, телефон владельца и пароль (от 6 символов) обязательны" });
  if (db.prepare("SELECT 1 FROM users WHERE phone=?").get(phone)) return res.status(400).json({ error: "Этот телефон уже занят" });
  const c = Math.min(50, Math.max(0, num(b.commission) || 10));
  const tx = db.transaction(() => {
    const id = db.prepare("INSERT INTO vendors(type,name,emoji,address,commission) VALUES(?,?,?,?,?)").run(b.type, name, str(b.emoji, 8) || "🍽️", str(b.address, 200), c).lastInsertRowid;
    db.prepare("INSERT INTO users(role,phone,name,pass_hash,vendor_id) VALUES('vendor',?,?,?,?)").run(phone, name, bcrypt.hashSync(pass, 10), id);
    return id;
  });
  res.json({ id: tx() });
}));
app.patch("/api/admin/vendors/:id", admin, wrap((req, res) => {
  const b = req.body, id = +req.params.id;
  if (b.commission !== undefined) db.prepare("UPDATE vendors SET commission=? WHERE id=?").run(Math.min(50, Math.max(0, num(b.commission) || 0)), id);
  if (b.open !== undefined) db.prepare("UPDATE vendors SET open=? WHERE id=?").run(b.open ? 1 : 0, id);
  res.json({ ok: true });
}));
app.delete("/api/admin/vendors/:id", admin, wrap((req, res) => {
  const id = +req.params.id;
  if (db.prepare("SELECT 1 FROM orders WHERE vendor_id=?").get(id)) { db.prepare("UPDATE vendors SET open=0 WHERE id=?").run(id); return res.json({ ok: true, hidden: true }); }
  db.prepare("DELETE FROM vendors WHERE id=?").run(id); res.json({ ok: true });
}));
app.get("/api/admin/couriers", admin, wrap((req, res) => res.json(db.prepare("SELECT id,phone,name,active FROM users WHERE role='courier' ORDER BY id DESC").all())));
app.post("/api/admin/couriers", admin, wrap((req, res) => {
  const phone = str(req.body.phone, 30), name = str(req.body.name, 80), pass = String(req.body.password || "");
  if (!name || phone.length < 5 || pass.length < 6) return res.status(400).json({ error: "Имя, телефон и пароль (от 6 символов) обязательны" });
  if (db.prepare("SELECT 1 FROM users WHERE phone=?").get(phone)) return res.status(400).json({ error: "Этот телефон уже занят" });
  db.prepare("INSERT INTO users(role,phone,name,pass_hash) VALUES('courier',?,?,?)").run(phone, name, bcrypt.hashSync(pass, 10));
  res.json({ ok: true });
}));
app.patch("/api/admin/couriers/:id", admin, wrap((req, res) => {
  db.prepare("UPDATE users SET active=? WHERE id=? AND role='courier'").run(req.body.active ? 1 : 0, +req.params.id); res.json({ ok: true });
}));
app.get("/api/admin/settings", admin, wrap((req, res) => res.json({ delivery_fee: +getSet("delivery_fee"), kaspi_phone: getSet("kaspi_phone") })));
app.put("/api/admin/settings", admin, wrap((req, res) => {
  const f = num(req.body.delivery_fee); if (f >= 0 && f <= 20000) putSet("delivery_fee", Math.round(f));
  putSet("kaspi_phone", str(req.body.kaspi_phone, 30)); res.json({ ok: true });
}));
app.get("/api/admin/orders", admin, wrap((req, res) => res.json(parse(db.prepare(orderSel + " ORDER BY o.id DESC LIMIT 200").all()))));
app.patch("/api/admin/orders/:id", admin, wrap((req, res) => {
  const id = +req.params.id;
  if (req.body.pay_status) db.prepare("UPDATE orders SET pay_status=? WHERE id=?").run(req.body.pay_status === "paid" ? "paid" : "unpaid", id);
  if (req.body.status === "cancelled") db.prepare("UPDATE orders SET status='cancelled' WHERE id=? AND status!='delivered'").run(id);
  res.json({ ok: true });
}));

// ---------- панель заведения ----------
const vendor = auth("vendor");
app.get("/api/vendor/me", vendor, wrap((req, res) => res.json(db.prepare("SELECT id,type,name,emoji,address,commission,open FROM vendors WHERE id=?").get(req.user.vendor_id))));
app.patch("/api/vendor/me", vendor, wrap((req, res) => {
  if (req.body.open !== undefined) db.prepare("UPDATE vendors SET open=? WHERE id=?").run(req.body.open ? 1 : 0, req.user.vendor_id);
  if (req.body.address !== undefined) db.prepare("UPDATE vendors SET address=? WHERE id=?").run(str(req.body.address, 200), req.user.vendor_id);
  res.json({ ok: true });
}));
app.get("/api/vendor/products", vendor, wrap((req, res) => res.json(db.prepare("SELECT * FROM products WHERE vendor_id=? ORDER BY id DESC").all(req.user.vendor_id))));
app.post("/api/vendor/products", vendor, wrap((req, res) => {
  const name = str(req.body.name, 80), price = Math.round(num(req.body.price));
  if (!name || !(price > 0 && price < 10000000)) return res.status(400).json({ error: "Введите название и цену" });
  db.prepare("INSERT INTO products(vendor_id,name,unit,price) VALUES(?,?,?,?)").run(req.user.vendor_id, name, str(req.body.unit, 30), price); res.json({ ok: true });
}));
app.patch("/api/vendor/products/:id", vendor, wrap((req, res) => {
  const b = req.body, id = +req.params.id, vid = req.user.vendor_id;
  if (b.available !== undefined) db.prepare("UPDATE products SET available=? WHERE id=? AND vendor_id=?").run(b.available ? 1 : 0, id, vid);
  if (b.price !== undefined && num(b.price) > 0) db.prepare("UPDATE products SET price=? WHERE id=? AND vendor_id=?").run(Math.round(num(b.price)), id, vid);
  res.json({ ok: true });
}));
app.delete("/api/vendor/products/:id", vendor, wrap((req, res) => { db.prepare("DELETE FROM products WHERE id=? AND vendor_id=?").run(+req.params.id, req.user.vendor_id); res.json({ ok: true }); }));
app.get("/api/vendor/orders", vendor, wrap((req, res) => res.json(parse(db.prepare(orderSel + " WHERE o.vendor_id=? ORDER BY o.id DESC LIMIT 100").all(req.user.vendor_id)))));
app.patch("/api/vendor/orders/:id", vendor, wrap((req, res) => {
  const id = +req.params.id, vid = req.user.vendor_id, s = req.body.status;
  const next = { accepted: "new", ready: "accepted", cancelled: "new" }; // допустимые переходы: из какого статуса
  if (s && next[s]) db.prepare("UPDATE orders SET status=? WHERE id=? AND vendor_id=? AND status=?").run(s, id, vid, next[s]);
  if (req.body.pay_status === "paid") db.prepare("UPDATE orders SET pay_status='paid' WHERE id=? AND vendor_id=?").run(id, vid);
  res.json({ ok: true });
}));

// ---------- курьер ----------
const courier = auth("courier");
app.get("/api/courier/orders", courier, wrap((req, res) => res.json({
  available: parse(db.prepare(orderSel + " WHERE o.status='ready' AND o.courier_id IS NULL ORDER BY o.id").all()),
  mine: parse(db.prepare(orderSel + " WHERE o.courier_id=? AND o.status IN('ready','picked') ORDER BY o.id").all(req.user.id)),
  done_today: db.prepare("SELECT COUNT(*) n, COALESCE(SUM(delivery_fee),0) earned FROM orders WHERE courier_id=? AND status='delivered' AND date(created_at)=date('now')").get(req.user.id)
})));
app.post("/api/courier/orders/:id/take", courier, wrap((req, res) => {
  const r = db.prepare("UPDATE orders SET courier_id=? WHERE id=? AND status='ready' AND courier_id IS NULL").run(req.user.id, +req.params.id);
  r.changes ? res.json({ ok: true }) : res.status(409).json({ error: "Заказ уже взял другой курьер" });
}));
app.patch("/api/courier/orders/:id", courier, wrap((req, res) => {
  const id = +req.params.id, s = req.body.status, prev = { picked: "ready", delivered: "picked" };
  if (prev[s]) db.prepare("UPDATE orders SET status=? WHERE id=? AND courier_id=? AND status=?").run(s, id, req.user.id, prev[s]);
  if (s === "delivered" && req.body.paid_cash) db.prepare("UPDATE orders SET pay_status='paid' WHERE id=? AND courier_id=? AND pay_method='cash'").run(id, req.user.id);
  res.json({ ok: true });
}));

app.use("/admin", (req, res) => res.sendFile(path.join(__dirname, "public/admin.html")));
app.use("/vendor", (req, res) => res.sendFile(path.join(__dirname, "public/vendor.html")));
app.use("/courier", (req, res) => res.sendFile(path.join(__dirname, "public/courier.html")));
app.use(express.static(path.join(__dirname, "public")));
app.listen(PORT, () => console.log("Сервер запущен: http://localhost:" + PORT));
