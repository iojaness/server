import express from 'express';
import cors from 'cors';
import pg from 'pg';
import { randomBytes, scryptSync, timingSafeEqual, createHash } from 'node:crypto';

if (!process.env.DATABASE_URL) {
  console.error('Falta DATABASE_URL. Agrega Postgres en Railway y referenciala en el servicio.');
  process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());

// Con la URL publica (proxy) de Railway hace falta SSL: define PGSSL=true.
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false,
});

const hashPassword = (password, salt) => scryptSync(password, salt, 64).toString('hex');
const hashToken = (token) => createHash('sha256').update(token).digest('hex');

async function userFromRequest(req) {
  const token = /^Bearer (.+)$/.exec(req.headers.authorization || '')?.[1];
  if (!token) return null;
  const { rows } = await pool.query('select u.id, u.name, u.username, u.role from sessions s join users u on u.id=s.user_id where s.token_hash=$1 and s.expires_at > now()', [hashToken(token)]);
  return rows[0] || null;
}

async function requireUser(req, res, next) {
  if (!/^Bearer (.+)$/.test(req.headers.authorization || '')) return res.status(401).json({ error: 'Inicia sesión para comprar' });
  try {
    const user = await userFromRequest(req);
    if (!user) return res.status(401).json({ error: 'Sesión vencida. Vuelve a iniciar sesión.' });
    req.user = user; next();
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al validar sesión' }); }
}

// Sesion opcional: el catalogo es publico, pero el admin ve tambien lo agotado.
async function optionalUser(req, _res, next) {
  try { req.user = await userFromRequest(req); } catch (e) { console.error(e); req.user = null; }
  next();
}

const requireAdmin = [requireUser, (req, res, next) => (req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Solo administradores' }))];

async function createSession(userId) {
  const token = randomBytes(32).toString('hex');
  await pool.query("insert into sessions(token_hash,user_id,expires_at) values($1,$2,now()+interval '30 days')", [hashToken(token), userId]);
  return token;
}

// Los precios son pesos colombianos enteros (COP no usa decimales).
async function init() {
  await pool.query(`
    create table if not exists products (
      id serial primary key,
      name text not null,
      category text not null,
      description text not null,
      price integer not null,
      image text not null
    )`);
  await pool.query(`create table if not exists users (id serial primary key, username text unique not null, name text not null, password_salt text not null, password_hash text not null)`);
  await pool.query(`create table if not exists sessions (token_hash text primary key, user_id integer not null references users(id), expires_at timestamptz not null)`);
  await pool.query(`
    create table if not exists orders (
      id text primary key,
      total integer not null,
      items jsonb not null,
      created_at timestamptz not null default now()
    )`);
  await pool.query('alter table orders add column if not exists user_id integer references users(id)');
  await pool.query('alter table orders add column if not exists customer_name text');
  await pool.query('alter table orders add column if not exists delivery_address text');
  // Roles ('admin' | 'buyer') y stock. Los productos existentes arrancan con 20 unidades.
  await pool.query("alter table users add column if not exists role text not null default 'buyer'");
  await pool.query('alter table products add column if not exists stock integer not null default 20');
  await pool.query('alter table products drop constraint if exists products_stock_nonneg');
  await pool.query('alter table products add constraint products_stock_nonneg check (stock >= 0)');
  try { await pool.query('create unique index if not exists users_username_lower_idx on users (lower(username))'); }
  catch (e) { console.error('No se pudo crear el indice unico de usuario (hay usuarios que solo difieren en mayusculas):', e.message); }
  // Administrador: ADMIN_USER, ADMIN_PASSWORD y ADMIN_NAME en Railway. En cada arranque ese usuario
  // queda como admin con esa contrasena (si ya existia, se promueve).
  if (process.env.ADMIN_USER && process.env.ADMIN_PASSWORD) {
    const salt = randomBytes(16).toString('hex');
    await pool.query(
      `insert into users(username,name,password_salt,password_hash,role) values($1,$2,$3,$4,'admin')
       on conflict(username) do update set role='admin', name=excluded.name, password_salt=excluded.password_salt, password_hash=excluded.password_hash`,
      [process.env.ADMIN_USER.trim().toLowerCase(), process.env.ADMIN_NAME || process.env.ADMIN_USER, salt, hashPassword(process.env.ADMIN_PASSWORD, salt)]
    );
  }
  // Usuario inicial opcional: configurar BOOTSTRAP_USER, BOOTSTRAP_PASSWORD y BOOTSTRAP_NAME en Railway.
  if (process.env.BOOTSTRAP_USER && process.env.BOOTSTRAP_PASSWORD) {
    const salt = randomBytes(16).toString('hex');
    await pool.query('insert into users(username,name,password_salt,password_hash) values($1,$2,$3,$4) on conflict(username) do nothing', [process.env.BOOTSTRAP_USER, process.env.BOOTSTRAP_NAME || process.env.BOOTSTRAP_USER, salt, hashPassword(process.env.BOOTSTRAP_PASSWORD, salt)]);
  }
}

app.post('/login', async (req,res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') return res.status(400).json({ error: 'Datos inválidos' });
  try {
    const { rows } = await pool.query('select * from users where lower(username)=lower($1)', [username.trim()]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const expected = Buffer.from(user.password_hash, 'hex');
    const actual = Buffer.from(hashPassword(password, user.password_salt), 'hex');
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const token = await createSession(user.id);
    res.json({ token, user: { id: user.id, name: user.name, username: user.username, role: user.role } });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Error de inicio de sesión' }); }
});

// Registro publico: SIEMPRE crea un comprador. El rol nunca se lee del cuerpo de la peticion.
app.post('/register', async (req, res) => {
  const { username, password, name } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' || typeof name !== 'string') return res.status(400).json({ error: 'Datos inválidos' });
  const uname = username.trim().toLowerCase();
  const fullName = name.trim();
  if (!/^[a-z0-9_.]{3,30}$/.test(uname)) return res.status(400).json({ error: 'Usuario: 3 a 30 caracteres (letras, números, punto o guion bajo)' });
  if (fullName.length < 2 || fullName.length > 60) return res.status(400).json({ error: 'Escribe tu nombre (2 a 60 caracteres)' });
  if (password.length < 6 || password.length > 100) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  try {
    const salt = randomBytes(16).toString('hex');
    const { rows } = await pool.query(
      "insert into users(username,name,password_salt,password_hash,role) values($1,$2,$3,$4,'buyer') returning id, name, username, role",
      [uname, fullName, salt, hashPassword(password, salt)]
    );
    const token = await createSession(rows[0].id);
    res.status(201).json({ token, user: rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Ese usuario ya existe' });
    console.error(e); res.status(500).json({ error: 'No se pudo crear la cuenta' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true }));

// Compradores y visitantes: solo productos con stock. Admin: todos, para poder reponer.
app.get('/products', optionalUser, async (req, res) => {
  try {
    const where = req.user?.role === 'admin' ? '' : 'where stock > 0';
    const { rows } = await pool.query(`select id, name, category, description, price, image, stock from products ${where} order by id`);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// Admin: { delta: +10 } suma o resta (nunca baja de 0); { stock: 25 } fija el valor exacto.
app.patch('/admin/products/:id/stock', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const { delta, stock } = req.body || {};
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'producto inválido' });
  try {
    let result;
    if (Number.isInteger(delta) && Math.abs(delta) <= 100000) {
      result = await pool.query('update products set stock = greatest(0, stock + $1) where id=$2 returning id, name, category, description, price, image, stock', [delta, id]);
    } else if (Number.isInteger(stock) && stock >= 0 && stock <= 1000000) {
      result = await pool.query('update products set stock = $1 where id=$2 returning id, name, category, description, price, image, stock', [stock, id]);
    } else {
      return res.status(400).json({ error: 'Indica delta o stock como número entero' });
    }
    if (!result.rows.length) return res.status(404).json({ error: 'Producto no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// El id lo genera el cliente. Si el movil reintenta un pedido que ya llego,
// se devuelve el existente y NO se vuelve a descontar stock.
app.post('/orders', requireUser, async (req, res) => {
  const { id, items, createdAt, deliveryAddress } = req.body || {};
  if (!id || typeof deliveryAddress !== 'string' || !deliveryAddress.trim() || deliveryAddress.length > 500 || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'pedido invalido' });
  }
  if (items.some((i) => !Number.isInteger(i?.productId) || !Number.isInteger(i?.qty) || i.qty < 1)) {
    return res.status(400).json({ error: 'producto o cantidad invalida' });
  }
  // Si llega el mismo producto dos veces, se suman las cantidades.
  const qtyById = new Map();
  for (const i of items) qtyById.set(i.productId, (qtyById.get(i.productId) || 0) + i.qty);
  const ids = [...qtyById.keys()].sort((a, b) => a - b);

  const selectOrder = 'select id, total, items, created_at as "createdAt", customer_name as "customerName", delivery_address as "deliveryAddress" from orders where id = $1 and user_id = $2';
  const client = await pool.connect();
  try {
    await client.query('begin');
    // Bloquea las filas de producto (en orden de id) para que dos compras a la vez no vendan el mismo stock.
    const { rows: prods } = await client.query('select id, name, price, stock from products where id = any($1) order by id for update', [ids]);
    const byId = new Map(prods.map((p) => [p.id, p]));

    const { rows: existing } = await client.query('select user_id from orders where id = $1', [id]);
    if (existing.length) {
      await client.query('rollback');
      if (existing[0].user_id !== req.user.id) return res.status(409).json({ error: 'El pedido pertenece a otro usuario' });
      const { rows } = await pool.query(selectOrder, [id, req.user.id]);
      return res.status(201).json(rows[0]);
    }

    for (const pid of ids) {
      const p = byId.get(pid);
      if (!p) { await client.query('rollback'); return res.status(409).json({ error: 'Un producto del pedido ya no existe' }); }
      if (p.stock < qtyById.get(pid)) {
        await client.query('rollback');
        return res.status(409).json({ error: p.stock > 0 ? `Stock insuficiente de "${p.name}": quedan ${p.stock}` : `"${p.name}" está agotado` });
      }
    }

    // El precio se toma de la base, nunca del cliente.
    const lines = ids.map((pid) => { const p = byId.get(pid); return { productId: p.id, name: p.name, price: p.price, qty: qtyById.get(pid) }; });
    const total = lines.reduce((sum, l) => sum + l.price * l.qty, 0);
    await client.query(
      'insert into orders (id, total, items, created_at, user_id, customer_name, delivery_address) values ($1, $2, $3, $4, $5, $6, $7)',
      [id, total, JSON.stringify(lines), createdAt || new Date().toISOString(), req.user.id, req.user.name, deliveryAddress.trim()]
    );
    for (const l of lines) await client.query('update products set stock = stock - $1 where id = $2', [l.qty, l.productId]);
    await client.query('commit');

    const { rows } = await pool.query(selectOrder, [id, req.user.id]);
    res.status(201).json(rows[0]);
  } catch (err) {
    await client.query('rollback').catch(() => {});
    console.error(err);
    res.status(500).json({ error: 'server error' });
  } finally {
    client.release();
  }
});

const port = process.env.PORT || 3000;
init()
  .then(() => app.listen(port, () => console.log(`API en puerto ${port}`)))
  .catch((err) => {
    console.error('No se pudo iniciar la base de datos', err);
    process.exit(1);
  });
