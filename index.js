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

async function requireUser(req, res, next) {
  const token = /^Bearer (.+)$/.exec(req.headers.authorization || '')?.[1];
  if (!token) return res.status(401).json({ error: 'Inicia sesión para comprar' });
  try {
    const { rows } = await pool.query('select u.id, u.name from sessions s join users u on u.id=s.user_id where s.token_hash=$1 and s.expires_at > now()', [hashToken(token)]);
    if (!rows.length) return res.status(401).json({ error: 'Sesión vencida. Vuelve a iniciar sesión.' });
    req.user = rows[0]; next();
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al validar sesión' }); }
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
    const { rows } = await pool.query('select * from users where username=$1', [username]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const expected = Buffer.from(user.password_hash, 'hex');
    const actual = Buffer.from(hashPassword(password, user.password_salt), 'hex');
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const token = randomBytes(32).toString('hex');
    await pool.query("insert into sessions(token_hash,user_id,expires_at) values($1,$2,now()+interval '30 days')", [hashToken(token), user.id]);
    res.json({ token, user: { id: user.id, name: user.name, username: user.username } });
  } catch(e) { console.error(e); res.status(500).json({ error: 'Error de inicio de sesión' }); }
});

app.get('/health', (_req, res) => res.json({ ok: true }));

app.get('/products', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      'select id, name, category, description, price, image from products order by id'
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// El id lo genera el cliente. Si el movil reintenta un pedido que ya llego,
// el "on conflict" lo ignora y se devuelve el existente, asi no se duplica.
app.post('/orders', requireUser, async (req, res) => {
  const { id, items, createdAt, deliveryAddress } = req.body || {};
  if (!id || typeof deliveryAddress !== 'string' || !deliveryAddress.trim() || deliveryAddress.length > 500 || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'pedido invalido' });
  }

  try {
    const ids = items.map((i) => i.productId);
    const { rows: prods } = await pool.query(
      'select id, name, price from products where id = any($1)',
      [ids]
    );
    const byId = new Map(prods.map((p) => [p.id, p]));

    const invalid = items.some((i) => !byId.has(i.productId) || !Number.isInteger(i.qty) || i.qty < 1);
    if (invalid) return res.status(400).json({ error: 'producto o cantidad invalida' });

    // El precio se toma de la base, nunca del cliente.
    const lines = items.map((i) => {
      const p = byId.get(i.productId);
      return { productId: p.id, name: p.name, price: p.price, qty: i.qty };
    });
    const total = lines.reduce((sum, l) => sum + l.price * l.qty, 0);

    await pool.query(
      `insert into orders (id, total, items, created_at, user_id, customer_name, delivery_address)
       values ($1, $2, $3, $4, $5, $6, $7) on conflict (id) do nothing`,
      [id, total, JSON.stringify(lines), createdAt || new Date().toISOString(), req.user.id, req.user.name, deliveryAddress.trim()]
    );

    const { rows } = await pool.query(
      'select id, total, items, created_at as "createdAt", customer_name as "customerName", delivery_address as "deliveryAddress" from orders where id = $1 and user_id = $2',
      [id, req.user.id]
    );
    if (!rows.length) return res.status(409).json({ error: 'El pedido pertenece a otro usuario' });
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

const port = process.env.PORT || 3000;
init()
  .then(() => app.listen(port, () => console.log(`API en puerto ${port}`)))
  .catch((err) => {
    console.error('No se pudo iniciar la base de datos', err);
    process.exit(1);
  });
