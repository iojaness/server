import express from 'express';
import cors from 'cors';
import pg from 'pg';

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
  await pool.query(`
    create table if not exists orders (
      id text primary key,
      total integer not null,
      items jsonb not null,
      created_at timestamptz not null default now()
    )`);
}

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
app.post('/orders', async (req, res) => {
  const { id, items, createdAt } = req.body || {};
  if (!id || !Array.isArray(items) || items.length === 0) {
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
      `insert into orders (id, total, items, created_at)
       values ($1, $2, $3, $4) on conflict (id) do nothing`,
      [id, total, JSON.stringify(lines), createdAt || new Date().toISOString()]
    );

    const { rows } = await pool.query(
      'select id, total, items, created_at as "createdAt" from orders where id = $1',
      [id]
    );
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
