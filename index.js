import express from 'express';
import cors from 'cors';
import pg from 'pg';

const app = express();
app.use(cors());
app.use(express.json());

// Railway inyecta DATABASE_URL al agregar el plugin de Postgres.
// Con la URL pública (proxy) hace falta SSL: define PGSSL=true.
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false,
});

// [nombre, categoria, descripcion, precio en centavos]
const SEED = [
  ['Minifigura Goku Ultra Instinto', 'Anime', 'Figura articulada de 12 cm con base y efecto de aura.', 2499],
  ['Minifigura Naruto Modo Sabio', 'Anime', 'Figura de PVC de 10 cm, pintada a mano.', 1999],
  ['Luffy Gear 5 Mini', 'Anime', 'Figura coleccionable de 11 cm con cabeza intercambiable.', 2299],
  ['Funko Spider-Man', 'Minifiguras', 'Vinilo de 9 cm en caja de coleccion.', 1599],
  ['Funko Darth Vader', 'Minifiguras', 'Edicion con casco desmontable.', 1799],
  ['Mini Batman 1989', 'Minifiguras', 'Figura de 10 cm con capa de tela.', 2099],
  ['Amiibo Link', 'Videojuegos', 'Figura NFC compatible con Nintendo Switch.', 1899],
  ['Master Chief Mini', 'Videojuegos', 'Figura de 12 cm con rifle y casco.', 2699],
  ['Pixel Heart Llavero', 'Videojuegos', 'Llavero metalico de corazon pixelado.', 699],
  ['Batman: Year One', 'Comics', 'Tomo en tapa dura, edicion coleccionista.', 2999],
  ['Saga Vol. 1', 'Comics', 'Tomo en tapa blanda, edicion en espanol.', 1699],
  ['Watchmen', 'Comics', 'Edicion absoluta con sobrecubierta.', 3999],
];

async function init() {
  await pool.query(`
    create table if not exists products (
      id serial primary key,
      name text not null,
      category text not null,
      description text not null,
      price_cents integer not null,
      image text not null
    )`);
  await pool.query(`
    create table if not exists orders (
      id text primary key,
      total_cents integer not null,
      items jsonb not null,
      created_at timestamptz not null default now()
    )`);

  const { rows } = await pool.query('select count(*)::int as n from products');
  if (rows[0].n > 0) return;
  for (const [name, category, description, price] of SEED) {
    // Imagenes de relleno: reemplazalas por las URLs reales de tu catalogo.
    const image = `https://picsum.photos/seed/${encodeURIComponent(name)}/600/600`;
    await pool.query(
      'insert into products (name, category, description, price_cents, image) values ($1,$2,$3,$4,$5)',
      [name, category, description, price, image]
    );
  }
}

app.get('/health', (_req, res) => res.json({ ok: true }));

app.get('/products', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      'select id, name, category, description, price_cents as "priceCents", image from products order by id'
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
      'select id, name, price_cents from products where id = any($1)',
      [ids]
    );
    const byId = new Map(prods.map((p) => [p.id, p]));

    const invalid = items.some((i) => !byId.has(i.productId) || !Number.isInteger(i.qty) || i.qty < 1);
    if (invalid) return res.status(400).json({ error: 'producto o cantidad invalida' });

    // El precio se toma de la base, nunca del cliente.
    const lines = items.map((i) => {
      const p = byId.get(i.productId);
      return { productId: p.id, name: p.name, priceCents: p.price_cents, qty: i.qty };
    });
    const total = lines.reduce((sum, l) => sum + l.priceCents * l.qty, 0);

    await pool.query(
      `insert into orders (id, total_cents, items, created_at)
       values ($1, $2, $3, $4) on conflict (id) do nothing`,
      [id, total, JSON.stringify(lines), createdAt || new Date().toISOString()]
    );

    const { rows } = await pool.query(
      'select id, total_cents as "totalCents", items, created_at as "createdAt" from orders where id = $1',
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
