require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const { customAlphabet } = require('nanoid');

const app = express();
app.use(express.json());

// Gerador de código curto
const BASE = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
const nanoid = customAlphabet(BASE, 6);

// Conexão com Postgres (Render fornece DATABASE_URL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Criação da tabela
const init = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS links (
      id SERIAL PRIMARY KEY,
      code VARCHAR(16) UNIQUE NOT NULL,
      url TEXT NOT NULL,
      password_hash TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
};
init().catch(err => console.error('Erro criando tabela', err));

// Criar link encurtado
app.post('/shorten', async (req, res) => {
  try {
    const { url, password } = req.body;
    if (!url) return res.status(400).json({ error: 'url é obrigatória' });

    // validar url
    try { new URL(url); } catch { return res.status(400).json({ error: 'url inválida' }); }

    let passHash = null;
    if (password) passHash = await bcrypt.hash(password, 10);

    // gerar código único
    let code;
    for (let i = 0; i < 5; i++) {
      code = nanoid();
      const r = await pool.query('SELECT 1 FROM links WHERE code=$1', [code]);
      if (r.rowCount === 0) break;
    }

    await pool.query(
      'INSERT INTO links (code, url, password_hash) VALUES ($1,$2,$3)',
      [code, url, passHash]
    );

    const full = `${process.env.APP_URL || 'http://localhost:3000'}/${code}`;
    res.json({ short: full, code });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'erro do servidor' });
  }
});

// Redirecionamento
app.get('/:code', async (req, res) => {
  try {
    const { code } = req.params;
    const { password } = req.query;

    const r = await pool.query('SELECT url, password_hash FROM links WHERE code=$1', [code]);
    if (r.rowCount === 0) return res.status(404).send('Link não encontrado');

    const { url, password_hash } = r.rows[0];

    if (password_hash) {
      if (!password) return res.status(401).send('Senha necessária');
      const ok = await bcrypt.compare(password, password_hash);
      if (!ok) return res.status(403).send('Senha incorreta');
    }

    res.redirect(url);
  } catch (err) {
    console.error(err);
    res.status(500).send('erro do servidor');
  }
});

// Health check
app.get('/health', (req, res) => res.json({ ok: true }));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Rodando na porta ${port}`));
