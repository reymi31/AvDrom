const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const path = require('path');

const app = express();
const port = 3000;
const sessions = new Map();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '11111',
  database: 'auth_db',
});

db.connect((err) => {
  if (err) {
    console.error('Ошибка подключения к MySQL:', err);
    return;
  }

  console.log('Успешное подключение к MySQL');
  initializeDatabase();
});

function runQuery(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, results) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(results);
    });
  });
}

async function initializeDatabase() {
  try {
    await ensureUsersTable();
    await ensureItemsTable();
    console.log('Структура БД готова к работе');
  } catch (error) {
    console.error('Ошибка инициализации БД:', error);
  }
}

async function ensureUsersTable() {
  const tables = await runQuery("SHOW TABLES LIKE 'users'");

  if (tables.length === 0) {
    await runQuery(`
      CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        passwordHash VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    return;
  }

  const columns = await runQuery('DESCRIBE users');
  const columnNames = columns.map((column) => column.Field);

  const hasLabSchema =
    columnNames.includes('email') &&
    columnNames.includes('passwordHash') &&
    columnNames.includes('name') &&
    columnNames.includes('createdAt');

  if (hasLabSchema) {
    return;
  }

  await runQuery('DROP TABLE IF EXISTS items');
  await runQuery('DROP TABLE users');

  await runQuery(`
    CREATE TABLE users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) NOT NULL UNIQUE,
      passwordHash VARCHAR(255) NOT NULL,
      name VARCHAR(255) NOT NULL,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

async function ensureItemsTable() {
  await runQuery(`
    CREATE TABLE IF NOT EXISTS items (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      description TEXT,
      ownerId INT NOT NULL,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (ownerId) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
}

function parseCookies(req) {
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) {
    return {};
  }

  return cookieHeader.split(';').reduce((acc, cookiePart) => {
    const [rawName, ...rest] = cookiePart.trim().split('=');
    acc[rawName] = decodeURIComponent(rest.join('='));
    return acc;
  }, {});
}

function setSession(res, userId) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, userId);
  res.setHeader('Set-Cookie', `sessionId=${token}; HttpOnly; Path=/; SameSite=Lax`);
}

function clearSession(req, res) {
  const cookies = parseCookies(req);
  if (cookies.sessionId) {
    sessions.delete(cookies.sessionId);
  }
  res.setHeader('Set-Cookie', 'sessionId=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax');
}

function getCurrentUser(req) {
  const cookies = parseCookies(req);
  const sessionId = cookies.sessionId;

  if (!sessionId || !sessions.has(sessionId)) {
    return null;
  }

  return sessions.get(sessionId);
}

function requireAuthApi(req, res, next) {
  const userId = getCurrentUser(req);
  if (!userId) {
    return res.status(401).json({ message: 'Требуется авторизация' });
  }

  req.userId = userId;
  next();
}

function requireAuthPage(req, res, next) {
  const userId = getCurrentUser(req);
  if (!userId) {
    return res.redirect('/auth/login');
  }

  req.userId = userId;
  next();
}

app.get('/', (req, res) => {
  res.redirect('/auth/login');
});

app.get('/auth/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/auth/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/profile', requireAuthPage, (req, res) => {
  res.sendFile(path.join(__dirname, 'profile.html'));
});

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).send('Все поля обязательны');
  }

  if (name.trim().length < 2) {
    return res.status(400).send('Имя должно содержать минимум 2 символа');
  }

  if (password.length < 6) {
    return res.status(400).send('Пароль должен быть не короче 6 символов');
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).send('Некорректный email');
  }

  try {
    const existingUsers = await runQuery('SELECT id FROM users WHERE email = ?', [email]);

    if (existingUsers.length > 0) {
      return res.status(400).send('Пользователь с таким email уже существует');
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await runQuery(
      'INSERT INTO users (email, passwordHash, name) VALUES (?, ?, ?)',
      [email, passwordHash, name.trim()]
    );

    setSession(res, result.insertId);
    res.redirect('/profile');
  } catch (error) {
    console.error(error);
    res.status(500).send(`Ошибка сервера: ${error.sqlMessage || error.message}`);
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('Введите email и пароль');
  }

  try {
    const results = await runQuery('SELECT * FROM users WHERE email = ?', [email]);

    if (results.length === 0) {
      return res.status(404).send('Пользователь не найден');
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.passwordHash);

    if (!match) {
      return res.status(401).send('Неверный пароль');
    }

    setSession(res, user.id);
    res.redirect('/profile');
  } catch (error) {
    console.error(error);
    res.status(500).send(`Ошибка сервера: ${error.sqlMessage || error.message}`);
  }
});

app.post('/api/auth/logout', (req, res) => {
  clearSession(req, res);
  res.redirect('/auth/login');
});

app.get('/api/auth/me', requireAuthApi, async (req, res) => {
  try {
    const results = await runQuery(
      'SELECT id, email, name, createdAt FROM users WHERE id = ?',
      [req.userId]
    );

    if (results.length === 0) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    res.json(results[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.sqlMessage || error.message });
  }
});

app.get('/api/items', async (req, res) => {
  try {
    const results = await runQuery(`
      SELECT items.id, items.title, items.description, items.createdAt, users.name AS ownerName
      FROM items
      JOIN users ON users.id = items.ownerId
      ORDER BY items.createdAt DESC
    `);

    res.json(results);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.sqlMessage || error.message });
  }
});

app.post('/api/items', requireAuthApi, async (req, res) => {
  const { title, description } = req.body;

  if (!title || title.trim().length < 2) {
    return res.status(400).json({ message: 'Название должно содержать минимум 2 символа' });
  }

  try {
    const result = await runQuery(
      'INSERT INTO items (title, description, ownerId) VALUES (?, ?, ?)',
      [title.trim(), description || '', req.userId]
    );

    res.status(201).json({
      id: result.insertId,
      title: title.trim(),
      description: description || '',
      ownerId: req.userId,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.sqlMessage || error.message });
  }
});

app.listen(port, () => {
  console.log(`Сервер запущен: http://localhost:${port}`);
});
