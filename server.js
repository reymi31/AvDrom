const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const path = require('path');

const app = express();
const port = 3000;
const sessions = new Map();

const ADMIN_EMAIL = 'admin@avdrom.local';
const ADMIN_PASSWORD = 'Admin12345';
const ADMIN_NAME = 'Администратор';

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
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
    await ensureFavoritesTable();
    await ensureAdminUser();
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
        role VARCHAR(20) NOT NULL DEFAULT 'user',
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

  if (!hasLabSchema) {
    await runQuery('DROP TABLE IF EXISTS favorites');
    await runQuery('DROP TABLE IF EXISTS items');
    await runQuery('DROP TABLE users');

    await runQuery(`
      CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        passwordHash VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'user',
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    return;
  }

  if (!columnNames.includes('role')) {
    await runQuery("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user' AFTER name");
  }
}

async function ensureItemsTable() {
  await runQuery(`
    CREATE TABLE IF NOT EXISTS items (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      brand VARCHAR(100) NOT NULL,
      model VARCHAR(100) NOT NULL,
      price DECIMAL(12, 2) NOT NULL,
      year INT,
      description TEXT,
      imageData LONGTEXT,
      ownerId INT NOT NULL,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (ownerId) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  const columns = await runQuery('DESCRIBE items');
  const columnNames = columns.map((column) => column.Field);

  if (!columnNames.includes('brand')) {
    await runQuery('ALTER TABLE items ADD COLUMN brand VARCHAR(100) NOT NULL DEFAULT "Не указано" AFTER title');
  }
  if (!columnNames.includes('model')) {
    await runQuery('ALTER TABLE items ADD COLUMN model VARCHAR(100) NOT NULL DEFAULT "Не указано" AFTER brand');
  }
  if (!columnNames.includes('price')) {
    await runQuery('ALTER TABLE items ADD COLUMN price DECIMAL(12, 2) NOT NULL DEFAULT 0 AFTER model');
  }
  if (!columnNames.includes('year')) {
    await runQuery('ALTER TABLE items ADD COLUMN year INT NULL AFTER price');
  }
  if (!columnNames.includes('imageData')) {
    await runQuery('ALTER TABLE items ADD COLUMN imageData LONGTEXT NULL AFTER description');
  }
}

async function ensureFavoritesTable() {
  await runQuery(`
    CREATE TABLE IF NOT EXISTS favorites (
      id INT AUTO_INCREMENT PRIMARY KEY,
      userId INT NOT NULL,
      itemId INT NOT NULL,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY unique_favorite (userId, itemId),
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (itemId) REFERENCES items(id) ON DELETE CASCADE
    )
  `);
}

async function ensureAdminUser() {
  const existingAdmins = await runQuery('SELECT id FROM users WHERE email = ?', [ADMIN_EMAIL]);

  if (existingAdmins.length > 0) {
    await runQuery("UPDATE users SET role = 'admin', name = ? WHERE email = ?", [ADMIN_NAME, ADMIN_EMAIL]);
    return;
  }

  const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
  await runQuery(
    "INSERT INTO users (email, passwordHash, name, role) VALUES (?, ?, ?, 'admin')",
    [ADMIN_EMAIL, passwordHash, ADMIN_NAME]
  );
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

async function loadUserById(userId) {
  const users = await runQuery('SELECT id, email, name, role, createdAt FROM users WHERE id = ?', [userId]);
  return users[0] || null;
}

async function requireAuthApi(req, res, next) {
  try {
    const userId = getCurrentUser(req);
    if (!userId) {
      return res.status(401).json({ message: 'Требуется авторизация' });
    }

    const user = await loadUserById(userId);
    if (!user) {
      return res.status(401).json({ message: 'Пользователь не найден' });
    }

    req.userId = user.id;
    req.user = user;
    next();
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.sqlMessage || error.message });
  }
}

async function requireAuthPage(req, res, next) {
  try {
    const userId = getCurrentUser(req);
    if (!userId) {
      return res.redirect('/auth/login');
    }

    const user = await loadUserById(userId);
    if (!user) {
      return res.redirect('/auth/login');
    }

    req.userId = user.id;
    req.user = user;
    next();
  } catch (error) {
    console.error(error);
    res.redirect('/auth/login');
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Требуются права администратора' });
  }
  next();
}

function normalizeItem(item) {
  return {
    id: item.id,
    title: item.title,
    brand: item.brand,
    model: item.model,
    price: Number(item.price),
    year: item.year,
    description: item.description,
    imageData: item.imageData,
    ownerId: item.ownerId,
    ownerName: item.ownerName,
    createdAt: item.createdAt,
    isFavorite: Boolean(item.isFavorite),
    isOwner: Boolean(item.isOwner),
  };
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
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
      "INSERT INTO users (email, passwordHash, name, role) VALUES (?, ?, ?, 'user')",
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
  res.redirect('/');
});

app.get('/api/auth/me', async (req, res) => {
  try {
    const userId = getCurrentUser(req);
    if (!userId) {
      return res.status(401).json({ message: 'Требуется авторизация' });
    }

    const user = await loadUserById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.sqlMessage || error.message });
  }
});

app.get('/api/users', requireAuthApi, requireAdmin, async (req, res) => {
  try {
    const users = await runQuery(
      'SELECT id, email, name, role, createdAt FROM users ORDER BY createdAt DESC'
    );
    res.json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.sqlMessage || error.message });
  }
});

app.patch('/api/users/:id/role', requireAuthApi, requireAdmin, async (req, res) => {
  const targetUserId = Number(req.params.id);
  const { role } = req.body;

  if (!Number.isInteger(targetUserId)) {
    return res.status(400).json({ message: 'Некорректный идентификатор пользователя' });
  }
  if (!['admin', 'user'].includes(role)) {
    return res.status(400).json({ message: 'Допустимые роли: admin или user' });
  }
  if (targetUserId === req.userId && role !== 'admin') {
    return res.status(400).json({ message: 'Администратор не может снять роль сам у себя' });
  }

  try {
    const users = await runQuery('SELECT id FROM users WHERE id = ?', [targetUserId]);
    if (users.length === 0) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    await runQuery('UPDATE users SET role = ? WHERE id = ?', [role, targetUserId]);
    res.json({ message: 'Роль пользователя обновлена' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.sqlMessage || error.message });
  }
});

app.delete('/api/users/:id', requireAuthApi, requireAdmin, async (req, res) => {
  const targetUserId = Number(req.params.id);

  if (!Number.isInteger(targetUserId)) {
    return res.status(400).json({ message: 'Некорректный идентификатор пользователя' });
  }
  if (targetUserId === req.userId) {
    return res.status(400).json({ message: 'Нельзя удалить собственный аккаунт администратора' });
  }

  try {
    const users = await runQuery('SELECT id FROM users WHERE id = ?', [targetUserId]);
    if (users.length === 0) {
      return res.status(404).json({ message: 'Пользователь не найден' });
    }

    await runQuery('DELETE FROM users WHERE id = ?', [targetUserId]);
    res.json({ message: 'Пользователь удален' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.sqlMessage || error.message });
  }
});

app.get('/api/items', async (req, res) => {
  const currentUserId = getCurrentUser(req) || 0;
  const { brand = '', model = '', minPrice = '', maxPrice = '', year = '', favoritesOnly = 'false', ownerOnly = 'false' } = req.query;

  const conditions = [];
  const params = [currentUserId, currentUserId];

  if (brand) {
    conditions.push('items.brand LIKE ?');
    params.push(`%${brand}%`);
  }
  if (model) {
    conditions.push('items.model LIKE ?');
    params.push(`%${model}%`);
  }
  if (minPrice) {
    conditions.push('items.price >= ?');
    params.push(Number(minPrice));
  }
  if (maxPrice) {
    conditions.push('items.price <= ?');
    params.push(Number(maxPrice));
  }
  if (year) {
    conditions.push('items.year = ?');
    params.push(Number(year));
  }
  if (favoritesOnly === 'true') {
    conditions.push('favorites.id IS NOT NULL');
  }
  if (ownerOnly === 'true') {
    conditions.push('items.ownerId = ?');
    params.push(currentUserId);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  try {
    const results = await runQuery(
      `
        SELECT
          items.id,
          items.title,
          items.brand,
          items.model,
          items.price,
          items.year,
          items.description,
          items.imageData,
          items.ownerId,
          items.createdAt,
          users.name AS ownerName,
          CASE WHEN favorites.id IS NULL THEN 0 ELSE 1 END AS isFavorite,
          CASE WHEN items.ownerId = ? THEN 1 ELSE 0 END AS isOwner
        FROM items
        JOIN users ON users.id = items.ownerId
        LEFT JOIN favorites
          ON favorites.itemId = items.id
         AND favorites.userId = ?
        ${whereClause}
        ORDER BY items.createdAt DESC
      `,
      params
    );

    res.json(results.map(normalizeItem));
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.sqlMessage || error.message });
  }
});

app.post('/api/items', requireAuthApi, async (req, res) => {
  const { title, brand, model, price, year, description, imageData } = req.body;

  if (!title || title.trim().length < 2) {
    return res.status(400).json({ message: 'Название должно содержать минимум 2 символа' });
  }
  if (!brand || brand.trim().length < 2) {
    return res.status(400).json({ message: 'Укажи марку автомобиля' });
  }
  if (!model || model.trim().length < 1) {
    return res.status(400).json({ message: 'Укажи модель автомобиля' });
  }

  const numericPrice = Number(price);
  if (!Number.isFinite(numericPrice) || numericPrice <= 0) {
    return res.status(400).json({ message: 'Цена должна быть положительным числом' });
  }

  const numericYear = year ? Number(year) : null;
  if (numericYear && (!Number.isInteger(numericYear) || numericYear < 1950 || numericYear > 2035)) {
    return res.status(400).json({ message: 'Год указан некорректно' });
  }
  if (imageData && !String(imageData).startsWith('data:image/')) {
    return res.status(400).json({ message: 'Фотография должна быть изображением' });
  }

  try {
    const result = await runQuery(
      `INSERT INTO items (title, brand, model, price, year, description, imageData, ownerId)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [title.trim(), brand.trim(), model.trim(), numericPrice, numericYear, description || '', imageData || null, req.userId]
    );

    res.status(201).json({
      id: result.insertId,
      title: title.trim(),
      brand: brand.trim(),
      model: model.trim(),
      price: numericPrice,
      year: numericYear,
      description: description || '',
      imageData: imageData || null,
      ownerId: req.userId,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.sqlMessage || error.message });
  }
});

app.delete('/api/items/:id', requireAuthApi, async (req, res) => {
  const itemId = Number(req.params.id);

  if (!Number.isInteger(itemId)) {
    return res.status(400).json({ message: 'Некорректный идентификатор объявления' });
  }

  try {
    const results = await runQuery('SELECT ownerId FROM items WHERE id = ?', [itemId]);
    if (results.length === 0) {
      return res.status(404).json({ message: 'Объявление не найдено' });
    }

    const canDelete = results[0].ownerId === req.userId || req.user.role === 'admin';
    if (!canDelete) {
      return res.status(403).json({ message: 'Удалять можно только свои объявления или делать это от имени администратора' });
    }

    await runQuery('DELETE FROM items WHERE id = ?', [itemId]);
    res.json({ message: 'Объявление удалено' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.sqlMessage || error.message });
  }
});

app.get('/api/favorites', requireAuthApi, async (req, res) => {
  try {
    const results = await runQuery(
      `
        SELECT
          items.id,
          items.title,
          items.brand,
          items.model,
          items.price,
          items.year,
          items.description,
          items.imageData,
          items.ownerId,
          items.createdAt,
          users.name AS ownerName,
          1 AS isFavorite,
          CASE WHEN items.ownerId = ? THEN 1 ELSE 0 END AS isOwner
        FROM favorites
        JOIN items ON items.id = favorites.itemId
        JOIN users ON users.id = items.ownerId
        WHERE favorites.userId = ?
        ORDER BY favorites.createdAt DESC
      `,
      [req.userId, req.userId]
    );

    res.json(results.map(normalizeItem));
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.sqlMessage || error.message });
  }
});

app.post('/api/favorites/:itemId', requireAuthApi, async (req, res) => {
  const itemId = Number(req.params.itemId);

  if (!Number.isInteger(itemId)) {
    return res.status(400).json({ message: 'Некорректный идентификатор объявления' });
  }

  try {
    const items = await runQuery('SELECT id FROM items WHERE id = ?', [itemId]);
    if (items.length === 0) {
      return res.status(404).json({ message: 'Объявление не найдено' });
    }

    await runQuery('INSERT IGNORE INTO favorites (userId, itemId) VALUES (?, ?)', [req.userId, itemId]);
    res.status(201).json({ message: 'Добавлено в избранное' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.sqlMessage || error.message });
  }
});

app.delete('/api/favorites/:itemId', requireAuthApi, async (req, res) => {
  const itemId = Number(req.params.itemId);

  if (!Number.isInteger(itemId)) {
    return res.status(400).json({ message: 'Некорректный идентификатор объявления' });
  }

  try {
    await runQuery('DELETE FROM favorites WHERE userId = ? AND itemId = ?', [req.userId, itemId]);
    res.json({ message: 'Удалено из избранного' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.sqlMessage || error.message });
  }
});

app.listen(port, () => {
  console.log(`Сервер запущен: http://localhost:${port}`);
  console.log(`Админ: ${ADMIN_EMAIL} / ${ADMIN_PASSWORD}`);
});
