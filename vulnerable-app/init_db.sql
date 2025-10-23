-- init_db.sql
DROP TABLE IF EXISTS users;
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  email TEXT,
  password TEXT
);
INSERT INTO users (username, email, password) VALUES ('alice', 'alice@example.com', 'password123');
INSERT INTO users (username, email, password) VALUES ('bob', 'bob@example.com', 'secret456');

DROP TABLE IF EXISTS products;
CREATE TABLE products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  description TEXT,
  price REAL
);
INSERT INTO products (name, description, price) VALUES ('Laptop', 'A powerful laptop', 1200.50);
INSERT INTO products (name, description, price) VALUES ('Mouse', 'A wireless mouse', 25.00);
INSERT INTO products (name, description, price) VALUES ('Keyboard', 'A mechanical keyboard', 75.99);

DROP TABLE IF EXISTS orders;
CREATE TABLE orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  product_id INTEGER,
  quantity INTEGER,
  total_price REAL,
  order_date TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(product_id) REFERENCES products(id)
);
INSERT INTO orders (user_id, product_id, quantity, total_price, order_date) VALUES (1, 1, 1, 1200.50, '2025-09-26');
INSERT INTO orders (user_id, product_id, quantity, total_price, order_date) VALUES (2, 2, 2, 50.00, '2025-09-26');

DROP TABLE IF EXISTS reviews;
CREATE TABLE reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER,
  user_id INTEGER,
  review TEXT,
  rating INTEGER,
  review_date TEXT,
  FOREIGN KEY(product_id) REFERENCES products(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
INSERT INTO reviews (product_id, user_id, review, rating, review_date) VALUES (1, 1, 'Great laptop!', 5, '2025-09-26');
INSERT INTO reviews (product_id, user_id, review, rating, review_date) VALUES (1, 2, 'A bit expensive, but worth it.', 4, '2025-09-26');