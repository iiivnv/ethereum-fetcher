CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY,
    username VARCHAR(32) UNIQUE,
    password TEXT
);

CREATE EXTENSION IF NOT EXISTS pgcrypto;
INSERT INTO users (id, username, password) VALUES (1, 'alice', crypt('alice', gen_salt('bf')));
INSERT INTO users (id, username, password) VALUES (2, 'bob', crypt('bob', gen_salt('bf')));
INSERT INTO users (id, username, password) VALUES (3, 'carol', crypt('carol', gen_salt('bf')));
INSERT INTO users (id, username, password) VALUES (4, 'dave', crypt('dave', gen_salt('bf')));

