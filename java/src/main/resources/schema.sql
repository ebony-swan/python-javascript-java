-- Shared demo schema. Mirrors the Python and JavaScript apps so the docs can
-- cross-reference the same tables/data across all three languages.

DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50)  NOT NULL,
    password VARCHAR(200) NOT NULL,   -- unsalted MD5 hash (see crypto demo)
    email    VARCHAR(100),
    role     VARCHAR(20)  NOT NULL DEFAULT 'user',
    ssn      VARCHAR(20)                -- "sensitive" field used by IDOR / crypto demos
);

DROP TABLE IF EXISTS notes;
CREATE TABLE notes (
    id      INT AUTO_INCREMENT PRIMARY KEY,
    owner   VARCHAR(50)   NOT NULL,
    title   VARCHAR(200),
    body    VARCHAR(2000),             -- rendered unescaped by the stored-XSS demo
    private INT           NOT NULL DEFAULT 0
);
