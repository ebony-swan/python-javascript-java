-- Seed data. Password column holds unsalted MD5 hashes, matching the Python
-- and JavaScript apps (md5('password1'), md5('bobs-dog-2019'), md5('admin123')).

INSERT INTO users (username, password, email, role, ssn) VALUES
  ('alice', '7c6a180b36896a0a8c02787eeafb0e4c', 'alice@example.com', 'user',  '111-11-1111'),
  ('bob',   'fa49ba3a742b254a13d665b07f81ae80', 'bob@example.com',   'user',  '222-22-2222'),
  ('admin', '0192023a7bbd73250516f069df18b500', 'admin@example.com', 'admin', '999-99-9999');

INSERT INTO notes (owner, title, body, private) VALUES
  ('alice', 'Shopping list',     'milk, eggs, bread',          0),
  ('alice', 'Bank PIN reminder', 'PIN is 4821 (do not share)', 1),
  ('bob',   'Public note',       'hello world',                0),
  ('admin', 'Ops runbook',       'prod db password: hunter2',  1);
