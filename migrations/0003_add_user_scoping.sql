BEGIN;

ALTER TABLE clients
ADD COLUMN IF NOT EXISTS user_id BIGINT REFERENCES users(id) ON DELETE CASCADE;

UPDATE clients
SET user_id = sub.id
FROM (SELECT id FROM users ORDER BY id LIMIT 1) AS sub
WHERE clients.user_id IS NULL;

ALTER TABLE clients
ALTER COLUMN user_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_clients_user_id ON clients(user_id);

COMMIT;
