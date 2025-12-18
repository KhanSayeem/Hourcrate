const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");

async function createPool(options = {}) {
  const connectionString =
    options.connectionString || process.env.DATABASE_URL || "";

  const config = parseConnectionString(connectionString);
  const pool = new Pool(config);
  await runMigrations(pool);
  return pool;
}

async function runMigrations(pool) {
  const migrationsDir = path.join(__dirname, "..", "migrations");
  const files = fs
    .readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();

  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  for (const file of files) {
    const applied = await pool.query(
      "SELECT 1 FROM schema_migrations WHERE name = $1",
      [file]
    );
    if (applied.rowCount > 0) continue;

    const sql = fs.readFileSync(path.join(migrationsDir, file), "utf8");
    try {
      await pool.query(sql);
      await pool.query(
        "INSERT INTO schema_migrations (name) VALUES ($1)",
        [file]
      );
    } catch (err) {
      console.error(`Failed to apply migration ${file}`, err);
      throw err;
    }
  }
}

module.exports = {
  createPool,
  runMigrations,
};

function parseConnectionString(connStr) {
  if (!connStr || typeof connStr !== "string") {
    throw new Error("DATABASE_URL/connectionString is required for Postgres");
  }
  const url = new URL(connStr);
  const sslmode = url.searchParams.get("sslmode");
  const ssl =
    sslmode && sslmode.toLowerCase() !== "disable"
      ? { rejectUnauthorized: false }
      : undefined;

  let password = url.password;
  if (!password) {
    // Fallback only if userinfo is present before "@"
    const match = connStr.match(/^[^:]+:\/\/([^@]+)@/);
    if (match && match[1]) {
      const userInfo = match[1];
      const parts = userInfo.split(":");
      password = parts.length > 1 ? parts.slice(1).join(":") : "";
    }
  }
  if (!password) {
    throw new Error("Postgres password is required in connection string");
  }

  return {
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(password),
    host: url.hostname,
    port: Number(url.port) || 5432,
    database: url.pathname.replace(/^\//, ""),
    ssl,
  };
}
