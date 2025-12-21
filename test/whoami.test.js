const test = require("node:test");
const assert = require("assert");
const request = require("supertest");
const bcrypt = require("bcryptjs");
const { createPool } = require("../src/db");
const { createApp } = require("../src/app");

const TEST_DB_URL =
  process.env.TEST_DATABASE_URL ||
  process.env.DATABASE_URL ||
  "postgres://localhost:5432/hourcrate_test";

async function seedUser(pool, email = "whoami@example.com", password = "password123") {
  const hash = await bcrypt.hash(password, 10);
  await pool.query(
    "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
    [email, hash]
  );
}

async function login(app, email = "whoami@example.com", password = "password123") {
  const res = await request(app)
    .post("/sessions")
    .send({ email, password });
  assert.strictEqual(res.status, 201);
  const setCookie = res.headers["set-cookie"];
  assert.ok(setCookie);
  return setCookie[0].split(";")[0];
}

test("whoami returns current user and environment info", async (t) => {
  const pool = await createPool({ connectionString: TEST_DB_URL });
  await pool.query(
    "TRUNCATE time_entries, retainers, clients, sessions, users RESTART IDENTITY CASCADE"
  );
  await seedUser(pool);
  const app = createApp(pool);

  t.after(async () => {
    await pool.end();
  });

  const session = await login(app);
  const res = await request(app).get("/whoami").set("Cookie", session);
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.user.email, "whoami@example.com");
  assert.strictEqual(res.body.user.is_paid, false);
  assert.ok(res.body.environment);
});
