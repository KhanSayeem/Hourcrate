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

async function setupTest() {
  const pool = await createPool({ connectionString: TEST_DB_URL });
  await pool.query(
    "TRUNCATE time_entries, retainers, clients, sessions, users RESTART IDENTITY CASCADE"
  );
  await seedUser(pool);
  const app = createApp(pool);
  return { pool, app };
}

async function seedUser(pool) {
  const hash = await bcrypt.hash("password123", 10);
  await pool.query(
    "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
    ["test@example.com", hash]
  );
}

test("GET /login renders an HTML form with email and password fields", async (t) => {
  const { app, pool } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const res = await request(app).get("/login").set("Accept", "text/html");
  assert.strictEqual(res.status, 200);
  assert.ok(res.headers["content-type"].startsWith("text/html"));
  assert.ok(res.text.includes('<form action="/sessions" method="post">'));
  assert.ok(res.text.includes('name="email"'));
  assert.ok(res.text.includes('name="password"'));
});

test("HTML session creation redirects to dashboard on success", async (t) => {
  const { app, pool } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const res = await request(app)
    .post("/sessions")
    .set("Accept", "text/html")
    .type("form")
    .send({ email: "test@example.com", password: "password123" });

  assert.strictEqual(res.status, 303);
  assert.strictEqual(res.headers.location, "/dashboard");
  assert.ok(res.headers["set-cookie"]);
});

test("HTML session creation normalizes email casing", async (t) => {
  const { app, pool } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const res = await request(app)
    .post("/sessions")
    .set("Accept", "text/html")
    .type("form")
    .send({ email: "TEST@EXAMPLE.COM", password: "password123" });

  assert.strictEqual(res.status, 303);
  assert.strictEqual(res.headers.location, "/dashboard");
});

test("HTML session creation re-renders login with an error on failure", async (t) => {
  const { app, pool } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const res = await request(app)
    .post("/sessions")
    .set("Accept", "text/html")
    .type("form")
    .send({ email: "test@example.com", password: "wrongpass" });

  assert.strictEqual(res.status, 401);
  assert.ok(res.headers["content-type"].startsWith("text/html"));
  assert.ok(res.text.includes("Invalid credentials"));
  assert.ok(res.text.includes('<form action="/sessions" method="post">'));
});

test("unauthenticated HTML request to protected route redirects to /login", async (t) => {
  const { app, pool } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const res = await request(app).get("/dashboard").set("Accept", "text/html");
  assert.strictEqual(res.status, 302);
  assert.strictEqual(res.headers.location, "/login");
});
