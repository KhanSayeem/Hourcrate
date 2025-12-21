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

async function createUser(pool, email, password = "password123") {
  const hash = await bcrypt.hash(password, 10);
  await pool.query(
    "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
    [email, hash]
  );
}

async function login(app, email, password = "password123") {
  const res = await request(app)
    .post("/sessions")
    .send({ email, password });
  assert.strictEqual(res.status, 201);
  const setCookie = res.headers["set-cookie"];
  assert.ok(setCookie);
  return setCookie[0].split(";")[0];
}

test("clients and entries are isolated per user", async (t) => {
  const pool = await createPool({ connectionString: TEST_DB_URL });
  await pool.query(
    "TRUNCATE time_entries, retainers, clients, sessions, users RESTART IDENTITY CASCADE"
  );
  await createUser(pool, "owner1@example.com");
  await createUser(pool, "owner2@example.com");

  const app = createApp(pool);

  t.after(async () => {
    await pool.end();
  });

  const session1 = await login(app, "owner1@example.com");
  const session2 = await login(app, "owner2@example.com");

  const createRes = await request(app)
    .post("/clients")
    .set("Cookie", session1)
    .send({ name: "User One Client", monthly_hour_limit: 10 });
  assert.strictEqual(createRes.status, 201);
  const clientId = createRes.body.id;

  const listOne = await request(app)
    .get("/clients")
    .set("Cookie", session1);
  assert.strictEqual(listOne.status, 200);
  assert.ok(listOne.body.clients.some((c) => c.id === clientId));

  const listTwo = await request(app)
    .get("/clients")
    .set("Cookie", session2);
  assert.strictEqual(listTwo.status, 200);
  assert.strictEqual(listTwo.body.clients.length, 0);

  const today = new Date().toISOString().slice(0, 10);
  const forbiddenEntry = await request(app)
    .post(`/clients/${clientId}/entries`)
    .set("Cookie", session2)
    .send({ date: today, hours: 1 });
  assert.strictEqual(forbiddenEntry.status, 404);
});
