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
  const sessionCookie = await login(app);
  return { pool, app, sessionCookie };
}

async function seedUser(pool) {
  const hash = await bcrypt.hash("password123", 10);
  await pool.query(
    "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
    ["test@example.com", hash]
  );
}

async function login(app) {
  const res = await request(app)
    .post("/sessions")
    .send({ email: "test@example.com", password: "password123" });
  assert.strictEqual(res.status, 201);
  const setCookie = res.headers["set-cookie"];
  assert.ok(setCookie);
  return setCookie[0].split(";")[0];
}

test("GET /clients shows current-month totals and ignores other months", async (t) => {
  const { app, pool, sessionCookie } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const createRes = await request(app)
    .post("/clients")
    .set("Cookie", sessionCookie)
    .send({ name: "Acme", monthly_hour_limit: 10 });
  const clientId = createRes.body.id;
  const today = currentDateUTC();

  await request(app)
    .post(`/clients/${clientId}/entries`)
    .set("Cookie", sessionCookie)
    .send({ date: today, hours: 3.25 });
  await request(app)
    .post(`/clients/${clientId}/entries`)
    .set("Cookie", sessionCookie)
    .send({ date: today, hours: 1.75 });

  // Insert an entry from last month directly; should be ignored in totals.
  await pool.query(
    "INSERT INTO time_entries (client_id, entry_date, hours) VALUES ($1, $2, $3)",
    [clientId, firstDayPreviousMonthUTC(), 5]
  );

  const listRes = await request(app)
    .get("/clients")
    .set("Cookie", sessionCookie);
  assert.strictEqual(listRes.status, 200);
  const client = listRes.body.clients.find((c) => c.id === clientId);
  assert.ok(client);
  assert.strictEqual(client.hours_used, 5);
  assert.strictEqual(client.hours_remaining, 5);
});

test("hours_remaining can be negative when usage exceeds limit", async (t) => {
  const { app, pool, sessionCookie } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const createRes = await request(app)
    .post("/clients")
    .set("Cookie", sessionCookie)
    .send({ name: "Overage", monthly_hour_limit: 3 });
  const clientId = createRes.body.id;
  const today = currentDateUTC();

  await request(app)
    .post(`/clients/${clientId}/entries`)
    .set("Cookie", sessionCookie)
    .send({ date: today, hours: 2.5 });
  await request(app)
    .post(`/clients/${clientId}/entries`)
    .set("Cookie", sessionCookie)
    .send({ date: today, hours: 1.25 });

  const listRes = await request(app)
    .get("/clients")
    .set("Cookie", sessionCookie);
  assert.strictEqual(listRes.status, 200);
  const client = listRes.body.clients.find((c) => c.id === clientId);
  assert.ok(client);
  assert.strictEqual(client.hours_used, 3.75);
  assert.strictEqual(client.hours_remaining, -0.75);
});

function currentDateUTC() {
  return new Date().toISOString().slice(0, 10);
}

function firstDayPreviousMonthUTC() {
  const d = new Date();
  d.setUTCDate(1);
  d.setUTCMonth(d.getUTCMonth() - 1);
  return d.toISOString().slice(0, 10);
}
