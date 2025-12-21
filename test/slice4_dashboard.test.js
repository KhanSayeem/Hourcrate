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

test("dashboard shows current-month totals per client with no overages", async (t) => {
  const { app, pool, sessionCookie } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const createRes = await request(app)
    .post("/clients")
    .set("Cookie", sessionCookie)
    .send({ name: "Acme Co", monthly_hour_limit: 12 });
  const clientId = createRes.body.id;

  const today = currentDateUTC();
  await request(app)
    .post(`/clients/${clientId}/entries`)
    .set("Cookie", sessionCookie)
    .send({ date: today, hours: 3.5 });
  await request(app)
    .post(`/clients/${clientId}/entries`)
    .set("Cookie", sessionCookie)
    .send({ date: today, hours: 2 });

  await pool.query(
    "INSERT INTO time_entries (client_id, entry_date, hours) VALUES ($1, $2, $3)",
    [clientId, firstDayPreviousMonthUTC(), 9]
  );

  const res = await request(app)
    .get("/dashboard")
    .set("Cookie", sessionCookie);
  assert.strictEqual(res.status, 200);
  assert.ok(res.headers["content-type"].startsWith("text/html"));
  assert.ok(res.text.includes("<table"));
  assert.ok(res.text.includes("Acme Co"));
  assert.ok(res.text.includes("12"));
  assert.ok(res.text.includes("5.5"));
  assert.ok(res.text.includes("6.5 hours remaining"));
  assert.ok(!res.text.includes("9")); // past month entry ignored in totals
});

test("dashboard highlights overages in red with over text", async (t) => {
  const { app, pool, sessionCookie } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const createRes = await request(app)
    .post("/clients")
    .set("Cookie", sessionCookie)
    .send({ name: "Overage LLC", monthly_hour_limit: 2 });
  const clientId = createRes.body.id;

  const today = currentDateUTC();
  await request(app)
    .post(`/clients/${clientId}/entries`)
    .set("Cookie", sessionCookie)
    .send({ date: today, hours: 1.25 });
  await request(app)
    .post(`/clients/${clientId}/entries`)
    .set("Cookie", sessionCookie)
    .send({ date: today, hours: 1.5 });

  const res = await request(app)
    .get("/dashboard")
    .set("Cookie", sessionCookie);
  assert.strictEqual(res.status, 200);
  assert.ok(res.text.includes('class="overage">0.75 hours over'));
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
