const test = require("node:test");
const assert = require("assert");
const request = require("supertest");
const { createPool } = require("../src/db");
const { createApp } = require("../src/app");
const bcrypt = require("bcryptjs");

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

test("creates a client with a single retainer and starts at 0 hours used", async (t) => {
  const { app, pool, sessionCookie } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const res = await request(app)
    .post("/clients")
    .set("Cookie", sessionCookie)
    .send({ name: "Acme", monthly_hour_limit: 50.5 });
  assert.strictEqual(res.status, 201);
  assert.strictEqual(res.body.name, "Acme");
  assert.strictEqual(res.body.monthly_hour_limit, 50.5);
  assert.strictEqual(res.body.hours_used, 0);
  assert.strictEqual(res.body.hours_remaining, 50.5);

  const row = await pool.query(
    "SELECT r.monthly_hour_limit FROM retainers r JOIN clients c ON r.client_id = c.id WHERE c.name = $1",
    ["Acme"]
  );
  assert.strictEqual(row.rowCount, 1);
  assert.strictEqual(Number(row.rows[0].monthly_hour_limit), 50.5);
});

test("rejects creation without auth", async (t) => {
  const { app, pool } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const res = await request(app)
    .post("/clients")
    .send({ name: "NoAuth", monthly_hour_limit: 10 });
  assert.strictEqual(res.status, 401);
});

test("blocks additional retainers for the same client (unique constraint)", async (t) => {
  const { app, pool, sessionCookie } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const createRes = await request(app)
    .post("/clients")
    .set("Cookie", sessionCookie)
    .send({ name: "Solo", monthly_hour_limit: 20 });
  assert.strictEqual(createRes.status, 201);

  const clientId = createRes.body.id;
  await assert.rejects(() =>
    pool.query(
      "INSERT INTO retainers (client_id, monthly_hour_limit) VALUES ($1, $2)",
      [clientId, 5]
    )
  );
});

test("deletes a client with no time entries", async (t) => {
  const { app, pool, sessionCookie } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const createRes = await request(app)
    .post("/clients")
    .set("Cookie", sessionCookie)
    .send({ name: "DeleteMe", monthly_hour_limit: 12.5 });
  const clientId = createRes.body.id;

  const delRes = await request(app)
    .delete(`/clients/${clientId}`)
    .set("Cookie", sessionCookie);
  assert.strictEqual(delRes.status, 204);

  const clientRow = await pool.query("SELECT id FROM clients WHERE id = $1", [
    clientId,
  ]);
  const retainerRow = await pool.query(
    "SELECT id FROM retainers WHERE client_id = $1",
    [clientId]
  );
  assert.strictEqual(clientRow.rowCount, 0);
  assert.strictEqual(retainerRow.rowCount, 0);
});

test("blocks deletion when time entries exist", async (t) => {
  const { app, pool, sessionCookie } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const createRes = await request(app)
    .post("/clients")
    .set("Cookie", sessionCookie)
    .send({ name: "Locked", monthly_hour_limit: 8 });
  const clientId = createRes.body.id;

  await pool.query(
    "INSERT INTO time_entries (client_id, entry_date, hours) VALUES ($1, $2, $3)",
    [clientId, "2025-12-01", 2]
  );

  const delRes = await request(app)
    .delete(`/clients/${clientId}`)
    .set("Cookie", sessionCookie);
  assert.strictEqual(delRes.status, 409);

  const stillThere = await pool.query(
    "SELECT id FROM clients WHERE id = $1",
    [clientId]
  );
  assert.strictEqual(stillThere.rowCount, 1);
});

test("does not allow editing retainer limit (no route)", async (t) => {
  const { app, pool, sessionCookie } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const createRes = await request(app)
    .post("/clients")
    .set("Cookie", sessionCookie)
    .send({ name: "Immutable", monthly_hour_limit: 30 });
  const clientId = createRes.body.id;

  const res = await request(app)
    .patch(`/clients/${clientId}/retainer`)
    .set("Cookie", sessionCookie)
    .send({ monthly_hour_limit: 99 });
  assert.strictEqual(res.status, 404);
});

test("creates a time entry for current month and today or earlier", async (t) => {
  const { app, pool, sessionCookie } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const clientRes = await request(app)
    .post("/clients")
    .set("Cookie", sessionCookie)
    .send({ name: "EntriesCo", monthly_hour_limit: 40 });
  const clientId = clientRes.body.id;

  const today = currentDateUTC();
  const res = await request(app)
    .post(`/clients/${clientId}/entries`)
    .set("Cookie", sessionCookie)
    .send({ date: today, hours: 2.5 });
  assert.strictEqual(res.status, 201);
  assert.strictEqual(res.body.date, today);
  assert.strictEqual(res.body.hours, 2.5);

  const row = await pool.query(
    "SELECT entry_date::text AS entry_date, hours FROM time_entries WHERE client_id = $1",
    [clientId]
  );
  assert.strictEqual(row.rowCount, 1);
  assert.strictEqual(row.rows[0].entry_date, today);
  assert.strictEqual(Number(row.rows[0].hours), 2.5);
});

test("rejects time entry with future date in current month", async (t) => {
  const { app, pool, sessionCookie } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const clientRes = await request(app)
    .post("/clients")
    .set("Cookie", sessionCookie)
    .send({ name: "FutureCo", monthly_hour_limit: 40 });
  const clientId = clientRes.body.id;

  const tomorrow = tomorrowUTC();
  const res = await request(app)
    .post(`/clients/${clientId}/entries`)
    .set("Cookie", sessionCookie)
    .send({ date: tomorrow, hours: 1 });
  assert.strictEqual(res.status, 400);
});

test("rejects time entry with past month date", async (t) => {
  const { app, pool, sessionCookie } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const clientRes = await request(app)
    .post("/clients")
    .set("Cookie", sessionCookie)
    .send({ name: "PastCo", monthly_hour_limit: 40 });
  const clientId = clientRes.body.id;

  const past = previousMonthDateUTC();
  const res = await request(app)
    .post(`/clients/${clientId}/entries`)
    .set("Cookie", sessionCookie)
    .send({ date: past, hours: 1 });
  assert.strictEqual(res.status, 400);
});

function currentDateUTC() {
  return new Date().toISOString().slice(0, 10);
}

function tomorrowUTC() {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().slice(0, 10);
}

function previousMonthDateUTC() {
  const d = new Date();
  d.setUTCMonth(d.getUTCMonth() - 1);
  return d.toISOString().slice(0, 10);
}
