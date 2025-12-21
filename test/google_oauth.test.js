const test = require("node:test");
const assert = require("assert");
const request = require("supertest");
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
  const app = createApp(pool, {
    googleOAuth: {
      clientId: "test-client",
      clientSecret: "test-secret",
      baseUrl: "http://localhost:3000",
      exchangeCodeForTokens: async () => ({
        id_token: "test-id-token",
        access_token: "test-access-token",
      }),
      verifyIdToken: async () => ({
        sub: "google-sub-123",
        email: "operator@example.com",
        email_verified: true,
      }),
    },
  });
  return { pool, app };
}

function extractCookie(cookies, name) {
  const header = Array.isArray(cookies) ? cookies.find((value) => value.startsWith(name)) : "";
  return header ? header.split(";")[0] : "";
}

function extractStateFromRedirect(location) {
  const url = new URL(location);
  return url.searchParams.get("state");
}

test("Google login is blocked when user does not exist", async (t) => {
  const { app, pool } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const startRes = await request(app).get("/auth/google");
  const stateCookie = extractCookie(startRes.headers["set-cookie"], "oauth_state=");
  const state = extractStateFromRedirect(startRes.headers.location);

  const callbackRes = await request(app)
    .get("/auth/google/callback")
    .query({ code: "test-code", state })
    .set("Cookie", stateCookie)
    .set("Accept", "text/html");

  assert.strictEqual(callbackRes.status, 303);
  assert.ok(callbackRes.headers.location.includes("/login?error="));
});

test("Google login updates existing user google_sub", async (t) => {
  const { app, pool } = await setupTest();
  await pool.query("INSERT INTO users (email, password_hash) VALUES ($1, $2)", [
    "operator@example.com",
    "hash",
  ]);

  t.after(async () => {
    await pool.end();
  });

  const startRes = await request(app).get("/auth/google");
  const stateCookie = extractCookie(startRes.headers["set-cookie"], "oauth_state=");
  const state = extractStateFromRedirect(startRes.headers.location);

  const callbackRes = await request(app)
    .get("/auth/google/callback")
    .query({ code: "test-code", state })
    .set("Cookie", stateCookie)
    .set("Accept", "text/html");

  assert.strictEqual(callbackRes.status, 303);
  assert.strictEqual(callbackRes.headers.location, "/dashboard");

  const userResult = await pool.query(
    "SELECT email, google_sub, auth_provider FROM users ORDER BY id LIMIT 1"
  );
  assert.strictEqual(userResult.rowCount, 1);
  assert.strictEqual(userResult.rows[0].email, "operator@example.com");
  assert.strictEqual(userResult.rows[0].google_sub, "google-sub-123");
  assert.strictEqual(userResult.rows[0].auth_provider, "google");
});

test("First Google login creates operator when no users exist", async (t) => {
  const { app, pool } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const startRes = await request(app).get("/auth/google");
  const stateCookie = extractCookie(startRes.headers["set-cookie"], "oauth_state=");
  const state = extractStateFromRedirect(startRes.headers.location);

  const callbackRes = await request(app)
    .get("/auth/google/callback")
    .query({ code: "test-code", state })
    .set("Cookie", stateCookie)
    .set("Accept", "text/html");

  assert.strictEqual(callbackRes.status, 303);
  assert.strictEqual(callbackRes.headers.location, "/dashboard");

  const userResult = await pool.query(
    "SELECT email, google_sub, auth_provider FROM users ORDER BY id LIMIT 1"
  );
  assert.strictEqual(userResult.rowCount, 1);
  assert.strictEqual(userResult.rows[0].email, "operator@example.com");
  assert.strictEqual(userResult.rows[0].google_sub, "google-sub-123");
  assert.strictEqual(userResult.rows[0].auth_provider, "google");
});

test("Google login sets session cookie and allows dashboard", async (t) => {
  const { app, pool } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const startRes = await request(app).get("/auth/google");
  const stateCookie = extractCookie(startRes.headers["set-cookie"], "oauth_state=");
  const state = extractStateFromRedirect(startRes.headers.location);

  const callbackRes = await request(app)
    .get("/auth/google/callback")
    .query({ code: "test-code", state })
    .set("Cookie", stateCookie)
    .set("Accept", "text/html");

  const sessionCookie = extractCookie(callbackRes.headers["set-cookie"], "session_token=");
  assert.ok(sessionCookie);

  const dashboardRes = await request(app)
    .get("/dashboard")
    .set("Cookie", sessionCookie)
    .set("Accept", "text/html");

  assert.strictEqual(dashboardRes.status, 200);
  assert.ok(dashboardRes.text.includes("Monthly Hours"));
});

test("Google signup works when no users exist", async (t) => {
  const { app, pool } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const startRes = await request(app).get("/auth/google?mode=signup");
  const stateCookie = extractCookie(startRes.headers["set-cookie"], "oauth_state=");
  const state = extractStateFromRedirect(startRes.headers.location);

  const callbackRes = await request(app)
    .get("/auth/google/callback")
    .query({ code: "test-code", state })
    .set("Cookie", stateCookie)
    .set("Accept", "text/html");

  assert.strictEqual(callbackRes.status, 303);
  assert.strictEqual(callbackRes.headers.location, "/dashboard");

  const userResult = await pool.query(
    "SELECT email, google_sub, auth_provider, is_paid FROM users ORDER BY id LIMIT 1"
  );
  assert.strictEqual(userResult.rowCount, 1);
  assert.strictEqual(userResult.rows[0].email, "operator@example.com");
  assert.strictEqual(userResult.rows[0].google_sub, "google-sub-123");
  assert.strictEqual(userResult.rows[0].auth_provider, "google");
  assert.strictEqual(userResult.rows[0].is_paid, false);
});

test("Google signup is blocked when the email already exists", async (t) => {
  const { app, pool } = await setupTest();
  await pool.query("INSERT INTO users (email, password_hash) VALUES ($1, $2)", [
    "operator@example.com",
    "hash",
  ]);

  t.after(async () => {
    await pool.end();
  });

  const startRes = await request(app).get("/auth/google?mode=signup");
  const stateCookie = extractCookie(startRes.headers["set-cookie"], "oauth_state=");
  const state = extractStateFromRedirect(startRes.headers.location);

  const callbackRes = await request(app)
    .get("/auth/google/callback")
    .query({ code: "test-code", state })
    .set("Cookie", stateCookie)
    .set("Accept", "text/html");

  assert.strictEqual(callbackRes.status, 303);
  assert.ok(callbackRes.headers.location.includes("/login?error="));

  const countResult = await pool.query("SELECT COUNT(*) AS count FROM users");
  assert.strictEqual(Number(countResult.rows[0].count), 1);
});

test("Google signup creates exactly one user and allows dashboard access", async (t) => {
  const { app, pool } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  const startRes = await request(app).get("/auth/google?mode=signup");
  const stateCookie = extractCookie(startRes.headers["set-cookie"], "oauth_state=");
  const state = extractStateFromRedirect(startRes.headers.location);

  const callbackRes = await request(app)
    .get("/auth/google/callback")
    .query({ code: "test-code", state })
    .set("Cookie", stateCookie)
    .set("Accept", "text/html");

  const sessionCookie = extractCookie(callbackRes.headers["set-cookie"], "session_token=");
  assert.ok(sessionCookie);

  const countResult = await pool.query("SELECT COUNT(*) AS count FROM users");
  assert.strictEqual(Number(countResult.rows[0].count), 1);

  const dashboardRes = await request(app)
    .get("/dashboard")
    .set("Cookie", sessionCookie)
    .set("Accept", "text/html");

  assert.strictEqual(dashboardRes.status, 200);
});
