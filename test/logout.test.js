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

test("Logout flow", async (t) => {
  const { app, pool } = await setupTest();
  t.after(async () => {
    await pool.end();
  });

  // 1. Login to get a session cookie
  const loginRes = await request(app)
    .post("/sessions")
    .set("Accept", "text/html")
    .type("form")
    .send({ email: "test@example.com", password: "password123" });

  assert.strictEqual(loginRes.status, 303);
  const cookies = loginRes.headers["set-cookie"];
  assert.ok(cookies, "Should receive cookies on login");
  
  const sessionCookie = cookies.find(c => c.startsWith("session_token="));
  assert.ok(sessionCookie, "Should have session_token cookie");

  // 2. Verify authenticated access to dashboard
  const dashRes = await request(app)
    .get("/dashboard")
    .set("Cookie", [sessionCookie]);
  assert.strictEqual(dashRes.status, 200, "Should be able to access dashboard");

  // 3. Logout
  const logoutRes = await request(app)
    .get("/logout")
    .set("Cookie", [sessionCookie]);

  assert.strictEqual(logoutRes.status, 302, "Logout should redirect");
  assert.strictEqual(logoutRes.headers.location, "/", "Should redirect to landing page");

  // Verify cookie is cleared (look for expires/Max-Age=0 or empty value)
  const logoutCookies = logoutRes.headers["set-cookie"];
  assert.ok(logoutCookies, "Should receive set-cookie on logout");
  const clearedCookie = logoutCookies.find(c => c.startsWith("session_token="));
  // Often cleared cookies have an old date or empty value. 
  // Express res.clearCookie usually sets expires to epoch.
  assert.ok(clearedCookie.includes("Expires=") || clearedCookie.includes("Max-Age=0"), "Cookie should be expired");

  // 4. Verify session is gone from DB
  const tokenVal = sessionCookie.split(";")[0].split("=")[1];
  const dbSession = await pool.query("SELECT * FROM sessions WHERE session_token = $1", [tokenVal]);
  assert.strictEqual(dbSession.rowCount, 0, "Session should be removed from DB");

  // 5. Verify cannot access dashboard anymore
  const dashRes2 = await request(app)
    .get("/dashboard")
    .set("Accept", "text/html")
    .set("Cookie", [sessionCookie]); // Try using the old cookie
  assert.strictEqual(dashRes2.status, 302, "Should redirect to login");
  assert.strictEqual(dashRes2.headers.location, "/login");
});
