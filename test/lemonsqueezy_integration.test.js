const test = require("node:test");
const assert = require("assert");
const request = require("supertest");
const crypto = require("crypto");
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
  const userId = await seedUser(pool);
  const app = createApp(pool);
  return { pool, app, userId };
}

async function seedUser(pool) {
  const email = "payer@example.com";
  const result = await pool.query(
    "INSERT INTO users (email, password_hash, is_paid) VALUES ($1, $2, false) RETURNING id",
    [email, "hash"]
  );
  return result.rows[0].id;
}

test("Lemon Squeezy webhook updates user to paid status", async (t) => {
  process.env.LEMONSQUEEZY_WEBHOOK_SECRET = "test_secret";
  const { app, pool, userId } = await setupTest();
  t.after(async () => {
    await pool.end();
    delete process.env.LEMONSQUEEZY_WEBHOOK_SECRET;
  });

  const payload = JSON.stringify({
    meta: {
      event_name: "order_created",
      custom_data: {
        user_id: userId,
      },
    },
    data: {
      attributes: {
        user_email: "payer@example.com",
      },
    },
  });

  const signature = crypto
    .createHmac("sha256", "test_secret")
    .update(payload)
    .digest("hex");

  const res = await request(app)
    .post("/api/webhooks/lemonsqueezy")
    .set("Content-Type", "application/json")
    .set("X-Signature", signature)
    .send(payload);

  assert.strictEqual(res.status, 200);

  const userResult = await pool.query("SELECT is_paid FROM users WHERE id = $1", [
    userId,
  ]);
  assert.strictEqual(userResult.rows[0].is_paid, true);
});

test("Lemon Squeezy webhook rejects invalid signature", async (t) => {
  process.env.LEMONSQUEEZY_WEBHOOK_SECRET = "test_secret";
  const { app, pool } = await setupTest();
  t.after(async () => {
    await pool.end();
    delete process.env.LEMONSQUEEZY_WEBHOOK_SECRET;
  });

  const payload = JSON.stringify({ meta: { event_name: "order_created" } });
  const signature = "invalid_signature";

  const res = await request(app)
    .post("/api/webhooks/lemonsqueezy")
    .set("Content-Type", "application/json")
    .set("X-Signature", signature)
    .send(payload);

  assert.strictEqual(res.status, 401);
});

test("/upgrade redirects to Lemon Squeezy checkout with custom data", async (t) => {
  process.env.LEMONSQUEEZY_CHECKOUT_URL = "https://store.lemonsqueezy.com/checkout/buy/variant_123";
  
  const { app, pool, userId } = await setupTest();
  
  // Create a session for the user
  const token = "valid_session_token";
  await pool.query(
    "INSERT INTO sessions (user_id, session_token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')",
    [userId, token]
  );

  t.after(async () => {
    await pool.end();
    delete process.env.LEMONSQUEEZY_CHECKOUT_URL;
  });

  const res = await request(app)
    .get("/upgrade")
    .set("Cookie", `session_token=${token}`);

  assert.strictEqual(res.status, 302);
  const location = new URL(res.headers.location);
  assert.strictEqual(location.hostname, "store.lemonsqueezy.com");
  assert.strictEqual(location.pathname, "/checkout/buy/variant_123");
  assert.strictEqual(location.searchParams.get("checkout[custom][user_id]"), String(userId));
  assert.strictEqual(location.searchParams.get("checkout[email]"), "payer@example.com");
});
