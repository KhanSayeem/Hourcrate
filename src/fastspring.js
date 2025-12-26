const crypto = require("crypto");

/**
 * Verifies the FastSpring webhook signature.
 * FastSpring sends the signature in the 'X-FS-Signature' header.
 * The signature is an HMAC-SHA256 hash of the request body.
 */
function verifySignature(body, signature, secret) {
  if (!body || !signature || !secret) return false;
  
  // FastSpring sends the raw body for signature verification.
  // Ensure 'body' passed here is a string (req.rawBody or JSON.stringify if exact match).
  // Note: If using express.json(), getting the exact raw body can be tricky.
  // It is often safer to compute the hash on the incoming raw stream or ensure strict JSON serialization.
  // For this implementation, we'll assume 'body' is the raw string.
  
  const hmac = crypto.createHmac("sha256", secret);
  const digest = hmac.update(body).digest("base64");
  return signature === digest;
}

/**
 * Processes the FastSpring webhook events.
 */
async function processWebhook(pool, events) {
  if (!Array.isArray(events)) return;

  for (const event of events) {
    if (event.type === "order.completed") {
      await handleOrderCompleted(pool, event.data);
    }
  }
}

async function handleOrderCompleted(pool, data) {
  console.log("[FastSpring] Order Data:", JSON.stringify(data, null, 2));
  
  const tags = data.tags || {};
  const customUserId = tags.userId;
  const email = data.customer?.email;

  if (customUserId) {
    console.log(`[FastSpring] Processing payment for userId: ${customUserId}`);
    const res = await pool.query("UPDATE users SET is_paid = true WHERE id = $1 RETURNING id", [customUserId]);
    if (res.rowCount === 0) {
       console.error(`[FastSpring] ERROR: User ID ${customUserId} found in tags but not in database.`);
    } else {
       console.log(`[FastSpring] SUCCESS: User ID ${customUserId} marked as paid.`);
    }
    return;
  } 
  
  if (email) {
    console.log(`[FastSpring] No userId tag found. Fallback to email: ${email}`);
    const res = await pool.query("UPDATE users SET is_paid = true WHERE email = $1 RETURNING id", [email]);
    if (res.rowCount === 0) {
      console.error(`[FastSpring] ERROR: Payment received for ${email}, but no user with this email exists in the database.`);
    } else {
      console.log(`[FastSpring] SUCCESS: User with email ${email} marked as paid.`);
    }
  } else {
    console.warn("[FastSpring] No userId tag or email found in order data.");
  }
}

module.exports = {
  verifySignature,
  processWebhook,
};
