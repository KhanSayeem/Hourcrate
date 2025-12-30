const crypto = require("crypto");

/**
 * Verifies the Lemon Squeezy webhook signature.
 * Lemon Squeezy sends the signature in the 'X-Signature' header.
 * The signature is an HMAC-SHA256 hash of the request body.
 */
function verifySignature(rawBody, signature, secret) {
  if (!rawBody || !signature || !secret) return false;

  const hmac = crypto.createHmac("sha256", secret);
  const digest = hmac.update(rawBody).digest("hex");
  const signatureBuffer = Buffer.from(signature, 'utf8');
  const digestBuffer = Buffer.from(digest, 'utf8');

  if (signatureBuffer.length !== digestBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(signatureBuffer, digestBuffer);
}

/**
 * Processes the Lemon Squeezy webhook events.
 */
async function processWebhook(pool, body) {
  const eventName = body.meta.event_name;
  const customData = body.meta.custom_data || {};
  const data = body.data;

  if (eventName === "order_created") {
     await handleOrderCreated(pool, data, customData);
  }
}

async function handleOrderCreated(pool, data, customData) {
  console.log("[Lemon Squeezy] Order Data:", JSON.stringify(data, null, 2));

  // In Lemon Squeezy, custom data passed during checkout is available in meta.custom_data
  const customUserId = customData.user_id; 
  const email = data.attributes.user_email;

  if (customUserId) {
    console.log(`[Lemon Squeezy] Processing payment for userId: ${customUserId}`);
    const res = await pool.query("UPDATE users SET is_paid = true WHERE id = $1 RETURNING id", [customUserId]);
    if (res.rowCount === 0) {
       console.error(`[Lemon Squeezy] ERROR: User ID ${customUserId} found in custom_data but not in database.`);
    } else {
       console.log(`[Lemon Squeezy] SUCCESS: User ID ${customUserId} marked as paid.`);
    }
    return;
  }

  if (email) {
    console.log(`[Lemon Squeezy] No user_id custom data found. Fallback to email: ${email}`);
    const res = await pool.query("UPDATE users SET is_paid = true WHERE email = $1 RETURNING id", [email]);
    if (res.rowCount === 0) {
      console.error(`[Lemon Squeezy] ERROR: Payment received for ${email}, but no user with this email exists in the database.`);
    } else {
      console.log(`[Lemon Squeezy] SUCCESS: User with email ${email} marked as paid.`);
    }
  } else {
    console.warn("[Lemon Squeezy] No user_id or email found in order data.");
  }
}

module.exports = {
  verifySignature,
  processWebhook,
};
