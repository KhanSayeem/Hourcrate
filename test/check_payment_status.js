require("dotenv").config();
const { createPool } = require("../src/db");

async function checkStatus() {
  const pool = await createPool();
  try {
    const res = await pool.query("SELECT id, email, is_paid FROM users");
    console.log("Registered Users:", res.rows);
  } catch (err) {
    console.error("Error querying database:", err);
  } finally {
    await pool.end();
  }
}

checkStatus();
