require("dotenv").config();
const { createPool } = require("../src/db");

async function checkStatus() {
  const pool = await createPool();
  try {
    const res = await pool.query(
      "SELECT id, email, is_paid FROM users WHERE id = 2 OR email = 'khansayeem03@gmail.com'"
    );
    if (res.rows.length > 0) {
      console.log("Users found:", res.rows);
    } else {
      console.log("No matching users found.");
    }
  } catch (err) {
    console.error("Error querying database:", err);
  } finally {
    await pool.end();
  }
}

checkStatus();
