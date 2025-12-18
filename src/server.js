const { createPool } = require("./db");
const { createApp } = require("./app");

async function start() {
  const pool = await createPool({
    connectionString: process.env.DATABASE_URL,
  });
  const app = createApp(pool, {
    userTimeZone: process.env.USER_TIMEZONE || "UTC",
  });

  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`HourCrate server running on port ${port}`);
  });
}

start().catch((err) => {
  console.error("Failed to start server", err);
  process.exit(1);
});
