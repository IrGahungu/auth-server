// c:/gahungu-pharmacy-current/auth-server/db.js
const { Pool } = require("pg");

let pool;

function getPool() {
  if (!pool) {
    console.log("Attempting to create new database connection pool...");

    const connectionString = process.env.SUPABASE_DB_URL;
    if (!connectionString) {
      console.error("FATAL: SUPABASE_DB_URL environment variable is not set.");
      // This will cause the function to fail loudly if the env var is missing.
      throw new Error("Database connection string is missing.");
    }

    pool = new Pool({
      connectionString: connectionString,
      ssl: {
        rejectUnauthorized: false,
      },
      // Important: Timeout if a connection cannot be established
      connectionTimeoutMillis: 5000, // 5 seconds
      // Optional: Timeout for idle clients in the pool
      idleTimeoutMillis: 30000,
    });
    console.log("Database connection pool created successfully.");
  }
  return pool;
}

module.exports = { getPool };
