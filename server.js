// server.js
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { getPool } = require("./db"); // 👈 Import from our new db.js file

const app = express();
const cors = require("cors");
app.use(cors());
app.use(bodyParser.json());

// -----------------------------
// Config
// -----------------------------
const pool = getPool(); // 👈 Get the shared pool instance
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";
const SALT_ROUNDS = 10;

// -----------------------------
// REGISTER
// -----------------------------
// -----------------------------
// REGISTER
// -----------------------------
app.post("/register", async (req, res) => {
  const {
    fullname,
    password,
    whatsapp_number,
    gender,
    country,
    secret_question,
    secret_answer,
  } = req.body;

  // Validate required fields
  if (!fullname || !password || !whatsapp_number || !gender || !country || !secret_question || !secret_answer) {
    return res.status(400).json({ error: "All fields are required, including the secret question." });
  }

  // Password validation: ≥8 chars, letters & numbers
  const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({
      error: "Password must be at least 8 characters and include letters and numbers",
    });
  }

  try {
    // Check if WhatsApp number is unique
    const existing = await pool.query(
      "SELECT id FROM users WHERE whatsapp_number=$1",
      [whatsapp_number]
    );
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: "WhatsApp number already registered" });
    }

    // Hash the password
    const hashed = await bcrypt.hash(password, SALT_ROUNDS);

    // Insert the new user with default wallet balance
    const result = await pool.query(
      `INSERT INTO users 
         (fullname, password_hash, whatsapp_number, gender, country, secret_question, secret_answer, wallet_balance)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, fullname, whatsapp_number, gender, country, created_at, wallet_balance`, // Set default wallet_balance to 1000000
      [fullname, hashed, whatsapp_number, gender, country, secret_question, secret_answer, 1000000]
    );

    // Respond with the created user
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});


// -----------------------------
// CHECK WHATSAPP
// -----------------------------
app.post("/check-whatsapp", async (req, res) => {
  const { whatsapp_number } = req.body;
  if (!whatsapp_number) return res.status(400).json({ error: "WhatsApp number required" });

  try {
    const result = await pool.query("SELECT id FROM users WHERE whatsapp_number=$1", [whatsapp_number]);
    res.json({ exists: result.rows.length > 0 });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ Health check route
app.get("/", (_req, res) => {
  res.send("Auth server is running! Healthy and ready.");
});

// -----------------------------
// LOGIN
// -----------------------------
app.post("/login", async (req, res) => {
  console.log("Login request body:", req.body); // 👈 Debug log
  const { whatsapp_number, password } = req.body;

  if (!whatsapp_number || !password) {
    console.log("Missing one of:", { whatsapp_number, password }); // 👈 Debug log
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const result = await pool.query("SELECT * FROM users WHERE whatsapp_number=$1", [whatsapp_number]);
    console.log("DB result:", result.rows); // 👈 Debug log
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user.id, fullname: user.fullname, role: user.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );
    res.json({ token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// -----------------------------
// Middleware → Auth
// -----------------------------
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "No token" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { id: decoded.userId, fullname: decoded.fullname, role: decoded.role };
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
};
const adminOnly = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access denied. Admins only." });
  }
  next();
};


// -----------------------------
// GET CURRENT USER (/me)
// -----------------------------
app.get("/me", authMiddleware, async (req, res) => {
  try {
    // TEMPORARY: bypass RLS for testing by using a regular query
    const result = await pool.query(
      `SELECT id, fullname, whatsapp_number, gender, country, created_at, role, wallet_balance
       FROM users
       WHERE id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0)
      return res.status(404).json({ error: "User not found" });

    console.log("ME query result (for debugging):", result.rows[0]);

    res.json(result.rows[0]);
  } catch (err) {
    console.error("ME error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


// -----------------------------
// UPDATE USER PROFILE (/update-profile)
// -----------------------------
app.put("/update-profile", authMiddleware, async (req, res) => {
  const { fullname, whatsapp_number, gender, country } = req.body;
  if (!fullname && !whatsapp_number && !gender && !country) {
    return res.status(400).json({ error: "Provide at least one field to update." });
  }

  try {
    const updates = [];
    const values = [];
    let index = 1;

    if (fullname) {
      updates.push(`fullname = $${index++}`);
      values.push(fullname);
    }

    if (whatsapp_number) {
      // Check uniqueness
      const existing = await pool.query(
        "SELECT id FROM users WHERE whatsapp_number=$1 AND id <> $2",
        [whatsapp_number, req.user.id]
      );
      if (existing.rows.length > 0) {
        return res.status(400).json({ error: "WhatsApp number already registered" });
      }
      updates.push(`whatsapp_number = $${index++}`);
      values.push(whatsapp_number);

      // ✅ Reset verification if number changes
      updates.push(`is_verified = $${index++}`);
      values.push(false);
    }

    if (gender) {
      updates.push(`gender = $${index++}`);
      values.push(gender);
    }
    if (country) {
      updates.push(`country = $${index++}`);
      values.push(country);
    }

    values.push(req.user.id);

    const result = await pool.query(
      `UPDATE users SET ${updates.join(", ")} WHERE id=$${index} RETURNING id, fullname, whatsapp_number, gender, country, is_verified`,
      values
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Update profile error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


// -----------------------------
// VERIFY CREDENTIALS
// -----------------------------
app.post("/verify-credentials", async (req, res) => {
  const { fullname, whatsapp_number, secret_answer } = req.body;

  if (!fullname || !whatsapp_number || !secret_answer) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const result = await pool.query(
      "SELECT id, fullname, secret_answer FROM users WHERE whatsapp_number=$1",
      [whatsapp_number]
    );

    const user = result.rows[0];
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Compare fullname (case-insensitive) and secret_answer (case-insensitive)
    if (
      user.fullname.toLowerCase() !== fullname.toLowerCase() ||
      user.secret_answer.toLowerCase() !== secret_answer.toLowerCase()
    ) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // ✅ Verified
    res.json({ success: true, whatsapp_number });
  } catch (err) {
    console.error("Verify credentials error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


// -----------------------------
// RESET PASSWORD
// -----------------------------
app.post("/reset-password", async (req, res) => {
  const { whatsapp_number, new_password } = req.body;

  if (!whatsapp_number || !new_password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  // Validate password
  const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
  if (!passwordRegex.test(new_password)) {
    return res.status(400).json({
      error: "Password must be at least 8 characters and include letters and numbers",
    });
  }

  try {
    const hashed = await bcrypt.hash(new_password, SALT_ROUNDS);

    const result = await pool.query(
      "UPDATE users SET password_hash=$1 WHERE whatsapp_number=$2 RETURNING id, fullname, whatsapp_number",
      [hashed, whatsapp_number]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// -----------------------------
// CHECK VERIFICATION STATUS
// -----------------------------
app.post("/auth/check-verification", async (req, res) => {
  const { phone } = req.body;
  if (!phone) {
    return res.status(400).json({ error: "WhatsApp number required" });
  }

  try {
    const result = await pool.query(
      "SELECT is_verified FROM users WHERE whatsapp_number=$1",
      [phone]
    );

    if (result.rows.length === 0) {
      return res.json({ verified: false });
    }

    res.json({ verified: result.rows[0].is_verified });
  } catch (err) {
    console.error("Check verification error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// -----------------------------
// ADMIN → VERIFY USER
// -----------------------------
app.put("/admin/verify-user", async (req, res) => {
  const { whatsapp_number } = req.body;
  if (!whatsapp_number) {
    return res.status(400).json({ error: "WhatsApp number required" });
  }

  try {
    const result = await pool.query(
      "UPDATE users SET is_verified=true WHERE whatsapp_number=$1 RETURNING id, fullname, whatsapp_number, is_verified",
      [whatsapp_number]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error("Admin verify user error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// -----------------------------
// ADMIN → UPDATE USER (role, verification, wallet)
// -----------------------------
app.put("/admin/users", authMiddleware, async (req, res) => {
  const { id, role, is_verified, wallet_balance } = req.body;

  if (!id) {
    return res.status(400).json({ error: "User ID is required" });
  }

  try {
    // ✅ Ensure the requester is an admin
    const resultAdmin = await pool.query("SELECT role FROM users WHERE id=$1", [req.user.id]);
    if (resultAdmin.rows.length === 0 || resultAdmin.rows[0].role !== "admin") {
      return res.status(403).json({ error: "Access denied. Admins only." });
    }

    // Build dynamic update query
    const fields = [];
    const values = [];
    let index = 1;

    if (role) {
      fields.push(`role=$${index++}`);
      values.push(role);
    }

    if (typeof is_verified === "boolean") {
      fields.push(`is_verified=$${index++}`);
      values.push(is_verified);
    }

    if (wallet_balance !== undefined) {
      fields.push(`wallet_balance=$${index++}`);
      values.push(wallet_balance);
    }

    if (fields.length === 0) {
      return res.status(400).json({ error: "No fields provided for update" });
    }

    values.push(id);
    const query = `UPDATE users SET ${fields.join(", ")} WHERE id=$${index} RETURNING id, fullname, role, is_verified, wallet_balance`;

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Admin update user error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


// -----------------------------
// ADMIN → UPDATE USER BALANCE
// -----------------------------
// -----------------------------
// ADMIN → UPDATE USER BALANCE
// -----------------------------
app.put("/admin/update-balance", authMiddleware, async (req, res) => {
  const { whatsapp_number, new_balance } = req.body;

  if (!whatsapp_number || new_balance === undefined) {
    return res.status(400).json({ error: "WhatsApp number and new balance are required" });
  }

  try {
    // ✅ Check if requester is admin
    const resultAdmin = await pool.query(
      "SELECT role FROM users WHERE id=$1",
      [req.user.id]
    );
    if (resultAdmin.rows.length === 0 || resultAdmin.rows[0].role !== "admin") {
      return res.status(403).json({ error: "Access denied. Admins only." });
    }

    // ✅ Update target user's balance
    const result = await pool.query(
      "UPDATE users SET wallet_balance=$1 WHERE whatsapp_number=$2 RETURNING id, fullname, whatsapp_number, wallet_balance",
      [new_balance, whatsapp_number]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      success: true,
      message: "Wallet balance updated successfully",
      user: result.rows[0],
    });
  } catch (err) {
    console.error("Admin update balance error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// -----------------------------
// CREATE ORDER
// -----------------------------
app.post("/orders", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const { items, subtotal, service_fee, total_amount, payment_method } = req.body;

    // Validate input
    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "No items in order" });
    }

    if (!subtotal || !total_amount || !payment_method) {
      return res.status(400).json({ error: "Missing order details" });
    }

    // Get user wallet
    const userRes = await pool.query("SELECT wallet_balance FROM users WHERE id=$1", [req.user.id]);
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const wallet_balance = parseFloat(userRes.rows[0].wallet_balance);
    const total = parseFloat(total_amount);

    // Check balance
    if (wallet_balance < total) {
      return res.status(400).json({ error: "Insufficient wallet balance" });
    }

    // Start transaction
    await client.query("BEGIN");

    // Deduct from wallet
    await client.query("UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2", [total, req.user.id]);

    // Insert into orders
    const orderRes = await client.query(
      `INSERT INTO orders (user_id, subtotal, service_fee, total_amount, payment_method)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [req.user.id, subtotal, service_fee, total_amount, payment_method]
    );

    const orderId = orderRes.rows[0].id;

    // Insert order items
    for (const item of items) {
      await client.query(
        `INSERT INTO order_items (order_id, medicine_id, quantity, price)
         VALUES ($1, $2, $3, $4)`,
        [orderId, item.medicine_id, item.quantity, item.price]
      );
    }

    // Commit transaction
    await client.query("COMMIT");

    res.json({ success: true, order_id: orderId, message: "Order created successfully" });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Create order error:", err);
    res.status(500).json({ error: "Server error while creating order" });
  } finally {
    client.release();
  }
});

// -----------------------------
// GET USER ORDERS
// -----------------------------
app.get("/orders", authMiddleware, async (req, res) => {
  try {
    const ordersResult = await pool.query(
      `SELECT
          o.id, o.subtotal, o.service_fee, o.total_amount, o.status, o.created_at,
          COALESCE(
            (
              SELECT json_agg(
                json_build_object(
                  'id', COALESCE(i.id::text, gen_random_uuid()::text),
                  'quantity', i.quantity,
                  'price', i.price,
                  'medicine_id', COALESCE(m.id::text, ''),
                  'medicine_name', COALESCE(m.name, 'Unknown'),
                  'medicine_image_url', COALESCE(m.image, '')
                )
              )
              FROM order_items i
              LEFT JOIN medicines m ON i.medicine_id = m.id
              WHERE i.order_id = o.id
            ),
            '[]'::json
          ) AS items
        FROM orders o
        WHERE o.user_id = $1
        ORDER BY o.created_at DESC`,
      [req.user.id]
    );

    res.json(ordersResult.rows);
  } catch (err) {
    console.error("Get orders error:", err);
    res.status(500).json({ error: "Server error while fetching orders" });
  }
});

// -----------------------------
// GET SINGLE ORDER
// -----------------------------
app.get("/orders/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const orderResult = await pool.query(
      `SELECT
          o.id, o.subtotal, o.service_fee, o.total_amount, o.status, o.created_at,
          COALESCE(
            (SELECT json_agg(
              json_build_object(
                'id', i.id,
                'quantity', i.quantity,
                'price', i.price,
                'medicine_id', m.id,
                'medicine_name', m.name,
                'medicine_image_url', m.image
              )
            )
            FROM order_items i
            LEFT JOIN medicines m ON i.medicine_id = m.id
            WHERE i.order_id = o.id),
            '[]'::json
          ) AS items
        FROM orders o
        WHERE o.id = $1 AND o.user_id = $2`,
      [id, req.user.id]
    );

    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: "Order not found or access denied" });
    }

    res.json(orderResult.rows[0]);
  } catch (err) {
    console.error("Get single order error:", err);
    res.status(500).json({ error: "Server error while fetching order" });
  }
});

// -----------------------------
// ADMIN → GET ALL ORDERS
// -----------------------------
app.get("/admin/orders", authMiddleware, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.*, u.fullname as user_fullname
       FROM orders o
       JOIN users u ON o.user_id = u.id
       ORDER BY o.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Admin get all orders error:", err);
    res.status(500).json({ error: "Server error while fetching all orders" });
  }
});

// -----------------------------
// ADMIN → GET SINGLE ORDER
// -----------------------------
app.get("/admin/orders/:id", authMiddleware, adminOnly, async (req, res) => {
  const { id } = req.params;
  try {
    const orderResult = await pool.query(
      `SELECT
          o.id, o.subtotal, o.service_fee, o.total_amount, o.status, o.created_at, o.payment_method,
          json_build_object('fullname', u.fullname) as customer,
          COALESCE(
            (SELECT json_agg(
              json_build_object(
                'id', i.id,
                'name', p.name,
                'image', p.image,
                'quantity', i.quantity,
                'price', i.price
              )
            )
            FROM order_items i
            LEFT JOIN medicines p ON i.product_id = p.id
            WHERE i.order_id = o.id),
            '[]'::json
          ) as items
        FROM orders o
        JOIN users u ON o.user_id = u.id
        WHERE o.id = $1`,
      [id]
    );

    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: "Order not found" });
    }

    res.json(orderResult.rows[0]);
  } catch (err) {
    console.error("Admin get single order error:", err);
    res.status(500).json({ error: "Server error while fetching order" });
  }
});

// -----------------------------
// ADMIN → UPDATE ORDER STATUS
// -----------------------------
app.put("/admin/orders/:id", authMiddleware, adminOnly, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!status) {
    return res.status(400).json({ error: "Status is required" });
  }

  try {
    const result = await pool.query(
      "UPDATE orders SET status = $1 WHERE id = $2 RETURNING *",
      [status, id]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: "Order not found" });

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Admin update order status error:", err);
    res.status(500).json({ error: "Server error while updating order status" });
  }
});

// -----------------------------
// DEDUCT FOR VIEW
// -----------------------------
app.post("/wallet/deduct-for-view", authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    const { amount, reason } = req.body;
    const userId = req.user.id;

    if (!amount || typeof amount !== 'number' || amount <= 0) {
      return res.status(400).json({ error: "Invalid amount specified." });
    }

    await client.query("BEGIN");

    // 1. Get user and lock the row for update to prevent race conditions
    const userRes = await client.query("SELECT wallet_balance FROM users WHERE id = $1 FOR UPDATE", [userId]);

    if (userRes.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found." });
    }

    const user = userRes.rows[0];

    // 2. Check for sufficient balance
    if (user.wallet_balance < amount) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Insufficient wallet balance." });
    }

    // 3. Deduct amount from wallet
    const updateRes = await client.query("UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2 RETURNING wallet_balance", [amount, userId]);

    await client.query("COMMIT");

    res.json({ success: true, new_balance: updateRes.rows[0].wallet_balance });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Deduct for view error:", err);
    res.status(500).json({ error: "Server error during wallet deduction." });
  } finally {
    client.release();
  }
});

// -----------------------------
// SERVER
// -----------------------------

// This block will only run when you are NOT on Vercel
if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`🚀 Server is running locally on http://localhost:${PORT}`);
  });
}

module.exports = app;
