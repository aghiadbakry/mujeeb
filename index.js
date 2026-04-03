import "dotenv/config";
import bcrypt from "bcryptjs";
import cors from "cors";
import express from "express";
import jwt from "jsonwebtoken";
import pg from "pg";
import crypto from "crypto";

const { Pool } = pg;

const port = Number(process.env.PORT || 3000);
const jwtSecret = process.env.JWT_SECRET || "dev-only-change-me";
const nodeEnv = process.env.NODE_ENV || "development";
const isProduction = nodeEnv === "production";
/** Include debugVerificationCode / debugResetToken when not production or DEBUG_API=1 */
const showDebugApi =
  !isProduction || process.env.DEBUG_API === "1" || process.env.DEBUG_API === "true";

/** If the app is mounted under a subpath (e.g. https://domain.com/api), set BASE_PATH=/api */
const basePath = (process.env.BASE_PATH || "").replace(/\/$/, "") || "";

function buildPoolConfig() {
  const url = process.env.DATABASE_URL;
  if (!url) return { connectionString: undefined };
  const urlWantsSsl = /sslmode=require|ssl=true/i.test(url);
  const useSsl =
    process.env.DATABASE_SSL === "true" ||
    process.env.DATABASE_SSL === "1" ||
    urlWantsSsl;
  return {
    connectionString: url,
    ssl: useSsl
      ? {
          rejectUnauthorized:
            process.env.DATABASE_SSL_REJECT_UNAUTHORIZED === "true",
        }
      : false,
    max: Number(process.env.PG_POOL_MAX || 10),
    idleTimeoutMillis: Number(process.env.PG_IDLE_TIMEOUT_MS || 30000),
    connectionTimeoutMillis: Number(process.env.PG_CONNECTION_TIMEOUT_MS || 10000),
  };
}

if (isProduction) {
  if (!process.env.DATABASE_URL) {
    console.error("FATAL: DATABASE_URL is required in production");
    process.exit(1);
  }
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 16) {
    console.error("FATAL: JWT_SECRET must be set (at least 16 characters) in production");
    process.exit(1);
  }
}

const pool = new Pool(buildPoolConfig());

const corsOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",").map((s) => s.trim()).filter(Boolean)
  : null;

const app = express();
app.set("trust proxy", 1);
app.use(
  cors({
    origin: corsOrigins && corsOrigins.length ? corsOrigins : true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Authorization", "Content-Type"],
    credentials: true,
  })
);
app.use(express.json({ limit: "512kb" }));

const router = express.Router();

function signToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      emailVerified: user.email_verified,
    },
    jwtSecret,
    { expiresIn: "30d" }
  );
}

async function getUserById(id) {
  const { rows } = await pool.query(
    `SELECT id, email, display_name, email_verified FROM users WHERE id = $1`,
    [id]
  );
  return rows[0] || null;
}

function mapUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    emailVerified: row.email_verified,
  };
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing token" });
  }
  try {
    const payload = jwt.verify(h.slice(7), jwtSecret);
    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

router.get("/health", (_req, res) => {
  res.json({ ok: true, env: nodeEnv });
});

router.post("/auth/register", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    const password = String(req.body.password || "");
    const displayName = String(req.body.displayName || "").trim();
    if (!email || !password || password.length < 6) {
      return res.status(400).json({ error: "Invalid email or password" });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const code = String(Math.floor(1000 + Math.random() * 9000));
    const codeHash = await bcrypt.hash(code, 10);
    const expires = new Date(Date.now() + 15 * 60 * 1000);

    const { rows } = await pool.query(
      `INSERT INTO users (email, password_hash, display_name, email_verified, verification_code_hash, verification_expires_at)
       VALUES ($1, $2, $3, FALSE, $4, $5)
       RETURNING id, email, display_name, email_verified`,
      [email, passwordHash, displayName, codeHash, expires]
    );
    const accessToken = signToken({ ...rows[0], email_verified: false });
    const body = { accessToken, user: mapUser(rows[0]) };
    if (showDebugApi) body.debugVerificationCode = code;
    res.status(201).json(body);
  } catch (e) {
    if (e.code === "23505") {
      return res.status(409).json({ error: "Email already registered" });
    }
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    const password = String(req.body.password || "");
    const { rows } = await pool.query(
      `SELECT id, email, display_name, email_verified, password_hash FROM users WHERE email = $1`,
      [email]
    );
    const row = rows[0];
    if (!row || !(await bcrypt.compare(password, row.password_hash))) {
      return res.status(401).json({ error: "Invalid email or password" });
    }
    const accessToken = signToken(row);
    res.json({ accessToken, user: mapUser(row) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

router.get("/auth/me", authMiddleware, async (req, res) => {
  try {
    const user = await getUserById(req.userId);
    if (!user) return res.status(404).json({ error: "Not found" });
    res.json({ user: mapUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/auth/verify-email", authMiddleware, async (req, res) => {
  try {
    const code = String(req.body.code || "").trim();
    if (!/^\d{4}$/.test(code)) {
      return res.status(400).json({ error: "Enter the 4-digit code" });
    }
    const { rows } = await pool.query(
      `SELECT id, email_verified, verification_code_hash, verification_expires_at FROM users WHERE id = $1`,
      [req.userId]
    );
    const row = rows[0];
    if (!row) return res.status(404).json({ error: "Not found" });
    if (row.email_verified) {
      const u = await getUserById(req.userId);
      return res.json({
        user: mapUser(u),
        accessToken: signToken({ ...u, email_verified: true }),
      });
    }
    if (!row.verification_code_hash || !row.verification_expires_at) {
      return res.status(400).json({ error: "No verification pending" });
    }
    if (new Date(row.verification_expires_at) < new Date()) {
      return res.status(400).json({ error: "Code expired. Resend a new code." });
    }
    const ok = await bcrypt.compare(code, row.verification_code_hash);
    if (!ok) return res.status(400).json({ error: "Invalid code" });

    await pool.query(
      `UPDATE users SET email_verified = TRUE, verification_code_hash = NULL, verification_expires_at = NULL WHERE id = $1`,
      [req.userId]
    );
    const user = await getUserById(req.userId);
    const accessToken = signToken({ ...user, email_verified: true });
    res.json({ user: mapUser(user), accessToken });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/auth/resend-verification", authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, email_verified FROM users WHERE id = $1`,
      [req.userId]
    );
    const row = rows[0];
    if (!row) return res.status(404).json({ error: "Not found" });
    if (row.email_verified) {
      return res.json({ ok: true });
    }
    const code = String(Math.floor(1000 + Math.random() * 9000));
    const codeHash = await bcrypt.hash(code, 10);
    const expires = new Date(Date.now() + 15 * 60 * 1000);
    await pool.query(
      `UPDATE users SET verification_code_hash = $1, verification_expires_at = $2 WHERE id = $3`,
      [codeHash, expires, req.userId]
    );
    const body = { ok: true };
    if (showDebugApi) body.debugVerificationCode = code;
    res.json(body);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/auth/forgot-password", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    const { rows } = await pool.query(`SELECT id FROM users WHERE email = $1`, [email]);
    const row = rows[0];
    const generic = {
      ok: true,
      message: "If an account exists, you can reset using the link or code.",
    };
    if (!row) {
      return res.json(generic);
    }
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = await bcrypt.hash(rawToken, 10);
    const expires = new Date(Date.now() + 60 * 60 * 1000);
    await pool.query(`DELETE FROM password_reset_tokens WHERE user_id = $1`, [row.id]);
    await pool.query(
      `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
      [row.id, tokenHash, expires]
    );
    if (showDebugApi) {
      return res.json({ ...generic, debugResetToken: rawToken });
    }
    res.json(generic);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

router.post("/auth/reset-password", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    const token = String(req.body.token || "").trim();
    const newPassword = String(req.body.newPassword || "");
    if (!email || !token || newPassword.length < 6) {
      return res.status(400).json({ error: "Invalid input" });
    }
    const { rows: users } = await pool.query(
      `SELECT id FROM users WHERE email = $1`,
      [email]
    );
    if (!users[0]) return res.status(400).json({ error: "Invalid or expired token" });
    const userId = users[0].id;
    const { rows: tokens } = await pool.query(
      `SELECT id, token_hash, expires_at FROM password_reset_tokens WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [userId]
    );
    const t = tokens[0];
    if (!t || new Date(t.expires_at) < new Date()) {
      return res.status(400).json({ error: "Invalid or expired token" });
    }
    const match = await bcrypt.compare(token, t.token_hash);
    if (!match) return res.status(400).json({ error: "Invalid or expired token" });

    const passwordHash = await bcrypt.hash(newPassword, 10);
    await pool.query(`UPDATE users SET password_hash = $1 WHERE id = $2`, [passwordHash, userId]);
    await pool.query(`DELETE FROM password_reset_tokens WHERE user_id = $1`, [userId]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.use(basePath || "/", router);

const host = process.env.HOST || "0.0.0.0";
const server = app.listen(port, host, () => {
  console.log(`API listening on http://${host}:${port}${basePath || ""}`);
});

function shutdown(signal) {
  console.log(`${signal} received, closing server`);
  server.close(() => {
    pool.end(() => process.exit(0));
  });
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
