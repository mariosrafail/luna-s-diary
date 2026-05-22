const crypto = require("crypto");
const { neon } = require("@neondatabase/serverless");

const DATABASE_URL = process.env.DATABASE_URL;
const AUTH_SECRET = process.env.LUNA_AUTH_SECRET;
const SESSION_DAYS = 30;

let initialized = false;

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    },
    body: JSON.stringify(body)
  };
}

function requireConfig() {
  if (!DATABASE_URL) throw new Error("Missing DATABASE_URL");
  if (!AUTH_SECRET) throw new Error("Missing LUNA_AUTH_SECRET");
}

function getSql() {
  requireConfig();
  return neon(DATABASE_URL);
}

async function init(sql) {
  if (initialized) return;
  await sql`
    create table if not exists luna_users (
      id text primary key,
      username text not null,
      username_norm text not null unique,
      salt text not null,
      auth_hash text not null,
      created_at timestamptz not null default now()
    )
  `;
  await sql`
    create table if not exists luna_sessions (
      token_hash text primary key,
      user_id text not null references luna_users(id) on delete cascade,
      expires_at timestamptz not null,
      created_at timestamptz not null default now()
    )
  `;
  await sql`
    create table if not exists luna_entries (
      user_id text primary key references luna_users(id) on delete cascade,
      payload jsonb not null,
      updated_at timestamptz not null default now()
    )
  `;
  initialized = true;
}

function normalizeUsername(username) {
  return String(username || "").trim().toLowerCase();
}

function hashAuth(authHash, salt) {
  return crypto
    .createHmac("sha256", AUTH_SECRET)
    .update(`${salt}:${authHash}`)
    .digest("hex");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ""), "hex");
  const right = Buffer.from(String(b || ""), "hex");
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

async function createSession(sql, userId) {
  const token = crypto.randomBytes(32).toString("base64url");
  const tokenHash = hashToken(token);
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  await sql`
    insert into luna_sessions (token_hash, user_id, expires_at)
    values (${tokenHash}, ${userId}, ${expiresAt})
  `;
  return token;
}

async function currentUser(sql, event) {
  const header = event.headers.authorization || event.headers.Authorization || "";
  const token = header.replace(/^Bearer\s+/i, "").trim();
  if (!token) return null;
  const rows = await sql`
    select user_id
    from luna_sessions
    where token_hash = ${hashToken(token)}
      and expires_at > now()
    limit 1
  `;
  return rows[0] || null;
}

function validateEncryptedPayload(payload) {
  return payload
    && payload.version === 1
    && typeof payload.iv === "string"
    && typeof payload.data === "string";
}

exports.handler = async event => {
  if (event.httpMethod !== "POST") {
    return json(405, { ok: false, error: "Method not allowed" });
  }

  try {
    const sql = getSql();
    await init(sql);

    const body = JSON.parse(event.body || "{}");
    const action = String(body.action || "");

    if (action === "salt") {
      const usernameNorm = normalizeUsername(body.username);
      const rows = await sql`select salt from luna_users where username_norm = ${usernameNorm} limit 1`;
      return json(200, { ok: true, exists: Boolean(rows[0]), salt: rows[0]?.salt || "" });
    }

    if (action === "signup") {
      const username = String(body.username || "").trim();
      const usernameNorm = normalizeUsername(username);
      if (username.length < 2 || username.length > 64) {
        return json(400, { ok: false, error: "Username must be 2-64 characters" });
      }
      if (!body.salt || !body.authHash) {
        return json(400, { ok: false, error: "Missing auth data" });
      }

      const userId = crypto.randomUUID();
      const serverHash = hashAuth(body.authHash, body.salt);
      await sql`
        insert into luna_users (id, username, username_norm, salt, auth_hash)
        values (${userId}, ${username}, ${usernameNorm}, ${body.salt}, ${serverHash})
      `;
      const token = await createSession(sql, userId);
      return json(200, { ok: true, token });
    }

    if (action === "login") {
      const usernameNorm = normalizeUsername(body.username);
      const rows = await sql`select id, salt, auth_hash from luna_users where username_norm = ${usernameNorm} limit 1`;
      const user = rows[0];
      if (!user || !body.authHash || !safeEqual(hashAuth(body.authHash, user.salt), user.auth_hash)) {
        return json(401, { ok: false, error: "Wrong username or password" });
      }
      const token = await createSession(sql, user.id);
      return json(200, { ok: true, token });
    }

    const user = await currentUser(sql, event);
    if (!user) return json(401, { ok: false, error: "Unauthorized" });

    if (action === "load") {
      const rows = await sql`select payload, updated_at from luna_entries where user_id = ${user.user_id} limit 1`;
      return json(200, { ok: true, payload: rows[0]?.payload || null, updatedAt: rows[0]?.updated_at || null });
    }

    if (action === "save") {
      if (!validateEncryptedPayload(body.payload)) {
        return json(400, { ok: false, error: "Invalid encrypted payload" });
      }
      await sql`
        insert into luna_entries (user_id, payload, updated_at)
        values (${user.user_id}, ${JSON.stringify(body.payload)}::jsonb, now())
        on conflict (user_id)
        do update set payload = excluded.payload, updated_at = now()
      `;
      return json(200, { ok: true, syncedAt: new Date().toISOString() });
    }

    return json(400, { ok: false, error: "Unknown action" });
  } catch (error) {
    return json(500, { ok: false, error: error.message || "Server error" });
  }
};
