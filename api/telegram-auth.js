// Vercel Serverless Function: /api/telegram-auth
// Keep TELEGRAM_BOT_TOKEN in Vercel Environment Variables.
// The Telegram Login Widget redirects here with signed Telegram user data.

const crypto = require("crypto");

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHANNEL_ID = process.env.TELEGRAM_CHANNEL_ID || "-1003997928411";
const SITE_URL = (process.env.SITE_URL || "").replace(/\/$/, "");
const COOKIE_NAME = "k4king_tg_session";
const SESSION_TTL = 60 * 60 * 24 * 7;

function telegramHashOk(query) {
  if (!BOT_TOKEN) return false;
  const receivedHash = query.hash;
  if (!receivedHash) return false;

  const dataCheck = Object.keys(query)
    .filter(k => k !== "hash")
    .sort()
    .map(k => `${k}=${query[k]}`)
    .join("\n");

  const secret = crypto.createHash("sha256").update(BOT_TOKEN).digest();
  const expected = crypto.createHmac("sha256", secret).update(dataCheck).digest("hex");

  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(receivedHash));
  } catch {
    return false;
  }
}

function signSession(userId) {
  const payload = `${userId}.${Date.now()}`;
  const sig = crypto.createHmac("sha256", BOT_TOKEN).update(payload).digest("hex");
  return Buffer.from(`${payload}.${sig}`).toString("base64url");
}

async function isMember(userId) {
  const url = `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(CHANNEL_ID)}&user_id=${encodeURIComponent(userId)}`;
  const r = await fetch(url);
  const data = await r.json();
  if (!data.ok) throw new Error(data.description || "Telegram membership check failed");
  const status = data.result?.status;
  return ["creator", "administrator", "member"].includes(status) ||
         (status === "restricted" && data.result?.is_member === true);
}

module.exports = async (req, res) => {
  if (req.method !== "GET") return res.status(405).send("Method Not Allowed");
  if (!BOT_TOKEN) return res.status(500).send("TELEGRAM_BOT_TOKEN is not configured");

  const q = req.query || {};
  if (!telegramHashOk(q)) return res.status(401).send("Invalid Telegram authentication");

  const authAge = Math.floor(Date.now() / 1000) - Number(q.auth_date || 0);
  if (!Number.isFinite(authAge) || authAge < 0 || authAge > 86400) {
    return res.status(401).send("Telegram authentication expired");
  }

  const userId = String(q.id || "");
  if (!/^\d+$/.test(userId)) return res.status(400).send("Invalid Telegram user");

  try {
    const member = await isMember(userId);
    if (!member) {
      return res.redirect(302, `${SITE_URL || "/"}?tg_error=not_member`);
    }

    const session = signSession(userId);
    res.setHeader("Set-Cookie",
      `${COOKIE_NAME}=${session}; Path=/; Max-Age=${SESSION_TTL}; HttpOnly; Secure; SameSite=Lax`);
    return res.redirect(302, `${SITE_URL || "/"}?tg_verified=1`);
  } catch (err) {
    console.error(err);
    return res.redirect(302, `${SITE_URL || "/"}?tg_error=verification_failed`);
  }
};
