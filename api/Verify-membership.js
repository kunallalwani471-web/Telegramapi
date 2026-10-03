// Vercel Serverless Function: /api/verify-membership
// Verifies the signed Telegram session and re-checks live channel membership.

const crypto = require("crypto");

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const CHANNEL_ID = process.env.TELEGRAM_CHANNEL_ID || "-1003997928411";
const COOKIE_NAME = "k4king_tg_session";

function parseCookies(header = "") {
  return Object.fromEntries(header.split(";").map(x => {
    const i = x.indexOf("=");
    if (i < 0) return [x.trim(), ""];
    return [x.slice(0,i).trim(), x.slice(i+1).trim()];
  }));
}

function getUserId(token) {
  if (!BOT_TOKEN || !token) return null;
  let raw;
  try { raw = Buffer.from(token, "base64url").toString(); } catch { return null; }
  const parts = raw.split(".");
  if (parts.length !== 3 || !/^\d+$/.test(parts[0])) return null;
  const payload = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac("sha256", BOT_TOKEN).update(payload).digest("hex");
  if (parts[2].length !== expected.length) return null;
  try {
    if (!crypto.timingSafeEqual(Buffer.from(parts[2]), Buffer.from(expected))) return null;
  } catch { return null; }
  if (Date.now() - Number(parts[1]) > 7 * 86400000) return null;
  return parts[0];
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "GET") return res.status(405).json({ok:false});
  if (!BOT_TOKEN) return res.status(500).json({ok:false,error:"TELEGRAM_BOT_TOKEN missing"});

  const cookies = parseCookies(req.headers.cookie || "");
  const userId = getUserId(cookies[COOKIE_NAME]);

  if (!userId) return res.status(200).json({ok:true,member:false});

  try {
    const url = `https://api.telegram.org/bot${BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(CHANNEL_ID)}&user_id=${encodeURIComponent(userId)}`;
    const r = await fetch(url);
    const data = await r.json();
    if (!data.ok) return res.status(200).json({ok:true,member:false});

    const status = data.result?.status;
    const member = ["creator","administrator","member"].includes(status) ||
                   (status === "restricted" && data.result?.is_member === true);

    return res.status(200).json({ok:true,member});
  } catch (e) {
    console.error(e);
    return res.status(200).json({ok:true,member:false});
  }
};
