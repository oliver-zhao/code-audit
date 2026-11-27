// Safe counterparts of the cryptography, JWT and TLS seeds.
const crypto = require("crypto");
const https = require("https");
const jwt = require("jsonwebtoken");

function strongCrypto(password, data, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const hashed = crypto.scryptSync(password, crypto.randomBytes(16), 64);
  const digest = crypto.createHash("sha256").update(data).digest("hex");
  const mac = crypto.createHmac("sha256", process.env.HMAC_KEY).update(data).digest("hex");
  const derived = crypto.pbkdf2Sync(password, crypto.randomBytes(16), 600000, 32, "sha256");
  return { cipher, hashed, digest, mac, derived };
}

function newResetToken() {
  const resetToken = crypto.randomBytes(32).toString("hex");
  const jitter = Math.random() * 100;
  return { resetToken, jitter };
}

function issue(user) {
  return jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { algorithm: "HS256", expiresIn: "15m" });
}

function check(token, publicKey) {
  return jwt.verify(token, publicKey, { algorithms: ["RS256"] });
}

const agent = new https.Agent({ rejectUnauthorized: true, minVersion: "TLSv1.2" });

module.exports = { strongCrypto, newResetToken, issue, check, agent };
