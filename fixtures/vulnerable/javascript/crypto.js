// Cryptography, JWT and TLS seeds.
const crypto = require("crypto");
const https = require("https");
const jwt = require("jsonwebtoken");

function weakCrypto(password, data, key) {
  const legacy = crypto.createCipher("aes-256-cbc", key);
  const des = crypto.createCipheriv("des-ede3-cbc", key, Buffer.alloc(8));
  const ecb = crypto.createCipheriv("aes-128-ecb", key, null);
  const hashed = crypto.createHash("md5").update(password).digest("hex");
  const fixed = crypto.createCipheriv("aes-256-gcm", "0123456789abcdef0123456789abcdef", crypto.randomBytes(12));
  const mac = crypto.createHmac("sha256", "hmac-signing-key-1234").update(data).digest("hex");
  const derived = crypto.pbkdf2Sync(password, "salt", 1000, 32, "sha256");
  return { legacy, des, ecb, hashed, fixed, mac, derived };
}

function newResetToken() {
  const resetToken = Math.random().toString(36).slice(2);
  return resetToken;
}

function issue(user) {
  return jwt.sign({ sub: user.id }, "jwt-signing-secret-1");
}

function check(token, publicKey) {
  const claims = jwt.verify(token, publicKey, { algorithms: ["RS256", "none"] });
  const loose = jwt.verify(token, publicKey);
  const stale = jwt.verify(token, publicKey, { algorithms: ["RS256"], ignoreExpiration: true });
  const unverified = jwt.decode(token);
  return { claims, loose, stale, unverified };
}

const agent = new https.Agent({ rejectUnauthorized: false });
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const legacyTls = { secureProtocol: "TLSv1_method" };
const oldTls = { minVersion: "TLSv1.1" };

module.exports = { weakCrypto, newResetToken, issue, check, agent, legacyTls, oldTls };
