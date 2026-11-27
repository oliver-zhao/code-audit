package com.example.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.SSLContext;
import javax.servlet.http.Cookie;

public class CryptoUtil {
    private static final SecureRandom RANDOM = new SecureRandom();

    public void ciphers(SecretKey key, char[] password, byte[] salt) throws Exception {
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        GCMParameterSpec iv = new GCMParameterSpec(128, nonce);
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        String resetToken = Base64.getUrlEncoder().encodeToString(raw);
        PBEKeySpec spec = new PBEKeySpec(password, salt, 600000, 256);
    }

    public void tls() throws Exception {
        SSLContext modern = SSLContext.getInstance("TLSv1.3");
    }

    public Object jwt(String token, SecretKey signingKey) {
        Object claims = Jwts.parserBuilder().setSigningKey(signingKey).build().parseClaimsJws(token);
        Object modern = Jwts.parser().verifyWith(signingKey).build().parse(token);
        Object verified = JWT.require(Algorithm.HMAC256(signingKey.getEncoded())).build().verify(token);
        return claims;
    }

    public Cookie cookie(String value) {
        Cookie cookie = new Cookie("session", value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        return cookie;
    }
}
