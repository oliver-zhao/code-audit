package com.example.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.Cookie;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.ssl.SSLContextBuilder;

public class CryptoUtil {
    public void ciphers() throws Exception {
        Cipher des = Cipher.getInstance("DES/CBC/PKCS5Padding");
        Cipher aes = Cipher.getInstance("AES");
        Cipher ecb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        IvParameterSpec iv = new IvParameterSpec(new byte[16]);
        SecretKeySpec key = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        SecureRandom seeded = new SecureRandom();
        seeded.setSeed(42L);
        String resetToken = Long.toHexString(new Random().nextLong());
        PBEKeySpec spec = new PBEKeySpec("pw".toCharArray(), new byte[16], 1000, 256);
    }

    public void tls() throws Exception {
        SSLContext legacy = SSLContext.getInstance("TLSv1");
        SSLContext generic = SSLContext.getInstance("SSL");
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        Object verifier = NoopHostnameVerifier.INSTANCE;
        new SSLContextBuilder().loadTrustMaterial(null, new TrustAllStrategy());
    }

    static class TrustEverything implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    public Object jwt(String token) {
        Object claims = Jwts.parser().setSigningKey("fixture-only-not-a-real-key").parseClaimsJwt(token);
        String issued = Jwts.builder().setSubject("u").signWith(SignatureAlgorithm.HS256, "fixture-only-signing-key").compact();
        Object decoded = JWT.decode(token).getClaims();
        return claims;
    }

    public Cookie cookie(String value) {
        Cookie cookie = new Cookie("session", value);
        cookie.setHttpOnly(false);
        cookie.setSecure(false);
        return cookie;
    }
}
