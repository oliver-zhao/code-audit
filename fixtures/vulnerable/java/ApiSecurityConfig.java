package com.example.config;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

public class ApiSecurityConfig {
    public SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.csrf(csrf -> csrf.disable());
        return http.build();
    }

    static class LenientVerifier implements HostnameVerifier {
        public boolean verify(String hostname, SSLSession session) {
            return hostname.endsWith(".internal");
        }
    }
}
