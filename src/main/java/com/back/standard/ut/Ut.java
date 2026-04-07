package com.back.standard.ut;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ClaimsBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.Map;

public class Ut {
    public static class jwt {
        public static String toString(String secret, long expireSeconds, Map<String, Object> body) {
            ClaimsBuilder claimsBuilder = Jwts.claims();

            for (Map.Entry<String, Object> entry : body.entrySet()) {
                claimsBuilder.add(entry.getKey(), entry.getValue());
            }

            Claims claims = claimsBuilder.build();

            Date issuedAt = new Date();
            Date expiration = new Date(issuedAt.getTime() + 1000L * expireSeconds);

            Key secretKey = Keys.hmacShaKeyFor(secret.getBytes());

            String jwt = Jwts.builder()
                    .claims(claims)
                    .issuedAt(issuedAt)
                    .expiration(expiration)
                    .signWith(secretKey)
                    .compact();

            return jwt;
        }

        public static boolean isValid(String jwt, String secret) {
            /*
            isValid() 목적 : 토큰 유효성 검사 - 이 토큰을 믿을 수 있는가?

            True : 서명이 일치하고, 유효기간(Expiration)이 지나지 않았으며, 토큰 형식이 올바른 경우
            False : 서명이 위조되었거나, 만료되었거나, 구조가 깨진 경우
            */

            byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
            SecretKey secretKey = Keys.hmacShaKeyFor(keyBytes);

            try {
                Jwts
                        .parser()
                        .verifyWith(secretKey)
                        .build()
                        .parse(jwt)
                        .getPayload();

                return true;
            } catch (Exception e) {
                return false;
            }
        }

        public static Map<String, Object> payloadOrNull(String jwt, String secret) {
            /*
            payload() 목적 : 데이터 추출 - 토큰 안에 어떤 정보가 들어있는가?

            - isValid와 마찬가지로 먼저 서명 검증 수행
            - 검증이 통과되면 토큰의 바디인 Payload(Claims)를 Map<> 형태로 반환
             */

            byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
            SecretKey secretKey = Keys.hmacShaKeyFor(keyBytes);

            if (isValid(jwt, secret)) {
                return (Map<String, Object>)Jwts
                        .parser()
                        .verifyWith(secretKey)
                        .build()
                        .parse(jwt)
                        .getPayload();
            }

            return null;
        }
    }
}