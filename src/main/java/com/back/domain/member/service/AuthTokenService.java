package com.back.domain.member.service;

import com.back.domain.member.entity.Member;
import com.back.standard.ut.Ut;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
class AuthTokenService {

    @Value("${custom.jwt.secretPattern}")
    private String secretKey;

    @Value("${custom.jwt.expiration}")
    private long expireTime;

    String genAccessToken(Member member) {
        return Ut.jwt.toString(
                secretKey,
                expireTime,
                Map.of(
                        "id", member.getId(),
                        "name", member.getName()
                )
        );
    }

    Map<String, Object> payloadOrNull(String jwt) {
        return Ut.jwt.payloadOrNull(jwt, secretKey);
    }
}
