package com.back.domain.member.service;

import com.back.domain.member.entity.Member;
import com.back.standard.ut.Ut;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class AuthTokenService {

    private String secretKey = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890";
    private final long expireTime = 1000L * 60 * 60 * 24 * 365;

    public String getAccessToken(Member member) {
        return Ut.jwt.toString(
                secretKey,
                expireTime,
                Map.of(
                        "id", member.getId(),
                        "name", member.getName()
                )
        );
    }
}
