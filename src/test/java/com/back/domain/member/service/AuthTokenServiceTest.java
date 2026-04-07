package com.back.domain.member.service;

import com.back.domain.member.entity.Member;
import com.back.domain.member.repository.MemberRepository;
import com.back.standard.ut.Ut;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class AuthTokenServiceTest {

    @Autowired
    private AuthTokenService authTokenService;

    @Autowired
    private MemberRepository memberRepository;

    private String secretPattern = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890";
    private long expireSeconds = 1000L * 60 * 60 * 24 * 365;

    @Test
    void t1() {
        assertThat(authTokenService).isNotNull();
    }

    @Test
    @DisplayName("jjwt 최신 방식으로 JWT 생성, {name=\\\"Paul\\\", age=23}")
    void t2() throws InterruptedException{

        Map<String, Object> payload = Map.of("name", "Paul", "age", 23);

        String jwt = Ut.jwt.toString(secretPattern, expireSeconds, payload);
        Map<String, Object> parsedPayload = Ut.jwt.payloadOrNull(jwt, secretPattern);

        assertThat(parsedPayload).containsAllEntriesOf(payload);

        assertThat(jwt).isNotBlank();

        System.out.println("jwt = " +jwt);

    }

    @Test
    @DisplayName("Ut.jwt.toString을 사용해서 JWT 생성, {name=\\\"Paul\\\", age=23}")
    void t3() {

        String jwt = Ut.jwt.toString(
                secretPattern,
                expireSeconds,
                Map.of("name", "Paul", "age", "23")
        );

        assertThat(jwt).isNotBlank();
        boolean rst = Ut.jwt.isValid(jwt, secretPattern);
        assertThat(rst).isTrue();

        System.out.println("jwt = " + jwt);
    }

    @Test
    @DisplayName("AuthTokenService를 통해서 accessToken 생성")
    void t4() {
        Member member1 = memberRepository.findByUsername("user1").get();
        String accessToken = authTokenService.genAccessToken(member1);
        assertThat(accessToken).isNotBlank();

        Map<String, Object> payload = authTokenService.payloadOrNull(accessToken);

        assertThat(payload).containsAllEntriesOf(
                Map.of(
                        "id", member1.getId(),
                        "name", member1.getName()
                )
        );

        System.out.println("accessToken = " +accessToken);
    }
}

