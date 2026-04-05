package com.back.global.rq;

import com.back.domain.member.entity.Member;
import com.back.domain.member.service.MemberService;
import com.back.global.exception.ServiceException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class Rq {

    private final MemberService memberService;
    private final HttpServletRequest request;
    private final HttpServletResponse response;

    public void addCookie(String name, String value) {
        response.addCookie(
                new Cookie(name, value)
        );
    }

    public Member getActor() {
        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader == null) {
            throw new ServiceException("401-1", "인증 정보가 헤더에 존재하지 않습니다.");
        }

        if (!authorizationHeader.startsWith("Bearer ")) {
            throw new ServiceException("401-2", "잘못된 형식의 인증 데이터입니다.");
        }

        String apiKey = authorizationHeader.replace("Bearer ", "");

        return memberService.findByApiKey(apiKey).orElseThrow(
                () -> new ServiceException("401-1", "유효하지 않은 API 키입니다.")
        );
    }
}
