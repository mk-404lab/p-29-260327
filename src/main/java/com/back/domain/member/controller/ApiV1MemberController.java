package com.back.domain.member.controller;

import com.back.domain.member.dto.MemberDto;
import com.back.domain.member.entity.Member;
import com.back.domain.member.service.MemberService;
import com.back.global.exception.ServiceException;
import com.back.global.rq.Rq;
import com.back.global.rsData.RsData;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/members")
@RequiredArgsConstructor
public class ApiV1MemberController {
    private final MemberService memberService;
    private final Rq rq;
    private final HttpServletResponse response;

    record MemberJoinReqBody(
            String username,
            String password,
            String nickname
    ){}

    record MemberJoinResBody(
            MemberDto memberDto
    ){}

    @PostMapping("/join")
    public RsData<MemberDto> join(@RequestBody @Valid MemberJoinReqBody reqBody) {

        Member member = memberService.join(reqBody.username, reqBody.password, reqBody.nickname);

        return new RsData(
                "회원가입이 완료되었습니다. %s님 환영합니다.".formatted(member.getName()),
                "201-1",
                new MemberJoinResBody(
                        new MemberDto(member)
                )
        );
    }


    record MemberLoginReqBody(
            String username,
            String password
    ) {
    }

    record MemberLoginResBody(
            String apiKey
    ) {
    }

    @PostMapping("/login")
    public RsData<MemberLoginResBody> login(@RequestBody @Valid MemberLoginReqBody reqBody) {

        Member actor = memberService.findByUsername(reqBody.username()).orElseThrow(
                () -> new ServiceException("401-1", "존재하지 않는 아이디입니다.")
        );

        if (!actor.getPassword().equals(reqBody.password)) {
            throw new ServiceException("401-2", "비밀번호가 일치하지 않습니다.");
        }

        rq.addCookie("apiKey", actor.getApiKey());

        return new RsData(
                "%s님 환영합니다.".formatted(actor.getName()),
                "200-1",
                new MemberLoginResBody(actor.getApiKey())
        );
    }

    @DeleteMapping("/logout")
    public RsData<Void> logout() {
        rq.deleteCookie("apiKey");

        return new RsData(
                "로그아웃 되었습니다.",
                "200-1"
        );
    }

    @GetMapping("/me")
    public MemberDto me() {

        Member actor = rq.getActor();
        return new MemberDto(actor);
    }
}
