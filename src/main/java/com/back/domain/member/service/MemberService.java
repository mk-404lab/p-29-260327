package com.back.domain.member.service;

import com.back.domain.member.entity.Member;
import com.back.domain.member.repository.MemberRepository;
import com.back.global.exception.ServiceException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;

    public Member join(String username, String password, String nickname) {

        return join(username, password, nickname, UUID.randomUUID().toString());
    }

    public Member join(String username, String password, String nickname, String apiKey) {

        findByUsername(username).ifPresent(
                m -> {
                    throw new ServiceException("409-1", "이미 사용중인 아이디입니다.");
                }
        );

        Member member = new Member(username, password, nickname, apiKey);
        return memberRepository.save(member);
    }

    public long count() {
        return memberRepository.count();
    }

    public Optional<Member> findByUsername(String username) {
        return memberRepository.findByUsername(username);
    }

    public Optional<Member> findByApiKey(String apiKey) {
        return memberRepository.findByApiKey(apiKey);
    }
}
