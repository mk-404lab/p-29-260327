package com.back.domain.member.dto;

import com.back.domain.member.entity.Member;

import java.time.LocalDateTime;

public record MemberDto (
        int id,
        String name,
        LocalDateTime createDate,
        LocalDateTime modifyDate
){
    public MemberDto(Member member) {
        this(
                member.getId(),
                member.getName(),
                member.getCreateDate(),
                member.getModifyDate()
        );
    }
}
