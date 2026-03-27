package com.back.domain.post.post.dto;

import com.back.domain.post.post.entity.Post;

import java.time.LocalDateTime;

public record PostDto(
        int id,
        String title,
        String content,
        LocalDateTime createDate,
        LocalDateTime modifyDate
) {

    public PostDto(Post post) {
        this(
                post.getId(),
                post.getTitle(),
                post.getContent(),
                post.getCreateDate(),
                post.getModifyDate()
        );
    }
}
