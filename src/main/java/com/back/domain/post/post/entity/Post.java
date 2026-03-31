package com.back.domain.post.post.entity;

import com.back.domain.member.entity.Member;
import com.back.domain.post.comment.entity.Comment;
import com.back.global.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Entity
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class Post extends BaseEntity {

    private String title;
    private String content;

    @ManyToOne(fetch = FetchType.LAZY)
    private Member author;

    @OneToMany(mappedBy = "post",
            cascade = {CascadeType.PERSIST, CascadeType.REMOVE},
            fetch = FetchType.LAZY,
            orphanRemoval = true)
    private List<Comment> comments = new ArrayList<>();

    public Post(Member author, String title, String content) {
        this.author = author;
        this.title = title;
        this.content = content;
    }

    public void update(String title, String content) {
        this.title = title;
        this.content = content;
    }

    // 댓글 추가

    public Comment addComment(Member author, String content) {
        Comment comment = new Comment(author, content, this);
        comments.add(comment);

        return comment;
    }

    // 댓글 조회
    public Optional<Comment> findCommentById(int commentId) {
        return comments.stream()
                .filter(c -> c.getId() == commentId)
                .findFirst();
    }

    // 댓글 삭제
    public void deleteComment(int id) {
        Comment comment = findCommentById(id).get();
        comments.remove(comment);
    }

    public void modifyComment(int commentId, String content) {
        Comment comment = findCommentById(commentId).get();
        comment.update(content);
    }
}
