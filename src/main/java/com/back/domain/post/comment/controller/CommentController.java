package com.back.domain.post.comment.controller;

import com.back.domain.post.comment.entity.Comment;
import com.back.domain.post.post.entity.Post;
import com.back.domain.post.post.service.PostService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
public class CommentController {

    private final PostService postService;

    record WriteRequestForm(
            @NotBlank(message = "01-content-댓글 내용은 필수입니다.") @Size(min = 2, max = 100, message = "02-content-댓글 내용은 2자 이상 100자 이하로 입력해주세요.") String content) {
    }

    @PostMapping("/posts/{postId}/comments/write")
    @Transactional
    public String writeComment(@PathVariable int postId, @Valid WriteRequestForm form) {


        Post post = postService.findById(postId).get();
        post.addComment(form.content);
        return "redirect:/posts/%d".formatted(post.getId());
    }

    @DeleteMapping("/posts/{postId}/comments/{commentId}")
    @Transactional
    public String delete(@PathVariable int postId, @PathVariable int commentId) {
        Post post = postService.findById(postId).get();
        post.deleteComment(commentId);

        return "redirect:/posts/%d".formatted(post.getId());
    }

    @GetMapping("/posts/{postId}/comments/{commentId}/modify")
    public String modify(@PathVariable int postId, @PathVariable int commentId, Model model) {
        Post post = postService.findById(postId).get();
        Comment comment = post.findCommentById(commentId).get();
        model.addAttribute("comment", comment);
        model.addAttribute("post", post);

        return "comment_modify";
    }

    record ModifyRequestForm(
            @NotBlank(message = "01-content-댓글 내용은 필수입니다.")
            @Size(min = 2, max = 100, message = "02-content-댓글 내용은 2자 이상 100자 이하로 입력해주세요.")
            String content) {}

    @PutMapping("/posts/{postId}/comments/{commentId}/modify")
    @Transactional
    public String modify(@PathVariable int postId, @PathVariable int commentId, @Valid ModifyRequestForm form) {
        Post post = postService.findById(postId).get();
        Comment comment = post.findCommentById(commentId).get();
        comment.update(form.content);

        return "redirect:/posts/%d".formatted(post.getId());
    }
}
