package com.back.domain.post.post.controller;

import com.back.domain.post.post.dto.PostDto;
import com.back.domain.post.post.entity.Post;
import com.back.domain.post.post.service.PostService;
import com.back.global.rsData.RsData;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/posts")
@Tag(name = "ApiV1PostController", description = "글 API")
public class ApiV1PostController {

    private final PostService postService;

    @GetMapping(produces= MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary="글 다건 조회")
    public List<PostDto> list() {
        List<Post> result = postService.findAll();

        List<PostDto> postDtoList = result.reversed().stream()
                .map(PostDto::new)
                .toList();

        return postDtoList;
    }

    @GetMapping("/{id}")
    @Operation(summary="글 단건 조회")
    public PostDto detail(@PathVariable int id) {

        Post post = postService.findById(id).get();
        return new PostDto(post);
    }

    record PostWriteReqBody(
            @Size(min = 2, max = 10, message = "03-title-제목은 2자 이상 10자 이하로 입력해주세요.")
            @NotBlank(message = "01-title-제목은 필수입니다.")
            String title,

            @NotBlank(message = "02-content-내용은 필수입니다.")
            @Size(min = 2, max = 100, message = "04-content-내용은 2자 이상 100자 이하로 입력해주세요.")
            String content
    ) {
    }

    record PostWriteResBody(
            PostDto postDto,
            long postsCount
    ) {
    }

    @PostMapping
    @Operation(summary="글 작성")
    public RsData<PostWriteResBody> write(@RequestBody @Valid PostWriteReqBody reqBody) {
        Post post = postService.write(reqBody.title, reqBody.content);
        long postsCount = postService.count();

        return new RsData<>(
                "%d번 게시물이 생성되었습니다.".formatted(post.getId()),
                "201-1",
                new PostWriteResBody(
                        new PostDto(post),
                        postsCount
                )
        );
    }


    record PostModifyReqBody(
            @Size(min = 2, max = 10, message = "03-title-제목은 2자 이상 10자 이하로 입력해주세요.")
            @NotBlank(message = "01-title-제목은 필수입니다.")
            String title,

            @NotBlank(message = "02-content-내용은 필수입니다.")
            @Size(min = 2, max = 100, message = "04-content-내용은 2자 이상 100자 이하로 입력해주세요.")
            String content
    ) {
    }

    record PostModifyResBody(
            PostDto postDto
    ) {
    }

    @PutMapping("/{id}")
    @Operation(summary="글 수정")
    @Transactional
    public RsData<PostModifyResBody> modify(
            @PathVariable int id,
            @RequestBody @Valid PostModifyReqBody reqBody
    ) {

        Post post = postService.modify(id, reqBody.title, reqBody.content);

        return new RsData<>(
                "%d번 게시물이 수정되었습니다.".formatted(post.getId()),
                "200-1",
                new PostModifyResBody(
                        new PostDto(post)
                )
        );
    }

    @DeleteMapping("/{id}")
    @Operation(summary="글 삭제")
    public RsData<Void> delete(
            @PathVariable int id
    ) {

        postService.deleteById(id);

        return new RsData<>(
                "%d번 게시물이 삭제되었습니다.".formatted(id),
                "200-1"
        );
    }
}
