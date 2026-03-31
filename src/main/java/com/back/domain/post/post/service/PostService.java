package com.back.domain.post.post.service;

import com.back.domain.member.entity.Member;
import com.back.domain.post.post.entity.Post;
import com.back.domain.post.post.repository.PostRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PostService {

    private final PostRepository postRepository;

    public Post write(Member author, String title, String content) {
        Post post = new Post(author, title, content);
        return postRepository.save(post);
    }

    public Post modify(int id, String title, String content) {
        Post post = postRepository.findById(id).get();
        post.update(title, content);

        return post;
    }

    public void deleteById(int id) {
        postRepository.deleteById(id);
    }

    public Optional<Post> findById(int id) {
        return postRepository.findById(id);
    }

    public long count() {
        return postRepository.count();
    }

    public List<Post> findAll() {
        return postRepository.findAll();
    }

    public void flush() {
        postRepository.flush();
    }
}

