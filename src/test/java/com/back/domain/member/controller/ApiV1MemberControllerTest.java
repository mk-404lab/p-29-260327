package com.back.domain.member.controller;

import com.back.domain.member.entity.Member;
import com.back.domain.member.repository.MemberRepository;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
@Transactional
public class ApiV1MemberControllerTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private MemberRepository memberRepository;

    @Test
    @DisplayName("회원 가입")
    void t1() throws Exception {

        String username = "newUser";
        String password = "1234";
        String nickname = "새유저";

        ResultActions resultActions = mvc
                .perform(
                        post("/api/v1/members/join")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {
                                            "username": "%s",
                                            "password": "%s",
                                            "nickname": "%s"
                                        }
                                        """.formatted(username, password, nickname)
                                )
                )
                .andDo(print());

        resultActions
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("join"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.resultCode").value("201-1"))
                .andExpect(jsonPath("$.msg").value("회원가입이 완료되었습니다. %s님 환영합니다.".formatted(nickname)))
                .andExpect(jsonPath("$.data.memberDto.id").value(6))
                .andExpect(jsonPath("$.data.memberDto.createDate").exists())
                .andExpect(jsonPath("$.data.memberDto.modifyDate").exists())
                .andExpect(jsonPath("$.data.memberDto.name").value(nickname));
    }

    @Test
    @DisplayName("회원 가입, 이미 존재하는 username으로 가입 - user1로 가입")
    void t2() throws Exception {

        String username = "user1";
        String password = "1234";
        String nickname = "새유저";

        ResultActions resultActions = mvc
                .perform(
                        post("/api/v1/members/join")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {
                                            "username" : "%s",
                                            "password": "%s",
                                            "nickname": "%s"
                                        
                                        }
                                        """.formatted(username, password, nickname)
                                )
                )
                .andDo(print());

        resultActions
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("join"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.resultCode").value("409-1"))
                .andExpect(jsonPath("$.msg").value("이미 사용중인 아이디입니다."));
    }

    @Test
    @DisplayName("로그인")
    void t3() throws Exception {

        String username = "user1";
        String password = "1234";
        String apiKey = "user1";

        ResultActions resultActions = mvc
                .perform(
                        post("/api/v1/members/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {
                                            "username": "%s",
                                            "password": "%s"
                                        }
                                        """.formatted(username, password)
                                )
                )
                .andDo(print());

        Member member = memberRepository.findByUsername(username).get();

        resultActions
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("login"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.resultCode").value("200-1"))
                .andExpect(jsonPath("$.msg").value("%s님 환영합니다.".formatted(member.getNickname())))
                .andExpect(jsonPath("$.data.apiKey").exists())
                .andExpect(jsonPath("$.data.accessToken").isNotEmpty());


        resultActions.andExpect(
                result -> {
                    Cookie apiKeyCookie = result.getResponse().getCookie("apiKey");

                    assertThat(apiKeyCookie).isNotNull();
                    assertThat(apiKeyCookie.getValue()).isEqualTo(apiKey);

                    assertThat(apiKeyCookie.getPath()).isEqualTo("/");
                    assertThat(apiKeyCookie.isHttpOnly()).isTrue();

                    assertThat(apiKeyCookie.getDomain()).isEqualTo("localhost");


                    Cookie accessTokenCookie = result.getResponse().getCookie("accessToken");
                    assertThat(accessTokenCookie).isNotNull();

                    assertThat(accessTokenCookie.getPath()).isEqualTo("/");
                    assertThat(accessTokenCookie.getDomain()).isEqualTo("localhost");
                    assertThat(accessTokenCookie.isHttpOnly()).isEqualTo(true);

                }
        );
    }

    @Test
    @DisplayName("로그아웃")
    void t4() throws Exception {
        ResultActions resultActions = mvc
                .perform(
                        delete("/api/v1/members/logout")
                )
                .andDo(print());

        resultActions
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("logout"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.resultCode").value("200-1"))
                .andExpect(jsonPath("$.msg").value("로그아웃 되었습니다."))
                .andExpect(result -> {
                    Cookie apiKeyCookie = result.getResponse().getCookie("apiKey");
                    assertThat(apiKeyCookie.getValue()).isEmpty();
                    assertThat(apiKeyCookie.getMaxAge()).isEqualTo(0);
                    assertThat(apiKeyCookie.getPath()).isEqualTo("/");
                    assertThat(apiKeyCookie.isHttpOnly()).isTrue();
                });
    }

    @Test
    @DisplayName("내 정보")
    void t5() throws Exception {
        Member author = memberRepository.findByUsername("user1").get();
        String actorApiKey = author.getApiKey();

        ResultActions resultActions = mvc
                .perform(
                        get("/api/v1/members/me")
                                .header("Authorization", "Bearer " + actorApiKey)

                )
                .andDo(print());

        Member member = memberRepository.findByUsername("user1").get();

        resultActions
                .andExpect(handler().handlerType(ApiV1MemberController.class))
                .andExpect(handler().methodName("me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(member.getId()))
                .andExpect(jsonPath("$.name").value(member.getName()))
                .andExpect(jsonPath("$.createDate").exists())
                .andExpect(jsonPath("$.modifyDate").exists());

    }
}
