package com.example.basicsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        http
                .formLogin()
                //.loginPage("/loginPage")
                .defaultSuccessUrl("/") // 로그인 성공 시 루트페이지로 이동
                .failureUrl("/login") // 로그인 실패 시 로그인페이지로 이동
                .usernameParameter("userId") // 로그인 Form 에 있는 아이디 입력 name 값 설정
                .passwordParameter("passwd") // 로그인 Form 에 있는 비밀번호 입력 name 값 설정
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : " + authentication.getName()); // 인증에 성공한 사용자 이름 출력
                        response.sendRedirect("/"); // 루트 페이지로 이동
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : " + exception.getMessage()); // 예외 메시지 출력
                        response.sendRedirect("/");
                    }
                })
                .permitAll(); // 로그인페이지로 이동하는 유저는 인증없이 통과하게 설정

        return http.build();
    }
}
