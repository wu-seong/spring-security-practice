package io.security.springsecuritypractice.security;


import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import java.io.IOException;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final UserDetailsService userDetailService;
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .authorizeHttpRequests((authz) -> authz
                        .requestMatchers("/loginPage").permitAll()
                        .anyRequest().authenticated()
                        .anyRequest().anonymous()
                );
        http
                .formLogin((formLogin) -> formLogin
                        .usernameParameter("username")// 사용자 지정으로 만들 때도 이와 통일 되어야 함
                        .passwordParameter("password")
                        //.loginPage("/login")
                        //.failureUrl("/login")
                        //.loginProcessingUrl("/authentication/login/process") //form 처리 url
                        .successHandler(new AuthenticationSuccessHandler() {
                            //인증 성공 시 인증 객체인 Authentication 객체까지 같이 넘어 오게 됨
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                System.out.println("authentication = " + authentication.getName());
                                response.sendRedirect("/");
                            }
                        })
                        .failureHandler(new AuthenticationFailureHandler() {
                            //인증 실패하여 예외 객체를 같이 전달
                            @Override
                            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                System.out.println("exception.getMessage() = " + exception.getMessage());
                                response.sendRedirect("/login");
                            }
                        })
                );

        http.
                logout(logout ->
                    logout.logoutUrl("/logout") //디폴트가 "logout

                            .addLogoutHandler(new SecurityContextLogoutHandler())
                            .addLogoutHandler(new LogoutHandler() {
                                @Override
                                public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                                    //사용저 정의 로그아웃 처리 핸들러
                                }
                            })
                            .logoutSuccessHandler(new LogoutSuccessHandler() {
                                @Override
                                public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                    //로그아웃 성공 후 처리 핸들러
                                    response.sendRedirect("/login");
                                    System.out.println("redirect");
                                }
                            })
                            .logoutSuccessUrl("/redirect")
            );

        http.
                rememberMe(httpSecurityRememberMeConfigurer ->
                    httpSecurityRememberMeConfigurer.rememberMeParameter("remember")
                            .tokenValiditySeconds(3600)
                            .alwaysRemember(false)
                            .userDetailsService(userDetailService)
            );

        http.
                anonymous(httpSecurityAnonymousConfigurer -> new AnonymousConfigurer<>() //인증되지 않은 사용자 전용 인증 토큰을 만듦
                );

        http.
                sessionManagement(httpSecuritySessionManagementConfigurer -> {
                            //httpSecuritySessionManagementConfigurer
                                    //.invalidSessionUrl("invalid")
                                    //.maximumSessions(1) //최대 세션 개수 1개
                                    //.maxSessionsPreventsLogin(true) // true: 새로운 로그인 차단 ,default(false): 기존 세션 만료
                                    //.expiredUrl("expired");

                        }
                )
                .sessionManagement(httpSecuritySessionManagementConfigurer -> {
                    httpSecuritySessionManagementConfigurer
                            .sessionFixation().changeSessionId();
                })
                .sessionManagement(httpSecuritySessionManagementConfigurer -> {
                    httpSecuritySessionManagementConfigurer
                            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED); //기본값
                });

        return http.build();
    }
}
