package io.security.springsecuritypractice.security.config;


import io.security.springsecuritypractice.security.provider.CustomAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
//    @Bean
//    public
//    UserDetailsManager users() {
//
//
//        UserDetails user = User.builder()
//                .username("user")
//                .password("{noop}1111")
//                .roles("USER")
//                .build();
//
//        UserDetails manager = User.builder()
//                .username("manager")
//                .password("{noop}1111")
//                .roles("MANAGER", "USER")
//                .build();
//
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password("{noop}1111")
//                .roles("ADMIN", "MANAGER", "USER")
//                .build();
//
//        return new InMemoryUserDetailsManager( user, manager, admin );
//    }

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws  Exception{
        auth.authenticationProvider(authenticationProvider());
    }

    @Bean
    protected AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider(userDetailsService, );
    }

    @Bean
    public WebSecurityCustomizer configure() throws Exception{
        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .authorizeHttpRequests( auth -> {
                    auth
                            .requestMatchers("/", "/users").permitAll()
                            .requestMatchers("/mypage").hasRole("USER")
                            .requestMatchers("/messages").hasRole("MANAGER")
                            .requestMatchers("/config").hasRole("ADMIN")
                            .anyRequest().authenticated();
                })
                .formLogin( config ->{

                });

        return http.build();
    }
}
