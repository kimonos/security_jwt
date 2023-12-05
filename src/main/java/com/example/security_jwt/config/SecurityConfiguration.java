package com.example.security_jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)//關閉csrf
                .authorizeHttpRequests(req ->
                                req.requestMatchers("/security/**")
                                        .permitAll()//接受"/security/**"開頭的所有請求
//                                .requestMatchers(POST,"api/v1/auth/").hasAnyRole(ADMIN.name(), USER.name())
//                                .requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority()
//                                .requestMatchers(POST, "/login").hasAnyAuthority()
//                                .requestMatchers(PUT, "/api/v1/management/**").hasAnyAuthority()
//                                .requestMatchers(DELETE, "/api/v1/management/**").hasAnyAuthority()
                                        .anyRequest()//其他非"/security/**"開頭的request單需要驗證
                                        .authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);//在執行UsernamePasswordAuthenticationFilter前，把jwtAuthFilter加入

        return http.build();
    }
}
