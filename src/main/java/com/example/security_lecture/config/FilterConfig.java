package com.example.security_lecture.config;

import com.example.security_lecture.common.JwtUtil;
import com.example.security_lecture.domain.user.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class FilterConfig {

    private final JwtUtil jwtUtil;

    private final TokenService tokenService;

    private final CustomUserDetailsService customUserDetailsService;

    @Bean
    public JwtFilter jwtFilter() {
        return new JwtFilter(jwtUtil, tokenService, customUserDetailsService);
    }


    // spring security 체인에서 jwtfilter를 활용하기 때문에 filterRegistrationBean은 삭제
//    @Bean
//    public FilterRegistrationBean<JwtFilter> jwtFilter() {
//        FilterRegistrationBean<JwtFilter> registrationBean = new FilterRegistrationBean<>();
//        registrationBean.setFilter(new JwtFilter(jwtUtil));
//        registrationBean.addUrlPatterns("/*"); // 필터를 적용할 URL 패턴을 지정합니다.
//
//        return registrationBean;
//    }
}
