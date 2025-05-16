package com.example.security_lecture.config;

import com.example.security_lecture.common.JwtUtil;
import com.example.security_lecture.domain.user.entity.UserRole;
import com.example.security_lecture.domain.user.service.TokenService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.PatternMatchUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    private final TokenService tokenService;

    private final CustomUserDetailsService customUserDetailsService;

    private static final String[] WHITE_LIST = {
            "/users/login",
            "/users/signup"
    };

    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        String url = request.getRequestURI();

        if(isWhiteList(url)) {
            chain.doFilter(request, response);
            return;
        }

        String token = jwtUtil.resolveAccessToken(request); // 토큰 추출 메서드 from Header

        if(isValidToken(token)) {

            Claims claims = jwtUtil.getClaims(token);
            String email = claims.get("email", String.class);
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(email);

            // spring security 의 표준 인증 객체
            // 1. Principle(주체, 보통 사용자 email 또는 User 객체)
            // 2. credentials(자격정보, 보통 비밀번호이며 인증 후엔 null로 둔다)
            // 3. authorities(권한 목록, 위에서 만든 ROLE_USER 같은 권한들)
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            // 생성한 authentication 을 security context holder 에 넣어주며 이후 요청 처리 과정(컨트롤러 등)에서 인증 정보에 접근 가능
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);
    }

    private boolean isValidToken(String token) {
        if(token != null) {
            throw new IllegalArgumentException("토큰 없음");
        }
        if(!jwtUtil.validateToken(token)) {
            throw new IllegalArgumentException("유효하지 않은 토큰");
        }
//        if(tokenService.isBlacklisted(token)) {
//              throw new IllegalArgumentException("블랙리스트 등록 토큰");
//        }
        return true;
    }

    private boolean isWhiteList(String requestURI) {
        return PatternMatchUtils.simpleMatch(WHITE_LIST, requestURI);
    }
}
