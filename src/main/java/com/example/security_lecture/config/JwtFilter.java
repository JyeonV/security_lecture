package com.example.security_lecture.config;

import com.example.security_lecture.common.JwtUtil;
import com.example.security_lecture.domain.user.entity.UserRole;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.PatternMatchUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

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

        String token = null;
        if(request.getCookies() != null) { // request.getCookies는 cookie[]로 반환
            for (Cookie cookie : request.getCookies()) {
                if ("accessToken".equals(cookie.getName())) {
                    token = cookie.getValue();
                    break;
                }
            }
        }

        if(token == null || !jwtUtil.validateToken(token)) {
            throw new IllegalArgumentException("유효하지 않은 토큰");
        }

        Claims claims = jwtUtil.getClaims(token);
        Long userId = Long.parseLong(claims.getSubject());
        UserRole userRole = UserRole.valueOf(claims.get("userRole", String.class));

        // 권한 설정 -> GrantedAuthority 인터페이스로 관리
        // security 는 내부적으로 권한을 식별할 때 ROLE_ prefix가 있는지 확인하기 때문에 붙여준다
        // security 는 기본적으로 권한이 여러 개일 수 있다는 전제가 기반이므로 list 이며 실제로 밑에서 권한을 추가 가능
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + userRole.name()));

        // spring security 의 표준 인증 객체
        // 1. Principle(주체, 보통 사용자 email 또는 User 객체)
        // 2. credentials(자격정보, 보통 비밀번호이며 인증 후엔 null로 둔다)
        // 3. authorities(권한 목록, 위에서 만든 ROLE_USER 같은 권한들)
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userId, null, authorities);

        // 생성한 authentication 을 securitycontextholder 에 넣어주며 이후 요청 처리 과정(컨트롤러 등)에서 인증 정보에 접근 가능
        SecurityContextHolder.getContext().setAuthentication(authentication);

        chain.doFilter(request, response);
    }

    private boolean isWhiteList(String requestURI) {
        return PatternMatchUtils.simpleMatch(WHITE_LIST, requestURI);
    }
}
