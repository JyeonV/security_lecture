package com.example.security_lecture.domain.user.service;

import com.example.security_lecture.common.JwtUtil;
import com.example.security_lecture.domain.user.dto.SignUpResponseDto;
import com.example.security_lecture.domain.user.dto.TokenDto;
import com.example.security_lecture.domain.user.entity.User;
import com.example.security_lecture.domain.user.entity.UserRole;
import com.example.security_lecture.domain.user.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtUtil jwtUtil;

    private final TokenService tokenService;

    public SignUpResponseDto signUp(String email, String password, UserRole userRole) {
        String encodePassword = passwordEncoder.encode(password);

        User saveUser = new User(email, encodePassword, userRole);

        userRepository.save(saveUser);

        return new SignUpResponseDto(email, userRole);

    }

    public TokenDto login(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("이메일이 없음"));

        if(!passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("잘못된 비밀번호");
        }

        String accessToken = jwtUtil.createAccessToken(user.getId(), user.getEmail(), user.getUserRole());

        String refreshToken = jwtUtil.createRefreshToken(user.getId());

        tokenService.saveRefreshToken(user.getId(), refreshToken);

        TokenDto tokenDto = new TokenDto(accessToken, refreshToken);

        return tokenDto;
    }

    public String reissueToken(HttpServletRequest request) {
        String refreshToken = extractTokenFromCookie(request, "refreshToken");

        Long userId = jwtUtil.getUserIdFromToken(refreshToken);

        String savedRefreshToken = tokenService.getRefreshToken(userId);

        if(!refreshToken.equals(savedRefreshToken)) {
            throw new IllegalArgumentException("리프레시 토큰 불일치");
        }

        String oldAccessToken = jwtUtil.resolveAccessToken(request);

        if(!jwtUtil.isExpired(oldAccessToken)) { // 기존 어세스 토큰이 살아있다면 블랙리스트 처리
            tokenService.blacklistAccessToken(oldAccessToken);
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 계정"));

        String newAccessToken = jwtUtil.createAccessToken(userId, user.getEmail(), user.getUserRole());

        return newAccessToken;
    }

    public void logout(HttpServletRequest request) {
        tokenService.blacklistAccessToken(jwtUtil.resolveAccessToken(request));
        tokenService.deleteRefreshToken(getUserId());
    }

    public User testLogin() {
        Long UserId = getUserId();

        User user = userRepository.findById(UserId)
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 사용자 정보"));

        return user;
    }

    private Long getUserId() {
        return (Long) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    private String extractTokenFromCookie(HttpServletRequest request, String name) {
        if(request.getCookies() == null) return null;

        for(Cookie cookie : request.getCookies()) {
            if(cookie.getName().equals(name)) {
                return cookie.getValue();
            }
        }
        return null;
    }

}
