package com.example.security_lecture.domain.user.service;

import com.example.security_lecture.common.JwtUtil;
import com.example.security_lecture.domain.user.dto.SignUpResponseDto;
import com.example.security_lecture.domain.user.entity.User;
import com.example.security_lecture.domain.user.entity.UserRole;
import com.example.security_lecture.domain.user.repository.UserRepository;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
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

    public SignUpResponseDto signUp(String email, String password, UserRole userRole) {

        String encodePassword = passwordEncoder.encode(password);

        User saveUser = new User(email, encodePassword, userRole);

        userRepository.save(saveUser);

        return new SignUpResponseDto(email, userRole);

    }

    public String login(String email, String password) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("이메일이 없음"));

        if(!passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("잘못된 비밀번호");
        }

        String token = jwtUtil.createAccessToken(user.getId(), user.getEmail(), user.getUserRole());

        return token;
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
}
