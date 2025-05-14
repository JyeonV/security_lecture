package com.example.security_lecture.domain.user.controller;

import com.example.security_lecture.domain.user.dto.*;
import com.example.security_lecture.domain.user.entity.User;
import com.example.security_lecture.domain.user.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<SignUpResponseDto> signUp(@Valid @RequestBody SignUpRequestDto requestDto) {

        SignUpResponseDto responseDto = userService.signUp(requestDto.getEmail(), requestDto.getPassword(), requestDto.getUserRole());

        return new ResponseEntity<>(responseDto, HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDto requestDto, HttpServletResponse response) {

        TokenDto tokenDto = userService.login(requestDto.getEmail(), requestDto.getPassword());

        ResponseCookie refreshCookie = ResponseCookie.from("refreshToken", tokenDto.getRefreshToken()) // 쿠키의 이름과 값을 설정하는 부분
                .httpOnly(true) // JS 에서의 접근을 막는다
                .secure(true)         // HTTPS만 사용할 경우 true
                .path("/")            // 전체 경로에서 사용 가능
                .maxAge(60 * 60)      // 1시간
                .sameSite("Lax") // 브라우저가 이 쿠키를 어떤 상황에서 요청에 자동으로 포함시킬지, Lax = 같은 사이트 + 대부분의 get요청 허용
                .build();

        // HTTP 응답 헤더에 Set-Cookie로 추가
        response.addHeader("Set-Cookie", refreshCookie.toString());

        return new ResponseEntity<>(tokenDto.getAccessToken(), HttpStatus.OK);
    }

    @PostMapping("/reissue")
    public ResponseEntity<?> reissueToken(HttpServletRequest request) {

        String accessToken = userService.reissueToken(request);

        return new ResponseEntity<>(accessToken, HttpStatus.OK);
    }

    @PostMapping("/logout")
    public void logout(HttpServletRequest request) {
        userService.logout(request);
    }

    @GetMapping("/testLogin")
    public ResponseEntity<TestLoginDto> testLogin() {

        User user = userService.testLogin();

        TestLoginDto response = new TestLoginDto(user.getEmail(), user.getUserRole());

        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
