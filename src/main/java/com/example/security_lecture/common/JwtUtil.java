package com.example.security_lecture.common;

import com.example.security_lecture.domain.user.entity.UserRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {

    private static final long ACCESS_TOKEN_EXPIRATION = 1000L * 60 * 60; // 토큰 만료 시간

    private static final long REFRESH_TOKEN_EXPIRATION = 1000L * 60 * 60 * 24 * 7;

    @Value("${jwt.secret}")
    private String secretKey; // signature를 만드는게 필요한 secretkey, value를 통해 properties에서 환경변수로 설정

    private Key key; // secretkey는 단순한 문자열이기 때문에 실제 인증인가에 사용할 key라는 객체 필요

    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    @PostConstruct // 의존성 주입 이후에 자동 호출 메서드, 생성자나 autowired로 해결이 어려운 초기화 작업을 넣는 어노테이션
    public void init() {
        key = Keys.hmacShaKeyFor(secretKey.getBytes()); // secretkey를 단순한 문자열에서 jwt 서명에 쓸수있는 key 객체로 바꿔주는 역할
    }

    public String createAccessToken(Long userId, String email, UserRole uesrRole) { // access 토큰 생성 메서드
        Date now = new Date();
        Date expiration = new Date(now.getTime() + ACCESS_TOKEN_EXPIRATION);

        return Jwts.builder()
                .setSubject(String.valueOf(userId)) // 주제설정, string 으로만 주입 가능
                .claim("email", email)
                .claim("userRole", uesrRole)
                .setIssuedAt(now) // 발급날짜
                .setExpiration(expiration) // 만료날짜
                .signWith(key, signatureAlgorithm) // 암호화 알고리즘
                .compact();
    }

    public String createRefreshToken(Long userId) { // refresh 토큰 생성 메서드
        Date now = new Date();
        Date expiration = new Date(now.getTime() + REFRESH_TOKEN_EXPIRATION);

        return Jwts.builder()
                .setSubject(String.valueOf(userId)) // 주제설정, string 으로만 주입 가능
                .setIssuedAt(now) // 발급날짜
                .setExpiration(expiration) // 만료날짜
                .signWith(key, signatureAlgorithm) // 암호화 알고리즘
                .compact();
    }

    public Claims getClaims(String token) { // jwt 토큰을 파싱하고 내부(payload)에 있는 정보들을 꺼내오기 위함
        return Jwts.parserBuilder() // 토큰을 검증하고 해석하려면 parserBuilder로 시작해야함
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token) { // 토큰 유효성 검증
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }
}
