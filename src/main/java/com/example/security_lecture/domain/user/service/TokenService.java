package com.example.security_lecture.domain.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/* TokenService는 왜 util(component)가 아니라 service 인가
    1. 외부 시스템 연동 : redis는 db처럼 별도의 저장소 이기 때문에 직접 연결은 service 계층에서 담당하는게 맞다
    2. 재사용 가능 : 로그인, 로그아웃, 토큰 재발급 등 다양한 곳에서 호출될 수 있다
    3. 비지니스 로직 일부 : 사용자 식별자 기반으로 토큰 저장, ttl 설정 등은 단순 기술 처리 이상의 의미
*/
@Service
@RequiredArgsConstructor
public class TokenService {

    private final StringRedisTemplate redisTemplate;

    /* key = RT:{userId}, value = refreshToken, TTL = 7일
       opsForValue : redis의 String 타입에 대한 작업을 수행할 수 있는 인터페이스 제공
       redisTemplate.opsForValue().set(key,value) -> SET key value 랑 같다
     */
    public void saveRefreshToken(Long userId, String refreshToken) {

        String key = "RT:" + userId;

        redisTemplate.opsForValue().set(key, refreshToken, 7, TimeUnit.DAYS);
    }

    public String getRefreshToken(Long userId) {
        return redisTemplate.opsForValue().get("RT:" + userId);
    }

    public void deleteRefreshToken(Long userId) {
        redisTemplate.delete("RT:" + userId);
    }

}
