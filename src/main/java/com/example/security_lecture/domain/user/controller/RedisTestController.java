package com.example.security_lecture.domain.user.controller;

import com.example.security_lecture.domain.user.service.RedisService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/redis")
@RequiredArgsConstructor
public class RedisTestController {

    private final RedisService redisService;

    @PostMapping("/set")
    public String set(@RequestParam String key, @RequestParam String value) {
        redisService.setValue(key, value);
        return "저장 완료";
    }

    @GetMapping("/get")
    public String get(@RequestParam String key) {
        String value = redisService.getValue(key);
        return value != null ? value : "값 없음";
    }
}
