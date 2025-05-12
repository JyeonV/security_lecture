package com.example.security_lecture.domain.user.dto;

import com.example.security_lecture.domain.user.entity.UserRole;
import lombok.Getter;

@Getter
public class TestLoginDto {

    private String email;

    private UserRole userRole;

    public TestLoginDto(String email, UserRole userRole) {
        this.email = email;
        this.userRole = userRole;
    }
}
