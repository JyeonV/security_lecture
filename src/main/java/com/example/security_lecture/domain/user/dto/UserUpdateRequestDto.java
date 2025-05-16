package com.example.security_lecture.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class UserUpdateRequestDto {

    @NotBlank(message = "비밀번호는 필수 입력 대상입니다.")
    private String password;

    private String newEmail;

    private String newPassword;

    public boolean hasNewEmail() {
        return newEmail != null && !newEmail.isBlank();
    }

    public boolean hasNewPassword() {
        return newPassword != null && !newPassword.isBlank();
    }

}
