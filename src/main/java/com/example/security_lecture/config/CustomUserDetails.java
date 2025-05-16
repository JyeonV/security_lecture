package com.example.security_lecture.config;

import com.example.security_lecture.domain.user.entity.UserRole;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Getter
public class CustomUserDetails implements UserDetails {

    private final Long id;

    private final String email;

    private final UserRole userRole;

    public CustomUserDetails(Long id, String email, UserRole userRole) {
        this.id = id;
        this.email = email;
        this.userRole = userRole;
    }

    // 권한 설정 -> GrantedAuthority 인터페이스로 관리
    // security 는 내부적으로 권한을 식별할 때 ROLE_ prefix가 있는지 확인하기 때문에 붙여준다
    // security 는 기본적으로 권한이 여러 개일 수 있다는 전제가 기반이므로 list 이며 실제로 밑에서 권한을 추가 가능
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { return List.of(() -> "ROLE_" + userRole.name()); }

    @Override
    public String getPassword() { return ""; }

    @Override
    public String getUsername() { return email; }

    @Override // false 일 경우 : 계정이 만료되어 로그인 불가
    public boolean isAccountNonExpired() { return true; }

    @Override // false 일 경우 : 계정이 잠금처리 되어 로그인 불가
    public boolean isAccountNonLocked() { return true; }

    @Override // false 일 경우 : 비밀번호 유효기간이 만료되어 로그인 불가
    public boolean isCredentialsNonExpired() { return true; }

    @Override // false 일 경우 : 계정이 비활성화됨
    public boolean isEnabled() { return true; }
}
