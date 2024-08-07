package net.yuqiong.oauthserver.oauthserver.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class UserService {

    public Map<String, Object> getCurrentUserInfo() {
        // 从 SecurityContextHolder 中获取当前认证信息
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // 确保 Authentication 是 Jwt 类型
        if (authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            return jwt.getClaims(); // 获取 JWT 中的所有 claims
        }

        throw new IllegalArgumentException("Current principal is not an instance of Jwt");
    }

}
