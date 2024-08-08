package net.yuqiong.oauthserver.oauthserver.service;

import net.yuqiong.oauthserver.oauthserver.dto.UserInfoDTO;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
public class UserService {

    public UserInfoDTO getCurrentUserInfo() {
        UserInfoDTO userInfoDTO = null;
        // 从 SecurityContextHolder 中获取当前认证信息
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // 确保 Authentication 是 Jwt 类型
        if (authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();

            Object userInfo = jwt.getClaim("userInfo");
            userInfoDTO = new UserInfoDTO();

            if(userInfo!=null && userInfo instanceof Map<?,?>){
                Map<String, Object> map = (Map<String, Object>) userInfo;
                userInfoDTO.setUsername(map.get("username").toString());

                Object authsObj = map.get("authorities");
                if(authsObj!=null&&authsObj instanceof List<?>) {
                    List<Object> authorities = (List<Object>) map.get("authorities");
                    List<String> auths = new ArrayList<>();
                    for (Object auth : authorities) {
                        auths.add(auth.toString());
                    }
                    userInfoDTO.setAuthorities(auths);
                }
            }

            return userInfoDTO; // 获取 JWT 中的所有 claims
        }

        throw new IllegalArgumentException("Current principal is not an instance of Jwt");
    }

}
