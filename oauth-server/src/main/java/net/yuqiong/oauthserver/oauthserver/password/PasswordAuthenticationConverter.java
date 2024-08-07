package net.yuqiong.oauthserver.oauthserver.password;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * TODO:
 * @Author: MountCloud
 * @Date: 2024年08月07日
 */
public class PasswordAuthenticationConverter implements AuthenticationConverter {


    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter("grant_type");
        if (!"password".equals(grantType)) {
            return null;
        }

        String username = request.getParameter("username");
        String password = request.getParameter("password");
        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            return null;
        }

        return new PasswordAuthenticationToken(username, password);
    }
}
