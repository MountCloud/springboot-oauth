package net.yuqiong.oauthserver.oauthserver.token;

import lombok.extern.slf4j.Slf4j;
import net.yuqiong.oauthserver.oauthserver.dto.UserInfoDTO;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.ArrayList;
import java.util.List;

@Slf4j
public class AppJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    /**
     * add custom claims to the JWT token
     * @param context the context containing the OAuth 2.0 Token attributes
     */
    @Override
    public void customize(JwtEncodingContext context) {
        log.info("customize jwt token");

        String grantType = context.getAuthorizationGrantType().getValue();
        context.getClaims().claim("grantType",grantType);

        if(context.getAuthorizationGrantType().equals(AuthorizationGrantType.PASSWORD)){
            //is user login
            context.getClaims().claim("grantType",grantType);
            Object obj = context.getPrincipal().getPrincipal();
            User user = (User) obj;

            //add user info to jwt token
            UserInfoDTO userInfoDTO = new UserInfoDTO();
            userInfoDTO.setUsername(user.getUsername());
            if(user.getAuthorities()!=null && user.getAuthorities().size()>0){
                List<String> userAuths = new ArrayList<>();
                user.getAuthorities().forEach(authority -> userAuths.add(authority.getAuthority()));
                userInfoDTO.setAuthorities(userAuths);
            }

            context.getClaims().claim("userInfo",userInfoDTO);
        }
//        else if(context.getAuthorizationGrantType().equals(AuthorizationGrantType.REFRESH_TOKEN)){
//            //is refresh token
//            context.getClaims().claim("grantType",grantType);
//        }else if(context.getAuthorizationGrantType().equals(AuthorizationGrantType.CLIENT_CREDENTIALS)){
//            //is refresh token
//            context.getClaims().claim("grantType",grantType);
//        }
    }
}
