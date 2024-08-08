package net.yuqiong.oauthserver.oauthserver.utils;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * TODO:
 *
 * @Author: MountCloud
 * @Date: 2024年08月08日
 */
public class GrantTypeUtil {

    public static AuthorizationGrantType getGrantType(String grantType){
        if(grantType.equals("password")){
            return AuthorizationGrantType.PASSWORD;
        }else if(grantType.equals("refresh_token")){
            return AuthorizationGrantType.REFRESH_TOKEN;
        }else if(grantType.equals("client_credentials")){
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
        }
        return null;
    }

}
