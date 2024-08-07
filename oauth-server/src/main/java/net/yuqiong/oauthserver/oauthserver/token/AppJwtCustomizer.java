package net.yuqiong.oauthserver.oauthserver.token;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

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

        if(context.getAuthorizationGrantType().equals(AuthorizationGrantType.PASSWORD)){
            //is user login
            context.getClaims().claim("grantType",grantType);
            Object obj = context.getPrincipal().getPrincipal();
            System.out.printf("1");
        }
    }
}
