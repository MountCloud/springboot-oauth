package net.yuqiong.oauthserver.oauthserver.converter;

import net.yuqiong.oauthserver.oauthserver.utils.GrantTypeUtil;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * TODO:
 *
 * @Author: MountCloud
 * @Date: 2024年08月08日
 */
public class AppJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        String grantType = source.getClaim("grantType");
        AuthorizationGrantType type = GrantTypeUtil.getGrantType(grantType);

        Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(source);

        if(type==null){
            return authorities;
        }

        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        if(authorities!=null){
            grantedAuthorities.addAll(authorities);
        }

        if(type.equals(AuthorizationGrantType.PASSWORD)){
            //is user login
            Object obj = source.getClaim("userInfo");
            if(obj!=null && obj instanceof Map<?,?>){
                Map map = (Map) obj;
                Object userAuthsObj = map.get("authorities");
                if(userAuthsObj !=null && userAuthsObj instanceof List<?>){
                    List<Object> userAuths = (List<Object>) userAuthsObj;
                    for(Object auth : userAuths){
                        SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(auth.toString());
                        grantedAuthorities.add(simpleGrantedAuthority);
                    }
                }
            }
        }

        return grantedAuthorities;
    }
}
