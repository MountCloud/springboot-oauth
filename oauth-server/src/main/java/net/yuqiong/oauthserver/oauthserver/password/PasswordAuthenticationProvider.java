package net.yuqiong.oauthserver.oauthserver.password;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * TODO:
 *
 * @Author: MountCloud
 * @Date: 2024年08月07日
 */
public class PasswordAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<OAuth2AccessToken> accessTokenGenerator;
    private final AuthenticationManager authenticationManager;

    public PasswordAuthenticationProvider(UserDetailsService userDetailsService,
                                          PasswordEncoder passwordEncoder,
                                          RegisteredClientRepository registeredClientRepository,
                                          OAuth2AuthorizationService authorizationService,
                                          AuthenticationManager authenticationManager,
                                          OAuth2TokenGenerator<OAuth2AccessToken> accessTokenGenerator) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.accessTokenGenerator = accessTokenGenerator;
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PasswordAuthenticationToken passwordAuthenticationToken = (PasswordAuthenticationToken) authentication;

        String username = passwordAuthenticationToken.getName();
        String password = (String) passwordAuthenticationToken.getCredentials();

        // 用户名密码身份验证，成功后返回带有权限的认证信息
        Authentication usernamePasswordAuthentication;
        try {
            usernamePasswordAuthentication = authenticationManager.authenticate(passwordAuthenticationToken);
        } catch (Exception e) {
            // 需要将其他类型的异常转换为 OAuth2AuthenticationException 才能被自定义异常捕获处理，逻辑源码 OAuth2TokenEndpointFilter#doFilterInternal
            throw new OAuth2AuthenticationException(e.getCause() != null ? e.getCause().getMessage() : e.getMessage());
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (userDetails == null || !passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new UsernameNotFoundException("Invalid username or password");
        }

        RegisteredClient registeredClient = registeredClientRepository.findByClientId("client");
        if (registeredClient == null) {
            throw new IllegalArgumentException("Invalid client");
        }
        Set<String> scopes = registeredClient.getScopes();
        // 访问令牌(Access Token) 构造器
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(usernamePasswordAuthentication) // 身份验证成功的认证信息(用户名、权限等信息)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(scopes)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD) // 授权方式
                .authorizationGrant(passwordAuthenticationToken) // 授权具体对象
                ;

        // 生成访问令牌(Access Token)
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType((OAuth2TokenType.ACCESS_TOKEN)).build();
        // 生成访问令牌

        org.springframework.security.oauth2.core.OAuth2Token generatedToken = accessTokenGenerator.generate(tokenContext);
        if (!(generatedToken instanceof Jwt)) {
            throw new IllegalArgumentException("Token generation failed");
        }
        Jwt jwt = (Jwt) generatedToken;

        // 将 JWT 包装为 OAuth2AccessToken
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                jwt.getTokenValue(),
                jwt.getIssuedAt(),
                jwt.getExpiresAt(),
                tokenContext.getAuthorizedScopes());

        if (accessToken == null) {
            throw new IllegalArgumentException(OAuth2ErrorCodes.SERVER_ERROR);
        }

        org.springframework.security.oauth2.core.OAuth2Token generatedRefreshToken = accessTokenGenerator.generate(tokenContext);

        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                UUID.randomUUID().toString(),
                generatedRefreshToken.getIssuedAt(),
                generatedRefreshToken.getExpiresAt());

        // 创建 OAuth2Authorization
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(username)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .authorizedScopes(scopes)
                .attribute(Principal.class.getName(), usernamePasswordAuthentication)
                .build();
        authorizationService.save(authorization);

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, usernamePasswordAuthentication, accessToken,refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private OAuth2RefreshToken generateRefreshToken(RegisteredClient registeredClient, Authentication principal) {
        // Generate a refresh token and return it
        // This logic needs to be implemented as per your requirements
        return new OAuth2RefreshToken("refresh-token-value", Instant.now(), Instant.now().plus(30, ChronoUnit.DAYS));
    }
}
