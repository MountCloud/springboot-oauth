package net.yuqiong.oauthserver.oauthserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import net.yuqiong.oauthserver.oauthserver.password.PasswordAuthenticationConverter;
import net.yuqiong.oauthserver.oauthserver.password.PasswordAuthenticationProvider;
import net.yuqiong.oauthserver.oauthserver.token.KeyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig  {

    @Autowired
    private KeyService keyService;

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
                                                                      UserDetailsService userDetailsService,
                                                                      PasswordEncoder passwordEncoder,
                                                                      RegisteredClientRepository registeredClientRepository,
                                                                      OAuth2AuthorizationService oAuth2AuthorizationService,
                                                                      AuthenticationManager authenticationManager,
                                                                      OAuth2TokenGenerator<OAuth2AccessToken> tokenGenerator

    ) throws Exception {
//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        authorizationServerConfigurer
                .tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint
                                .accessTokenRequestConverters(
                                        authenticationConverters ->// <1>
                                                authenticationConverters.addAll(
                                                        // 自定义授权模式转换器(Converter)
                                                        List.of(
                                                                new PasswordAuthenticationConverter()
                                                        )
                                                )
                                )
                                .authenticationProviders(authenticationProviders ->// <2>
                                        authenticationProviders.addAll(
                                                // 自定义授权模式提供者(Provider)
                                                List.of(
                                                        new PasswordAuthenticationProvider(userDetailsService,
                                                                passwordEncoder,
                                                                registeredClientRepository,
                                                                oAuth2AuthorizationService,
                                                                authenticationManager,
                                                                tokenGenerator
                                                        )
                                                )
                                        )
                                )
//                                .accessTokenResponseHandler(new MyAuthenticationSuccessHandler()) // 自定义成功响应
//                                .errorResponseHandler(new MyAuthenticationFailureHandler()) // 自定义失败响应
                );


        RequestMatcher endpointsMatcher = authorizationServerConfigurer
                .getEndpointsMatcher();

        http
                .securityMatcher(endpointsMatcher)
                .authorizeHttpRequests((authorize) ->
                        authorize.anyRequest().authenticated()
                )
                .csrf((csrf) -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationServerConfigurer);

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret(passwordEncoder().encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD) // 支持密码模式（尽管过时）
                .redirectUri("http://localhost:8080/login/oauth2/code/client-oidc")
                .redirectUri("http://localhost:8080/authorized")
                .scope("read")
                .scope("write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(1)).build())
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtEncoder jwtEncoder() throws NoSuchAlgorithmException {
        JWKSource<SecurityContext> jwkSource = jwkSource();
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(keyService.getAccessTokenPublicKey()).build();
    }

    private JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = new RSAKey.Builder(keyService.getAccessTokenPublicKey())
                .privateKey(keyService.getAccessTokenPrivateKey())
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        JWKSource<SecurityContext> jwkSource = jwkSource();
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator);
    }

//    @Bean
//    public AuthenticationManager authenticationManager(HttpSecurity http,PasswordAuthenticationProvider passwordAuthenticationProvider) throws Exception {
//        return http.getSharedObject(AuthenticationManagerBuilder.class)
//                .authenticationProvider(passwordAuthenticationProvider)
//                .build();
//    }
//
//    @Bean
//    public PasswordAuthenticationToken passwordAuthenticationToken(OAuth2TokenContext context) {
//        return new PasswordAuthenticationToken(null,null);
//    }


}
