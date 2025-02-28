package com.restaurant.api.authorizationserver.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.restaurant.api.authorizationserver.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        var authorizationServerConfigure = OAuth2AuthorizationServerConfigurer.authorizationServer();
        http.securityMatcher(authorizationServerConfigure.getEndpointsMatcher())
                .with(authorizationServerConfigure, authorizationServer ->
                        authorizationServer.oidc(Customizer.withDefaults())    // Enable OpenID Connect 1.0
                ).authorizeHttpRequests(authorize ->
                        authorize.anyRequest().authenticated()
                ).exceptionHandling(exceptions ->
                        exceptions.defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize ->
                authorize.anyRequest().authenticated()
        ).formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        RegisteredClient appRestaurant = RegisteredClient.withId("1")
                .clientId("app-restaurant")
                .clientSecret(passwordEncoder.encode("backend123"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("READ")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .build())
                .build();

        RegisteredClient appRestaurantWeb = RegisteredClient.withId("2")
                .clientId("app-restaurant-mobile")
                .clientSecret(passwordEncoder.encode("mobile123"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("READ")
                .scope("WRITE")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .reuseRefreshTokens(false)
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .build())
                .redirectUri("http://127.0.0.1:8000/authorized")
                .postLogoutRedirectUri("http://127.0.0.1:8000/")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .build();
        return new InMemoryRegisteredClientRepository(Arrays.asList(appRestaurant, appRestaurantWeb));
    }

    @Bean
    public JWKSource<SecurityContext> securityContextJWKSource(JwtKeyStoreProperties jwtKeyStoreProperties) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, JOSEException {
        char[] keyStorePass = jwtKeyStoreProperties.getPassword().toCharArray();
        String keypairAlias = jwtKeyStoreProperties.getKeypairAlias();
        Resource jksLocation = jwtKeyStoreProperties.getJksLocation();
        InputStream inputStream = jksLocation.getInputStream();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(inputStream, keyStorePass);
        RSAKey rsaKey = RSAKey.load(keyStore, keypairAlias, keyStorePass);
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(AuthorizationServerSecurityProperties properties) {
        return AuthorizationServerSettings.builder()
                .issuer(properties.getProviderUrl())
                .build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtEncodingContextOAuth2TokenCustomizer(UserRepository userRepository) {
        return context -> {
            Authentication authentication = context.getPrincipal();
            if (authentication.getPrincipal() instanceof User principal) {
                com.restaurant.api.authorizationserver.entity.User user = userRepository.findByEmail(principal.getUsername())
                        .orElseThrow(EntityNotFoundException::new);
                Set<String> authorities = new HashSet<>();
                for (GrantedAuthority grantedAuthority : principal.getAuthorities()) {
                    authorities.add(grantedAuthority.getAuthority());
                }
                context.getClaims().claim("user_id", user.getId().toString());
                context.getClaims().claim("fullname", user.getFullname());
                context.getClaims().claim("username", user.getUsername());
                context.getClaims().claim("email", user.getEmail());
                context.getClaims().claim("language_code", user.getLanguageCode());
                context.getClaims().claim("currency_code", user.getCurrencyCode());
                context.getClaims().claim("timezone", user.getTimezone());
                context.getClaims().claim("authorities", authorities);
                context.getClaims().claim("creation_date", user.getCreationDate().toString());
            }
        };
    }

}
