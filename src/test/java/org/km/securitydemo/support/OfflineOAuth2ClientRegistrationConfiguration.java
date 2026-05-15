package org.km.securitydemo.support;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

/**
 * Prevents live OIDC discovery to Keycloak during tests. Production uses
 * {@code application.properties} registrations resolved from the issuer.
 */
@TestConfiguration
public class OfflineOAuth2ClientRegistrationConfiguration {

    private static final String AUTH_BASE = "https://auth.invalid.example";

    @Bean
    @Primary
    ClientRegistrationRepository offlineClientRegistrationRepository() {
        ClientRegistration pkce = ClientRegistration.withRegistrationId("keycloak-pkce")
                .clientId("test-pkce")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .scope("openid", "profile", "email", "offline_access")
                .authorizationUri(AUTH_BASE + "/protocol/openid-connect/auth")
                .tokenUri(AUTH_BASE + "/protocol/openid-connect/token")
                .jwkSetUri(AUTH_BASE + "/protocol/openid-connect/certs")
                .userInfoUri(AUTH_BASE + "/protocol/openid-connect/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .issuerUri(AUTH_BASE + "/realms/auth-server")
                .build();

        ClientRegistration authcode = ClientRegistration.withRegistrationId("keycloak-authcode")
                .clientId("test-authcode")
                .clientSecret("test-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .scope("openid", "profile", "email", "offline_access")
                .authorizationUri(AUTH_BASE + "/protocol/openid-connect/auth")
                .tokenUri(AUTH_BASE + "/protocol/openid-connect/token")
                .jwkSetUri(AUTH_BASE + "/protocol/openid-connect/certs")
                .userInfoUri(AUTH_BASE + "/protocol/openid-connect/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .issuerUri(AUTH_BASE + "/realms/auth-server")
                .build();

        ClientRegistration m2m = ClientRegistration.withRegistrationId("keycloak-m2m")
                .clientId("test-m2m")
                .clientSecret("test-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenUri(AUTH_BASE + "/protocol/openid-connect/token")
                .build();

        return new InMemoryClientRegistrationRepository(pkce, authcode, m2m);
    }
}
