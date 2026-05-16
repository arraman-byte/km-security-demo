package org.km.securitydemo.config;

import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Spring Security 7 enables PKCE for every authorization-code client by default
     * (ClientSettings.requireProofKey defaults to true). For the "raw Authorization Code"
     * teaching demo we deliberately want NO PKCE on the {@code keycloak-authcode}
     * registration so the audience can compare it to {@code keycloak-pkce} side by side.
     * Spring Boot does not yet expose this as a property, so we mutate the registration
     * after Boot has built the {@link ClientRegistrationRepository}.
     */
    @Bean
    public BeanPostProcessor disablePkceForRawAuthCodeClient() {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if (!(bean instanceof InMemoryClientRegistrationRepository repo)) {
                    return bean;
                }
                List<ClientRegistration> rebuilt = new ArrayList<>();
                for (ClientRegistration reg : repo) {
                    if ("keycloak-authcode".equals(reg.getRegistrationId())) {
                        rebuilt.add(ClientRegistration.withClientRegistration(reg)
                                .clientSettings(ClientRegistration.ClientSettings.builder()
                                        .requireProofKey(false)
                                        .build())
                                .build());
                    } else {
                        rebuilt.add(reg);
                    }
                }
                return new InMemoryClientRegistrationRepository(rebuilt);
            }
        };
    }

    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/**")
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        AuthenticationSuccessHandler successHandler = (request, response, authentication) -> {
            String target = "/flows/auth-code-pkce/result";
            if (authentication instanceof OAuth2AuthenticationToken token) {
                String reg = token.getAuthorizedClientRegistrationId();
                if ("keycloak-authcode".equals(reg)) {
                    target = "/flows/auth-code/result";
                }
            }
            response.sendRedirect(request.getContextPath() + target);
        };

        PathPatternRequestMatcher.Builder mvc = PathPatternRequestMatcher.withDefaults();
        http.csrf(csrf -> csrf.ignoringRequestMatchers(
                        mvc.matcher("/demo/device-code/**"),
                        mvc.matcher("/demo/implicit/**"),
                        mvc.matcher("/demo/oidc/**")))
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers(
                        "/",
                        "/flows/**",
                        "/oauth2/**",
                        "/login/**",
                        "/error",
                        "/demo/client-credentials",
                        "/demo/client-credentials/run",
                        "/demo/device-code/**",
                        "/demo/implicit/**",
                        "/demo/oidc/**",
                        "/css/**",
                        "/js/**",
                        "/webjars/**")
                    .permitAll()
                .requestMatchers("/profile", "/demo/refresh-info", "/demo/refresh-info/run")
                    .authenticated()
                .anyRequest()
                    .authenticated())
            .oauth2Login(oauth2 -> oauth2.successHandler(successHandler));
        return http.build();
    }
}
