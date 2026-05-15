package org.km.securitydemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

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

        http.authorizeHttpRequests(authorize -> authorize
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
