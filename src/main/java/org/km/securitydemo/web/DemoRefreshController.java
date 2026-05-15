package org.km.securitydemo.web;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.km.securitydemo.demo.TokenDecoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestClient;

@Controller
public class DemoRefreshController {

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final TokenDecoder tokenDecoder;

    public DemoRefreshController(
            ClientRegistrationRepository clientRegistrationRepository, TokenDecoder tokenDecoder) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.tokenDecoder = tokenDecoder;
    }

    @GetMapping("/flows/refresh")
    public String page(
            OAuth2AuthenticationToken auth,
            @RegisteredOAuth2AuthorizedClient("keycloak-pkce") OAuth2AuthorizedClient authorizedClient,
            Model model) {
        if (auth == null) {
            return "redirect:/oauth2/authorization/keycloak-pkce";
        }

        if (authorizedClient == null) {
            model.addAttribute("authorizedClient", null);
            return "flows/refresh";
        }
        model.addAttribute("hasRefreshToken", authorizedClient.getRefreshToken() != null);
        OAuth2AccessToken at = authorizedClient.getAccessToken();
        model.addAttribute("accessTokenExpiresAt", at != null ? at.getExpiresAt() : null);
        if (at != null) {
            model.addAttribute("accessToken", tokenDecoder.decode(at.getTokenValue()));
        }
        if (authorizedClient.getRefreshToken() != null) {
            model.addAttribute("refreshToken",
                    tokenDecoder.decode(authorizedClient.getRefreshToken().getTokenValue()));
        }
        return "flows/refresh";
    }

    /**
     * Forces a refresh by calling Keycloak's /token endpoint directly with grant_type=refresh_token.
     * Spring's default authorized-client manager only refreshes when the access token is already
     * expired; bypassing it lets the demo show a before/after every time.
     */
    @GetMapping("/demo/refresh-info/run")
    public String run(
            Authentication authentication,
            @RegisteredOAuth2AuthorizedClient("keycloak-pkce") OAuth2AuthorizedClient authorizedClient,
            Model model) {

        if (authorizedClient == null || authorizedClient.getRefreshToken() == null) {
            model.addAttribute("error", "No refresh token on this session. Login via PKCE with scope offline_access.");
            return "flows/refresh-result";
        }

        OAuth2AccessToken previousAccess = authorizedClient.getAccessToken();
        Instant previousExpiry = previousAccess != null ? previousAccess.getExpiresAt() : null;
        String previousAccessRaw = previousAccess != null ? previousAccess.getTokenValue() : null;

        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId("keycloak-pkce");
        String tokenUri = registration.getProviderDetails().getTokenUri();

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", authorizedClient.getRefreshToken().getTokenValue());
        form.add("client_id", registration.getClientId());
        if (registration.getClientSecret() != null && !registration.getClientSecret().isBlank()) {
            form.add("client_secret", registration.getClientSecret());
        }

        Map<?, ?> response;
        try {
            response = RestClient.create()
                    .post()
                    .uri(tokenUri)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(form)
                    .retrieve()
                    .body(Map.class);
        } catch (RuntimeException ex) {
            model.addAttribute("error",
                    "Refresh failed at " + tokenUri + ": " + ex.getClass().getSimpleName() + " - " + ex.getMessage());
            return "flows/refresh-result";
        }

        if (response == null) {
            model.addAttribute("error", "Empty response from token endpoint.");
            return "flows/refresh-result";
        }

        String newAccess = (String) response.get("access_token");
        String newRefresh = (String) response.get("refresh_token");

        Map<String, Object> before = new LinkedHashMap<>();
        before.put("expiresAt", previousExpiry != null ? previousExpiry.toString() : null);
        model.addAttribute("before", before);
        model.addAttribute("previousAccessToken", previousAccessRaw != null ? tokenDecoder.decode(previousAccessRaw) : null);
        model.addAttribute("newAccessToken", newAccess != null ? tokenDecoder.decode(newAccess) : null);
        model.addAttribute("newRefreshToken", newRefresh != null ? tokenDecoder.decode(newRefresh) : null);
        model.addAttribute("rotated",
                newRefresh != null && !newRefresh.equals(authorizedClient.getRefreshToken().getTokenValue()));
        return "flows/refresh-result";
    }
}
