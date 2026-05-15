package org.km.securitydemo.demo;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

@Service
public class ClientCredentialsDemoService {

    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final TokenDecoder tokenDecoder;

    @Value("${demo.app-base-url}")
    private String appBaseUrl;

    public ClientCredentialsDemoService(
            OAuth2AuthorizedClientManager authorizedClientManager, TokenDecoder tokenDecoder) {
        this.authorizedClientManager = authorizedClientManager;
        this.tokenDecoder = tokenDecoder;
    }

    public Map<String, Object> runDemo() {
        Map<String, Object> body = new LinkedHashMap<>();

        Authentication principal = new UsernamePasswordAuthenticationToken(
                "client-credentials-demo", "n/a", java.util.Collections.emptyList());
        OAuth2AuthorizeRequest request = OAuth2AuthorizeRequest.withClientRegistrationId("keycloak-m2m")
                .principal(principal)
                .build();

        OAuth2AuthorizedClient client;
        try {
            client = authorizedClientManager.authorize(request);
        } catch (RuntimeException ex) {
            body.put("status", "error");
            body.put(
                    "errorMessage",
                    "Token request failed (Keycloak unreachable or invalid client; check KEYCLOAK_M2M_* env vars).");
            body.put("errorType", ex.getClass().getSimpleName());
            return body;
        }

        if (client == null || client.getAccessToken() == null) {
            body.put("status", "error");
            body.put("errorMessage", "Token request failed (check Keycloak client and KEYCLOAK_M2M_CLIENT_SECRET).");
            return body;
        }

        body.put("status", "ok");
        body.put("accessToken", tokenDecoder.decode(client.getAccessToken().getTokenValue()));
        body.put("apiUrl", appBaseUrl + "/api/demo");

        RestClient http = RestClient.create();
        try {
            String responseBody = http.get()
                    .uri(appBaseUrl + "/api/demo")
                    .headers(h -> h.setBearerAuth(client.getAccessToken().getTokenValue()))
                    .retrieve()
                    .body(String.class);
            body.put("apiStatus", 200);
            body.put("apiResponse", responseBody);
        } catch (RestClientResponseException ex) {
            HttpStatusCode status = ex.getStatusCode();
            body.put("apiStatus", status.value());
            body.put("apiResponse", ex.getResponseBodyAsString());
        } catch (RuntimeException ex) {
            body.put("apiStatus", -1);
            body.put("apiResponse", ex.getClass().getSimpleName() + ": " + ex.getMessage());
        }
        return body;
    }
}
