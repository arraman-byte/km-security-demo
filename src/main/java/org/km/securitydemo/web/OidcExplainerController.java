package org.km.securitydemo.web;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

@Controller
public class OidcExplainerController {

    private final String issuerUri;
    private final RestClient http = RestClient.create();

    public OidcExplainerController(@Value("${demo.keycloak.issuer-uri}") String issuerUri) {
        this.issuerUri = issuerUri;
    }

    @GetMapping("/flows/oidc-vs-oauth")
    public String page(@AuthenticationPrincipal OidcUser user, Model model) {
        model.addAttribute("issuer", issuerUri);
        model.addAttribute("loggedIn", user != null);
        return "flows/oidc-vs-oauth";
    }

    @GetMapping("/demo/oidc/discovery")
    @ResponseBody
    public ResponseEntity<Map<?, ?>> discovery() {
        try {
            Map<?, ?> disc = http.get()
                    .uri(issuerUri + "/.well-known/openid-configuration")
                    .retrieve()
                    .body(Map.class);
            return ResponseEntity.ok(disc);
        } catch (RuntimeException ex) {
            Map<String, Object> err = new LinkedHashMap<>();
            err.put("error", ex.getClass().getSimpleName());
            err.put("message", ex.getMessage());
            return ResponseEntity.status(502).body(err);
        }
    }

    @GetMapping("/demo/oidc/userinfo")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> userinfo(
            @RegisteredOAuth2AuthorizedClient("keycloak-pkce") OAuth2AuthorizedClient client) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (client == null) {
            out.put("error", "not_authenticated");
            out.put("message", "Login via PKCE first.");
            return ResponseEntity.status(401).body(out);
        }
        String userinfoEndpoint = issuerUri + "/protocol/openid-connect/userinfo";
        try {
            Map<?, ?> resp = http.get()
                    .uri(userinfoEndpoint)
                    .headers(h -> h.setBearerAuth(client.getAccessToken().getTokenValue()))
                    .retrieve()
                    .body(Map.class);
            out.put("endpoint", userinfoEndpoint);
            out.put("status", 200);
            out.put("response", resp);
            return ResponseEntity.ok(out);
        } catch (RestClientResponseException ex) {
            out.put("endpoint", userinfoEndpoint);
            out.put("status", ex.getStatusCode().value());
            out.put("response", ex.getResponseBodyAsString());
            return ResponseEntity.ok(out);
        } catch (RuntimeException ex) {
            out.put("error", ex.getClass().getSimpleName());
            out.put("message", ex.getMessage());
            return ResponseEntity.status(502).body(out);
        }
    }
}
