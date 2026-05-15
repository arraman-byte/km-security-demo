package org.km.securitydemo.web;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiDemoController {

    @GetMapping("/api/demo")
    public Map<String, Object> demo(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", "Resource server accepted this Bearer JWT.");
        body.put("subject", jwt.getSubject());
        body.put("issuer", jwt.getIssuer() != null ? jwt.getIssuer().toString() : null);
        body.put("audience", jwt.getAudience());
        body.put("scopes", jwt.getClaim("scope"));
        body.put("expiresAt", jwt.getExpiresAt());
        return body;
    }
}
