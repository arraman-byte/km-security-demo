package org.km.securitydemo.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    private final String issuerUri;

    public DashboardController(@Value("${demo.keycloak.issuer-uri}") String issuerUri) {
        this.issuerUri = issuerUri;
    }

    @GetMapping("/")
    public String index(@AuthenticationPrincipal OidcUser user, Model model) {
        model.addAttribute("issuer", issuerUri);
        model.addAttribute("username", user != null ? user.getPreferredUsername() : null);
        return "index";
    }

    @GetMapping("/flows/login-result")
    public String loginResult() {
        return "redirect:/flows/auth-code-pkce/result";
    }
}
