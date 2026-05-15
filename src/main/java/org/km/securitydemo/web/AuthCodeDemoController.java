package org.km.securitydemo.web;

import org.km.securitydemo.demo.TokenDecoder;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthCodeDemoController {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final TokenDecoder tokenDecoder;

    public AuthCodeDemoController(OAuth2AuthorizedClientService authorizedClientService, TokenDecoder tokenDecoder) {
        this.authorizedClientService = authorizedClientService;
        this.tokenDecoder = tokenDecoder;
    }

    @GetMapping("/flows/auth-code")
    public String page() {
        return "flows/auth-code";
    }

    @GetMapping("/flows/auth-code/result")
    public String result(@AuthenticationPrincipal OidcUser user, Model model) {
        if (user == null) {
            return "redirect:/flows/auth-code";
        }
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                "keycloak-authcode", user.getName());

        model.addAttribute("user", user);
        model.addAttribute("idToken", tokenDecoder.decode(user.getIdToken().getTokenValue()));
        if (client != null) {
            model.addAttribute("accessToken", tokenDecoder.decode(client.getAccessToken().getTokenValue()));
            model.addAttribute("refreshToken",
                    client.getRefreshToken() != null
                            ? tokenDecoder.decode(client.getRefreshToken().getTokenValue())
                            : null);
        }
        return "flows/auth-code-result";
    }
}
