package org.km.securitydemo.web;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import org.km.securitydemo.demo.TokenDecoder;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PkceDemoController {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final TokenDecoder tokenDecoder;

    public PkceDemoController(OAuth2AuthorizedClientService authorizedClientService, TokenDecoder tokenDecoder) {
        this.authorizedClientService = authorizedClientService;
        this.tokenDecoder = tokenDecoder;
    }

    @GetMapping("/flows/auth-code-pkce")
    public String page(Model model) {
        // Generate a fresh verifier/challenge purely for display so the audience can see
        // what shape these values take. Spring Security generates its own at redirect time.
        byte[] verifierBytes = new byte[32];
        RANDOM.nextBytes(verifierBytes);
        String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(verifierBytes);
        String challenge = sha256Base64Url(verifier);

        model.addAttribute("sampleVerifier", verifier);
        model.addAttribute("sampleChallenge", challenge);
        model.addAttribute("startUrl", "/oauth2/authorization/keycloak-pkce");
        return "flows/auth-code-pkce";
    }

    @GetMapping("/flows/auth-code-pkce/result")
    public String result(@AuthenticationPrincipal OidcUser user, Model model) {
        if (user == null) {
            return "redirect:/flows/auth-code-pkce";
        }
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                "keycloak-pkce", user.getName());

        model.addAttribute("user", user);
        model.addAttribute("idToken", tokenDecoder.decode(user.getIdToken().getTokenValue()));
        if (client != null) {
            model.addAttribute("accessToken", tokenDecoder.decode(client.getAccessToken().getTokenValue()));
            model.addAttribute("refreshToken",
                    client.getRefreshToken() != null
                            ? tokenDecoder.decode(client.getRefreshToken().getTokenValue())
                            : null);
        }
        return "flows/auth-code-pkce-result";
    }

    private static String sha256Base64Url(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
