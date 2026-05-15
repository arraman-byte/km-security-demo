package org.km.securitydemo.web;

import java.util.LinkedHashMap;
import java.util.Map;
import org.km.securitydemo.demo.TokenDecoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Implicit flow: teaching-only. The token is returned by Keycloak in the URL fragment
 * (#access_token=...&id_token=...), so JavaScript reads it directly and posts back to
 * us for decoding. No server-side state.
 */
@Controller
public class ImplicitDemoController {

    private final String issuerUri;
    private final String clientId;
    private final TokenDecoder tokenDecoder;

    public ImplicitDemoController(
            @Value("${demo.keycloak.issuer-uri}") String issuerUri,
            @Value("${demo.implicit.client-id}") String clientId,
            TokenDecoder tokenDecoder) {
        this.issuerUri = issuerUri;
        this.clientId = clientId;
        this.tokenDecoder = tokenDecoder;
    }

    @GetMapping("/flows/implicit")
    public String page(Model model) {
        model.addAttribute("issuer", issuerUri);
        model.addAttribute("clientId", clientId);
        model.addAttribute("authorizeEndpoint", issuerUri + "/protocol/openid-connect/auth");
        model.addAttribute("redirectUri", "http://localhost:8081/flows/implicit/callback");
        return "flows/implicit";
    }

    @GetMapping("/flows/implicit/callback")
    public String callback() {
        return "flows/implicit-callback";
    }

    @GetMapping("/demo/implicit/decode")
    @ResponseBody
    public Map<String, Object> decode(
            @RequestParam(value = "access_token", required = false) String accessToken,
            @RequestParam(value = "id_token", required = false) String idToken) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (accessToken != null) body.put("accessToken", tokenDecoder.decode(accessToken));
        if (idToken != null) body.put("idToken", tokenDecoder.decode(idToken));
        return body;
    }
}
