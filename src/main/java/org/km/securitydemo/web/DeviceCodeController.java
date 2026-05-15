package org.km.securitydemo.web;

import java.util.LinkedHashMap;
import java.util.Map;
import org.km.securitydemo.demo.TokenDecoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

/**
 * RFC 8628 Device Authorization Grant against Keycloak.
 *
 * <p>Page renders a "Start" button; JS posts to /demo/device-code/start to obtain a
 * (user_code, verification_uri, device_code) and then polls /demo/device-code/poll
 * until Keycloak issues tokens or the code expires.
 */
@Controller
public class DeviceCodeController {

    private final String issuerUri;
    private final String clientId;
    private final TokenDecoder tokenDecoder;
    private final RestClient http = RestClient.create();

    private volatile Map<String, String> cachedEndpoints;

    public DeviceCodeController(
            @Value("${demo.keycloak.issuer-uri}") String issuerUri,
            @Value("${demo.device.client-id}") String clientId,
            TokenDecoder tokenDecoder) {
        this.issuerUri = issuerUri;
        this.clientId = clientId;
        this.tokenDecoder = tokenDecoder;
    }

    @GetMapping("/flows/device-code")
    public String page(Model model) {
        model.addAttribute("clientId", clientId);
        model.addAttribute("issuer", issuerUri);
        return "flows/device-code";
    }

    @PostMapping("/demo/device-code/start")
    @ResponseBody
    public Map<String, Object> start() {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, String> ep;
        try {
            ep = endpoints();
        } catch (RuntimeException ex) {
            out.put("error", "discovery_failed");
            out.put("message", ex.getMessage());
            return out;
        }
        String deviceEndpoint = ep.get("device_authorization_endpoint");
        if (deviceEndpoint == null) {
            out.put("error", "no_device_endpoint");
            out.put("message", "Realm discovery has no device_authorization_endpoint. Enable Device flow on the client.");
            return out;
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("scope", "openid profile email");

        try {
            Map<?, ?> resp = http.post()
                    .uri(deviceEndpoint)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(form)
                    .retrieve()
                    .body(Map.class);
            if (resp == null) {
                out.put("error", "empty_response");
                return out;
            }
            out.putAll((Map<String, Object>) resp);
            return out;
        } catch (RestClientResponseException ex) {
            out.put("error", "http_" + ex.getStatusCode().value());
            out.put("message", ex.getResponseBodyAsString());
            return out;
        } catch (RuntimeException ex) {
            out.put("error", "request_failed");
            out.put("message", ex.getMessage());
            return out;
        }
    }

    @PostMapping("/demo/device-code/poll")
    @ResponseBody
    public Map<String, Object> poll(@RequestParam("device_code") String deviceCode) {
        Map<String, Object> out = new LinkedHashMap<>();
        String tokenEndpoint = endpoints().get("token_endpoint");

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
        form.add("device_code", deviceCode);

        try {
            Map<?, ?> resp = http.post()
                    .uri(tokenEndpoint)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(form)
                    .retrieve()
                    .body(Map.class);
            if (resp == null) {
                out.put("status", "error");
                return out;
            }
            out.put("status", "done");
            String at = (String) resp.get("access_token");
            String idt = (String) resp.get("id_token");
            String rt = (String) resp.get("refresh_token");
            if (at != null) {
                out.put("accessToken", tokenDecoder.decode(at));
            }
            if (idt != null) {
                out.put("idToken", tokenDecoder.decode(idt));
            }
            if (rt != null) {
                out.put("refreshToken", tokenDecoder.decode(rt));
            }
            return out;
        } catch (RestClientResponseException ex) {
            String body = ex.getResponseBodyAsString();
            String error = extractError(body);
            if ("authorization_pending".equals(error) || "slow_down".equals(error)) {
                out.put("status", "pending");
                out.put("oauthError", error);
                return out;
            }
            out.put("status", "error");
            out.put("oauthError", error);
            out.put("message", body);
            return out;
        } catch (RuntimeException ex) {
            out.put("status", "error");
            out.put("message", ex.getMessage());
            return out;
        }
    }

    private static String extractError(String body) {
        if (body == null) return null;
        int i = body.indexOf("\"error\"");
        if (i < 0) return null;
        int colon = body.indexOf(':', i);
        int q1 = body.indexOf('"', colon + 1);
        int q2 = body.indexOf('"', q1 + 1);
        if (q1 < 0 || q2 < 0) return null;
        return body.substring(q1 + 1, q2);
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> endpoints() {
        Map<String, String> local = this.cachedEndpoints;
        if (local != null) {
            return local;
        }
        Map<String, Object> disc = http.get()
                .uri(issuerUri + "/.well-known/openid-configuration")
                .retrieve()
                .body(Map.class);
        if (disc == null) {
            throw new IllegalStateException("Empty discovery response");
        }
        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : disc.entrySet()) {
            if (e.getValue() instanceof String s) {
                result.put(e.getKey(), s);
            }
        }
        this.cachedEndpoints = result;
        return result;
    }
}
