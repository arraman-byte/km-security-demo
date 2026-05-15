package org.km.securitydemo.demo;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

/**
 * Decodes JWTs for display in the demo dashboard. Two paths:
 * <ul>
 *   <li>"unsafe" Base64URL split — always works, never verifies signature.</li>
 *   <li>Issuer-backed JwtDecoder — verifies signature/issuer/exp; surfaces a boolean.</li>
 * </ul>
 */
@Component
public class TokenDecoder {

    private static final ObjectMapper MAPPER = JsonMapper.builder().build();

    private final String issuerUri;
    private volatile JwtDecoder verifyingDecoder;

    public TokenDecoder(@Value("${demo.keycloak.issuer-uri}") String issuerUri) {
        this.issuerUri = issuerUri;
    }

    public Map<String, Object> decode(String token) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (token == null || token.isBlank()) {
            result.put("present", false);
            return result;
        }
        result.put("present", true);
        result.put("raw", token);
        result.put("length", token.length());

        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            result.put("error", "Not a JWT (no dot-separated segments).");
            return result;
        }
        try {
            Map<String, Object> header = parseJsonSegment(parts[0]);
            Map<String, Object> claims = parseJsonSegment(parts[1]);
            result.put("header", header);
            result.put("claims", claims);
            result.put("headerJson", pretty(header));
            result.put("claimsJson", pretty(claims));

            Object exp = claims.get("exp");
            if (exp instanceof Number n) {
                Instant expiresAt = Instant.ofEpochSecond(n.longValue());
                result.put("expiresAt", expiresAt.toString());
                long secs = Duration.between(Instant.now(), expiresAt).toSeconds();
                result.put("expiresInSeconds", secs);
                result.put("expired", secs <= 0);
            }
            Object iss = claims.get("iss");
            if (iss != null) {
                result.put("issuer", iss.toString());
            }
            Object sub = claims.get("sub");
            if (sub != null) {
                result.put("subject", sub.toString());
            }
        } catch (RuntimeException ex) {
            result.put("error", "Failed to parse JWT segments: " + ex.getMessage());
            return result;
        }

        // Best-effort signature verification (skip if not a Keycloak JWT, e.g. opaque)
        try {
            Jwt verified = verifier().decode(token);
            result.put("signatureValid", true);
            result.put("verifiedAt", Instant.now().toString());
            result.put("verifiedIssuer", verified.getIssuer() != null ? verified.getIssuer().toString() : null);
        } catch (JwtException ex) {
            result.put("signatureValid", false);
            result.put("signatureError", ex.getMessage());
        } catch (RuntimeException ex) {
            result.put("signatureValid", false);
            result.put("signatureError", ex.getClass().getSimpleName() + ": " + ex.getMessage());
        }
        return result;
    }

    private static Map<String, Object> parseJsonSegment(String segment) {
        byte[] decoded = Base64.getUrlDecoder().decode(padBase64(segment));
        try {
            return MAPPER.readValue(new String(decoded, StandardCharsets.UTF_8), new TypeReference<>() {});
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex);
        }
    }

    private static String padBase64(String input) {
        int rem = input.length() % 4;
        if (rem == 0) {
            return input;
        }
        return input + "====".substring(rem);
    }

    private static String pretty(Object value) {
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(value);
        } catch (Exception ex) {
            return String.valueOf(value);
        }
    }

    private JwtDecoder verifier() {
        JwtDecoder local = this.verifyingDecoder;
        if (local == null) {
            synchronized (this) {
                if (this.verifyingDecoder == null) {
                    this.verifyingDecoder = JwtDecoders.fromIssuerLocation(issuerUri);
                }
                local = this.verifyingDecoder;
            }
        }
        return local;
    }
}
