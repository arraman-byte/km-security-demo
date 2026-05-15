package org.km.securitydemo.demo;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TokenDecoderTests {

    private final TokenDecoder decoder = new TokenDecoder("http://127.0.0.1:9/realms/auth-server");

    @Test
    void decode_returnsAbsent_forNullToken() {
        Map<String, Object> result = decoder.decode(null);
        assertThat(result.get("present")).isEqualTo(false);
    }

    @Test
    void decode_parsesHeaderAndClaims_andFailsSignatureGracefully() {
        String header = encode("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"k1\"}");
        String payload = encode("{\"sub\":\"abc\",\"iss\":\"http://example/issuer\",\"exp\":9999999999}");
        String fakeSig = encode("not-a-real-signature");
        String token = header + "." + payload + "." + fakeSig;

        Map<String, Object> result = decoder.decode(token);

        assertThat(result.get("present")).isEqualTo(true);
        assertThat(result.get("raw")).isEqualTo(token);
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) result.get("claims");
        assertThat(claims).containsEntry("sub", "abc");
        assertThat(result.get("subject")).isEqualTo("abc");
        assertThat(result.get("issuer")).isEqualTo("http://example/issuer");
        assertThat(result.get("expired")).isEqualTo(false);
        // No real JWKS available; signature verification must report false but not throw.
        assertThat(result.get("signatureValid")).isEqualTo(false);
        assertThat(result.get("headerJson")).asString().contains("\"alg\"");
    }

    @Test
    void decode_reportsError_forMalformedToken() {
        Map<String, Object> result = decoder.decode("not-a-jwt");
        assertThat(result.get("error")).asString().contains("Not a JWT");
    }

    private static String encode(String json) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
