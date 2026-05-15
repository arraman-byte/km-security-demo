package org.km.securitydemo;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.km.securitydemo.support.OfflineOAuth2ClientRegistrationConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@SpringBootTest
@Import(OfflineOAuth2ClientRegistrationConfiguration.class)
class SecurityDemoMvcTests {

    private static final String ISSUER = "http://localhost:8080/realms/auth-server";

    @Autowired
    private WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).apply(springSecurity()).build();
    }

    @Test
    void dashboard_index_isPermitted_andLinksToFlows() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("/flows/auth-code-pkce")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("/flows/client-credentials")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("/flows/device-code")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("/flows/implicit")));
    }

    @Test
    void publicFlowPages_areReachable() throws Exception {
        mockMvc.perform(get("/flows/auth-code-pkce")).andExpect(status().isOk());
        mockMvc.perform(get("/flows/auth-code")).andExpect(status().isOk());
        mockMvc.perform(get("/flows/client-credentials")).andExpect(status().isOk());
        mockMvc.perform(get("/flows/device-code")).andExpect(status().isOk());
        mockMvc.perform(get("/flows/implicit")).andExpect(status().isOk());
        mockMvc.perform(get("/flows/implicit/callback")).andExpect(status().isOk());
        mockMvc.perform(get("/flows/oidc-vs-oauth")).andExpect(status().isOk());
    }

    @Test
    void profile_withoutLogin_redirectsToOAuth2() throws Exception {
        mockMvc.perform(get("/profile")).andExpect(status().is3xxRedirection());
    }

    @Test
    void apiDemo_withoutBearer_isUnauthorized() throws Exception {
        mockMvc.perform(get("/api/demo")).andExpect(status().isUnauthorized());
    }

    @Test
    void apiDemo_withJwt_isOk() throws Exception {
        mockMvc.perform(get("/api/demo")
                        .with(jwt()
                                .jwt(j -> j.subject("demo-user").issuer(ISSUER))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("demo-user"))
                .andExpect(jsonPath("$.issuer").value(ISSUER));
    }
}
