package org.km.securitydemo;

import org.junit.jupiter.api.Test;
import org.km.securitydemo.support.OfflineOAuth2ClientRegistrationConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@SpringBootTest
@Import(OfflineOAuth2ClientRegistrationConfiguration.class)
class SecurityDemoApplicationTests {

    @Test
    void contextLoads() {}

}
