package org.km.securitydemo.web;

import java.util.Map;
import org.km.securitydemo.demo.ClientCredentialsDemoService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DemoClientCredentialsController {

    private final ClientCredentialsDemoService clientCredentialsDemoService;

    public DemoClientCredentialsController(ClientCredentialsDemoService clientCredentialsDemoService) {
        this.clientCredentialsDemoService = clientCredentialsDemoService;
    }

    @GetMapping("/flows/client-credentials")
    public String page() {
        return "flows/client-credentials";
    }

    @GetMapping("/demo/client-credentials/run")
    public String run(Model model) {
        Map<String, Object> result = clientCredentialsDemoService.runDemo();
        model.addAttribute("result", result);
        return "flows/client-credentials-result";
    }
}
