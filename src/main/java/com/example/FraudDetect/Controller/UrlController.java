package com.example.FraudDetect.Controller;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.FraudDetect.Service.RiskScoreService;
import com.example.FraudDetect.Service.SafeBrowsingService;

@RestController
@RequestMapping("/")
public class UrlController {

    private final ChatClient chatClient;
    private final SafeBrowsingService safeBrowsingService;
    private final RiskScoreService riskScoreService;

    public UrlController(ChatClient.Builder builder , SafeBrowsingService safeBrowsingService,RiskScoreService riskScoreService) 
    {

        this.chatClient = builder.build();
        this.safeBrowsingService = safeBrowsingService;
        this.riskScoreService = riskScoreService;
    }

    // @GetMapping("/analyze/{url}")
    // public String analyze(@PathVariable String url) {

    // System.out.println("URL RECEIVED: " + url);

    // boolean threatDetected = safeBrowsingService.isThreatDetected(url);

    // System.out.println(threatDetected ? "THREAT DETECTED" : "NO THREAT DETECTED");

    

    // // System.out.println("========== CONTROLLER CALLED ==========");

    // // String key = System.getenv("OPEN_AI_API");

    // // System.out.println("GROQ KEY PRESENT: " + (key != null));
    // // System.out.println("GROQ KEY LENGTH: " + (key == null ? 0 : key.length()));

    // // String response = chatClient
    // //         .prompt()
    // //         .user("IS this url is safe to visit? there is any conflict ?,give answer in yes or NO,you can use help of another website also ,url is " + url)
    // //         .call()
    // //         .content();

    // // return response;

    // return threatDetected ? "THREAT DETECTED" : "NO THREAT DETECTED";

// }

@GetMapping("/analyze")
public String analyze(@RequestParam String url) {

    System.out.println("========== URL ANALYSIS ==========");
    System.out.println("URL: " + url);

    // STEP 1: Google Safe Browsing
    boolean threatDetected =
            safeBrowsingService.isThreatDetected(url);

    System.out.println(
            "Threat detected: " + threatDetected
    );


    // STEP 2: Calculate risk score
    int riskScore =
            riskScoreService.calculateRiskScore(
                    url,
                    threatDetected
            );

    System.out.println(
            "Risk Score: " + riskScore
    );


    // STEP 3: Recommendation
    String recommendation;

    if (riskScore >= 70) {

        recommendation = "DO NOT USE";

    } else if (riskScore >= 30) {

        recommendation = "USE WITH CAUTION";

    } else {

        recommendation = "LOW RISK";
    }


    // STEP 4: Send information to Groq
    String prompt = """
            You are a cybersecurity assistant.

            Analyze the following URL.

            URL:
            %s

            Google Safe Browsing detected a known threat:
            %s

            Risk Score:
            %d / 100

            Recommendation:
            %s

            Explain why this URL received this risk score.

            Do not change the risk score.
            Do not invent threats.

            Give the explanation in 3-5 simple sentences.
            """.formatted(
                    url,
                    threatDetected,
                    riskScore,
                    recommendation
            );


    String aiExplanation =
            chatClient
                    .prompt()
                    .user(prompt)
                    .call()
                    .content();


    // STEP 5: Return final result
    return """
            {
                "url": "%s",
                "threatDetected": %s,
                "riskScore": %d,
                "recommendation": "%s",
                "aiExplanation": "%s"
            }
            """.formatted(
                    url,
                    threatDetected,
                    riskScore,
                    recommendation,
                    aiExplanation
                            .replace("\"", "\\\"")
            );
}
}