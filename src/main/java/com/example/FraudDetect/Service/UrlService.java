package com.example.FraudDetect.Service;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.stereotype.Service;

@Service
public class UrlService {

    private final ChatClient chatClient;
    private final SafeBrowsingService safeBrowsingService;
    private final RiskScoreService riskScoreService;

    public UrlService(
            ChatClient.Builder builder,
            SafeBrowsingService safeBrowsingService,
            RiskScoreService riskScoreService) {

        this.chatClient = builder.build();
        this.safeBrowsingService = safeBrowsingService;
        this.riskScoreService = riskScoreService;
    }

    public String analyzeUrl(String url) {

        System.out.println("========== URL ANALYSIS ==========");
        System.out.println("URL: " + url);

        // STEP 1: Google Safe Browsing
        boolean threatDetected =
                safeBrowsingService.isThreatDetected(url);

        System.out.println(
                "Threat detected: " + threatDetected
        );


        // STEP 2: Calculate Risk Score
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

                Rules:
                - Do not change the risk score.
                - Do not invent threats.
                - Give the explanation in 3-5 simple sentences.

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
                        escapeJson(url),
                        threatDetected,
                        riskScore,
                        recommendation,
                        escapeJson(aiExplanation)
                );
    }


    private String escapeJson(String text) {

        if (text == null) {
            return "";
        }

        return text
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }
}