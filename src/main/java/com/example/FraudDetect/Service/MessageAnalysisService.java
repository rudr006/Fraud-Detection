package com.example.FraudDetect.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.stereotype.Service;

@Service
public class MessageAnalysisService {

    private final SafeBrowsingService safeBrowsingService;
    private final RiskScoreService riskScoreService;
    private final ChatClient chatClient;

    public MessageAnalysisService(
            SafeBrowsingService safeBrowsingService,
            RiskScoreService riskScoreService,
            ChatClient.Builder builder) {

        this.safeBrowsingService = safeBrowsingService;
        this.riskScoreService = riskScoreService;
        this.chatClient = builder.build();
    }

    public String analyze(String message) {

        System.out.println("========== MESSAGE ANALYSIS ==========");
        System.out.println("Message: " + message);

        int messageScore = 0;

        List<String> riskFactors = new ArrayList<>();

        String text = message.toLowerCase();

        
        // STEP 1: Detect suspicious words
             
    

        String[] urgencyWords = {
            "urgent",
            "immediately",
            "right now",
            "today",
            "hurry",
            "expire",
            "expired",
            "blocked",
            "suspended"
        };

        String[] financialWords = {
            "bank",
            "payment",
            "money",
            "transfer",
            "upi",
            "credit card",
            "debit card",
            "refund"
        };

        String[] credentialWords = {
            "password",
            "otp",
            "pin",
            "cvv",
            "login",
            "username",
            "verify",
            "verification"
        };

        String[] rewardWords = {
            "winner",
            "won",
            "lottery",
            "prize",
            "reward",
            "cashback",
            "free"
        };
             

        for (String word : urgencyWords) {

            if (text.contains(word)) {

                messageScore += 10;

                riskFactors.add(
                        "Urgency language detected: " + word
                );

                break;
            }
        }

        for (String word : financialWords) 
        {

            if (text.contains(word)) {
                messageScore += 15;
                riskFactors.add("Financial-related language detected: " + word);
            }
        }


        for (String word : urgencyWords) 
        {

            if (text.contains(word)) {
                messageScore += 10;
                riskFactors.add("Urgency language detected: " + word);
            }
        }

        for (String word : credentialWords) 
        {

            if (text.contains(word)) {
                messageScore += 15;
                riskFactors.add("Credential/verification request detected: " + word);
            }
        }

        for (String word : rewardWords) 
        {

            if (text.contains(word)) {
                messageScore += 10;
                riskFactors.add("Reward/prize language detected: " + word);
            }
        }
        
        // STEP 2: Extract URLs
        

        Pattern pattern = Pattern.compile(
                "https?://[^\\s]+"
        );

        Matcher matcher = pattern.matcher(message);

        int urlRiskScore = 0;

        while (matcher.find()) {

            String url = matcher.group();

            // Remove common punctuation at the end
            url = url.replaceAll("[.,!?;:]+$", "");

            System.out.println("URL FOUND: " + url);


            // STEP 3: Google Safe Browsing
            

            boolean threatDetected =
                    safeBrowsingService.isThreatDetected(url);

            System.out.println(
                    "URL Threat Detected: " + threatDetected
            );

            
            // STEP 4: URL Risk Score-

            int score =
                    riskScoreService.calculateRiskScore(
                            url,
                            threatDetected
                    );

            urlRiskScore = Math.max(urlRiskScore, score);

            System.out.println(
                    "URL Risk Score: " + score
            );

            if (threatDetected) {

                riskFactors.add(
                        "Known threat detected in URL: " + url
                );

            } else {

                riskFactors.add(
                        "URL analyzed but no known threat detected: "
                                + url
                );
            }
        }
        messageScore = Math.min(messageScore, 50);

       
        // STEP 5: Combine scores
        

        int finalScore;

        if (urlRiskScore > 0) {

            finalScore =
                    Math.min(
                            urlRiskScore + messageScore,
                            100
                    );

        } else {

            finalScore =
                    Math.min(messageScore, 100);
        }

        System.out.println(
                "Final Risk Score: " + finalScore
        );

        // STEP 6: Recommendation
        

        String recommendation;

        if (finalScore >= 70) {

            recommendation = "DO NOT USE";

        } else if (finalScore >= 30) {

            recommendation = "USE WITH CAUTION";

        } else {

            recommendation = "LOW RISK";
        }

        // --------------------------------
        // STEP 7: Groq explanation
        // --------------------------------

        String prompt = """
                You are a cybersecurity assistant.

                Analyze the following SMS or email message.

                Message:
                %s

                Calculated Risk Score:
                %d / 100

                Recommendation:
                %s

                Detected Risk Factors:
                %s

                Explain why this message received this risk score.

                Rules:
                - Do not change the risk score.
                - Do not invent threats.
                - Only use the detected risk factors.
                - Give the explanation in 3-5 simple sentences.
                """.formatted(
                        message,
                        finalScore,
                        recommendation,
                        String.join(", ", riskFactors)
                );

        String aiExplanation =
                chatClient
                        .prompt()
                        .user(prompt)
                        .call()
                        .content();

        // --------------------------------
        // STEP 8: Return JSON
        // --------------------------------

        return """
                {
                    "message": "%s",
                    "riskScore": %d,
                    "recommendation": "%s",
                    "riskFactors": %s,
                    "aiExplanation": "%s"
                }
                """.formatted(
                        escapeJson(message),
                        finalScore,
                        recommendation,
                        convertListToJson(riskFactors),
                        escapeJson(aiExplanation)
                );
    }

    private String convertListToJson(List<String> list) {

        StringBuilder result = new StringBuilder("[");

        for (int i = 0; i < list.size(); i++) {

            result.append("\"")
                    .append(escapeJson(list.get(i)))
                    .append("\"");

            if (i < list.size() - 1) {
                result.append(",");
            }
        }

        result.append("]");

        return result.toString();
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