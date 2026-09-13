package com.example.FraudDetect.Service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.Map;
import java.util.List;

@Service
public class SafeBrowsingService {

    @Value("${google.safe-browsing.api-key}")
    private String apiKey;

    private final RestClient restClient;

    public SafeBrowsingService(RestClient.Builder builder) {
        this.restClient = builder.build();
    }

    public boolean isThreatDetected(String url) {

        String apiUrl =
                "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
                        + apiKey;

        Map<String, Object> requestBody = Map.of(
                "client", Map.of(
                        "clientId", "FraudDetect",
                        "clientVersion", "1.0"
                ),
                "threatInfo", Map.of(
                        "threatTypes", List.of(
                                "MALWARE",
                                "SOCIAL_ENGINEERING",
                                "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"
                        ),
                        "platformTypes", List.of("ANY_PLATFORM"),
                        "threatEntryTypes", List.of("URL"),
                        "threatEntries", List.of(
                                Map.of("url", url)
                        )
                )
        );

        String response = restClient
                .post()
                .uri(apiUrl)
                .contentType(MediaType.APPLICATION_JSON)
                .body(requestBody)
                .retrieve()
                .body(String.class);

        System.out.println("SAFE BROWSING RESPONSE: " + response);

        return response != null
                && response.contains("\"matches\"");
    }
}