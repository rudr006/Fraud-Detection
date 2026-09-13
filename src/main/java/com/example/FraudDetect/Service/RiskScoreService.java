package com.example.FraudDetect.Service;

import org.springframework.stereotype.Service;

import java.net.URI;

@Service
public class RiskScoreService {

    public int calculateRiskScore(
            String url,
            boolean threatDetected) {

        int score = 0;

        // Google Safe Browsing
        if (threatDetected) {
            score += 80;
        }

        try {

            URI uri = URI.create(url);

            String host = uri.getHost();

            if (host != null) {

                // HTTP instead of HTTPS
                if ("http".equalsIgnoreCase(uri.getScheme())) {
                    score += 5;
                }

                // IP address
                if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                    score += 15;
                }

                // Punycode
                if (host.contains("xn--")) {
                    score += 15;
                }

                // Too many subdomains
                int subdomains =
                        host.split("\\.").length - 2;

                if (subdomains >= 3) {
                    score += 10;
                }
            }

            // Long URL
            if (url.length() > 100) {
                score += 5;
            }

            if (url.length() > 200) {
                score += 5;
            }

            // @ symbol
            if (url.contains("@")) {
                score += 10;
            }

        } catch (Exception e) {

            // Invalid URL
            score += 20;
        }

        return Math.min(score, 100);
    }
}