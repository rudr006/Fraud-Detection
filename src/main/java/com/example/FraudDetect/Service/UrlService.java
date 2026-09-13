package com.example.FraudDetect.Service;



import org.springframework.stereotype.Service;


@Service
public class UrlService {


    public String analyzeUrl(String url) {
        return "URL: " + url;
    }
}
