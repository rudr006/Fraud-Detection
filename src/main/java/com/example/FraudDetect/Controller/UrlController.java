package com.example.FraudDetect.Controller;

import com.example.FraudDetect.Service.UrlService;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class UrlController {

    private final UrlService urlService;

    public UrlController(UrlService urlService) {
        this.urlService = urlService;
    }

    @GetMapping("/analyze")
    public String analyze(@RequestParam String url) {

        return urlService.analyzeUrl(url);
    }
}