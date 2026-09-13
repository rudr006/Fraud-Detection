package com.example.FraudDetect.Controller;

import com.example.FraudDetect.Service.MessageAnalysisService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController 
@RequestMapping("/message")
public class MessageController {

    private final MessageAnalysisService messageAnalysisService;

    public MessageController(
            MessageAnalysisService messageAnalysisService) {

        this.messageAnalysisService = messageAnalysisService;
    }

    @PostMapping("/analyze")
    public String analyze(@RequestBody Map<String, String> request) {

        String message = request.get("message");

        return messageAnalysisService.analyze(message);
    }
}