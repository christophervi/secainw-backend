package edu.sjsu.cmpe.secainw.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import edu.sjsu.cmpe.secainw.dto.AnomalyDetectionRequest;
import edu.sjsu.cmpe.secainw.dto.AnomalyDetectionResponse;
import edu.sjsu.cmpe.secainw.dto.FeedbackRequest;
import edu.sjsu.cmpe.secainw.dto.FeedbackResponseDto;
import edu.sjsu.cmpe.secainw.model.AnalystFeedback;
import edu.sjsu.cmpe.secainw.model.AnomalyEvent;
import edu.sjsu.cmpe.secainw.model.User;
import edu.sjsu.cmpe.secainw.repository.AnomalyEventRepository;
import edu.sjsu.cmpe.secainw.security.UserDetailsImpl;
import edu.sjsu.cmpe.secainw.service.AnomalyDetectionService;
import edu.sjsu.cmpe.secainw.service.FeedbackService;
import edu.sjsu.cmpe.secainw.service.UserService;
import jakarta.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/anomaly")
public class AnomalyController {
    @Autowired
    private AnomalyDetectionService anomalyDetectionService;

    @Autowired
    private FeedbackService feedbackService;

    @Autowired
    private UserService userService;

    @Autowired
    private AnomalyEventRepository anomalyEventRepository;

    @PostMapping("/detect")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<?> detectAnomaly(@Valid @RequestBody AnomalyDetectionRequest request,
                                         Authentication authentication) {
        try {
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            User user = userService.findByUsername(userDetails.getUsername()).orElse(null);
            
            if (user == null) {
                return ResponseEntity.badRequest()
                        .body(createErrorResponse("User not found"));
            }

            AnomalyEvent event = anomalyDetectionService.analyzeEvent(request, user);
            AnomalyDetectionResponse response = new AnomalyDetectionResponse(event);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Error analyzing event: " + e.getMessage()));
        }
    }

    @PostMapping("/detect/{model}")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<?> detectAnomalyWithModel(@PathVariable String model,
                                                  @Valid @RequestBody AnomalyDetectionRequest request,
                                                  Authentication authentication) {
        try {
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            User user = userService.findByUsername(userDetails.getUsername()).orElse(null);
            
            if (user == null) {
                return ResponseEntity.badRequest()
                        .body(createErrorResponse("User not found"));
            }

            // Validate model type
            if (!isValidModel(model)) {
                return ResponseEntity.badRequest()
                        .body(createErrorResponse("Invalid model type. Supported models: anthropic, openai, deepseek"));
            }

            AnomalyEvent event = anomalyDetectionService.analyzeEventWithModel(request, user, model);
            AnomalyDetectionResponse response = new AnomalyDetectionResponse(event);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Error analyzing event with " + model + ": " + e.getMessage()));
        }
    }

    @PostMapping("/detect/compare")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<?> compareModels(@Valid @RequestBody AnomalyDetectionRequest request,
                                         Authentication authentication) {
        try {
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            User user = userService.findByUsername(userDetails.getUsername()).orElse(null);
            
            if (user == null) {
                return ResponseEntity.badRequest()
                        .body(createErrorResponse("User not found"));
            }

            AnomalyEvent event = anomalyDetectionService.compareModels(request, user);
            AnomalyDetectionResponse response = new AnomalyDetectionResponse(event);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Error comparing models: " + e.getMessage()));
        }
    }

    @GetMapping("/models")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN') or hasRole('VIEWER')")
    public ResponseEntity<?> getAvailableModels() {
        try {
            Map<String, Object> models = new HashMap<>();
            models.put("anthropic", Map.of(
                "name", "Claude Opus 4.1",
                "provider", "Anthropic",
                "description", "Advanced reasoning and analysis capabilities"
            ));
            models.put("openai", Map.of(
                "name", "GPT-5 (High)",
                "provider", "OpenAI",
                "description", "Latest OpenAI model with enhanced capabilities"
            ));
            models.put("deepseek", Map.of(
                "name", "DeepSeek-R1 (Reasoner)",
                "provider", "DeepSeek",
                "description", "Specialized reasoning model"
            ));
            
            return ResponseEntity.ok(models);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Error retrieving available models: " + e.getMessage()));
        }
    }

    private boolean isValidModel(String model) {
        return model != null && (
            model.equalsIgnoreCase("anthropic") ||
            model.equalsIgnoreCase("claude") ||
            model.equalsIgnoreCase("openai") ||
            model.equalsIgnoreCase("gpt") ||
            model.equalsIgnoreCase("deepseek")
        );
    }

    @GetMapping("/events")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN') or hasRole('VIEWER')")
    public ResponseEntity<?> getAnomalyEvents(@RequestParam(defaultValue = "0") int page,
                                            @RequestParam(defaultValue = "20") int size,
                                            Authentication authentication) {
        try {
            Pageable pageable = PageRequest.of(page, size);
            Page<AnomalyEvent> events = anomalyEventRepository.findAllByOrderByCreatedAtDesc(pageable);
            
            Page<AnomalyDetectionResponse> response = events.map(AnomalyDetectionResponse::new);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Error retrieving events: " + e.getMessage()));
        }
    }

    @GetMapping("/events/{id}")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN') or hasRole('VIEWER')")
    public ResponseEntity<?> getAnomalyEvent(@PathVariable Long id) {
        try {
            Optional<AnomalyEvent> eventOpt = anomalyDetectionService.findById(id);
            
            if (eventOpt.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            
            AnomalyDetectionResponse response = new AnomalyDetectionResponse(eventOpt.get());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Error retrieving event: " + e.getMessage()));
        }
    }

    @PostMapping("/events/{id}/feedback")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<?> submitFeedback(@PathVariable Long id,
                                          @Valid @RequestBody FeedbackRequest request,
                                          Authentication authentication) {
        try {
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            User user = userService.findByUsername(userDetails.getUsername()).orElse(null);
            
            if (user == null) {
                return ResponseEntity.badRequest()
                        .body(createErrorResponse("User not found"));
            }

            Optional<AnomalyEvent> eventOpt = anomalyDetectionService.findById(id);
            if (eventOpt.isEmpty()) {
                return ResponseEntity.notFound().build();
            }

            AnalystFeedback feedback = feedbackService.submitFeedback(eventOpt.get(), user, request);
            
            return ResponseEntity.ok(createSuccessResponse("Feedback submitted successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Error submitting feedback: " + e.getMessage()));
        }
    }

    @GetMapping("/events/{id}/feedback")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN') or hasRole('VIEWER')")
    public ResponseEntity<?> getFeedback(@PathVariable Long id) {
        try {
            Optional<AnomalyEvent> eventOpt = anomalyDetectionService.findById(id);
            if (eventOpt.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            
            // Fetch the list of feedback entities
            List<AnalystFeedback> feedbackEntities = feedbackService.getFeedbackForEvent(eventOpt.get());
            
            // Map the entities to the DTO
            List<FeedbackResponseDto> feedbackDtos = feedbackEntities.stream()
                                                      .map(FeedbackResponseDto::new)
                                                      .collect(Collectors.toList());
            
            return ResponseEntity.ok(feedbackDtos);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Error retrieving feedback: " + e.getMessage()));
        }
    }

    @GetMapping("/stats")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN') or hasRole('VIEWER')")
    public ResponseEntity<?> getStatistics() {
        try {
            Map<String, Object> stats = new HashMap<>();
            
            // Event statistics
            stats.put("totalEvents", anomalyEventRepository.count());
            stats.put("anomalousEvents", anomalyEventRepository.countAnomalousEvents());
            stats.put("normalEvents", anomalyEventRepository.countNormalEvents());
            stats.put("averageSeverityScore", anomalyEventRepository.getAverageSeverityScore());
            
            // Feedback statistics
            stats.put("averageAccuracyRating", feedbackService.getAverageAccuracyRating());
            stats.put("averageExplanationQualityRating", feedbackService.getAverageExplanationQualityRating());
            stats.put("accuracyPercentage", feedbackService.getAccuracyPercentage());
            stats.put("correctDetections", feedbackService.getCorrectDetectionsCount());
            stats.put("incorrectDetections", feedbackService.getIncorrectDetectionsCount());
            
            return ResponseEntity.ok(stats);
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(createErrorResponse("Error retrieving statistics: " + e.getMessage()));
        }
    }

    private Map<String, String> createErrorResponse(String message) {
        Map<String, String> response = new HashMap<>();
        response.put("message", message);
        response.put("type", "error");
        return response;
    }

    private Map<String, String> createSuccessResponse(String message) {
        Map<String, String> response = new HashMap<>();
        response.put("message", message);
        response.put("type", "success");
        return response;
    }
}
