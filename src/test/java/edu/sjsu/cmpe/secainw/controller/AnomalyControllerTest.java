package edu.sjsu.cmpe.secainw.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import edu.sjsu.cmpe.secainw.dto.AnomalyDetectionRequest;
import edu.sjsu.cmpe.secainw.dto.FeedbackRequest;
import edu.sjsu.cmpe.secainw.model.AnomalyEvent;
import edu.sjsu.cmpe.secainw.model.AnomalyEvent.Verdict;
import edu.sjsu.cmpe.secainw.model.User;
import edu.sjsu.cmpe.secainw.repository.AnomalyEventRepository;
import edu.sjsu.cmpe.secainw.security.UserDetailsImpl;
import edu.sjsu.cmpe.secainw.service.AnomalyDetectionService;
import edu.sjsu.cmpe.secainw.service.FeedbackService;
import edu.sjsu.cmpe.secainw.service.UserService;

@ExtendWith(MockitoExtension.class)
class AnomalyControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Mock
    private AnomalyDetectionService anomalyDetectionService;

    @Mock
    private FeedbackService feedbackService;

    @Mock
    private UserService userService;

    @Mock
    private AnomalyEventRepository anomalyEventRepository;
    
    @Mock
    private Authentication authentication;
    
    @Mock
    private UserDetailsImpl userDetails;
    
    @InjectMocks
    private AnomalyController anomalyController;

    @Autowired
    private ObjectMapper objectMapper;

    private AnomalyDetectionRequest detectionRequest;
    private AnomalyEvent testEvent;
    private User testUser;
    private FeedbackRequest feedbackRequest;

    @BeforeEach
    void setUp() {
        detectionRequest = new AnomalyDetectionRequest();
        detectionRequest.setEventId("TEST-001");
        detectionRequest.setTimestamp(LocalDateTime.now());
        detectionRequest.setEventType("Network Connection");
        detectionRequest.setSourceIp("192.168.1.100");
        detectionRequest.setDestinationIp("203.0.113.42");
        detectionRequest.setDestinationPort(443);

        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setRole(User.Role.ANALYST);

        testEvent = new AnomalyEvent();
        testEvent.setId(1L);
        testEvent.setEventId("TEST-001");
        testEvent.setTimestamp(LocalDateTime.now());
        testEvent.setEventType("Network Connection");
        testEvent.setSourceIp("192.168.1.100");
        testEvent.setVerdict(Verdict.NORMAL);
        testEvent.setSeverityScore(2.5);
        testEvent.setConfidenceScore(0.85);
        testEvent.setExplanation("Normal HTTPS connection");
        testEvent.setSupportingEvidence("Standard browser behavior");
        testEvent.setUser(testUser);
        testEvent.setCreatedAt(LocalDateTime.now());

        feedbackRequest = new FeedbackRequest();
        feedbackRequest.setAccuracyRating(4);
        feedbackRequest.setExplanationQualityRating(5);
        feedbackRequest.setComments("Good analysis");
        feedbackRequest.setIsCorrectDetection(true);
    }

    @Test
    @WithMockUser(roles = "ANALYST")
    void detectAnomaly_ShouldReturnAnomalyEvent_WhenRequestIsValid() throws Exception {
        // Arrange
    	when(authentication.getPrincipal()).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn("testuser");
        when(userService.findByUsername(anyString())).thenReturn(Optional.of(testUser));
        when(anomalyDetectionService.analyzeEvent(any(AnomalyDetectionRequest.class), any(User.class)))
                .thenReturn(testEvent);

        // Act & Assert
        ResponseEntity<?> responseEntity = anomalyController.detectAnomaly(detectionRequest, authentication);
        /*mockMvc.perform(post("/api/anomaly/detect")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(detectionRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.eventId").value("TEST-001"))
                .andExpect(jsonPath("$.verdict").value("NORMAL"))
                .andExpect(jsonPath("$.severityScore").value(2.5));*/
        
        assertNotNull(responseEntity);
        assertEquals(200, responseEntity.getStatusCode().value());
        verify(userService).findByUsername(anyString());
        verify(anomalyDetectionService).analyzeEvent(any(AnomalyDetectionRequest.class), any(User.class));
    }

    @Test
    @WithMockUser(roles = "VIEWER")
    void detectAnomaly_ShouldReturnForbidden_WhenUserIsViewer() throws Exception {
        // Act & Assert
        mockMvc.perform(post("/api/anomaly/detect")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(detectionRequest)))
                .andExpect(status().isForbidden());

        verify(anomalyDetectionService, never()).analyzeEvent(any(), any());
    }

    @Test
    @WithMockUser(roles = "ANALYST")
    void getAnomalyEvents_ShouldReturnPagedEvents() throws Exception {
        // Arrange
        Page<AnomalyEvent> eventPage = new PageImpl<>(List.of(testEvent), PageRequest.of(0, 20), 1);
        when(anomalyEventRepository.findAllByOrderByCreatedAtDesc(any(PageRequest.class)))
                .thenReturn(eventPage);

        // Act & Assert
        mockMvc.perform(get("/api/anomaly/events")
                .param("page", "0")
                .param("size", "20"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.content[0].id").value(1))
                .andExpect(jsonPath("$.totalElements").value(1));

        verify(anomalyEventRepository).findAllByOrderByCreatedAtDesc(any(PageRequest.class));
    }

    @Test
    @WithMockUser(roles = "ANALYST")
    void getAnomalyEvent_ShouldReturnEvent_WhenEventExists() throws Exception {
        // Arrange
        when(anomalyDetectionService.findById(1L)).thenReturn(Optional.of(testEvent));

        // Act & Assert
        mockMvc.perform(get("/api/anomaly/events/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.eventId").value("TEST-001"));

        verify(anomalyDetectionService).findById(1L);
    }

    @Test
    @WithMockUser(roles = "ANALYST")
    void getAnomalyEvent_ShouldReturnNotFound_WhenEventDoesNotExist() throws Exception {
        // Arrange
        when(anomalyDetectionService.findById(999L)).thenReturn(Optional.empty());

        // Act & Assert
        mockMvc.perform(get("/api/anomaly/events/999"))
                .andExpect(status().isNotFound());

        verify(anomalyDetectionService).findById(999L);
    }

    @Test
    @WithMockUser(roles = "ANALYST")
    void submitFeedback_ShouldReturnSuccess_WhenRequestIsValid() throws Exception {
        // Arrange
        when(userService.findByUsername(anyString())).thenReturn(Optional.of(testUser));
        when(anomalyDetectionService.findById(1L)).thenReturn(Optional.of(testEvent));
        when(feedbackService.submitFeedback(any(), any(), any())).thenReturn(null);

        // Act & Assert
        mockMvc.perform(post("/api/anomaly/events/1/feedback")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(feedbackRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Feedback submitted successfully"))
                .andExpect(jsonPath("$.type").value("success"));

        verify(userService).findByUsername(anyString());
        verify(anomalyDetectionService).findById(1L);
        verify(feedbackService).submitFeedback(any(), any(), any());
    }

    @Test
    @WithMockUser(roles = "ANALYST")
    void submitFeedback_ShouldReturnNotFound_WhenEventDoesNotExist() throws Exception {
        // Arrange
        when(userService.findByUsername(anyString())).thenReturn(Optional.of(testUser));
        when(anomalyDetectionService.findById(999L)).thenReturn(Optional.empty());

        // Act & Assert
        mockMvc.perform(post("/api/anomaly/events/999/feedback")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(feedbackRequest)))
                .andExpect(status().isNotFound());

        verify(anomalyDetectionService).findById(999L);
        verify(feedbackService, never()).submitFeedback(any(), any(), any());
    }

    @Test
    @WithMockUser(roles = "ANALYST")
    void getStatistics_ShouldReturnStats() throws Exception {
        // Arrange
        when(anomalyEventRepository.count()).thenReturn(100L);
        when(anomalyEventRepository.countAnomalousEvents()).thenReturn(25L);
        when(anomalyEventRepository.countNormalEvents()).thenReturn(75L);
        when(anomalyEventRepository.getAverageSeverityScore()).thenReturn(3.5);
        when(feedbackService.getAverageAccuracyRating()).thenReturn(4.2);
        when(feedbackService.getAverageExplanationQualityRating()).thenReturn(4.5);
        when(feedbackService.getAccuracyPercentage()).thenReturn(85.0);
        when(feedbackService.getCorrectDetectionsCount()).thenReturn(85L);
        when(feedbackService.getIncorrectDetectionsCount()).thenReturn(15L);

        // Act & Assert
        mockMvc.perform(get("/api/anomaly/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEvents").value(100))
                .andExpect(jsonPath("$.anomalousEvents").value(25))
                .andExpect(jsonPath("$.normalEvents").value(75))
                .andExpect(jsonPath("$.averageSeverityScore").value(3.5))
                .andExpect(jsonPath("$.averageAccuracyRating").value(4.2))
                .andExpect(jsonPath("$.accuracyPercentage").value(85.0));

        verify(anomalyEventRepository).count();
        verify(anomalyEventRepository).countAnomalousEvents();
        verify(feedbackService).getAverageAccuracyRating();
    }

    @Test
    void detectAnomaly_ShouldReturnUnauthorized_WhenNotAuthenticated() throws Exception {
        // Act & Assert
        mockMvc.perform(post("/api/anomaly/detect")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(detectionRequest)))
                .andExpect(status().isUnauthorized());

        verify(anomalyDetectionService, never()).analyzeEvent(any(), any());
    }

    @Test
    @WithMockUser(roles = "ANALYST")
    void detectAnomaly_ShouldReturnBadRequest_WhenUserNotFound() throws Exception {
        // Arrange
        when(userService.findByUsername(anyString())).thenReturn(Optional.empty());

        // Act & Assert
        mockMvc.perform(post("/api/anomaly/detect")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(detectionRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("User not found"));

        verify(userService).findByUsername(anyString());
        verify(anomalyDetectionService, never()).analyzeEvent(any(), any());
    }
}
