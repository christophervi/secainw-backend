package edu.sjsu.cmpe.secainw.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;

import edu.sjsu.cmpe.secainw.dto.AnomalyDetectionRequest;
import edu.sjsu.cmpe.secainw.model.AnomalyEvent;
import edu.sjsu.cmpe.secainw.model.AnomalyEvent.Verdict;
import edu.sjsu.cmpe.secainw.model.User;
import edu.sjsu.cmpe.secainw.repository.AnomalyEventRepository;

@ExtendWith(MockitoExtension.class)
class AnomalyDetectionServiceTest {

    /*@Mock
    private AnomalyEventRepository anomalyEventRepository;

    @Mock
    private CveEnrichmentService cveEnrichmentService;

    @Mock
    private ChatClient chatClient;

    @Mock
    private ChatClient.ChatClientRequestSpec requestSpec;

    @Mock
    private ChatClient.ChatClientRequestSpec.CallResponseSpec callResponseSpec;

    @InjectMocks
    private AnomalyDetectionService anomalyDetectionService;

    private User testUser;
    private AnomalyDetectionRequest testRequest;
    private AnomalyEvent testEvent;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setUsername("testuser");
        testUser.setRole(User.Role.ANALYST);

        testRequest = new AnomalyDetectionRequest();
        testRequest.setEventId("TEST-001");
        testRequest.setTimestamp(LocalDateTime.now());
        testRequest.setEventType("Network Connection");
        testRequest.setSourceIp("192.168.1.100");
        testRequest.setDestinationIp("203.0.113.42");
        testRequest.setDestinationPort(443);
        testRequest.setProcessName("chrome.exe");

        testEvent = new AnomalyEvent();
        testEvent.setId(1L);
        testEvent.setEventId("TEST-001");
        testEvent.setTimestamp(LocalDateTime.now());
        testEvent.setEventType("Network Connection");
        testEvent.setSourceIp("192.168.1.100");
        testEvent.setDestinationIp("203.0.113.42");
        testEvent.setDestinationPort(443);
        testEvent.setProcessName("chrome.exe");
        testEvent.setVerdict(Verdict.NORMAL);
        testEvent.setSeverityScore(2.5);
        testEvent.setConfidenceScore(0.85);
        testEvent.setExplanation("Normal HTTPS connection to a trusted domain");
        testEvent.setSupportingEvidence("Standard browser behavior");
        testEvent.setAnalyzedBy(testUser);
        testEvent.setCreatedAt(LocalDateTime.now());
    }

    @Test
    void analyzeEvent_ShouldCreateAndSaveAnomalyEvent() {
        // Arrange
        String aiResponse = "VERDICT: NORMAL\nSEVERITY: 2.5\nCONFIDENCE: 0.85\nEXPLANATION: Normal HTTPS connection\nEVIDENCE: Standard browser behavior";
        
        ChatResponse mockChatResponse = mock(ChatResponse.class);
        Generation mockGeneration = mock(Generation.class);
        AssistantMessage mockMessage = mock(AssistantMessage.class);
        
        when(chatClient.prompt(anyString())).thenReturn(requestSpec);
        when(requestSpec.call()).thenReturn(callResponseSpec);
        when(callResponseSpec.chatResponse()).thenReturn(mockChatResponse);
        when(mockChatResponse.getResults()).thenReturn(List.of(mockGeneration));
        when(mockGeneration.getOutput()).thenReturn(mockMessage);
        when(mockMessage.getContent()).thenReturn(aiResponse);
        
        when(cveEnrichmentService.enrichWithCveData(any(AnomalyEvent.class))).thenReturn("No CVE data found");
        when(anomalyEventRepository.save(any(AnomalyEvent.class))).thenReturn(testEvent);

        // Act
        AnomalyEvent result = anomalyDetectionService.analyzeEvent(testRequest, testUser);

        // Assert
        assertNotNull(result);
        assertEquals("TEST-001", result.getEventId());
        assertEquals(Verdict.NORMAL, result.getVerdict());
        assertEquals(2.5, result.getSeverityScore(), 0.01);
        assertEquals(0.85, result.getConfidenceScore(), 0.01);
        
        verify(chatClient).prompt(anyString());
        verify(cveEnrichmentService).enrichWithCveData(any(AnomalyEvent.class));
        verify(anomalyEventRepository).save(any(AnomalyEvent.class));
    }

    @Test
    void analyzeEvent_ShouldHandleAnomalousVerdict() {
        // Arrange
        String aiResponse = "VERDICT: ANOMALOUS\nSEVERITY: 8.5\nCONFIDENCE: 0.92\nEXPLANATION: Suspicious network activity\nEVIDENCE: Unusual connection pattern";
        
        ChatResponse mockChatResponse = mock(ChatResponse.class);
        Generation mockGeneration = mock(Generation.class);
        AssistantMessage mockMessage = mock(AssistantMessage.class);
        
        when(chatClient.prompt(anyString())).thenReturn(requestSpec);
        when(requestSpec.call()).thenReturn(callResponseSpec);
        when(callResponseSpec.chatResponse()).thenReturn(mockChatResponse);
        when(mockChatResponse.getResults()).thenReturn(List.of(mockGeneration));
        when(mockGeneration.getOutput()).thenReturn(mockMessage);
        when(mockMessage.getContent()).thenReturn(aiResponse);
        
        when(cveEnrichmentService.enrichWithCveData(any(AnomalyEvent.class))).thenReturn("CVE-2023-1234 found");
        
        AnomalyEvent anomalousEvent = new AnomalyEvent();
        anomalousEvent.setVerdict(Verdict.ANOMALOUS);
        anomalousEvent.setSeverityScore(8.5);
        when(anomalyEventRepository.save(any(AnomalyEvent.class))).thenReturn(anomalousEvent);

        // Act
        AnomalyEvent result = anomalyDetectionService.analyzeEvent(testRequest, testUser);

        // Assert
        assertNotNull(result);
        assertEquals(Verdict.ANOMALOUS, result.getVerdict());
        assertEquals(8.5, result.getSeverityScore(), 0.01);
        
        verify(anomalyEventRepository).save(any(AnomalyEvent.class));
    }

    @Test
    void findById_ShouldReturnEvent_WhenEventExists() {
        // Arrange
        when(anomalyEventRepository.findById(1L)).thenReturn(Optional.of(testEvent));

        // Act
        Optional<AnomalyEvent> result = anomalyDetectionService.findById(1L);

        // Assert
        assertTrue(result.isPresent());
        assertEquals(1L, result.get().getId());
        verify(anomalyEventRepository).findById(1L);
    }

    @Test
    void findById_ShouldReturnEmpty_WhenEventDoesNotExist() {
        // Arrange
        when(anomalyEventRepository.findById(999L)).thenReturn(Optional.empty());

        // Act
        Optional<AnomalyEvent> result = anomalyDetectionService.findById(999L);

        // Assert
        assertFalse(result.isPresent());
        verify(anomalyEventRepository).findById(999L);
    }

    @Test
    void parseAiResponse_ShouldHandleIncompleteResponse() {
        // This would be a private method test, but we can test it indirectly
        // through the analyzeEvent method with malformed AI responses
        
        // Arrange
        String malformedResponse = "VERDICT: NORMAL\nSEVERITY: invalid\nCONFIDENCE: 0.85";
        
        ChatResponse mockChatResponse = mock(ChatResponse.class);
        Generation mockGeneration = mock(Generation.class);
        AssistantMessage mockMessage = mock(AssistantMessage.class);
        
        when(chatClient.prompt(anyString())).thenReturn(requestSpec);
        when(requestSpec.call()).thenReturn(callResponseSpec);
        when(callResponseSpec.chatResponse()).thenReturn(mockChatResponse);
        when(mockChatResponse.getResults()).thenReturn(List.of(mockGeneration));
        when(mockGeneration.getOutput()).thenReturn(mockMessage);
        when(mockMessage.getContent()).thenReturn(malformedResponse);
        
        when(cveEnrichmentService.enrichWithCveData(any(AnomalyEvent.class))).thenReturn("No CVE data");
        when(anomalyEventRepository.save(any(AnomalyEvent.class))).thenReturn(testEvent);

        // Act & Assert
        assertDoesNotThrow(() -> {
            AnomalyEvent result = anomalyDetectionService.analyzeEvent(testRequest, testUser);
            assertNotNull(result);
        });
    }

    @Test
    void analyzeEvent_ShouldHandleNullDestinationValues() {
        // Arrange
        testRequest.setDestinationIp(null);
        testRequest.setDestinationPort(null);
        testRequest.setProcessName(null);
        
        String aiResponse = "VERDICT: NORMAL\nSEVERITY: 1.0\nCONFIDENCE: 0.75\nEXPLANATION: Basic event\nEVIDENCE: Minimal data";
        
        ChatResponse mockChatResponse = mock(ChatResponse.class);
        Generation mockGeneration = mock(Generation.class);
        AssistantMessage mockMessage = mock(AssistantMessage.class);
        
        when(chatClient.prompt(anyString())).thenReturn(requestSpec);
        when(requestSpec.call()).thenReturn(callResponseSpec);
        when(callResponseSpec.chatResponse()).thenReturn(mockChatResponse);
        when(mockChatResponse.getResults()).thenReturn(List.of(mockGeneration));
        when(mockGeneration.getOutput()).thenReturn(mockMessage);
        when(mockMessage.getContent()).thenReturn(aiResponse);
        
        when(cveEnrichmentService.enrichWithCveData(any(AnomalyEvent.class))).thenReturn("No CVE data");
        when(anomalyEventRepository.save(any(AnomalyEvent.class))).thenReturn(testEvent);

        // Act
        AnomalyEvent result = anomalyDetectionService.analyzeEvent(testRequest, testUser);

        // Assert
        assertNotNull(result);
        verify(anomalyEventRepository).save(any(AnomalyEvent.class));
    }*/
}
