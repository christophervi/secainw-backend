package edu.sjsu.cmpe.secainw.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import edu.sjsu.cmpe.secainw.dto.AnomalyDetectionRequest;
import edu.sjsu.cmpe.secainw.model.AnomalyEvent;
import edu.sjsu.cmpe.secainw.model.AnomalyEvent.Verdict;
import edu.sjsu.cmpe.secainw.model.User;
import edu.sjsu.cmpe.secainw.repository.AnomalyEventRepository;

@Service
@Transactional
public class AnomalyDetectionService {
    private static final Logger logger = LoggerFactory.getLogger(AnomalyDetectionService.class);

    @Autowired
    private AnomalyEventRepository anomalyEventRepository;

    @Autowired
    @Qualifier("anthropicChatClient")
    private ChatClient anthropicChatClient;

    @Autowired
    @Qualifier("openAiChatClient")
    private ChatClient openAiChatClient;
    
    @Autowired
    @Qualifier("deepSeekChatClient")
    private ChatClient deepSeekChatClient;

    @Autowired
    private ChatClient chatClient; // Primary chat client (DeepSeek)

    @Autowired
    private VectorStore vectorStore;

    @Autowired
    private CveEnrichmentService cveEnrichmentService;

    @Value("${spring.ai.anthropic.chat.options.model:claude-opus-4-1-20250805}")
    private String anthropicModel;

    @Value("${spring.ai.openai.chat.options.model:gpt-5-2025-08-07}")
    private String openAiModel;
    
    @Value("${spring.ai.deepseek.chat.options.model:deepseek-reasoner}")
    private String deepSeekModel;

    private static final String ANOMALY_DETECTION_TEMPLATE = """
        You are a cybersecurity expert analyzing network and host events for anomaly detection.
        
        Event Data:
        - Event ID: %s
        - Timestamp: %s
        - Event Type: %s
        - Source IP: %s
        - Destination IP: %s
        - Destination Port: %s
        - Process Name: %s
        - Raw Data: %s
        
        Historical Context:
        %s
        
        Please analyze this event and provide:
        1. VERDICT: ANOMALOUS, NORMAL, or SUSPICIOUS
        2. SEVERITY_SCORE: A number between 0.0 and 10.0
        3. CONFIDENCE_SCORE: A number between 0.0 and 1.0
        4. EXPLANATION: A detailed explanation of your analysis
        5. SUPPORTING_EVIDENCE: Key data points that influenced your decision
        
        Format your response as:
        VERDICT: [verdict]
        SEVERITY_SCORE: [score]
        CONFIDENCE_SCORE: [score]
        EXPLANATION: [detailed explanation]
        SUPPORTING_EVIDENCE: [evidence points]
        """;

    public AnomalyEvent analyzeEvent(AnomalyDetectionRequest request, User user) {
        return analyzeEventWithModel(request, user, "anthropic");
    }

    public AnomalyEvent analyzeEventWithModel(AnomalyDetectionRequest request, User user, String modelType) {
        try {
            logger.info("Analyzing event: {} with model: {}", request.getEventId(), modelType);

            // Create the anomaly event
            AnomalyEvent event = new AnomalyEvent();
            event.setEventId(request.getEventId());
            event.setTimestamp(request.getTimestamp());
            event.setEventType(request.getEventType());
            event.setSourceIp(request.getSourceIp());
            event.setDestinationIp(request.getDestinationIp());
            event.setDestinationPort(request.getDestinationPort());
            event.setProcessName(request.getProcessName());
            //event.setAnalyzedBy(user);
            event.setUser(user);
            event.setCreatedAt(LocalDateTime.now());

            // Get historical context from vector store
            String historicalContext = getHistoricalContext(request);
            //String historicalContext = "";

            // Prepare the prompt
            String prompt = String.format(ANOMALY_DETECTION_TEMPLATE,
                request.getEventId(),
                request.getTimestamp(),
                request.getEventType(),
                request.getSourceIp(),
                request.getDestinationIp() != null ? request.getDestinationIp() : "N/A",
                request.getDestinationPort() != null ? request.getDestinationPort() : "N/A",
                request.getProcessName() != null ? request.getProcessName() : "N/A",
                request.getRawData() != null ? request.getRawData() : "N/A",
                historicalContext
            );

            // Select the appropriate chat client based on model type
            ChatClient selectedChatClient = selectChatClient(modelType);
            String modelName = getModelName(modelType);

            // Call AI for analysis
            ChatResponse response = selectedChatClient.prompt().user(prompt).call().chatResponse();
            String aiResponse = response.getResults().get(0).getOutput().getText();

            // Parse AI response
            parseAiResponse(aiResponse, event);

            // Set the model used for analysis
            event.setAiModel(modelName);

            // Enrich with CVE data
            try {
                String cveData = cveEnrichmentService.enrichWithCveData(event);
                event.setCveData(cveData);
            } catch (Exception e) {
                logger.warn("CVE enrichment failed: {}", e.getMessage());
                event.setCveData("CVE enrichment unavailable");
            }

            // Store event data in vector store for future context
            storeEventInVectorStore(event);

            // Save the event
            AnomalyEvent savedEvent = anomalyEventRepository.save(event);
            logger.info("Event analysis completed for: {} using model: {}", savedEvent.getEventId(), modelName);

            return savedEvent;

        } catch (Exception e) {
            logger.error("Error analyzing event {}: {}", request.getEventId(), e.getMessage(), e);
            throw new RuntimeException("Failed to analyze event: " + e.getMessage());
        }
    }

    private ChatClient selectChatClient(String modelType) {
        return switch (modelType.toLowerCase()) {
            case "openai", "gpt" -> openAiChatClient;
            case "anthropic", "claude" -> anthropicChatClient;
            case "deepseek" -> deepSeekChatClient;
            default -> chatClient; // Default to primary (DeepSeek)
        };
    }

    private String getModelName(String modelType) {
        return switch (modelType.toLowerCase()) {
            case "openai", "gpt" -> openAiModel;
            case "anthropic", "claude" -> anthropicModel;
            case "deepseek" -> deepSeekModel;
            default -> deepSeekModel;
        };
    }

    public AnomalyEvent compareModels(AnomalyDetectionRequest request, User user) {
        try {
            logger.info("Comparing models for event: {}", request.getEventId());
            
            // Analyze with DeepSeek
            AnomalyEvent deepSeekResult = analyzeEventWithModel(request, user, "deepseek");
            
            // Analyze with Anthropic
            AnomalyDetectionRequest anthropicRequest = new AnomalyDetectionRequest();
            anthropicRequest.setEventId(request.getEventId() + "_anthropic_comparison");
            anthropicRequest.setTimestamp(request.getTimestamp());
            anthropicRequest.setEventType(request.getEventType());
            anthropicRequest.setSourceIp(request.getSourceIp());
            anthropicRequest.setDestinationIp(request.getDestinationIp());
            anthropicRequest.setDestinationPort(request.getDestinationPort());
            anthropicRequest.setProcessName(request.getProcessName());
            anthropicRequest.setRawData(request.getRawData());
            AnomalyEvent anthropicResult = analyzeEventWithModel(anthropicRequest, user, "anthropic");
            
            // Analyze with OpenAI (create a copy of the request)
            AnomalyDetectionRequest openAiRequest = new AnomalyDetectionRequest();
            openAiRequest.setEventId(request.getEventId() + "_openai_comparison");
            openAiRequest.setTimestamp(request.getTimestamp());
            openAiRequest.setEventType(request.getEventType());
            openAiRequest.setSourceIp(request.getSourceIp());
            openAiRequest.setDestinationIp(request.getDestinationIp());
            openAiRequest.setDestinationPort(request.getDestinationPort());
            openAiRequest.setProcessName(request.getProcessName());
            openAiRequest.setRawData(request.getRawData());
            AnomalyEvent openAiResult = analyzeEventWithModel(openAiRequest, user, "openai");

            // Create a comparison summary
            String comparisonSummary = String.format(
                    "Model Comparison:\n" +
                    "DeepSeek (%s): Verdict=%s, Severity=%.2f, Confidence=%.2f\n" +
                    "Anthropic (%s): Verdict=%s, Severity=%.2f, Confidence=%.2f\n" +
                    "OpenAI (%s): Verdict=%s, Severity=%.2f, Confidence=%.2f\n" +
                    "Primary Result: DeepSeek",
                    deepSeekModel, deepSeekResult.getVerdict(), deepSeekResult.getSeverityScore(), deepSeekResult.getConfidenceScore(),
                    anthropicModel, anthropicResult.getVerdict(), anthropicResult.getSeverityScore(), anthropicResult.getConfidenceScore(),
                    openAiModel, openAiResult.getVerdict(), openAiResult.getSeverityScore(), openAiResult.getConfidenceScore()
                );

            // Append summary to the primary result and save
            deepSeekResult.setExplanation(deepSeekResult.getExplanation() + "\n\n" + comparisonSummary);
            anomalyEventRepository.save(deepSeekResult);

            return deepSeekResult;

        } catch (Exception e) {
            logger.error("Error comparing models for event {}: {}", request.getEventId(), e.getMessage(), e);
            // Fallback to single model analysis
            return analyzeEvent(request, user);
        }
    }

    private String getHistoricalContext(AnomalyDetectionRequest request) {
        try {
            // Search for similar events in vector store
            String searchQuery = String.format("Event: %s Source: %s Destination: %s Port: %s Process: %s",
                request.getEventType(),
                request.getSourceIp(),
                request.getDestinationIp() != null ? request.getDestinationIp() : "",
                request.getDestinationPort() != null ? request.getDestinationPort() : "",
                request.getProcessName() != null ? request.getProcessName() : ""
            );
            
            /*List<Document> similarEvents = vectorStore.similaritySearch(
                SearchRequest.query(searchQuery).withTopK(5)
            );*/
            
            List<Document> similarEvents = vectorStore.similaritySearch(searchQuery);

            if (similarEvents.isEmpty()) {
                return "No similar historical events found.";
            }

            StringBuilder context = new StringBuilder("Similar historical events:\n");
            for (Document doc : similarEvents) {
                context.append("- ").append(doc.getFormattedContent()).append("\n");
            }

            return context.toString();

        } catch (Exception e) {
            logger.warn("Failed to get historical context: {}", e.getMessage());
            return "Historical context unavailable.";
        }
    }

    private void storeEventInVectorStore(AnomalyEvent event) {
        try {
            String content = String.format(
                "Event ID: %s, Type: %s, Source: %s, Destination: %s, Port: %s, Process: %s, Verdict: %s, Severity: %.2f, Model: %s",
                event.getEventId(),
                event.getEventType(),
                event.getSourceIp(),
                event.getDestinationIp() != null ? event.getDestinationIp() : "N/A",
                event.getDestinationPort() != null ? event.getDestinationPort() : "N/A",
                event.getProcessName() != null ? event.getProcessName() : "N/A",
                event.getVerdict(),
                event.getSeverityScore(),
                event.getAiModel() != null ? event.getAiModel() : "Unknown"
            );

            Document document = new Document(content);
            document.getMetadata().put("eventId", event.getEventId());
            document.getMetadata().put("timestamp", event.getTimestamp().toString());
            document.getMetadata().put("verdict", event.getVerdict().toString());
            document.getMetadata().put("aiModel", event.getAiModel() != null ? event.getAiModel() : "Unknown");

            vectorStore.add(List.of(document));
            logger.debug("Stored event {} in vector store", event.getEventId());

        } catch (Exception e) {
            logger.warn("Failed to store event in vector store: {}", e.getMessage());
        }
    }

    private void parseAiResponse(String aiResponse, AnomalyEvent event) {
        try {
            String[] lines = aiResponse.split("\n");
            
            for (String line : lines) {
                line = line.trim();
                if (line.startsWith("VERDICT:")) {
                    String verdictStr = line.substring(8).trim();
                    event.setVerdict(Verdict.valueOf(verdictStr.toUpperCase()));
                } else if (line.startsWith("SEVERITY_SCORE:")) {
                    String scoreStr = line.substring(15).trim();
                    try {
                        event.setSeverityScore(Double.parseDouble(scoreStr));
                    } catch (NumberFormatException e) {
                        event.setSeverityScore(5.0); // Default value
                    }
                } else if (line.startsWith("CONFIDENCE_SCORE:")) {
                    String scoreStr = line.substring(17).trim();
                    try {
                        event.setConfidenceScore(Double.parseDouble(scoreStr));
                    } catch (NumberFormatException e) {
                        event.setConfidenceScore(0.5); // Default value
                    }
                } else if (line.startsWith("EXPLANATION:")) {
                    event.setExplanation(line.substring(12).trim());
                } else if (line.startsWith("SUPPORTING_EVIDENCE:")) {
                    event.setSupportingEvidence(line.substring(20).trim());
                }
            }

            // Set defaults if not parsed
            if (event.getVerdict() == null) {
                event.setVerdict(Verdict.NORMAL);
            }
            if (event.getSeverityScore() == null) {
                event.setSeverityScore(5.0);
            }
            if (event.getConfidenceScore() == null) {
                event.setConfidenceScore(0.5);
            }
            if (event.getExplanation() == null) {
                event.setExplanation("AI analysis completed");
            }
            if (event.getSupportingEvidence() == null) {
                event.setSupportingEvidence("Standard event analysis");
            }

        } catch (Exception e) {
            logger.error("Error parsing AI response: {}", e.getMessage());
            // Set default values
            event.setVerdict(Verdict.NORMAL);
            event.setSeverityScore(5.0);
            event.setConfidenceScore(0.5);
            event.setExplanation("AI analysis failed, using default values");
            event.setSupportingEvidence("Error in AI response parsing");
        }
    }

    public Optional<AnomalyEvent> findById(Long id) {
        return anomalyEventRepository.findById(id);
    }

    public Page<AnomalyEvent> findAll(Pageable pageable) {
        return anomalyEventRepository.findAllByOrderByCreatedAtDesc(pageable);
    }

    public List<AnomalyEvent> findByUser(User user) {
        return anomalyEventRepository.findByUserOrderByCreatedAtDesc(user);
    }

    public List<AnomalyEvent> findByVerdict(Verdict verdict) {
        return anomalyEventRepository.findByVerdictOrderByCreatedAtDesc(verdict);
    }
}
