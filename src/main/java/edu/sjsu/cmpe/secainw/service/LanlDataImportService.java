package edu.sjsu.cmpe.secainw.service;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;

import edu.sjsu.cmpe.secainw.model.AnomalyEvent.Verdict;
import edu.sjsu.cmpe.secainw.model.NetflowEvent;
import edu.sjsu.cmpe.secainw.model.User;
import edu.sjsu.cmpe.secainw.model.WindowsLogEvent;
import edu.sjsu.cmpe.secainw.repository.NetflowEventRepository;
import edu.sjsu.cmpe.secainw.repository.WindowsLogEventRepository;

@Service
@Transactional
public class LanlDataImportService {
    private static final Logger logger = LoggerFactory.getLogger(LanlDataImportService.class);

    @Autowired
    private NetflowEventRepository netflowEventRepository;

    @Autowired
    private WindowsLogEventRepository windowsLogEventRepository;

    @Autowired
    private VectorStore vectorStore;

    @Autowired
    private AnomalyDetectionService anomalyDetectionService;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AtomicInteger processedCount = new AtomicInteger(0);
    private final AtomicInteger totalCount = new AtomicInteger(0);

    public CompletableFuture<Map<String, Object>> importNetflowDataAsync(String filename, User user) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return importNetflowData(filename, user);
            } catch (Exception e) {
                logger.error("Error importing netflow data: {}", e.getMessage(), e);
                Map<String, Object> result = new HashMap<>();
                result.put("success", false);
                result.put("error", e.getMessage());
                return result;
            }
        });
    }

    public Map<String, Object> importNetflowData(String filename, User user) throws IOException {
        logger.info("Starting netflow data import from: {}", filename);
        
        ClassPathResource resource = new ClassPathResource("data/netflow/" + filename);
        if (!resource.exists()) {
            throw new FileNotFoundException("Netflow file not found: " + filename);
        }

        List<NetflowEvent> events = new ArrayList<>();
        List<Document> documents = new ArrayList<>();
        int batchSize = 1000;
        int processedEvents = 0;

        try (InputStream inputStream = resource.getInputStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(
                 new java.util.zip.GZIPInputStream(inputStream)))) {

            String line;
            boolean isFirstLine = true;
            
            while ((line = reader.readLine()) != null && processedEvents < 10000) { // Limit for demo
                if (isFirstLine) {
                    isFirstLine = false;
                    continue; // Skip header if present
                }

                try {
                    NetflowEvent event = parseNetflowLine(line, user);
                    if (event != null) {
                        events.add(event);
                        
                        // Create vector document
                        Document doc = createNetflowDocument(event);
                        documents.add(doc);
                        
                        processedEvents++;
                        
                        // Process in batches
                        if (events.size() >= batchSize) {
                            saveBatch(events, documents);
                            events.clear();
                            documents.clear();
                        }
                    }
                } catch (Exception e) {
                    logger.warn("Error parsing netflow line: {}", e.getMessage());
                }
            }

            // Process remaining events
            if (!events.isEmpty()) {
                saveBatch(events, documents);
            }

        } catch (Exception e) {
            if (e instanceof java.util.zip.ZipException) {
                // Try as bzip2
                return importNetflowDataBzip2(filename, user);
            }
            throw e;
        }

        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("processedEvents", processedEvents);
        result.put("filename", filename);
        result.put("importedAt", LocalDateTime.now());
        
        logger.info("Completed netflow data import: {} events processed", processedEvents);
        return result;
    }

    private Map<String, Object> importNetflowDataBzip2(String filename, User user) throws IOException {
        logger.info("Importing netflow data as bzip2: {}", filename);
        
        ClassPathResource resource = new ClassPathResource("data/netflow/" + filename);
        ProcessBuilder pb = new ProcessBuilder("bzip2", "-dc", resource.getFile().getAbsolutePath());
        Process process = pb.start();

        List<NetflowEvent> events = new ArrayList<>();
        List<Document> documents = new ArrayList<>();
        int batchSize = 1000;
        int processedEvents = 0;

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            
            while ((line = reader.readLine()) != null && processedEvents < 10000) { // Limit for demo
                try {
                    NetflowEvent event = parseNetflowLine(line, user);
                    if (event != null) {
                        events.add(event);
                        
                        Document doc = createNetflowDocument(event);
                        documents.add(doc);
                        
                        processedEvents++;
                        
                        if (events.size() >= batchSize) {
                            saveBatch(events, documents);
                            events.clear();
                            documents.clear();
                        }
                    }
                } catch (Exception e) {
                    logger.warn("Error parsing netflow line: {}", e.getMessage());
                }
            }

            if (!events.isEmpty()) {
                saveBatch(events, documents);
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("processedEvents", processedEvents);
        result.put("filename", filename);
        result.put("importedAt", LocalDateTime.now());
        
        return result;
    }

    public CompletableFuture<Map<String, Object>> importWindowsLogDataAsync(String filename, User user) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return importWindowsLogData(filename, user);
            } catch (Exception e) {
                logger.error("Error importing Windows log data: {}", e.getMessage(), e);
                Map<String, Object> result = new HashMap<>();
                result.put("success", false);
                result.put("error", e.getMessage());
                return result;
            }
        });
    }

    public Map<String, Object> importWindowsLogData(String filename, User user) throws IOException {
        logger.info("Starting Windows log data import from: {}", filename);
        
        ClassPathResource resource = new ClassPathResource("data/windows-logs/" + filename);
        if (!resource.exists()) {
            throw new FileNotFoundException("Windows log file not found: " + filename);
        }

        List<WindowsLogEvent> events = new ArrayList<>();
        List<Document> documents = new ArrayList<>();
        int batchSize = 1000;
        int processedEvents = 0;

        ProcessBuilder pb = new ProcessBuilder("bzip2", "-dc", resource.getFile().getAbsolutePath());
        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            
            while ((line = reader.readLine()) != null && processedEvents < 10000) { // Limit for demo
                try {
                    WindowsLogEvent event = parseWindowsLogLine(line, user);
                    if (event != null) {
                        events.add(event);
                        
                        Document doc = createWindowsLogDocument(event);
                        documents.add(doc);
                        
                        processedEvents++;
                        
                        if (events.size() >= batchSize) {
                            saveWindowsBatch(events, documents);
                            events.clear();
                            documents.clear();
                        }
                    }
                } catch (Exception e) {
                    logger.warn("Error parsing Windows log line: {}", e.getMessage());
                }
            }

            if (!events.isEmpty()) {
                saveWindowsBatch(events, documents);
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("processedEvents", processedEvents);
        result.put("filename", filename);
        result.put("importedAt", LocalDateTime.now());
        
        logger.info("Completed Windows log data import: {} events processed", processedEvents);
        return result;
    }

    private NetflowEvent parseNetflowLine(String line, User user) {
        try {
            String[] parts = line.split(",");
            if (parts.length < 11) {
                return null;
            }

            NetflowEvent event = new NetflowEvent();
            event.setTime(Long.parseLong(parts[0]));
            event.setDuration(Integer.parseInt(parts[1]));
            event.setSrcDevice(parts[2]);
            event.setDstDevice(parts[3]);
            event.setProtocol(Integer.parseInt(parts[4]));
            event.setSrcPort(parts[5]);
            event.setDstPort(parts[6]);
            event.setSrcPackets(Long.parseLong(parts[7]));
            event.setDstPackets(Long.parseLong(parts[8]));
            event.setSrcBytes(Long.parseLong(parts[9]));
            event.setDstBytes(Long.parseLong(parts[10]));
            event.setAnalyzedBy(user);
            
            // Simple rule-based analysis
            analyzeNetflowEvent(event);
            
            return event;
        } catch (Exception e) {
            logger.warn("Error parsing netflow line: {}", e.getMessage());
            return null;
        }
    }

    private WindowsLogEvent parseWindowsLogLine(String line, User user) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> json = objectMapper.readValue(line, Map.class);
            
            WindowsLogEvent event = new WindowsLogEvent();
            event.setUserName((String) json.get("UserName"));
            event.setEventId((Integer) json.get("EventID"));
            event.setLogHost((String) json.get("LogHost"));
            event.setLogonId((String) json.get("LogonID"));
            event.setDomainName((String) json.get("DomainName"));
            event.setParentProcessName((String) json.get("ParentProcessName"));
            event.setParentProcessId((String) json.get("ParentProcessID"));
            event.setProcessName((String) json.get("ProcessName"));
            event.setTime(((Number) json.get("Time")).longValue());
            event.setProcessId((String) json.get("ProcessID"));
            event.setLogonTypeDescription((String) json.get("LogonTypeDescription"));
            event.setSource((String) json.get("Source"));
            event.setAuthenticationPackage((String) json.get("AuthenticationPackage"));
            if (json.get("LogonType") != null) {
                event.setLogonType((Integer) json.get("LogonType"));
            }
            event.setAnalyzedBy(user);
            
            // Simple rule-based analysis
            analyzeWindowsLogEvent(event);
            
            return event;
        } catch (Exception e) {
            logger.warn("Error parsing Windows log line: {}", e.getMessage());
            return null;
        }
    }

    private void analyzeNetflowEvent(NetflowEvent event) {
        double severityScore = 0.0;
        
        // Check for suspicious ports
        if (event.getDstPort() != null) {
            try {
                int port = Integer.parseInt(event.getDstPort());
                if (port == 22 || port == 3389 || port == 445) {
                    severityScore += 2.0;
                }
            } catch (NumberFormatException ignored) {}
        }
        
        // Check for high data transfer
        if (event.getSrcBytes() != null && event.getSrcBytes() > 1000000) {
            severityScore += 1.0;
        }
        
        // Determine verdict
        if (severityScore >= 5.0) {
            event.setVerdict(Verdict.ANOMALOUS);
        } else if (severityScore >= 2.0) {
            event.setVerdict(Verdict.SUSPICIOUS);
        } else {
            event.setVerdict(Verdict.NORMAL);
        }
        
        event.setSeverityScore(Math.min(severityScore, 10.0));
        event.setConfidenceScore(0.75);
        event.setExplanation("Automated LANL dataset analysis");
    }

    private void analyzeWindowsLogEvent(WindowsLogEvent event) {
        double severityScore = 0.0;
        
        // Check for suspicious events
        if (event.getEventId() == 4625) { // Failed logon
            severityScore += 3.0;
        } else if (event.getEventId() == 4648) { // Explicit credentials
            severityScore += 2.0;
        } else if (event.getEventId() == 4688 && event.getProcessName() != null) {
            String process = event.getProcessName().toLowerCase();
            if (process.contains("powershell") || process.contains("cmd")) {
                severityScore += 1.5;
            }
        }
        
        // Determine verdict
        if (severityScore >= 5.0) {
            event.setVerdict(Verdict.ANOMALOUS);
        } else if (severityScore >= 2.0) {
            event.setVerdict(Verdict.SUSPICIOUS);
        } else {
            event.setVerdict(Verdict.NORMAL);
        }
        
        event.setSeverityScore(Math.min(severityScore, 10.0));
        event.setConfidenceScore(0.75);
        event.setExplanation("Automated LANL dataset analysis");
    }

    private Document createNetflowDocument(NetflowEvent event) {
        String content = String.format(
            "Netflow Event: %s -> %s:%s, Protocol: %s, Duration: %d, Bytes: %d/%d, Verdict: %s",
            event.getSrcDevice(), event.getDstDevice(), event.getDstPort(),
            event.getProtocolName(), event.getDuration(),
            event.getSrcBytes(), event.getDstBytes(), event.getVerdict()
        );
        
        Document doc = new Document(content);
        doc.getMetadata().put("type", "netflow");
        doc.getMetadata().put("eventId", event.getId());
        doc.getMetadata().put("verdict", event.getVerdict().toString());
        doc.getMetadata().put("timestamp", event.getTime().toString());
        
        return doc;
    }

    private Document createWindowsLogDocument(WindowsLogEvent event) {
        String content = String.format(
            "Windows Log Event: ID %d, User: %s, Host: %s, Process: %s, Verdict: %s, Description: %s",
            event.getEventId(), event.getUserName(), event.getLogHost(),
            event.getProcessName(), event.getVerdict(), event.getEventDescription()
        );
        
        Document doc = new Document(content);
        doc.getMetadata().put("type", "windows_log");
        doc.getMetadata().put("eventId", event.getId());
        doc.getMetadata().put("verdict", event.getVerdict().toString());
        doc.getMetadata().put("timestamp", event.getTime().toString());
        
        return doc;
    }

    private void saveBatch(List<NetflowEvent> events, List<Document> documents) {
        try {
            // Save to database
            netflowEventRepository.saveAll(events);
            
            // Save to vector store
            if (!documents.isEmpty()) {
                vectorStore.add(documents);
            }
            
            logger.debug("Saved batch of {} netflow events", events.size());
        } catch (Exception e) {
            logger.error("Error saving netflow batch: {}", e.getMessage(), e);
        }
    }

    private void saveWindowsBatch(List<WindowsLogEvent> events, List<Document> documents) {
        try {
            // Save to database
            windowsLogEventRepository.saveAll(events);
            
            // Save to vector store
            if (!documents.isEmpty()) {
                vectorStore.add(documents);
            }
            
            logger.debug("Saved batch of {} Windows log events", events.size());
        } catch (Exception e) {
            logger.error("Error saving Windows log batch: {}", e.getMessage(), e);
        }
    }

    public Map<String, Object> getImportStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("processedCount", processedCount.get());
        status.put("totalCount", totalCount.get());
        status.put("isProcessing", processedCount.get() < totalCount.get());
        
        if (totalCount.get() > 0) {
            status.put("progress", (double) processedCount.get() / totalCount.get() * 100);
        } else {
            status.put("progress", 0.0);
        }
        
        return status;
    }
}
