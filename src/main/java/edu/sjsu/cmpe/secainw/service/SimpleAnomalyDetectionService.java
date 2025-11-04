package edu.sjsu.cmpe.secainw.service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import edu.sjsu.cmpe.secainw.dto.AnomalyDetectionRequest;
import edu.sjsu.cmpe.secainw.model.AnomalyEvent;
import edu.sjsu.cmpe.secainw.model.AnomalyEvent.Verdict;
import edu.sjsu.cmpe.secainw.model.User;
import edu.sjsu.cmpe.secainw.repository.AnomalyEventRepository;

@Service
@Transactional
public class SimpleAnomalyDetectionService {
    private static final Logger logger = LoggerFactory.getLogger(SimpleAnomalyDetectionService.class);

    @Autowired
    private AnomalyEventRepository anomalyEventRepository;

    @Autowired
    private CveEnrichmentService cveEnrichmentService;

    private final Random random = new Random();

    public AnomalyEvent analyzeEvent(AnomalyDetectionRequest request, User user) {
        try {
            logger.info("Analyzing event: {}", request.getEventId());

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

            // Simple rule-based analysis (simulating AI analysis)
            analyzeEventWithRules(event);

            // Enrich with CVE data
            try {
                String cveData = cveEnrichmentService.enrichWithCveData(event);
                event.setCveData(cveData);
            } catch (Exception e) {
                logger.warn("CVE enrichment failed: {}", e.getMessage());
                event.setCveData("CVE enrichment unavailable");
            }

            // Save the event
            AnomalyEvent savedEvent = anomalyEventRepository.save(event);
            logger.info("Event analysis completed for: {}", savedEvent.getEventId());

            return savedEvent;

        } catch (Exception e) {
            logger.error("Error analyzing event {}: {}", request.getEventId(), e.getMessage(), e);
            throw new RuntimeException("Failed to analyze event: " + e.getMessage());
        }
    }

    private void analyzeEventWithRules(AnomalyEvent event) {
        double severityScore = 0.0;
        double confidenceScore = 0.7;
        Verdict verdict = Verdict.NORMAL;
        StringBuilder explanation = new StringBuilder();
        StringBuilder evidence = new StringBuilder();

        // Rule 1: Check for suspicious ports
        if (event.getDestinationPort() != null) {
            int port = event.getDestinationPort();
            if (isHighRiskPort(port)) {
                severityScore += 3.0;
                explanation.append("Connection to high-risk port ").append(port).append(". ");
                evidence.append("Destination port: ").append(port).append("; ");
            } else if (isCommonPort(port)) {
                explanation.append("Connection to common service port ").append(port).append(". ");
                evidence.append("Standard port usage: ").append(port).append("; ");
            } else {
                severityScore += 1.0;
                explanation.append("Connection to uncommon port ").append(port).append(". ");
                evidence.append("Uncommon port: ").append(port).append("; ");
            }
        }

        // Rule 2: Check source IP patterns
        if (event.getSourceIp() != null) {
            if (isPrivateIP(event.getSourceIp())) {
                explanation.append("Internal network source. ");
                evidence.append("Private IP source: ").append(event.getSourceIp()).append("; ");
            } else {
                severityScore += 2.0;
                explanation.append("External network source detected. ");
                evidence.append("External IP source: ").append(event.getSourceIp()).append("; ");
            }
        }

        // Rule 3: Check destination IP patterns
        if (event.getDestinationIp() != null) {
            if (!isPrivateIP(event.getDestinationIp())) {
                severityScore += 1.0;
                explanation.append("Outbound connection to external IP. ");
                evidence.append("External destination: ").append(event.getDestinationIp()).append("; ");
            }
        }

        // Rule 4: Check process patterns
        if (event.getProcessName() != null) {
            String processName = event.getProcessName().toLowerCase();
            if (isSuspiciousProcess(processName)) {
                severityScore += 4.0;
                explanation.append("Potentially suspicious process detected. ");
                evidence.append("Process: ").append(event.getProcessName()).append("; ");
            } else if (isSystemProcess(processName)) {
                explanation.append("System process activity. ");
                evidence.append("System process: ").append(event.getProcessName()).append("; ");
            } else {
                explanation.append("User application activity. ");
                evidence.append("User process: ").append(event.getProcessName()).append("; ");
            }
        }

        // Rule 5: Check event type patterns
        if (event.getEventType() != null) {
            String eventType = event.getEventType().toLowerCase();
            if (eventType.contains("execution") || eventType.contains("process")) {
                severityScore += 0.5;
                explanation.append("Process execution event. ");
                evidence.append("Event type: ").append(event.getEventType()).append("; ");
            } else if (eventType.contains("network") || eventType.contains("connection")) {
                explanation.append("Network activity event. ");
                evidence.append("Network event: ").append(event.getEventType()).append("; ");
            }
        }

        // Add some randomness to simulate AI variability
        severityScore += (random.nextDouble() - 0.5) * 1.0;
        confidenceScore += (random.nextDouble() - 0.5) * 0.2;

        // Ensure scores are within valid ranges
        severityScore = Math.max(0.0, Math.min(10.0, severityScore));
        confidenceScore = Math.max(0.0, Math.min(1.0, confidenceScore));

        // Determine verdict based on severity score
        if (severityScore >= 7.0) {
            verdict = Verdict.ANOMALOUS;
            explanation.append("High severity score indicates anomalous behavior.");
        } else if (severityScore >= 4.0) {
            verdict = Verdict.SUSPICIOUS;
            explanation.append("Moderate severity score indicates suspicious activity.");
        } else {
            verdict = Verdict.NORMAL;
            explanation.append("Low severity score indicates normal behavior.");
        }

        // Set the analysis results
        event.setVerdict(verdict);
        event.setSeverityScore(severityScore);
        event.setConfidenceScore(confidenceScore);
        event.setExplanation(explanation.toString().trim());
        event.setSupportingEvidence(evidence.toString().trim());
    }

    private boolean isHighRiskPort(int port) {
        // Common attack/backdoor ports
        return port == 1337 || port == 31337 || port == 12345 || port == 54321 || 
               port == 9999 || port == 6666 || port == 4444;
    }

    private boolean isCommonPort(int port) {
        // Standard service ports
        return port == 80 || port == 443 || port == 22 || port == 21 || port == 25 || 
               port == 53 || port == 110 || port == 143 || port == 993 || port == 995;
    }

    private boolean isPrivateIP(String ip) {
        if (ip == null) return false;
        return ip.startsWith("192.168.") || ip.startsWith("10.") || 
               ip.startsWith("172.16.") || ip.startsWith("172.17.") || 
               ip.startsWith("172.18.") || ip.startsWith("172.19.") ||
               ip.startsWith("172.2") || ip.startsWith("172.30.") ||
               ip.startsWith("172.31.") || ip.equals("127.0.0.1");
    }

    private boolean isSuspiciousProcess(String processName) {
        // Common suspicious process names
        return processName.contains("cmd.exe") || processName.contains("powershell") ||
               processName.contains("nc.exe") || processName.contains("netcat") ||
               processName.contains("mimikatz") || processName.contains("psexec") ||
               processName.contains("wmic") || processName.contains("rundll32");
    }

    private boolean isSystemProcess(String processName) {
        // Common system processes
        return processName.contains("svchost") || processName.contains("explorer") ||
               processName.contains("winlogon") || processName.contains("csrss") ||
               processName.contains("lsass") || processName.contains("smss");
    }

    public Optional<AnomalyEvent> findById(Long id) {
        return anomalyEventRepository.findById(id);
    }
}
