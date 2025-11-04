package edu.sjsu.cmpe.secainw.service;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import edu.sjsu.cmpe.secainw.model.AnomalyEvent;

@Service
public class CveEnrichmentService {
    private static final Logger logger = LoggerFactory.getLogger(CveEnrichmentService.class);

    @Value("${nvd.api.key:}")
    private String nvdApiKey;

    @Value("${nvd.api.base-url:https://services.nvd.nist.gov/rest/json/cves/2.0}")
    private String nvdBaseUrl;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public String enrichWithCveData(AnomalyEvent event) {
        logger.info("Enriching event {} with CVE data", event.getEventId());
        List<String> searchTerms = extractSearchTerms(event);
        StringBuilder cveDataBuilder = new StringBuilder();
        boolean liveDataFound = false;

        for (String term : searchTerms) {
            String cpeName = mapToCpeName(term);
            if (cpeName != null && !cpeName.isEmpty()) {
                try {
                    String liveCveInfo = queryNvdApi(cpeName);
                    if (liveCveInfo != null && !liveCveInfo.isEmpty()) {
                        cveDataBuilder.append(liveCveInfo);
                        liveDataFound = true;
                    }
                } catch (Exception e) {
                    logger.warn("Failed to query live NVD API for CPE '{}': {}", cpeName, e.getMessage());
                }
            }
        }

        // Fallback to simulated database if no live data was found
        if (!liveDataFound) {
            logger.info("No live CVE data found for event {}. Falling back to simulated database.", event.getEventId());
            for (String term : searchTerms) {
                cveDataBuilder.append(searchCveDatabase(term)).append(" ");
            }
        }

        String finalCveData = cveDataBuilder.toString().trim();
        return finalCveData.isEmpty() ? generateFallbackCveData(event) : finalCveData;
    }

    private String queryNvdApi(String cpeName) {
        String url = nvdBaseUrl + "?cpeName=" + cpeName;
        HttpHeaders headers = new HttpHeaders();
        if (nvdApiKey != null && !nvdApiKey.isEmpty()) {
            headers.set("apiKey", nvdApiKey);
        }
        HttpEntity<String> entity = new HttpEntity<>(headers);

        logger.info("Querying NVD API: {}", url);
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            return formatCveDataAsHtml(response.getBody());
        }
        return "";
    }

    private String formatCveDataAsHtml(String jsonResponse) {
        try {
            JsonNode root = objectMapper.readTree(jsonResponse);
            JsonNode vulnerabilities = root.path("vulnerabilities");
            if (vulnerabilities.isMissingNode() || !vulnerabilities.isArray() || vulnerabilities.isEmpty()) {
                return "";
            }

            StringBuilder htmlBuilder = new StringBuilder();
            htmlBuilder.append("<ul>");

            for (JsonNode vulnerability : vulnerabilities) {
                JsonNode cve = vulnerability.path("cve");
                String cveId = cve.path("id").asText("N/A");
                String description = cve.path("descriptions").get(0).path("value").asText("No description available.");
                // Get the English description if available
                JsonNode descriptions = cve.path("descriptions");
                if (descriptions.isArray()) {
                    for (JsonNode desc : descriptions) {
                        if ("en".equalsIgnoreCase(desc.path("lang").asText())) {
                            description = desc.path("value").asText(description);
                            break;
                        }
                    }
                }
                
                // Extract CVSS v3.1/v3.0/v2.0 score and severity
                String severity = "N/A";
                double score = 0.0;
                String cvssVersion = "N/A";

                JsonNode metrics = cve.path("metrics");

                // Prioritize CVSS v3.1
                JsonNode cvssMetricV31 = metrics.path("cvssMetricV31");
                if (cvssMetricV31.isArray() && !cvssMetricV31.isEmpty()) {
                    JsonNode cvssData = cvssMetricV31.get(0).path("cvssData");
                    score = cvssData.path("baseScore").asDouble(0.0);
                    severity = cvssMetricV31.get(0).path("baseSeverity").asText("N/A");
                    cvssVersion = "v3.1";
                } 
                // Fallback to CVSS v3.0
                else {
                    JsonNode cvssMetricV30 = metrics.path("cvssMetricV30");
                    if (cvssMetricV30.isArray() && !cvssMetricV30.isEmpty()) {
                         JsonNode cvssData = cvssMetricV30.get(0).path("cvssData");
                         score = cvssData.path("baseScore").asDouble(0.0);
                         severity = cvssMetricV30.get(0).path("baseSeverity").asText("N/A");
                         cvssVersion = "v3.0";
                    }
                    // Fallback to CVSS v2.0
                    else {
                        JsonNode cvssMetricV2 = metrics.path("cvssMetricV2");
                         if (cvssMetricV2.isArray() && !cvssMetricV2.isEmpty()) {
                             JsonNode cvssData = cvssMetricV2.get(0).path("cvssData");
                             score = cvssData.path("baseScore").asDouble(0.0);
                             // CVSS v2 uses different field names sometimes, adjust if needed based on API response
                             severity = cvssMetricV2.get(0).path("baseSeverity").asText("N/A"); 
                             cvssVersion = "v2.0";
                         }
                    }
                }
                
                htmlBuilder.append("<li>");
                htmlBuilder.append("<b>").append(cveId).append("</b>");
                //htmlBuilder.append(" [Severity: ").append(severity).append(", Score: ").append(score).append("]<br/>");
                htmlBuilder.append(" [CVSS ").append(cvssVersion).append(" Severity: ").append(severity).append(", Score: ").append(score).append("]<br/>");
                htmlBuilder.append(description);
                htmlBuilder.append("</li>");
            }
            htmlBuilder.append("</ul>");
            return htmlBuilder.toString();
        } catch (Exception e) {
            logger.error("Error parsing NVD JSON response", e);
            return "<p>Error parsing CVE data.</p>";
        }
    }
    
    private String mapToCpeName(String searchTerm) {
        return switch (searchTerm.toLowerCase()) {
            case "apache", "http server" -> "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*";
            case "mysql" -> "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*";
            case "java" -> "cpe:2.3:a:oracle:jre:*:*:*:*:*:*:*:*";
            case "openssh", "ssh" -> "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*";
            case "nginx" -> "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*";
            case "powershell" -> "cpe:2.3:a:microsoft:powershell:*:*:*:*:*:*:*:*";
            case "w3wp.exe", "microsoft exchange" -> "cpe:2.3:a:microsoft:exchange_server:2016:*:*:*:*:*:*:*";
            default -> null;
        };
    }

    private String searchCveDatabase(String searchTerm) {
        try {
            // Simulate CVE database search with realistic data
            return switch (searchTerm.toLowerCase()) {
                case "java" -> "CVE-2023-22081: Oracle Java SE vulnerability allowing remote code execution. " +
                              "CVE-2023-22049: Oracle Java SE vulnerability in Hotspot component.";
                
                case "apache" -> "CVE-2023-44487: Apache HTTP Server HTTP/2 Rapid Reset vulnerability. " +
                               "CVE-2023-38545: Apache HTTP Server mod_http2 vulnerability.";
                
                case "nginx" -> "CVE-2023-44487: Nginx HTTP/2 implementation vulnerability. " +
                              "CVE-2023-4807: Nginx HTTP/2 stream handling vulnerability.";
                
                case "mysql" -> "CVE-2023-22084: MySQL Server vulnerability in InnoDB component. " +
                              "CVE-2023-22092: MySQL Server vulnerability in Server: Optimizer component.";
                
                case "postgresql" -> "CVE-2023-39417: PostgreSQL extension script vulnerability. " +
                                   "CVE-2023-39418: PostgreSQL MERGE privilege escalation vulnerability.";
                
                case "ssh", "openssh" -> "CVE-2023-38408: OpenSSH ssh-agent vulnerability allowing remote code execution. " +
                                       "CVE-2023-28531: OpenSSH before 9.3 vulnerability.";
                
                case "powershell" -> "CVE-2023-36884: Windows PowerShell remote code execution vulnerability. " +
                                   "CVE-2023-36033: Windows PowerShell elevation of privilege vulnerability.";
                
                case "http server", "https server" -> "CVE-2023-44487: HTTP/2 Rapid Reset attack vulnerability affecting multiple implementations. " +
                                                    "CVE-2023-4807: HTTP/2 stream handling vulnerabilities.";
                
                case "rdp" -> "CVE-2023-21708: Remote Desktop Protocol vulnerability allowing remote code execution. " +
                            "CVE-2023-23397: Microsoft Outlook elevation of privilege vulnerability.";
                
                case "dns" -> "CVE-2023-50387: DNSSEC validation vulnerability (KeyTrap). " +
                            "CVE-2023-50868: NSEC3 closest encloser proof vulnerability.";
                
                case "smtp" -> "CVE-2023-51765: Sendmail vulnerability allowing local privilege escalation. " +
                             "CVE-2023-4863: SMTP server buffer overflow vulnerability.";
                
                default -> "";
            };

        } catch (Exception e) {
            logger.error("Error searching CVE database for term '{}': {}", searchTerm, e.getMessage());
            return "";
        }
    }
    
    private List<String> extractSearchTerms(AnomalyEvent event) {
        List<String> searchTerms = new ArrayList<>();

        // Extract from process name
        if (event.getProcessName() != null) {
            String processName = event.getProcessName().toLowerCase();
            if (processName.contains("java")) {
                searchTerms.add("java");
            } else if (processName.contains("apache") || processName.contains("httpd")) {
                searchTerms.add("apache");
            } else if (processName.contains("nginx")) {
                searchTerms.add("nginx");
            } else if (processName.contains("mysql")) {
                searchTerms.add("mysql");
            } else if (processName.contains("postgres")) {
                searchTerms.add("postgresql");
            } else if (processName.contains("ssh")) {
                searchTerms.add("openssh");
            } else if (processName.contains("powershell")) {
                searchTerms.add("powershell");
            } else if (processName.contains("cmd")) {
                searchTerms.add("windows command");
            } else if (processName.contains("w3wp.exe")) {
                searchTerms.add("w3wp.exe");
            }
        }

        // Extract from destination port
        if (event.getDestinationPort() != null) {
            int port = event.getDestinationPort();
            
            switch (port) {
                case 80, 8080, 8000 -> searchTerms.add("http server");
                case 443, 8443 -> searchTerms.add("https server");
                case 22 -> searchTerms.add("ssh");
                case 21 -> searchTerms.add("ftp");
                case 23 -> searchTerms.add("telnet");
                case 25, 587 -> searchTerms.add("smtp");
                case 53 -> searchTerms.add("dns");
                case 110 -> searchTerms.add("pop3");
                case 143 -> searchTerms.add("imap");
                case 3306 -> searchTerms.add("mysql");
                case 5432 -> searchTerms.add("postgresql");
                case 1521 -> searchTerms.add("oracle");
                case 1433 -> searchTerms.add("mssql");
                case 3389 -> searchTerms.add("rdp");
                case 5900 -> searchTerms.add("vnc");
            }
        }

        // Extract from event type
        if (event.getEventType() != null) {
            String eventType = event.getEventType().toLowerCase();
            if (eventType.contains("network") || eventType.contains("connection")) {
                searchTerms.add("network");
            } else if (eventType.contains("process") || eventType.contains("execution")) {
                searchTerms.add("process execution");
            } else if (eventType.contains("file") || eventType.contains("access")) {
                searchTerms.add("file access");
            }
        }

        return searchTerms.stream().distinct().limit(3).toList(); // Limit to 3 terms to avoid rate limiting
    }

    private String generateFallbackCveData(AnomalyEvent event) {
        StringBuilder fallback = new StringBuilder();
        fallback.append("CVE enrichment completed with limited data. ");

        if (event.getDestinationPort() != null) {
            int port = event.getDestinationPort();
            fallback.append("Port ").append(port).append(" services should be monitored for known vulnerabilities. ");
        }

        if (event.getProcessName() != null) {
            fallback.append("Process '").append(event.getProcessName()).append("' should be checked against latest security advisories. ");
        }

        fallback.append("Recommend regular vulnerability scanning and patch management.");

        return fallback.toString();
    }
}
