package edu.sjsu.cmpe.secainw.model;

import java.time.LocalDateTime;

import edu.sjsu.cmpe.secainw.model.AnomalyEvent.Verdict;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;

@Entity
@Table(name = "windows_log_events")
public class WindowsLogEvent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_name", length = 100)
    private String userName;

    @NotNull
    @Column(name = "event_id")
    private Integer eventId;

    @Column(name = "log_host", length = 100)
    private String logHost;

    @Column(name = "logon_id", length = 50)
    private String logonId;

    @Column(name = "domain_name", length = 100)
    private String domainName;

    @Column(name = "parent_process_name", length = 200)
    private String parentProcessName;

    @Column(name = "parent_process_id", length = 20)
    private String parentProcessId;

    @Column(name = "process_name", length = 200)
    private String processName;

    @NotNull
    @Column(name = "event_time")
    private Long time; // Unix timestamp

    @Column(name = "process_id", length = 20)
    private String processId;

    @Column(name = "logon_type_description", length = 50)
    private String logonTypeDescription;

    @Column(name = "source", length = 100)
    private String source;

    @Column(name = "authentication_package", length = 50)
    private String authenticationPackage;

    @Column(name = "logon_type")
    private Integer logonType;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "analyzed_by")
    private User analyzedBy;

    @Enumerated(EnumType.STRING)
    @Column(name = "verdict")
    private Verdict verdict;

    @Column(name = "severity_score")
    private Double severityScore;

    @Column(name = "confidence_score")
    private Double confidenceScore;

    @Column(name = "explanation", columnDefinition = "CLOB")
    private String explanation;

    // Constructors
    public WindowsLogEvent() {
        this.createdAt = LocalDateTime.now();
    }

    public WindowsLogEvent(String userName, Integer eventId, String logHost, Long time) {
        this();
        this.userName = userName;
        this.eventId = eventId;
        this.logHost = logHost;
        this.time = time;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUserName() { return userName; }
    public void setUserName(String userName) { this.userName = userName; }

    public Integer getEventId() { return eventId; }
    public void setEventId(Integer eventId) { this.eventId = eventId; }

    public String getLogHost() { return logHost; }
    public void setLogHost(String logHost) { this.logHost = logHost; }

    public String getLogonId() { return logonId; }
    public void setLogonId(String logonId) { this.logonId = logonId; }

    public String getDomainName() { return domainName; }
    public void setDomainName(String domainName) { this.domainName = domainName; }

    public String getParentProcessName() { return parentProcessName; }
    public void setParentProcessName(String parentProcessName) { this.parentProcessName = parentProcessName; }

    public String getParentProcessId() { return parentProcessId; }
    public void setParentProcessId(String parentProcessId) { this.parentProcessId = parentProcessId; }

    public String getProcessName() { return processName; }
    public void setProcessName(String processName) { this.processName = processName; }

    public Long getTime() { return time; }
    public void setTime(Long time) { this.time = time; }

    public String getProcessId() { return processId; }
    public void setProcessId(String processId) { this.processId = processId; }

    public String getLogonTypeDescription() { return logonTypeDescription; }
    public void setLogonTypeDescription(String logonTypeDescription) { this.logonTypeDescription = logonTypeDescription; }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    public String getAuthenticationPackage() { return authenticationPackage; }
    public void setAuthenticationPackage(String authenticationPackage) { this.authenticationPackage = authenticationPackage; }

    public Integer getLogonType() { return logonType; }
    public void setLogonType(Integer logonType) { this.logonType = logonType; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public User getAnalyzedBy() { return analyzedBy; }
    public void setAnalyzedBy(User analyzedBy) { this.analyzedBy = analyzedBy; }

    public Verdict getVerdict() { return verdict; }
    public void setVerdict(Verdict verdict) { this.verdict = verdict; }

    public Double getSeverityScore() { return severityScore; }
    public void setSeverityScore(Double severityScore) { this.severityScore = severityScore; }

    public Double getConfidenceScore() { return confidenceScore; }
    public void setConfidenceScore(Double confidenceScore) { this.confidenceScore = confidenceScore; }

    public String getExplanation() { return explanation; }
    public void setExplanation(String explanation) { this.explanation = explanation; }

    // Helper methods
    public String getEventDescription() {
        return switch (eventId) {
            case 4624 -> "Successful logon";
            case 4625 -> "Failed logon";
            case 4634 -> "Logoff";
            case 4647 -> "User initiated logoff";
            case 4648 -> "Logon using explicit credentials";
            case 4672 -> "Special privileges assigned";
            case 4688 -> "Process creation";
            case 4689 -> "Process termination";
            case 4697 -> "Service installed";
            case 4698 -> "Scheduled task created";
            case 4699 -> "Scheduled task deleted";
            case 4700 -> "Scheduled task enabled";
            case 4701 -> "Scheduled task disabled";
            case 4702 -> "Scheduled task updated";
            default -> "Event ID " + eventId;
        };
    }

    public LocalDateTime getEventDateTime() {
        return LocalDateTime.ofEpochSecond(time, 0, java.time.ZoneOffset.UTC);
    }

    public boolean isSuspiciousEvent() {
        // Define suspicious event patterns
        return eventId == 4625 || // Failed logon
               eventId == 4648 || // Explicit credentials
               (eventId == 4688 && processName != null && 
                (processName.toLowerCase().contains("powershell") || 
                 processName.toLowerCase().contains("cmd") ||
                 processName.toLowerCase().contains("wmic")));
    }

    @Override
    public String toString() {
        return "WindowsLogEvent{" +
                "id=" + id +
                ", userName='" + userName + '\'' +
                ", eventId=" + eventId +
                ", logHost='" + logHost + '\'' +
                ", processName='" + processName + '\'' +
                ", time=" + time +
                '}';
    }
}
