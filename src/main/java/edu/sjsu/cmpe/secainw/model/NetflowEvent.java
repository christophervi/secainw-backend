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
@Table(name = "netflow_events")
public class NetflowEvent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @Column(name = "event_time")
    private Long time; // Unix timestamp

    @Column(name = "duration")
    private Integer duration;

    @Column(name = "src_device", length = 50)
    private String srcDevice;

    @Column(name = "dst_device", length = 50)
    private String dstDevice;

    @Column(name = "protocol")
    private Integer protocol; // 6=TCP, 17=UDP

    @Column(name = "src_port", length = 20)
    private String srcPort;

    @Column(name = "dst_port", length = 20)
    private String dstPort;

    @Column(name = "src_packets")
    private Long srcPackets;

    @Column(name = "dst_packets")
    private Long dstPackets;

    @Column(name = "src_bytes")
    private Long srcBytes;

    @Column(name = "dst_bytes")
    private Long dstBytes;

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
    public NetflowEvent() {
        this.createdAt = LocalDateTime.now();
    }

    public NetflowEvent(Long time, Integer duration, String srcDevice, String dstDevice, 
                       Integer protocol, String srcPort, String dstPort) {
        this();
        this.time = time;
        this.duration = duration;
        this.srcDevice = srcDevice;
        this.dstDevice = dstDevice;
        this.protocol = protocol;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getTime() { return time; }
    public void setTime(Long time) { this.time = time; }

    public Integer getDuration() { return duration; }
    public void setDuration(Integer duration) { this.duration = duration; }

    public String getSrcDevice() { return srcDevice; }
    public void setSrcDevice(String srcDevice) { this.srcDevice = srcDevice; }

    public String getDstDevice() { return dstDevice; }
    public void setDstDevice(String dstDevice) { this.dstDevice = dstDevice; }

    public Integer getProtocol() { return protocol; }
    public void setProtocol(Integer protocol) { this.protocol = protocol; }

    public String getSrcPort() { return srcPort; }
    public void setSrcPort(String srcPort) { this.srcPort = srcPort; }

    public String getDstPort() { return dstPort; }
    public void setDstPort(String dstPort) { this.dstPort = dstPort; }

    public Long getSrcPackets() { return srcPackets; }
    public void setSrcPackets(Long srcPackets) { this.srcPackets = srcPackets; }

    public Long getDstPackets() { return dstPackets; }
    public void setDstPackets(Long dstPackets) { this.dstPackets = dstPackets; }

    public Long getSrcBytes() { return srcBytes; }
    public void setSrcBytes(Long srcBytes) { this.srcBytes = srcBytes; }

    public Long getDstBytes() { return dstBytes; }
    public void setDstBytes(Long dstBytes) { this.dstBytes = dstBytes; }

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
    public String getProtocolName() {
        return switch (protocol) {
            case 6 -> "TCP";
            case 17 -> "UDP";
            case 1 -> "ICMP";
            default -> "Unknown (" + protocol + ")";
        };
    }

    public LocalDateTime getEventDateTime() {
        return LocalDateTime.ofEpochSecond(time, 0, java.time.ZoneOffset.UTC);
    }

    @Override
    public String toString() {
        return "NetflowEvent{" +
                "id=" + id +
                ", time=" + time +
                ", srcDevice='" + srcDevice + '\'' +
                ", dstDevice='" + dstDevice + '\'' +
                ", protocol=" + protocol +
                ", srcPort='" + srcPort + '\'' +
                ", dstPort='" + dstPort + '\'' +
                '}';
    }
}
