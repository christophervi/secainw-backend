package edu.sjsu.cmpe.secainw.model;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonBackReference;

import jakarta.persistence.CascadeType;
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
import jakarta.persistence.OneToMany;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Entity
@Table(name = "anomaly_events")
public class AnomalyEvent {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@NotBlank
	@Column(name = "event_id")
	private String eventId;

	@NotNull
	@Column(name = "timestamp")
	private LocalDateTime timestamp;

	@NotBlank
	@Column(name = "event_type")
	private String eventType;

	@NotBlank
	@Column(name = "source_ip")
	private String sourceIp;

	@Column(name = "destination_ip")
	private String destinationIp;

	@Column(name = "destination_port")
	private Integer destinationPort;

	@Column(name = "process_name")
	private String processName;

	@Enumerated(EnumType.STRING)
	@Column(name = "verdict")
	private Verdict verdict;

	@Column(name = "severity_score")
	private Double severityScore;

	@Column(name = "confidence_score")
	private Double confidenceScore;

	@Column(name = "explanation", columnDefinition = "CLOB")
	private String explanation;

	@Column(name = "supporting_evidence", columnDefinition = "CLOB")
	private String supportingEvidence;

	@Column(name = "cve_data", columnDefinition = "CLOB")
	private String cveData;

	@Column(name = "raw_data", columnDefinition = "CLOB")
	private String rawData;

	@Column(name = "ai_model")
	private String aiModel;

	@Column(name = "report_url")
	private String reportUrl;

	@Column(name = "created_at")
	private LocalDateTime createdAt;

	@Column(name = "updated_at")
	private LocalDateTime updatedAt;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "user_id")
	@JsonBackReference
	private User user;

	@OneToMany(mappedBy = "anomalyEvent", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
	private Set<AnalystFeedback> feedbacks = new HashSet<>();

	public enum Verdict {
		ANOMALOUS, NORMAL, SUSPICIOUS
	}

	@PrePersist
	protected void onCreate() {
		createdAt = LocalDateTime.now();
		updatedAt = LocalDateTime.now();
	}

	@PreUpdate
	protected void onUpdate() {
		updatedAt = LocalDateTime.now();
	}

	public AnomalyEvent() {
	}

	// Getters and Setters
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getEventId() {
		return eventId;
	}

	public void setEventId(String eventId) {
		this.eventId = eventId;
	}

	public LocalDateTime getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(LocalDateTime timestamp) {
		this.timestamp = timestamp;
	}

	public String getEventType() {
		return eventType;
	}

	public void setEventType(String eventType) {
		this.eventType = eventType;
	}

	public String getSourceIp() {
		return sourceIp;
	}

	public void setSourceIp(String sourceIp) {
		this.sourceIp = sourceIp;
	}

	public String getDestinationIp() {
		return destinationIp;
	}

	public void setDestinationIp(String destinationIp) {
		this.destinationIp = destinationIp;
	}

	public Integer getDestinationPort() {
		return destinationPort;
	}

	public void setDestinationPort(Integer destinationPort) {
		this.destinationPort = destinationPort;
	}

	public String getProcessName() {
		return processName;
	}

	public void setProcessName(String processName) {
		this.processName = processName;
	}

	public Verdict getVerdict() {
		return verdict;
	}

	public void setVerdict(Verdict verdict) {
		this.verdict = verdict;
	}

	public Double getSeverityScore() {
		return severityScore;
	}

	public void setSeverityScore(Double severityScore) {
		this.severityScore = severityScore;
	}

	public Double getConfidenceScore() {
		return confidenceScore;
	}

	public void setConfidenceScore(Double confidenceScore) {
		this.confidenceScore = confidenceScore;
	}

	public String getExplanation() {
		return explanation;
	}

	public void setExplanation(String explanation) {
		this.explanation = explanation;
	}

	public String getSupportingEvidence() {
		return supportingEvidence;
	}

	public void setSupportingEvidence(String supportingEvidence) {
		this.supportingEvidence = supportingEvidence;
	}

	public String getCveData() {
		return cveData;
	}

	public void setCveData(String cveData) {
		this.cveData = cveData;
	}

	public String getRawData() {
		return rawData;
	}

	public void setRawData(String rawData) {
		this.rawData = rawData;
	}

	public String getAiModel() {
		return aiModel;
	}

	public void setAiModel(String aiModel) {
		this.aiModel = aiModel;
	}

	public String getReportUrl() {
		return reportUrl;
	}

	public void setReportUrl(String reportUrl) {
		this.reportUrl = reportUrl;
	}

	public LocalDateTime getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(LocalDateTime createdAt) {
		this.createdAt = createdAt;
	}

	public LocalDateTime getUpdatedAt() {
		return updatedAt;
	}

	public void setUpdatedAt(LocalDateTime updatedAt) {
		this.updatedAt = updatedAt;
	}

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	public Set<AnalystFeedback> getFeedbacks() {
		return feedbacks;
	}

	public void setFeedbacks(Set<AnalystFeedback> feedbacks) {
		this.feedbacks = feedbacks;
	}
}
