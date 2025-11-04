package edu.sjsu.cmpe.secainw.dto;

import java.time.LocalDateTime;

import edu.sjsu.cmpe.secainw.model.AnomalyEvent;

public class AnomalyDetectionResponse {
	private Long id;
	private String eventId;
	private LocalDateTime timestamp;
	private String eventType;
	private String sourceIp;
	private String destinationIp;
	private Integer destinationPort;
	private String processName;
	private AnomalyEvent.Verdict verdict;
	private Double severityScore;
	private Double confidenceScore;
	private String explanation;
	private String supportingEvidence;
	private String cveData;
	private String reportUrl;
	private LocalDateTime createdAt;

	public AnomalyDetectionResponse() {
	}

	public AnomalyDetectionResponse(AnomalyEvent event) {
		this.id = event.getId();
		this.eventId = event.getEventId();
		this.timestamp = event.getTimestamp();
		this.eventType = event.getEventType();
		this.sourceIp = event.getSourceIp();
		this.destinationIp = event.getDestinationIp();
		this.destinationPort = event.getDestinationPort();
		this.processName = event.getProcessName();
		this.verdict = event.getVerdict();
		this.severityScore = event.getSeverityScore();
		this.confidenceScore = event.getConfidenceScore();
		this.explanation = event.getExplanation();
		this.supportingEvidence = event.getSupportingEvidence();
		this.cveData = event.getCveData();
		this.reportUrl = event.getReportUrl();
		this.createdAt = event.getCreatedAt();
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

	public AnomalyEvent.Verdict getVerdict() {
		return verdict;
	}

	public void setVerdict(AnomalyEvent.Verdict verdict) {
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
}
