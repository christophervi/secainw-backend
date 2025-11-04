package edu.sjsu.cmpe.secainw.model;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

@Entity
@Table(name = "analyst_feedback")
public class AnalystFeedback {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@NotNull
	@Min(1)
	@Max(5)
	@Column(name = "accuracy_rating")
	private Integer accuracyRating;

	@NotNull
	@Min(1)
	@Max(5)
	@Column(name = "explanation_quality_rating")
	private Integer explanationQualityRating;

	@Column(name = "comments", columnDefinition = "CLOB")
	private String comments;

	@Column(name = "is_correct_detection")
	private Boolean isCorrectDetection;

	@Column(name = "created_at")
	private LocalDateTime createdAt;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "anomaly_event_id", nullable = false)
	private AnomalyEvent anomalyEvent;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "user_id", nullable = false)
	private User user;

	@PrePersist
	protected void onCreate() {
		createdAt = LocalDateTime.now();
	}

	public AnalystFeedback() {
	}

	// Getters and Setters
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Integer getAccuracyRating() {
		return accuracyRating;
	}

	public void setAccuracyRating(Integer accuracyRating) {
		this.accuracyRating = accuracyRating;
	}

	public Integer getExplanationQualityRating() {
		return explanationQualityRating;
	}

	public void setExplanationQualityRating(Integer explanationQualityRating) {
		this.explanationQualityRating = explanationQualityRating;
	}

	public String getComments() {
		return comments;
	}

	public void setComments(String comments) {
		this.comments = comments;
	}

	public Boolean getIsCorrectDetection() {
		return isCorrectDetection;
	}

	public void setIsCorrectDetection(Boolean isCorrectDetection) {
		this.isCorrectDetection = isCorrectDetection;
	}

	public LocalDateTime getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(LocalDateTime createdAt) {
		this.createdAt = createdAt;
	}

	public AnomalyEvent getAnomalyEvent() {
		return anomalyEvent;
	}

	public void setAnomalyEvent(AnomalyEvent anomalyEvent) {
		this.anomalyEvent = anomalyEvent;
	}

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}
}
