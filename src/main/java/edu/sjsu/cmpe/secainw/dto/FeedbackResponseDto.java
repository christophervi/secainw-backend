package edu.sjsu.cmpe.secainw.dto;

import java.time.LocalDateTime;

import edu.sjsu.cmpe.secainw.model.AnalystFeedback;

public class FeedbackResponseDto {

	private Long id;
	private Integer accuracyRating;
	private Integer explanationQualityRating;
	private String comments;
	private Boolean isCorrectDetection;
	private LocalDateTime createdAt;
	private String username;

	public FeedbackResponseDto(AnalystFeedback feedback) {
		this.id = feedback.getId();
		this.accuracyRating = feedback.getAccuracyRating();
		this.explanationQualityRating = feedback.getExplanationQualityRating();
		this.comments = feedback.getComments();
		this.isCorrectDetection = feedback.getIsCorrectDetection();
		this.createdAt = feedback.getCreatedAt();
		// Safely get the username from the associated User object
		if (feedback.getUser() != null) {
			this.username = feedback.getUser().getUsername();
		} else {
			this.username = "Unknown User";
		}
	}

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

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}
}
