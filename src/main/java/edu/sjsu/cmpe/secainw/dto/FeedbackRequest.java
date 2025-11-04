package edu.sjsu.cmpe.secainw.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

public class FeedbackRequest {
    @NotNull
    @Min(1)
    @Max(5)
    private Integer accuracyRating;

    @NotNull
    @Min(1)
    @Max(5)
    private Integer explanationQualityRating;

    private String comments;

    @NotNull
    private Boolean isCorrectDetection;

    public FeedbackRequest() {}

    public Integer getAccuracyRating() { return accuracyRating; }
    public void setAccuracyRating(Integer accuracyRating) { this.accuracyRating = accuracyRating; }

    public Integer getExplanationQualityRating() { return explanationQualityRating; }
    public void setExplanationQualityRating(Integer explanationQualityRating) { this.explanationQualityRating = explanationQualityRating; }

    public String getComments() { return comments; }
    public void setComments(String comments) { this.comments = comments; }

    public Boolean getIsCorrectDetection() { return isCorrectDetection; }
    public void setIsCorrectDetection(Boolean isCorrectDetection) { this.isCorrectDetection = isCorrectDetection; }
}
