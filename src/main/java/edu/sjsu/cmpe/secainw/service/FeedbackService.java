package edu.sjsu.cmpe.secainw.service;

import edu.sjsu.cmpe.secainw.dto.FeedbackRequest;
import edu.sjsu.cmpe.secainw.model.AnalystFeedback;
import edu.sjsu.cmpe.secainw.model.AnomalyEvent;
import edu.sjsu.cmpe.secainw.model.User;
import edu.sjsu.cmpe.secainw.repository.AnalystFeedbackRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@Transactional
public class FeedbackService {
    @Autowired
    private AnalystFeedbackRepository feedbackRepository;

    public AnalystFeedback submitFeedback(AnomalyEvent anomalyEvent, User user, FeedbackRequest request) {
        // Check if feedback already exists for this user and event
        Optional<AnalystFeedback> existingFeedback = feedbackRepository.findByAnomalyEventAndUser(anomalyEvent, user);
        
        AnalystFeedback feedback;
        if (existingFeedback.isPresent()) {
            // Update existing feedback
            feedback = existingFeedback.get();
        } else {
            // Create new feedback
            feedback = new AnalystFeedback();
            feedback.setAnomalyEvent(anomalyEvent);
            feedback.setUser(user);
        }
        
        feedback.setAccuracyRating(request.getAccuracyRating());
        feedback.setExplanationQualityRating(request.getExplanationQualityRating());
        feedback.setComments(request.getComments());
        feedback.setIsCorrectDetection(request.getIsCorrectDetection());
        
        return feedbackRepository.save(feedback);
    }

    public List<AnalystFeedback> getFeedbackForEvent(AnomalyEvent anomalyEvent) {
        return feedbackRepository.findByAnomalyEvent(anomalyEvent);
    }

    public List<AnalystFeedback> getFeedbackByUser(User user) {
        return feedbackRepository.findByUser(user);
    }

    public Optional<AnalystFeedback> getFeedbackByEventAndUser(AnomalyEvent anomalyEvent, User user) {
        return feedbackRepository.findByAnomalyEventAndUser(anomalyEvent, user);
    }

    public Double getAverageAccuracyRating() {
        return feedbackRepository.getAverageAccuracyRating();
    }

    public Double getAverageExplanationQualityRating() {
        return feedbackRepository.getAverageExplanationQualityRating();
    }

    public Long getCorrectDetectionsCount() {
        return feedbackRepository.countCorrectDetections();
    }

    public Long getIncorrectDetectionsCount() {
        return feedbackRepository.countIncorrectDetections();
    }

    public Double getAccuracyPercentage() {
        Long correct = getCorrectDetectionsCount();
        Long incorrect = getIncorrectDetectionsCount();
        Long total = correct + incorrect;
        
        if (total == 0) {
            return 0.0;
        }
        
        return (correct.doubleValue() / total.doubleValue()) * 100.0;
    }
}
